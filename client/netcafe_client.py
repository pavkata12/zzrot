import sys
import os
import asyncio
import json
import logging
from datetime import datetime
import socket
import uuid
import traceback
import ctypes
import threading
import psutil
import subprocess
import weakref
from contextlib import asynccontextmanager

from PySide6.QtWidgets import (
    QApplication, QWidget, QLabel, QVBoxLayout, QSystemTrayIcon, 
    QMenu, QPushButton, QLineEdit, QMessageBox, QDialog, QHBoxLayout
)
from PySide6.QtCore import Qt, QTimer, Signal, Slot, QThread
from PySide6.QtGui import QIcon, QAction, QPixmap, QPainter
import qasync
import aiohttp
import win32con
import win32api
import win32gui
import win32process

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('client.log', encoding='utf-8'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Global task manager to prevent concurrency issues
class TaskManager:
    def __init__(self):
        self._tasks = weakref.WeakSet()
        self._lock = asyncio.Lock()
        self._running_tasks = {}
    
    async def create_task(self, coro, name=None):
        # Check if task with same name is already running
        if name and name in self._running_tasks:
            existing_task = self._running_tasks[name]
            if not existing_task.done():
                print(f"⚠️  Task '{name}' already running, cancelling old one")
                existing_task.cancel()
                try:
                    await existing_task
                except asyncio.CancelledError:
                    pass
        
        async with self._lock:
            task = asyncio.create_task(coro, name=name)
            self._tasks.add(task)
            
            if name:
                self._running_tasks[name] = task
                # Clean up when task completes
                task.add_done_callback(lambda t: self._running_tasks.pop(name, None))
            
            return task
    
    async def cancel_all_tasks(self):
        async with self._lock:
            tasks = list(self._tasks)
            for task in tasks:
                if not task.done():
                    task.cancel()
            
            if tasks:
                await asyncio.gather(*tasks, return_exceptions=True)
            
            self._running_tasks.clear()

# Global task manager instance
task_manager = TaskManager()

class TimerOverlay(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowFlags(
            Qt.FramelessWindowHint |
            Qt.WindowStaysOnTopHint |
            Qt.Tool
        )
        self.setAttribute(Qt.WA_TranslucentBackground)
        self.setWindowTitle('🎮 NetCafe Experience Simulator - Session Timer')
        
        layout = QVBoxLayout(self)
        
        # Time display
        self.time_label = QLabel('00:00', self)
        self.time_label.setAlignment(Qt.AlignCenter)
        self.time_label.setStyleSheet('''
            background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
                stop:0 rgba(0,0,0,0.9), stop:1 rgba(26,26,46,0.9));
            color: #00FF88; 
            font-size: 60px; 
            border-radius: 24px; 
            padding: 40px 20px; 
            font-weight: bold;
            border: 3px solid rgba(0,255,136,0.5);
        ''')
        layout.addWidget(self.time_label)
        
        # Status display
        self.status_label = QLabel('🟢 Session Active', self)
        self.status_label.setAlignment(Qt.AlignCenter)
        self.status_label.setStyleSheet('''
            color: white; 
            font-size: 18px; 
            margin-top: 8px; 
            background: rgba(0,255,136,0.2); 
            padding: 10px; 
            border-radius: 8px;
            border: 2px solid rgba(0,255,136,0.3);
        ''')
        layout.addWidget(self.status_label)
        
        # Control buttons
        btn_layout = QHBoxLayout()
        
        self.minimize_btn = QPushButton('🔽 Minimize', self)
        self.minimize_btn.setStyleSheet(self.get_button_style('#00FF88'))
        
        self.end_btn = QPushButton('🛑 End Session', self)
        self.end_btn.setStyleSheet(self.get_button_style('#FF4444'))
        
        btn_layout.addWidget(self.minimize_btn)
        btn_layout.addWidget(self.end_btn)
        layout.addLayout(btn_layout)
        
        self.resize(800, 200)
        self.move(200, 40)
    
    def get_button_style(self, color):
        return f'''
            QPushButton {{
                font-size: 16px; 
                padding: 10px 20px; 
                background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
                    stop:0 {color}, stop:1 {color}AA);
                color: white; 
                border-radius: 8px; 
                font-weight: bold;
                border: 2px solid {color};
            }}
            QPushButton:hover {{
                background: {color};
                transform: translateY(-2px);
            }}
        '''
    
    def set_time(self, time_str):
        self.time_label.setText(time_str)
    
    def set_status(self, status):
        self.status_label.setText(status)

class LockScreen(QWidget):
    def __init__(self):
        super().__init__()
        # SECURITY: Remove all window controls, make it impossible to close
        self.setWindowFlags(
            Qt.Window | 
            Qt.FramelessWindowHint | 
            Qt.WindowStaysOnTopHint |
            Qt.CustomizeWindowHint  # This removes close button
        )
        self.setStyleSheet('''
            background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
                stop:0 #0a0a0a, stop:1 #1a1a2e);
        ''')
        
        layout = QVBoxLayout(self)
        
        # Logo
        logo_label = QLabel('🎮 NetCafe Experience Simulator', self)
        logo_label.setStyleSheet('''
            color: #00FF88; 
            font-size: 48px; 
            font-weight: bold; 
            margin-bottom: 30px;
            background: rgba(0,255,136,0.1);
            padding: 20px;
            border-radius: 16px;
            border: 3px solid rgba(0,255,136,0.3);
        ''')
        logo_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(logo_label)
        
        # Status message
        self.status_label = QLabel('🔒 Locked Simulator', self)
        self.status_label.setStyleSheet('''
            color: white; 
            font-size: 36px; 
            font-weight: bold;
            margin-bottom: 20px;
        ''')
        self.status_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(self.status_label)
        
        # Details
        self.details_label = QLabel('Simulating Real Experience\nPlease login to start your session...', self)
        self.details_label.setStyleSheet('''
            color: #aaa; 
            font-size: 20px; 
            margin-top: 24px;
            background: rgba(255,255,255,0.1);
            padding: 20px;
            border-radius: 12px;
        ''')
        self.details_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(self.details_label)
        
        # Connection indicator
        self.connection_label = QLabel('🔴 Connecting to server...', self)
        self.connection_label.setStyleSheet('''
            color: #FF4444;
            font-size: 18px;
            margin-top: 20px;
            padding: 10px;
            background: rgba(255,68,68,0.2);
            border-radius: 8px;
            border: 2px solid rgba(255,68,68,0.3);
        ''')
        self.connection_label.setAlignment(Qt.AlignCenter)
        layout.addWidget(self.connection_label)
        
        # Login Button - ALWAYS VISIBLE
        self.login_button = QPushButton('🔐 LOGIN', self)
        self.login_button.setStyleSheet('''
            QPushButton {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
                    stop:0 #00FF88, stop:1 #00D4AA);
                color: black;
                font-family: "Segoe UI", Arial, sans-serif;
                font-size: 28px;
                font-weight: bold;
                padding: 0px;
                border: 3px solid rgba(0,255,136,0.8);
                border-radius: 16px;
                margin-top: 30px;
                text-align: center;
            }
            QPushButton:hover {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
                    stop:0 #00D4AA, stop:1 #00FF88);
                border: 3px solid #00FF88;
                color: #001100;
            }
            QPushButton:pressed {
                background: #008855;
                border: 3px solid #00AA66;
                color: white;
            }
            QPushButton:disabled {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
                    stop:0 #444444, stop:1 #333333);
                color: #888888;
                border: 3px solid #666666;
            }
        ''')
        self.login_button.setFixedSize(350, 90)
        self.login_button.setFont(self.login_button.font())
        
        # Add some spacing before button
        layout.addStretch()
        
        # Center the button with proper spacing
        button_container = QWidget()
        button_layout = QVBoxLayout(button_container)
        button_layout.setContentsMargins(0, 20, 0, 40)
        
        # Horizontal centering
        h_layout = QHBoxLayout()
        h_layout.addStretch()
        h_layout.addWidget(self.login_button)
        h_layout.addStretch()
        
        button_layout.addLayout(h_layout)
        layout.addWidget(button_container)
        
        # Initially disabled until connected
        self.login_button.setEnabled(False)
    
    def show_lock(self, message='🔒 Locked Simulator', details='Please login to continue...'):
        self.status_label.setText(message)
        self.details_label.setText(details)
        self.showFullScreen()
        self.raise_()
        self.activateWindow()
    
    def hide_lock(self):
        self.hide()
    
    def set_connection_status(self, status, connected=False):
        if connected:
            self.connection_label.setText(f'🟢 {status}')
            self.connection_label.setStyleSheet('''
                color: #00FF88;
                font-size: 18px;
                margin-top: 20px;
                padding: 10px;
                background: rgba(0,255,136,0.2);
                border-radius: 8px;
                border: 2px solid rgba(0,255,136,0.3);
            ''')
            # Enable login button when connected
            self.login_button.setEnabled(True)
        else:
            self.connection_label.setText(f'🔴 {status}')
            self.connection_label.setStyleSheet('''
                color: #FF4444;
                font-size: 18px;
                margin-top: 20px;
                padding: 10px;
                background: rgba(255,68,68,0.2);
                border-radius: 8px;
                border: 2px solid rgba(255,68,68,0.3);
            ''')
            # Disable login button when not connected
            self.login_button.setEnabled(False)
    
    def set_login_callback(self, callback):
        """Set the callback function for when login button is clicked"""
        self.login_button.clicked.connect(callback)
    
    # SECURITY: Override close event to prevent closing
    def closeEvent(self, event):
        """Prevent lock screen from being closed by any means"""
        logger.warning("🔒 SECURITY: Attempt to close lock screen blocked!")
        event.ignore()  # Reject close event
    
    # SECURITY: Override key events to block Alt+F4
    def keyPressEvent(self, event):
        """Block all attempts to close via keyboard"""
        # Block Alt+F4
        if event.key() == Qt.Key_F4 and event.modifiers() == Qt.AltModifier:
            logger.warning("🔒 SECURITY: Alt+F4 blocked on lock screen!")
            event.ignore()
            return
        # Block Escape key
        elif event.key() == Qt.Key_Escape:
            logger.warning("🔒 SECURITY: Escape key blocked on lock screen!")
            event.ignore()
            return
        # Allow other keys
        super().keyPressEvent(event)

class LoginDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle('🎮 NetCafe Experience Simulator - Login')
        self.setFixedSize(450, 300)
        
        # SECURITY: Remove close button and make dialog modal + always on top
        self.setWindowFlags(
            Qt.Dialog | 
            Qt.WindowStaysOnTopHint | 
            Qt.CustomizeWindowHint |  # This removes close button
            Qt.WindowTitleHint |      # Keep title bar but no close button
            Qt.WindowSystemMenuHint |  # Keep system menu but no close
            Qt.Tool  # Tool windows appear above normal windows
        )
        
        # SECURITY: Make dialog modal so it blocks interaction with other windows
        self.setModal(True)
        
        # Force window to be on top layer
        self.setAttribute(Qt.WA_ShowWithoutActivating, False)
        self.setAttribute(Qt.WA_AlwaysShowToolTips, True)
        
        # Gaming style
        self.setStyleSheet('''
            QDialog {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
                    stop:0 #1a1a2e, stop:1 #16213e);
                border-radius: 12px;
                border: 3px solid rgba(0,255,136,0.5);
            }
            QLabel {
                color: white;
                font-size: 14px;
            }
            QLineEdit {
                background: rgba(255,255,255,0.1);
                border: 2px solid rgba(0,255,136,0.3);
                border-radius: 8px;
                padding: 12px;
                color: white;
                font-size: 14px;
            }
            QLineEdit:focus {
                border: 2px solid #00FF88;
                background: rgba(255,255,255,0.15);
            }
            QPushButton {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
                    stop:0 #00FF88, stop:1 #00D4AA);
                color: black;
                border: none;
                border-radius: 8px;
                padding: 12px 24px;
                font-size: 14px;
                font-weight: bold;
            }
            QPushButton:hover {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:1,
                    stop:0 #00D4AA, stop:1 #00FF88);
                transform: translateY(-2px);
            }
        ''')
        
        layout = QVBoxLayout(self)
        
        # Header
        header_label = QLabel('🎮 Welcome to NetCafe Pro 2.0')
        header_label.setAlignment(Qt.AlignCenter)
        header_label.setStyleSheet('''
            font-size: 20px; 
            font-weight: bold; 
            color: #00FF88; 
            margin-bottom: 20px;
            background: rgba(0,255,136,0.1);
            padding: 15px;
            border-radius: 8px;
        ''')
        layout.addWidget(header_label)
        
        # Username
        layout.addWidget(QLabel('👤 Username:'))
        self.username_input = QLineEdit()
        self.username_input.setPlaceholderText('Enter your username')
        layout.addWidget(self.username_input)
        
        # Password
        layout.addWidget(QLabel('🔒 Password:'))
        self.password_input = QLineEdit()
        self.password_input.setPlaceholderText('Enter your password')
        self.password_input.setEchoMode(QLineEdit.Password)
        layout.addWidget(self.password_input)
        
        # SECURITY: Only Login button, NO Cancel button
        login_btn = QPushButton('🚀 Start Gaming')
        login_btn.clicked.connect(self.try_login)
        login_btn.setDefault(True)
        layout.addWidget(login_btn)
        
        # Connect Enter key
        self.password_input.returnPressed.connect(self.try_login)
        self.username_input.returnPressed.connect(self.password_input.setFocus)
        
        self.accepted_login = False
        self.auto_retry = True  # Auto-retry on failed login
    
    def try_login(self):
        username = self.username_input.text().strip()
        password = self.password_input.text().strip()
        if not username or not password:
            QMessageBox.warning(self, '⚠️ Warning', 'Please enter both username and password!')
            # Clear fields and try again
            self.username_input.clear()
            self.password_input.clear()
            self.username_input.setFocus()
            return
        self.accepted_login = True
        self.accept()
    
    def get_credentials(self):
        return self.username_input.text().strip(), self.password_input.text().strip()
    
    # SECURITY: Override close event to prevent closing
    def closeEvent(self, event):
        """Prevent login dialog from being closed by any means"""
        logger.warning("🔒 SECURITY: Attempt to close login dialog blocked!")
        event.ignore()  # Reject close event
    
    # SECURITY: Override key events to block Alt+F4 and Escape
    def keyPressEvent(self, event):
        """Block all attempts to close via keyboard"""
        # Block Alt+F4
        if event.key() == Qt.Key_F4 and event.modifiers() == Qt.AltModifier:
            logger.warning("🔒 SECURITY: Alt+F4 blocked on login dialog!")
            event.ignore()
            return
        # Block Escape key
        elif event.key() == Qt.Key_Escape:
            logger.warning("🔒 SECURITY: Escape key blocked on login dialog!")
            event.ignore()
            return
        # Allow other keys (like Tab, Enter, etc.)
        super().keyPressEvent(event)
    
    # SECURITY: Override reject to prevent closing via any reject signal
    def reject(self):
        """Prevent dialog from being rejected/closed"""
        logger.warning("🔒 SECURITY: Attempt to reject login dialog blocked!")
        # Don't call super().reject() - this prevents closing

    # SECURITY: Show login with auto-retry on failed attempts
    def show_secure_login(self):
        """Show login dialog with automatic retry on failure"""
        while True:
            result = self.exec()
            if result == QDialog.Accepted and self.accepted_login:
                return True
            else:
                # Auto-retry: Clear fields and show again
                self.username_input.clear()
                self.password_input.clear()
                self.username_input.setFocus()
                self.accepted_login = False
                # Continue loop to show dialog again

class KeyboardBlocker:
    def __init__(self):
        self.hooked = None
        self.enabled = False
        self.lock_mode = False  # True = lock screen (strict), False = session mode (minimal)
        self.pointer = None
        self.thread = None
    
    def install(self, lock_mode=True):
        """Install keyboard blocker
        lock_mode=True: Lock screen mode (blocks Alt+Tab, Alt+F4, Windows keys)
        lock_mode=False: Session mode (minimal blocking, let users game freely)
        """
        if self.hooked:
            self.uninstall()  # Uninstall previous hook first
        
        self.lock_mode = lock_mode
        
        try:
            # Import required Windows APIs
            from ctypes import wintypes
            
            # Define hook function type
            HOOKPROC = ctypes.WINFUNCTYPE(ctypes.c_int, ctypes.c_int, wintypes.WPARAM, wintypes.LPARAM)
            
            # Get required DLLs
            user32 = ctypes.windll.user32
            kernel32 = ctypes.windll.kernel32
            
            # Constants for low-level keyboard hook
            WH_KEYBOARD_LL = 13
            WM_KEYDOWN = 0x0100
            WM_SYSKEYDOWN = 0x0104
            
            def low_level_keyboard_proc(nCode, wParam, lParam):
                try:
                    if not self.enabled or nCode < 0:
                        return user32.CallNextHookExW(self.hooked, nCode, wParam, lParam)
                    
                    if nCode == 0:  # HC_ACTION
                        # Get virtual key code from lParam structure
                        vk_code = ctypes.cast(lParam, ctypes.POINTER(wintypes.DWORD))[0]
                        
                        # Only process key down events
                        if wParam in (WM_KEYDOWN, WM_SYSKEYDOWN):
                            
                            # Lock mode: Strict blocking when computer is locked
                            if self.lock_mode:
                                # Block Windows keys (Left: 0x5B, Right: 0x5C)
                                if vk_code in (0x5B, 0x5C):
                                    logger.info(f"🔒 BLOCKED Windows key (VK: {hex(vk_code)})")
                                    return 1
                                
                                # Block Tab key completely (catches Alt+Tab)
                                if vk_code == 0x09:
                                    logger.info("🔒 BLOCKED Tab key (Alt+Tab prevention)")
                                    return 1
                                
                                # Block F4 key completely (catches Alt+F4)
                                if vk_code == 0x73:
                                    logger.info("🔒 BLOCKED F4 key (Alt+F4 prevention)")
                                    return 1
                                
                                # Block Escape key completely (catches Ctrl+Esc)
                                if vk_code == 0x1B:
                                    logger.info("🔒 BLOCKED Escape key (system menu prevention)")
                                    return 1
                                
                                # Block additional system keys
                                blocked_keys = {
                                    0x5D: "Menu/Context key",
                                    0x2C: "Print Screen",
                                    0x91: "Scroll Lock",
                                    0x13: "Pause/Break",
                                    0x2D: "Insert",
                                    0x2E: "Delete",
                                    0x24: "Home",
                                    0x23: "End",
                                    0x21: "Page Up",
                                    0x22: "Page Down"
                                }
                                
                                if vk_code in blocked_keys:
                                    logger.info(f"🔒 BLOCKED {blocked_keys[vk_code]} key")
                                    return 1
                                
                                # Block Alt key itself to prevent Alt+anything
                                if vk_code in (0x12, 0xA4, 0xA5):  # Alt, Left Alt, Right Alt
                                    logger.info("🔒 BLOCKED Alt key")
                                    return 1
                                
                                # Block Ctrl key to prevent Ctrl+anything
                                if vk_code in (0x11, 0xA2, 0xA3):  # Ctrl, Left Ctrl, Right Ctrl
                                    logger.info("🔒 BLOCKED Ctrl key")
                                    return 1
                                
                                # Block function keys
                                if 0x70 <= vk_code <= 0x87:  # F1-F24
                                    logger.info(f"🔒 BLOCKED F{vk_code - 0x6F} key")
                                    return 1
                            
                            # Session mode: Minimal blocking - let users game normally
                            else:
                                # Only block specific dangerous combinations during gaming
                                
                                # Block Ctrl+Shift+Esc (Task Manager)
                                if (vk_code == 0x1B and 
                                    user32.GetAsyncKeyState(0x11) & 0x8000 and  # Ctrl
                                    user32.GetAsyncKeyState(0x10) & 0x8000):    # Shift
                                    logger.info("🎮 BLOCKED Ctrl+Shift+Esc during gaming")
                                    return 1
                                
                                # Block Windows keys during gaming too
                                if vk_code in (0x5B, 0x5C):
                                    logger.info(f"🎮 BLOCKED Windows key during gaming")
                                    return 1
                    
                    return user32.CallNextHookExW(self.hooked, nCode, wParam, lParam)
                    
                except Exception as e:
                    logger.error(f"Hook procedure error: {e}")
                    return user32.CallNextHookExW(self.hooked, nCode, wParam, lParam)
            
            # Create hook function
            self.pointer = HOOKPROC(low_level_keyboard_proc)
            
            # Install the hook
            self.hooked = user32.SetWindowsHookExW(
                WH_KEYBOARD_LL,
                self.pointer,
                kernel32.GetModuleHandleW(None),
                0
            )
            
            if not self.hooked:
                error_code = ctypes.get_last_error()
                raise Exception(f"SetWindowsHookEx failed with error code: {error_code}")
            
            self.enabled = True
            
            mode_str = "Lock mode (strict blocking)" if lock_mode else "Gaming mode (minimal blocking)"
            logger.info(f"🔐 Keyboard blocker installed successfully ({mode_str})")
            
            # Test that blocking is working
            if lock_mode:
                logger.info("🔒 LOCK SCREEN PROTECTION ACTIVE:")
                logger.info("   - Windows keys BLOCKED")
                logger.info("   - Alt+Tab BLOCKED") 
                logger.info("   - Alt+F4 BLOCKED")
                logger.info("   - Ctrl+Esc BLOCKED")
                logger.info("   - Function keys BLOCKED")
                logger.info("   - System keys BLOCKED")
            else:
                logger.info("🎮 GAMING PROTECTION ACTIVE:")
                logger.info("   - Windows keys BLOCKED")
                logger.info("   - Task Manager BLOCKED")
                logger.info("   - Most gaming keys ALLOWED")
                
        except Exception as e:
            logger.error(f"❌ Failed to install keyboard blocker: {e}")
            logger.error(f"Error details: {traceback.format_exc()}")
            logger.warning("⚠️  ADMINISTRATOR PRIVILEGES REQUIRED for keyboard blocking!")
            logger.warning("⚠️  Please restart client as Administrator for full protection!")
            self.enabled = False
    
    def uninstall(self):
        if self.hooked:
            try:
                self.enabled = False
                ctypes.windll.user32.UnhookWindowsHookEx(self.hooked)
                self.hooked = None
                self.pointer = None
                
                # Stop message pump thread
                if self.thread and self.thread.is_alive():
                    self.thread.join(timeout=1)
                    
                logger.info("🔐 Keyboard blocker uninstalled successfully")
            except Exception as e:
                logger.error(f"Failed to uninstall keyboard blocker: {e}")

class FolderBlocker:
    """Blocks access to file manager and folders during gaming sessions"""
    
    def __init__(self):
        self.enabled = False
        self.monitor_thread = None
        self.blocked_processes = [
            'explorer.exe',      # Windows Explorer
            'cmd.exe',          # Command Prompt  
            'powershell.exe',   # PowerShell
            'winfile.exe',      # File Manager (old)
            'regedit.exe',      # Registry Editor
            'taskmgr.exe',      # Task Manager
            'msconfig.exe',     # System Configuration
            'control.exe',      # Control Panel
            'mmc.exe'           # Microsoft Management Console
        ]
        self.allowed_games = [
            # Gaming platforms
            'steam.exe', 'steamwebhelper.exe', 'gameoverlayui.exe', 'steamservice.exe',
            'origin.exe', 'originwebhelperservice.exe', 'originthinsetupinternal.exe',
            'epicgameslauncher.exe', 'epicgameslauncher-win32-shipping.exe', 'epicwebhelper.exe',
            'battle.net.exe', 'agent.exe', 'blizzard update agent.exe',
            'uplay.exe', 'upc.exe', 'ubisoftconnect.exe',
            'gog galaxy.exe', 'goggalaxy.exe',
            
            # League of Legends (ALL executables!)
            'leagueclient.exe', 'leagueclientux.exe', 'leagueclientuxrender.exe',
            'league of legends.exe', 'riotclientservices.exe', 'riotclientux.exe',
            'riotclientcrashhandler.exe', 'riotclientuxrender.exe',
            
            # Popular games
            'csgo.exe', 'cs2.exe', 'dota2.exe', 'valorant.exe', 'valorant-win64-shipping.exe',
            'fortnite.exe', 'fortniteclient-win64-shipping.exe',
            'gta5.exe', 'gtav.exe', 'rdr2.exe',
            'minecraft.exe', 'minecraftlauncher.exe', 'javaw.exe',
            'wow.exe', 'worldofwarcraft.exe', 'wowclassic.exe',
            'overwatch.exe', 'overwatch2.exe',
            'apex_legends.exe', 'r5apex.exe',
            'pubg.exe', 'tslgame.exe',
            'destiny2.exe', 'destiny2launcher.exe',
            'fifa23.exe', 'fifa24.exe', 'fc24.exe',
            'rocket league.exe', 'rocketleague.exe',
            'fall guys.exe', 'fallguys_client_game.exe',
            
            # Communication
            'discord.exe', 'discordptb.exe', 'discordcanary.exe',
            'teamspeak3.exe', 'ts3client_win64.exe',
            'skype.exe', 'slack.exe',
            
            # Web browsers for gaming
            'chrome.exe', 'firefox.exe', 'msedge.exe', 'opera.exe', 'brave.exe',
            
            # Media players
            'vlc.exe', 'wmplayer.exe', 'spotify.exe', 'musicbee.exe',
            
            # System processes that should not be blocked
            'dwm.exe', 'winlogon.exe', 'csrss.exe', 'smss.exe', 'wininit.exe',
            'services.exe', 'lsass.exe', 'svchost.exe', 'spoolsv.exe',
            'audiodg.exe', 'conhost.exe', 'fontdrvhost.exe',
            
            # Graphics and drivers
            'nvcontainer.exe', 'nvidia web helper.exe', 'nvidia share.exe',
            'amdrsserv.exe', 'radeoninstaller.exe', 'amdow.exe',
            'igfxem.exe', 'igfxtray.exe', 'hkcmd.exe',
            
            # Gaming accessories
            'logioptionsplus.exe', 'lghub.exe', 'razer synapse 3.exe',
            'corsair icue 4 software.exe', 'steelseries engine 3.exe'
        ]
    
    def install(self):
        """Start monitoring and blocking folder access"""
        if self.enabled:
            return
            
        self.enabled = True
        self.monitor_thread = threading.Thread(target=self._monitor_processes, daemon=True)
        self.monitor_thread.start()
        logger.info("🛡️  Folder blocker installed - File system access restricted")
    
    def uninstall(self):
        """Stop monitoring"""
        self.enabled = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=1)
            self.monitor_thread = None
        logger.info("🛡️  Folder blocker uninstalled - File system access restored")
    
    def _monitor_processes(self):
        """Monitor running processes and terminate blocked ones"""
        blocked_count = 0
        
        while self.enabled:
            try:
                for proc in psutil.process_iter(['pid', 'name', 'exe']):
                    if not self.enabled:
                        break
                        
                    try:
                        proc_name = proc.info['name'].lower()
                        
                        # Skip allowed processes
                        if any(allowed in proc_name for allowed in self.allowed_games):
                            continue
                        
                        # Check if process should be blocked
                        if any(blocked in proc_name for blocked in self.blocked_processes):
                            # Don't kill the main Windows explorer (shell)
                            if proc_name == 'explorer.exe':
                                # Check if it's a folder window (not the desktop shell)
                                if self._is_folder_explorer_window(proc.info['pid']):
                                    proc.terminate()
                                    blocked_count += 1
                                    logger.info(f"🚫 Blocked folder access: {proc_name} (PID: {proc.info['pid']})")
                            else:
                                proc.terminate()
                                blocked_count += 1
                                logger.info(f"🚫 Blocked system tool: {proc_name} (PID: {proc.info['pid']})")
                        
                        # Block new folder windows by checking window titles
                        elif proc_name == 'explorer.exe':
                            if self._check_explorer_windows():
                                blocked_count += 1
                    
                    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                        continue
                
                # Log summary periodically
                if blocked_count > 0 and blocked_count % 5 == 0:
                    logger.info(f"🛡️  Gaming session protected - {blocked_count} access attempts blocked")
                
                # Check every 2 seconds
                for _ in range(20):
                    if not self.enabled:
                        break
                    threading.Event().wait(0.1)
                        
            except Exception as e:
                logger.error(f"Folder blocker error: {e}")
                threading.Event().wait(1)
    
    def _is_folder_explorer_window(self, pid):
        """Check if explorer.exe process is a folder window"""
        try:
            # Get windows for this process
            def enum_windows_callback(hwnd, windows):
                if win32gui.IsWindowVisible(hwnd):
                    _, window_pid = win32process.GetWindowThreadProcessId(hwnd)
                    if window_pid == pid:
                        window_title = win32gui.GetWindowText(hwnd)
                        class_name = win32gui.GetClassName(hwnd)
                        windows.append((hwnd, window_title, class_name))
                return True
            
            windows = []
            win32gui.EnumWindows(enum_windows_callback, windows)
            
            for hwnd, title, class_name in windows:
                # Check for typical folder window indicators
                if (class_name == 'CabinetWClass' or  # Standard folder window
                    'Explorer' in class_name or
                    any(folder_indicator in title.lower() for folder_indicator in 
                        ['documents', 'downloads', 'desktop', 'pictures', 'music', 'videos', 
                         'program files', 'windows', 'users', 'local disk', 'drive'])):
                    return True
            
            return False
        except Exception:
            return False
    
    def _check_explorer_windows(self):
        """Check for and close unauthorized explorer windows"""
        try:
            def enum_windows_callback(hwnd, windows):
                if win32gui.IsWindowVisible(hwnd):
                    window_title = win32gui.GetWindowText(hwnd)
                    class_name = win32gui.GetClassName(hwnd)
                    
                    # Check for folder windows
                    if (class_name == 'CabinetWClass' or
                        any(folder_indicator in window_title.lower() for folder_indicator in 
                            ['documents', 'downloads', 'desktop', 'pictures', 'music', 'videos', 
                             'program files', 'windows', 'users', 'local disk', 'drive', 'folder'])):
                        try:
                            win32gui.PostMessage(hwnd, win32con.WM_CLOSE, 0, 0)
                            logger.info(f"🚫 Closed folder window: {window_title}")
                            windows.append(hwnd)
                        except Exception:
                            pass
                return True
            
            windows = []
            win32gui.EnumWindows(enum_windows_callback, windows)
            return len(windows) > 0
            
        except Exception as e:
            logger.debug(f"Window check error: {e}")
            return False

class NetCafeClient:
    def __init__(self):
        self.app = QApplication(sys.argv)
        self.loop = qasync.QEventLoop(self.app)
        asyncio.set_event_loop(self.loop)
        
        # Load configuration
        self.config = self._load_config()
        
        # Components
        self.timer_overlay = TimerOverlay()
        self.lock_screen = LockScreen()
        self.keyboard_blocker = KeyboardBlocker()
        self.folder_blocker = FolderBlocker()  # Add folder blocker
        
        # State
        self.session_active = False
        self.remaining_time = 0
        self.session_id = None
        self.computer_id = self._get_computer_id()
        
        # Server configuration
        self.server_hosts = [self.config['server']['host']] + self.config['server'].get('fallback_hosts', [])
        self.server_port = self.config['server']['port']
        self.current_host_index = 0
        
        # Network
        self.session = None
        self.ws = None
        self.ws_task = None
        self.reconnect_attempts = 0
        self.max_reconnect_attempts = self.config['server']['max_reconnect_attempts']
        
        # Timers
        self.session_timer = QTimer()
        self.session_timer.timeout.connect(self._tick)
        self.reconnect_timer = QTimer()
        self.reconnect_timer.timeout.connect(self._try_reconnect)
        
        # Notifications
        self._notified_5min = False
        self._notified_1min = False
        
        # Initialize system tray and UI
        self._init_tray()
        
        # Connect overlay button signals
        self.timer_overlay.minimize_btn.clicked.connect(self._minimize_overlay)
        self.timer_overlay.end_btn.clicked.connect(lambda: asyncio.create_task(self._end_session()))
        
        # Connect lock screen login button
        self.lock_screen.set_login_callback(self._manual_login)
        
        # Start with lock screen
        self._show_lock_screen()
        
        # Ensure lock screen is visible and active
        QTimer.singleShot(500, self._ensure_lock_screen_visible)
        
        logger.info(f"NetCafe Experience Simulator initialized. Computer ID: {self.computer_id}")
        
        # Set initial status
        self.set_status('Initializing...', False)
    
    def _load_config(self):
        """Load configuration from config.json"""
        try:
            with open('config.json', 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            logger.warning(f"Failed to load config.json: {e}, using defaults")
            return {
                "server": {
                    "host": "localhost",
                    "port": 8080,
                    "websocket_endpoint": "/ws",
                    "max_reconnect_attempts": 10,
                    "fallback_hosts": ["127.0.0.1"]
                }
            }
    
    def _get_current_server_url(self):
        """Get current server URL based on host index"""
        if self.current_host_index < len(self.server_hosts):
            host = self.server_hosts[self.current_host_index]
            return f"http://{host}:{self.server_port}"
        return f"http://{self.server_hosts[0]}:{self.server_port}"
    
    def _get_computer_id(self):
        try:
            hostname = socket.gethostname()
            mac = uuid.getnode()
            return f"{hostname}_{mac}"
        except Exception:
            return f"client_{uuid.uuid4().hex[:8]}"
    
    def _init_tray(self):
        try:
            self.tray = QSystemTrayIcon()
            
            # Create gaming icon
            pixmap = QPixmap(32, 32)
            pixmap.fill(Qt.transparent)
            painter = QPainter(pixmap)
            painter.setBrush(Qt.green)
            painter.drawEllipse(2, 2, 28, 28)
            painter.setBrush(Qt.black)
            painter.drawEllipse(8, 8, 16, 16)
            painter.end()
            
            self.tray.setIcon(QIcon(pixmap))
            self.tray.setToolTip('🎮 NetCafe Experience Simulator - Gaming Client')
            
            # Context menu
            menu = QMenu()
            
            self.status_action = QAction('🔴 Disconnected')
            self.status_action.setEnabled(False)
            menu.addAction(self.status_action)
            
            menu.addSeparator()
            
            # Login action
            self.login_action = QAction('🔐 Login')
            self.login_action.triggered.connect(self._manual_login)
            menu.addAction(self.login_action)
            
            show_timer_action = QAction('⏰ Show Timer')
            show_timer_action.triggered.connect(self._show_overlay)
            menu.addAction(show_timer_action)
            
            reconnect_action = QAction('🔄 Reconnect')
            reconnect_action.triggered.connect(self._manual_reconnect)
            menu.addAction(reconnect_action)
            
            # Login action
            self.login_action = QAction('🔐 Login')
            self.login_action.triggered.connect(self._manual_login)
            menu.addAction(self.login_action)
            
            menu.addSeparator()
            
            exit_action = QAction('❌ Exit')
            exit_action.triggered.connect(self._exit)
            menu.addAction(exit_action)
            
            self.tray.setContextMenu(menu)
            self.tray.activated.connect(self._on_tray_activated)
            self.tray.show()
            
            logger.info("System tray initialized")
        except Exception as e:
            logger.error(f"Failed to initialize tray: {e}")
    
    def _on_tray_activated(self, reason):
        if reason == QSystemTrayIcon.DoubleClick:
            if self.session_active:
                self._show_overlay()
            elif self.ws and not self.ws.closed:
                # Connected but no session - show login
                try:
                    if hasattr(self, 'loop') and not self.loop.is_closed():
                        self.loop.create_task(self.show_login())
                    else:
                        asyncio.create_task(self.show_login())
                except RuntimeError:
                    logger.warning("Unable to show login: event loop not available")
            else:
                # Not connected - show lock screen
                self._show_lock_screen()
    
    def _show_lock_screen(self):
        self.lock_screen.show_lock()
        self.keyboard_blocker.install(lock_mode=True)  # Strict blocking on lock screen
    
    def _ensure_lock_screen_visible(self):
        """Ensure lock screen is always visible when no session is active"""
        if not self.session_active:
            self.lock_screen.show_lock()
            self.lock_screen.raise_()
            self.lock_screen.activateWindow()
    
    def _hide_lock_screen(self):
        self.lock_screen.hide_lock()
        self.keyboard_blocker.uninstall()
    
    def _show_overlay(self):
        if self.session_active:
            self.timer_overlay.show()
            self.timer_overlay.raise_()
            self.timer_overlay.activateWindow()
    
    def _minimize_overlay(self):
        self.timer_overlay.hide()
        self.tray.showMessage(
            '🎮 NetCafe Experience Simulator',
            'Timer minimized. Double-click tray icon to restore.',
            QSystemTrayIcon.Information,
            3000
        )
    
    def _manual_reconnect(self):
        self.reconnect_attempts = 0
        asyncio.create_task(self.connect_to_server())
    
    def _manual_login(self):
        """Manual login trigger from tray menu"""
        if self.ws and not self.ws.closed and not self.session_active:
            try:
                if hasattr(self, 'loop') and not self.loop.is_closed():
                    self.loop.create_task(self.show_login())
                else:
                    asyncio.create_task(self.show_login())
            except RuntimeError:
                logger.warning("Unable to show login: event loop not available")
        else:
            self.tray.showMessage(
                '⚠️ Login Not Available',
                'Cannot login: Not connected to server or session already active.',
                QSystemTrayIcon.Warning,
                3000
            )
    
    def _exit(self):
        if self.session_active:
            asyncio.create_task(self._end_session())
        self._cleanup()
        self.app.quit()
    
    def _cleanup(self):
        try:
            self.session_timer.stop()
            self.reconnect_timer.stop()
            self.keyboard_blocker.uninstall()
            self.folder_blocker.uninstall()
            
            # Enhanced async resource cleanup
            try:
                # Cancel all managed tasks first
                if hasattr(task_manager, 'cancel_all_tasks'):
                    try:
                        loop = asyncio.get_running_loop()
                        if not loop.is_closed():
                            asyncio.create_task(task_manager.cancel_all_tasks())
                    except RuntimeError:
                        logger.info("Event loop not running, skipping async cleanup")
                
                # Close session if exists
                if self.session and not self.session.closed:
                    try:
                        # Try to close synchronously for cleanup
                        if hasattr(self.session, '_connector'):
                            self.session._connector_owner = False
                    except Exception:
                        pass  # Best effort cleanup
                        
            except Exception as e:
                logger.debug(f"Async cleanup handled: {e}")
            
            self.tray.hide()
            logger.info("Cleanup completed")
        except Exception as e:
            logger.error(f"Cleanup error: {e}")
    
    async def connect_to_server(self):
        if self.reconnect_attempts >= self.max_reconnect_attempts:
            self.set_status('Max reconnect attempts reached', False)
            return
        
        try:
            server_url = self._get_current_server_url()
            logger.info(f"Connecting to server: {server_url}")
            self.set_status('Connecting to server...', False)
            
            # Cancel existing WebSocket task first
            if hasattr(self, 'ws_task') and self.ws_task and not self.ws_task.done():
                self.ws_task.cancel()
                try:
                    await self.ws_task
                except asyncio.CancelledError:
                    pass
                self.ws_task = None
            
            # Close WebSocket connection
            if hasattr(self, 'ws') and self.ws and not self.ws.closed:
                try:
                    await self.ws.close()
                except Exception as e:
                    logger.debug(f"WebSocket close: {e}")
                self.ws = None
            
            # Close previous session properly
            if self.session and not self.session.closed:
                try:
                    await self.session.close()
                    await asyncio.sleep(0.1)  # Give time for cleanup
                except Exception as e:
                    logger.debug(f"Previous session cleanup: {e}")
                self.session = None
            
            # Create new session with proper timeout
            timeout = aiohttp.ClientTimeout(total=10, connect=5)
            self.session = aiohttp.ClientSession(timeout=timeout)
            
            # Test connection with better error handling
            try:
                async with self.session.get(f'{server_url}/api/status') as response:
                    if response.status == 200:
                        logger.info("Server is reachable")
                    else:
                        raise aiohttp.ClientError(f"Server returned status {response.status}")
            except asyncio.TimeoutError:
                raise Exception("Connection timeout - server not responding")
            except aiohttp.ClientConnectionError as e:
                raise Exception(f"Connection refused - server not running: {str(e)}")
            except Exception as e:
                raise Exception(f"Server test failed: {str(e)}")
            
            # Connect WebSocket with better error handling
            host = self.server_hosts[self.current_host_index]
            ws_url = f"ws://{host}:{self.server_port}/ws?computer_id={self.computer_id}"
            
            try:
                self.ws = await self.session.ws_connect(ws_url)
                logger.info("WebSocket connected")
            except Exception as e:
                raise Exception(f"WebSocket connection failed: {str(e)}")
            
            # Cancel any existing WebSocket handler first
            if hasattr(self, 'ws_task') and self.ws_task and not self.ws_task.done():
                self.ws_task.cancel()
                try:
                    await self.ws_task
                except asyncio.CancelledError:
                    pass
            
            # Start WebSocket message handler with proper task management
            try:
                self.ws_task = await task_manager.create_task(
                    self._handle_ws_messages(), 
                    name="websocket_handler"
                )
            except Exception as e:
                logger.error(f"Failed to start WebSocket handler: {e}")
                raise
            
            self.set_status('Ready for login', True)
            self.reconnect_attempts = 0
            
            # DON'T auto-show login - let user trigger it manually
            # This prevents auto-popup after session ends and reconnect
            logger.info("✅ Connected to server. Ready for manual login.")
            
        except Exception as e:
            # Enhanced error logging with specific error details
            error_msg = str(e) if str(e) else f"Unknown connection error: {type(e).__name__}"
            logger.error(f"Connection error: {error_msg}")
            
            self.reconnect_attempts += 1
            
            # Try next host if available
            if self.current_host_index < len(self.server_hosts) - 1:
                self.current_host_index += 1
                logger.info(f"Trying next host: {self.server_hosts[self.current_host_index]}")
            else:
                self.current_host_index = 0  # Reset to first host
            
            self.set_status(f'Connection failed (attempt {self.reconnect_attempts})', False)
            
            # Clean up failed connection
            if self.session:
                try:
                    await self.session.close()
                except Exception:
                    pass
                self.session = None
            
            self._start_reconnect_timer()
    
    async def show_login(self):
        """Show secure login dialog with auto-retry on failures"""
        try:
            dialog = LoginDialog()
            
            # Ensure lock screen is visible as background
            self._show_lock_screen()
            
            # Force dialog to appear on top of lock screen
            dialog.show()
            dialog.raise_()
            dialog.activateWindow()
            dialog.setFocus()
            
            # Give the system a moment to process window layering
            import time
            time.sleep(0.1)
            
            # Keep showing login until successful or user provides valid credentials
            max_attempts = 5
            attempt = 0
            
            while attempt < max_attempts:
                attempt += 1
                logger.info(f"🔐 Login attempt {attempt}/{max_attempts}")
                
                # Ensure dialog is on top before each attempt
                dialog.raise_()
                dialog.activateWindow()
                dialog.setFocus()
                
                if dialog.exec() and dialog.accepted_login:
                    username, password = dialog.get_credentials()
                    
                    # Try authentication
                    auth_result = await self.authenticate(username, password)
                    if auth_result:
                        # Success - break the loop
                        break
                    else:
                        # Failed authentication - clear fields and try again
                        dialog.username_input.clear()
                        dialog.password_input.clear()
                        dialog.username_input.setFocus()
                        dialog.accepted_login = False
                        
                        # Show retry message
                        if attempt < max_attempts:
                            QMessageBox.warning(
                                dialog, 
                                '❌ Login Failed', 
                                f'Invalid credentials!\n\nAttempt {attempt}/{max_attempts}\nPlease try again.'
                            )
                        else:
                            QMessageBox.critical(
                                dialog, 
                                '🚫 Access Denied', 
                                'Maximum login attempts reached!\nComputer will remain locked.'
                            )
                else:
                    # Dialog was somehow closed (shouldn't happen with our security)
                    logger.warning("🔒 SECURITY: Login dialog closed unexpectedly!")
                    dialog.accepted_login = False
                    # Continue loop to show again
            
            # If we got here without success, keep computer locked
            if attempt >= max_attempts:
                logger.warning("🔒 Maximum login attempts reached - keeping computer locked")
                self._show_lock_screen()
            
            # Always ensure lock screen is shown if no session is active
            elif not self.session_active:
                self._show_lock_screen()
                
        except Exception as e:
            logger.error(f"Login dialog error: {e}")
            # On error, show lock screen for security
            self._show_lock_screen()
    
    async def authenticate(self, username, password):
        """Authenticate user and return True on success, False on failure"""
        try:
            login_data = {
                'username': username,
                'password': password,
                'computer_id': self.computer_id
            }
            
            logger.info(f"🔐 Authenticating user: {username}")
            
            server_url = self._get_current_server_url()
            async with self.session.post(f'{server_url}/api/login', json=login_data) as response:
                if response.status == 200:
                    data = await response.json()
                    if data.get('success'):
                        self.session_id = data.get('session_id')
                        minutes = data.get('minutes', 0)
                        
                        logger.info(f"✅ Login successful: {username}, {minutes} minutes")
                        
                        if minutes > 0:
                            await self.start_session(minutes)
                            return True
                        else:
                            QMessageBox.warning(None, '⚠️ No Time', 'No time available for this user!')
                            return False
                    else:
                        logger.warning(f"❌ Authentication failed for {username}: {data.get('message', 'Unknown error')}")
                        return False
                        
                elif response.status == 401:
                    # Invalid credentials
                    logger.warning(f"❌ Invalid credentials for user: {username}")
                    return False
                    
                elif response.status == 403:
                    # User already logged in elsewhere or other restriction
                    data = await response.json()
                    logger.warning(f"❌ Access denied for {username}: {data.get('message', 'Access denied')}")
                    QMessageBox.warning(None, '🚫 Access Denied', data.get('message', 'Access denied'))
                    return False
                    
                else:
                    logger.error(f"❌ Server error during authentication: {response.status}")
                    QMessageBox.critical(None, '❌ Server Error', f'Server error: {response.status}')
                    return False
                    
        except Exception as e:
            logger.error(f"❌ Authentication error: {e}")
            QMessageBox.critical(None, '❌ Connection Error', f'Failed to connect to server: {str(e)}')
            return False
    
    async def start_session(self, minutes):
        try:
            logger.info(f"Starting session: {minutes} minutes")
            
            self.session_active = True
            self.remaining_time = minutes * 60
            self.initial_session_minutes = minutes  # Track initial minutes for proper calculation
            self.session_timer.start(1000)
            self._notified_5min = False
            self._notified_1min = False
            
            self._hide_lock_screen()
            
            # Gaming session: Only minimal keyboard blocking + folder blocking
            self.keyboard_blocker.install(lock_mode=False)  # Minimal blocking during gaming
            self.folder_blocker.install()  # Block folder access during session
            
            self._show_overlay()
            self._update_timer()
            
            self.set_status('🎮 Gaming Session Active', True)
            
            self.tray.showMessage(
                '🎮 NetCafe Pro 2.0',
                f'Gaming session started! {minutes} minutes available.\n📁 Folder access blocked.',
                QSystemTrayIcon.Information,
                5000
            )
            
        except Exception as e:
            logger.error(f"Start session error: {e}")
    
    async def _end_session(self):
        try:
            logger.info("Ending session")
            
            if self.session_id:
                # Fix: Calculate minutes used correctly
                # Total session time - remaining time = used time
                total_minutes = getattr(self, 'initial_session_minutes', 0)
                remaining_minutes = (self.remaining_time // 60) if self.remaining_time else 0
                minutes_used = max(0, total_minutes - remaining_minutes)
                
                logger.info(f"Session ending: Total={total_minutes}, Remaining={remaining_minutes}, Used={minutes_used}")
                
                logout_data = {
                    'session_id': self.session_id,
                    'minutes_used': minutes_used
                }
                
                try:
                    server_url = self._get_current_server_url()
                    async with self.session.post(f'{server_url}/api/logout', json=logout_data) as response:
                        if response.status == 200:
                            logger.info("Logout successful")
                        else:
                            logger.warning(f"Logout failed: {response.status}")
                except Exception as e:
                    logger.error(f"Logout error: {e}")
            
            # Force end locally
            self.session_active = False
            self.session_timer.stop()
            self.timer_overlay.hide()
            
            # Uninstall session protections
            self.keyboard_blocker.uninstall()
            self.folder_blocker.uninstall()
            
            # DON'T cancel WebSocket - we need it for future logins and force_logout messages
            # Keep WebSocket alive for admin communication
            
            # Reset session variables
            self.session_id = None
            self.remaining_time = 0
            self.initial_session_minutes = 0
            self._notified_5min = False
            self._notified_1min = False
            
            self._show_lock_screen()  # This will install strict lock-mode keyboard blocker
            
            # Set status but keep connection alive
            self.set_status('Ready for login', True if self.ws and not self.ws.closed else False)
            
            self.tray.showMessage(
                '🎮 NetCafe Pro 2.0',
                'Gaming session ended. Computer locked.\n🔒 Full keyboard protection active.',
                QSystemTrayIcon.Information,
                3000
            )
            
        except Exception as e:
            logger.error(f"End session error: {e}")
    
    def _tick(self):
        if not self.session_active:
            return
        
        self.remaining_time -= 1
        
        # Send session update every 10 seconds to keep server in sync
        if self.remaining_time % 10 == 0 and self.ws and self.session_id:
            try:
                # Send session update to server
                if hasattr(self, 'loop') and not self.loop.is_closed():
                    self.loop.create_task(self._send_session_update())
            except Exception as e:
                logger.debug(f"Failed to send session update: {e}")
        
        # Warnings
        if self.remaining_time <= 300 and not self._notified_5min:
            self._notified_5min = True
            self.tray.showMessage(
                '⚠️ Time Warning',
                'Your gaming session will end in 5 minutes!',
                QSystemTrayIcon.Warning,
                5000
            )
        
        if self.remaining_time <= 60 and not self._notified_1min:
            self._notified_1min = True
            self.tray.showMessage(
                '🚨 Final Warning',
                'Your gaming session will end in 1 minute!',
                QSystemTrayIcon.Critical,
                5000
            )
        
        if self.remaining_time <= 0:
            # Improved task creation with better error handling
            try:
                # Check if we're in the event loop context
                try:
                    current_task = asyncio.current_task()
                    if current_task and hasattr(self, 'loop') and not self.loop.is_closed():
                        # We're in an async context, use loop.create_task
                        self.loop.create_task(self._end_session())
                    else:
                        # Not in async context, queue for later execution
                        if hasattr(self, 'loop') and not self.loop.is_closed():
                            # Use call_soon_threadsafe for cross-thread safety
                            self.loop.call_soon_threadsafe(
                                lambda: self.loop.create_task(self._end_session())
                            )
                except RuntimeError:
                    # No current task, try direct task creation
                    if hasattr(self, 'loop') and not self.loop.is_closed():
                        self.loop.create_task(self._end_session())
                    else:
                        logger.warning("Unable to end session: no event loop available")
            except Exception as e:
                logger.error(f"Failed to schedule session end: {e}")
                # Force end session synchronously as last resort
                self.session_active = False
                self._show_lock_screen()
            return
        
        self._update_timer()
    
    async def _send_session_update(self):
        """Send session update to server"""
        try:
            if self.ws and self.session_id:
                update_data = {
                    'type': 'session_update',
                    'session_id': self.session_id,
                    'remaining_time': self.remaining_time
                }
                await self.ws.send_str(json.dumps(update_data))
        except Exception as e:
            logger.debug(f"Session update send error: {e}")
    
    def _update_timer(self):
        minutes = self.remaining_time // 60
        seconds = self.remaining_time % 60
        time_str = f"{minutes:02d}:{seconds:02d}"
        
        self.timer_overlay.set_time(time_str)
        self.tray.setToolTip(f'🎮 NetCafe Pro 2.0 - Time: {time_str}')
    
    def set_status(self, status, connected=False):
        self.lock_screen.set_connection_status(status, connected)
        self.timer_overlay.set_status(f"{'🟢' if connected else '🔴'} {status}")
        
        if hasattr(self, 'status_action'):
            self.status_action.setText(f"{'🟢' if connected else '🔴'} {status}")
        
        logger.info(f"Status: {status} (Connected: {connected})")
    
    async def _handle_ws_messages(self):
        """Enhanced WebSocket message handler with proper error handling"""
        if not self.ws:
            logger.error("WebSocket not connected")
            return
            
        try:
            logger.info("🔄 WebSocket message handler started")
            
            async for msg in self.ws:
                if msg.type == aiohttp.WSMsgType.TEXT:
                    try:
                        data = json.loads(msg.data)
                        await self._process_ws_message(data)
                    except json.JSONDecodeError as e:
                        logger.error(f"Invalid JSON in WebSocket message: {e}")
                    except Exception as e:
                        logger.error(f"Error processing WebSocket message: {e}")
                        
                elif msg.type == aiohttp.WSMsgType.ERROR:
                    logger.error(f'WebSocket error: {self.ws.exception()}')
                    break
                    
                elif msg.type in (aiohttp.WSMsgType.CLOSE, aiohttp.WSMsgType.CLOSED):
                    logger.info("WebSocket closed")
                    break
                    
        except asyncio.CancelledError:
            logger.info("WebSocket handler cancelled")
            raise  # Re-raise to properly handle cancellation
        except Exception as e:
            logger.error(f"WebSocket handler error: {e}")
        finally:
            logger.info("🔄 WebSocket message handler stopped")
    
    async def _process_ws_message(self, data):
        msg_type = data.get('type')
        
        if msg_type == 'force_logout':
            logger.info("🚨 Force logout received from server")
            
            # End the session first (but keep connection alive)
            await self._end_session()
            
            # Show message to user
            msg = QMessageBox()
            msg.setWindowTitle('⚠️ Session Ended')
            msg.setText(data.get('message', 'Your session was ended by administrator.'))
            msg.setIcon(QMessageBox.Information)
            msg.setStandardButtons(QMessageBox.Ok)
            msg.setStyleSheet('''
                QMessageBox {
                    background: #1a1a2e;
                    color: white;
                }
                QMessageBox QPushButton {
                    background: #00FF88;
                    color: black;
                    padding: 8px 16px;
                    border-radius: 4px;
                    font-weight: bold;
                }
            ''')
            
            # Show the message and wait for user to click OK
            result = msg.exec_()
            
            # After user clicks OK, reset to ready state instead of closing
            logger.info("🔄 Session ended by admin - client ready for new login")
            
            # Update status to show ready for login
            self.set_status('Ready for login', True)
            
            # Show notification
            self.tray.showMessage(
                '⚠️ Session Ended by Admin',
                'Your session was ended by administrator.\nComputer is now ready for new login.',
                QSystemTrayIcon.Warning,
                5000
            )
        
        elif msg_type == 'time_update':
            minutes = data.get('minutes', 0)
            if minutes > 0 and not self.session_active:
                await self.start_session(minutes)
    
    async def _cleanup_and_exit(self):
        """Clean shutdown of the application"""
        try:
            logger.info("🔄 Starting clean shutdown...")
            
            # Stop all timers
            if hasattr(self, 'session_timer'):
                self.session_timer.stop()
            if hasattr(self, 'reconnect_timer'):
                self.reconnect_timer.stop()
            
            # Cleanup resources
            self._cleanup()
            
            # Close WebSocket
            if self.ws and not self.ws.closed:
                await self.ws.close()
            
            # Close HTTP session
            if hasattr(self, 'session') and not self.session.closed:
                await self.session.close()
            
            # Hide all windows
            if hasattr(self, 'lock_screen'):
                self.lock_screen.hide()
            if hasattr(self, 'timer_overlay'):
                self.timer_overlay.hide()
            
            # Quit the application from main thread
            app = QApplication.instance()
            if app:
                # Use QTimer.singleShot to call quit from main thread
                QTimer.singleShot(100, app.quit)
            
            logger.info("✅ Clean shutdown completed")
            
        except Exception as e:
            logger.error(f"Error during cleanup: {e}")
            # Force quit even if cleanup fails
            app = QApplication.instance()
            if app:
                QTimer.singleShot(100, app.quit)
    
    def _start_reconnect_timer(self):
        if not self.reconnect_timer.isActive() and self.reconnect_attempts < self.max_reconnect_attempts:
            delay = min(5000 + (self.reconnect_attempts * 3000), 20000)
            self.reconnect_timer.start(delay)
            logger.info(f"Reconnecting in {delay/1000}s")
    
    def _try_reconnect(self):
        logger.info("Attempting reconnection...")
        try:
            if hasattr(self, 'loop') and not self.loop.is_closed():
                self.loop.create_task(self.connect_to_server())
            else:
                asyncio.create_task(self.connect_to_server())
        except RuntimeError:
            logger.warning("Unable to reconnect: event loop not available")
        self.reconnect_timer.stop()
    
    def run(self):
        logger.info("🎮 Starting NetCafe Pro 2.0 Gaming Client")
        
        try:
            with self.loop:
                self.loop.create_task(self.connect_to_server())
                self.loop.run_forever()
        except KeyboardInterrupt:
            logger.info("Interrupted by user")
        except Exception as e:
            logger.error(f"Application error: {e}")
        finally:
            # Proper async cleanup before loop closes
            try:
                if hasattr(self, 'loop') and not self.loop.is_closed():
                    # Cancel all pending tasks
                    pending = asyncio.all_tasks(self.loop)
                    if pending:
                        for task in pending:
                            if not task.done():
                                task.cancel()
                        
                        # Wait for cancelled tasks to complete
                        try:
                            self.loop.run_until_complete(
                                asyncio.gather(*pending, return_exceptions=True)
                            )
                        except Exception:
                            pass  # Ignore cancellation exceptions
            except Exception as e:
                logger.debug(f"Task cleanup handled: {e}")
            
            self._cleanup()

def main():
    try:
        client = NetCafeClient()
        client.run()
    except Exception as e:
        logger.error(f"Failed to start client: {e}")
        input("Press Enter to exit...")

if __name__ == '__main__':
    main() 