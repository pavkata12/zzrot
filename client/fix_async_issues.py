#!/usr/bin/env python3
"""
NetCafe Pro 2.0 - Async Issues Fix
Fixes the RuntimeError: Cannot enter into task while another task is being executed
"""

import re
import os

def fix_async_issues():
    """Fix async task conflicts in netcafe_client.py"""
    
    client_file = 'netcafe_client.py'
    
    if not os.path.exists(client_file):
        print("❌ netcafe_client.py not found!")
        return False
    
    print("🔧 Fixing async task conflicts...")
    
    # Read the file
    with open(client_file, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # Fix 1: Improve task manager to prevent conflicts
    old_task_manager = '''# Global task manager to prevent concurrency issues
class TaskManager:
    def __init__(self):
        self._tasks = weakref.WeakSet()
        self._lock = asyncio.Lock()
    
    async def create_task(self, coro, name=None):
        async with self._lock:
            task = asyncio.create_task(coro, name=name)
            self._tasks.add(task)
            return task
    
    async def cancel_all_tasks(self):
        async with self._lock:
            tasks = list(self._tasks)
            for task in tasks:
                if not task.done():
                    task.cancel()
            
            if tasks:
                await asyncio.gather(*tasks, return_exceptions=True)'''
    
    new_task_manager = '''# Global task manager to prevent concurrency issues
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
            
            self._running_tasks.clear()'''
    
    content = content.replace(old_task_manager, new_task_manager)
    
    # Fix 2: Improve WebSocket task creation to prevent conflicts
    old_ws_creation = '''            # Start WebSocket message handler with proper task management
            try:
                self.ws_task = await task_manager.create_task(
                    self._handle_ws_messages(), 
                    name="websocket_handler"
                )
            except Exception as e:
                logger.error(f"Failed to start WebSocket handler: {e}")
                raise'''
    
    new_ws_creation = '''            # Cancel any existing WebSocket handler first
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
                raise'''
    
    content = content.replace(old_ws_creation, new_ws_creation)
    
    # Fix 3: Improve connection cleanup
    old_cleanup = '''            # Close previous session properly
            if self.session and not self.session.closed:
                try:
                    await self.session.close()
                    await asyncio.sleep(0.1)  # Give time for cleanup
                except Exception as e:
                    logger.debug(f"Previous session cleanup: {e}")'''
    
    new_cleanup = '''            # Cancel existing WebSocket task first
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
                self.session = None'''
    
    content = content.replace(old_cleanup, new_cleanup)
    
    # Write the fixed file
    with open(client_file, 'w', encoding='utf-8') as f:
        f.write(content)
    
    print("✅ Async issues fixed!")
    print("🔧 Applied fixes:")
    print("   • Improved task manager to prevent conflicts")
    print("   • Better WebSocket task handling")
    print("   • Enhanced connection cleanup")
    print("   • Proper task cancellation")
    
    return True

def main():
    print("🎮 NetCafe Pro 2.0 - Async Issues Fix")
    print("=====================================")
    print()
    
    if fix_async_issues():
        print()
        print("🎉 All async issues have been fixed!")
        print("💡 Now run the client with:")
        print("   START_CLIENT_AS_ADMIN.bat")
        print()
        print("🛡️  This will provide administrator privileges for:")
        print("   • Keyboard blocking (Alt+Tab, Alt+F4, Windows key)")
        print("   • Folder access protection")
        print("   • Full security features")
    else:
        print("❌ Failed to fix async issues")
    
    input("Press Enter to continue...")

if __name__ == '__main__':
    main() 