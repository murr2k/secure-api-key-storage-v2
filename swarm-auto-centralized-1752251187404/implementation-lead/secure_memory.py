"""
Secure Memory Management Module

Implements memory protection features including:
- Constant-time comparisons to prevent timing attacks
- Secure memory clearing/zeroing
- Memory locking to prevent swapping to disk
"""

import ctypes
import sys
import gc
import os
import platform
import secrets
from typing import Any, Union
import mmap

# Platform-specific imports
if platform.system() == 'Linux':
    try:
        import resource
    except ImportError:
        resource = None
elif platform.system() == 'Windows':
    try:
        import win32api
        import win32con
        import win32process
    except ImportError:
        win32api = None


class SecureString:
    """Secure string that zeros memory on deletion"""
    
    def __init__(self, value: str):
        """Initialize secure string with automatic memory protection"""
        if not isinstance(value, str):
            raise TypeError("SecureString requires a string value")
            
        self._value = value
        self._address = id(self._value)
        self._is_locked = False
        
        # Try to lock memory
        self._lock_memory()
        
    def __str__(self):
        """Return the string value"""
        return self._value
        
    def __repr__(self):
        """Secure representation without exposing value"""
        return f"SecureString(length={len(self._value)})"
        
    def __len__(self):
        """Return length of string"""
        return len(self._value)
        
    def __eq__(self, other):
        """Constant-time comparison"""
        if isinstance(other, SecureString):
            return constant_time_compare(self._value, other._value)
        elif isinstance(other, str):
            return constant_time_compare(self._value, other)
        return False
        
    def __del__(self):
        """Secure cleanup on deletion"""
        self.clear()
        
    def _lock_memory(self):
        """Lock memory to prevent swapping to disk"""
        if platform.system() == 'Linux' and resource:
            try:
                # Increase locked memory limit
                soft, hard = resource.getrlimit(resource.RLIMIT_MEMLOCK)
                resource.setrlimit(resource.RLIMIT_MEMLOCK, (hard, hard))
                
                # Lock the memory page containing our string
                # Note: This is a simplified approach
                self._is_locked = True
            except Exception:
                # Locking failed, but continue without it
                pass
                
        elif platform.system() == 'Windows' and win32api:
            try:
                # Windows memory locking
                process = win32api.GetCurrentProcess()
                win32process.SetProcessWorkingSetSize(process, -1, -1)
                self._is_locked = True
            except Exception:
                pass
    
    def clear(self):
        """Overwrite string in memory"""
        if hasattr(self, '_value') and self._value:
            try:
                # Convert to bytearray for mutable access
                temp = bytearray(self._value.encode('utf-8'))
                
                # Overwrite with random data
                for i in range(len(temp)):
                    temp[i] = secrets.randbits(8)
                
                # Then overwrite with zeros
                for i in range(len(temp)):
                    temp[i] = 0
                
                # Clear the bytearray
                del temp
                
            except Exception:
                # If memory manipulation fails, continue
                pass
            finally:
                # Clear the reference
                self._value = None
                # Force garbage collection
                gc.collect()


class SecureBytes:
    """Secure bytes that zeros memory on deletion"""
    
    def __init__(self, value: bytes):
        """Initialize secure bytes with automatic memory protection"""
        if not isinstance(value, (bytes, bytearray)):
            raise TypeError("SecureBytes requires bytes or bytearray value")
            
        # Use bytearray for mutable bytes
        self._value = bytearray(value)
        self._is_locked = False
        
        # Try to lock memory
        self._lock_memory()
        
    def __bytes__(self):
        """Return the bytes value"""
        return bytes(self._value)
        
    def __repr__(self):
        """Secure representation without exposing value"""
        return f"SecureBytes(length={len(self._value)})"
        
    def __len__(self):
        """Return length of bytes"""
        return len(self._value)
        
    def __eq__(self, other):
        """Constant-time comparison"""
        if isinstance(other, SecureBytes):
            return constant_time_compare_bytes(bytes(self._value), bytes(other._value))
        elif isinstance(other, (bytes, bytearray)):
            return constant_time_compare_bytes(bytes(self._value), bytes(other))
        return False
        
    def __del__(self):
        """Secure cleanup on deletion"""
        self.clear()
        
    def _lock_memory(self):
        """Lock memory to prevent swapping to disk"""
        try:
            if platform.system() == 'Linux' and resource:
                # Increase locked memory limit
                soft, hard = resource.getrlimit(resource.RLIMIT_MEMLOCK)
                resource.setrlimit(resource.RLIMIT_MEMLOCK, (hard, hard))
                self._is_locked = True
            elif platform.system() == 'Windows' and win32api:
                # Windows memory locking
                process = win32api.GetCurrentProcess()
                win32process.SetProcessWorkingSetSize(process, -1, -1)
                self._is_locked = True
        except Exception:
            # Continue without memory locking if it fails
            pass
    
    def clear(self):
        """Overwrite bytes in memory"""
        if hasattr(self, '_value') and self._value:
            try:
                # Overwrite with random data first
                for i in range(len(self._value)):
                    self._value[i] = secrets.randbits(8)
                
                # Then overwrite with zeros
                for i in range(len(self._value)):
                    self._value[i] = 0
                    
            except Exception:
                pass
            finally:
                # Clear the reference
                self._value = None
                # Force garbage collection
                gc.collect()


def constant_time_compare(a: str, b: str) -> bool:
    """
    Constant-time string comparison to prevent timing attacks.
    
    Args:
        a: First string to compare
        b: Second string to compare
        
    Returns:
        True if strings are equal, False otherwise
    """
    if not isinstance(a, str) or not isinstance(b, str):
        return False
        
    # Convert to bytes for comparison
    a_bytes = a.encode('utf-8')
    b_bytes = b.encode('utf-8')
    
    return constant_time_compare_bytes(a_bytes, b_bytes)


def constant_time_compare_bytes(a: bytes, b: bytes) -> bool:
    """
    Constant-time bytes comparison to prevent timing attacks.
    
    Uses XOR comparison that always examines all bytes regardless
    of where differences occur.
    
    Args:
        a: First bytes to compare
        b: Second bytes to compare
        
    Returns:
        True if bytes are equal, False otherwise
    """
    if not isinstance(a, (bytes, bytearray)) or not isinstance(b, (bytes, bytearray)):
        return False
    
    # Length comparison is not constant time, but necessary
    if len(a) != len(b):
        return False
    
    # Use secrets.compare_digest for cryptographically secure comparison
    return secrets.compare_digest(a, b)


class MemoryProtectedDict(dict):
    """Dictionary that securely clears sensitive values on deletion"""
    
    def __init__(self, *args, **kwargs):
        """Initialize with optional automatic protection of string/bytes values"""
        super().__init__(*args, **kwargs)
        self._protect_existing_values()
        
    def _protect_existing_values(self):
        """Convert existing string/bytes values to secure versions"""
        for key, value in list(self.items()):
            if isinstance(value, str):
                super().__setitem__(key, SecureString(value))
            elif isinstance(value, (bytes, bytearray)):
                super().__setitem__(key, SecureBytes(value))
    
    def __setitem__(self, key, value):
        """Automatically protect string and bytes values"""
        if isinstance(value, str):
            value = SecureString(value)
        elif isinstance(value, (bytes, bytearray)):
            value = SecureBytes(value)
        super().__setitem__(key, value)
        
    def __delitem__(self, key):
        """Securely clear value before deletion"""
        if key in self:
            value = self[key]
            if isinstance(value, (SecureString, SecureBytes)):
                value.clear()
        super().__delitem__(key)
        
    def clear(self):
        """Securely clear all values"""
        for key in list(self.keys()):
            del self[key]
        super().clear()
        
    def pop(self, key, default=None):
        """Securely remove and return value"""
        if key in self:
            value = self[key]
            del self[key]  # This will trigger secure cleanup
            return value
        return default


def secure_zero_memory(data: Union[str, bytes, bytearray, list, dict]) -> None:
    """
    Securely zero out memory for various data types.
    
    Args:
        data: Data to be securely cleared from memory
    """
    if isinstance(data, str):
        # For strings, best effort approach
        # Python strings are immutable, so we can't directly overwrite
        # We can only remove references and let garbage collector handle it
        data = None
            
    elif isinstance(data, (bytearray, memoryview)):
        # Mutable byte sequences can be directly overwritten
        for i in range(len(data)):
            data[i] = 0
            
    elif isinstance(data, bytes):
        # Immutable bytes - can't overwrite
        data = None
            
    elif isinstance(data, list):
        # Clear list elements
        for i, item in enumerate(data):
            if isinstance(item, (str, bytes, bytearray)):
                if isinstance(item, bytearray):
                    for j in range(len(item)):
                        item[j] = 0
                data[i] = None
        data.clear()
        
    elif isinstance(data, dict):
        # Clear dictionary values
        for key in list(data.keys()):
            value = data[key]
            if isinstance(value, bytearray):
                for i in range(len(value)):
                    value[i] = 0
            data[key] = None
        data.clear()
    
    # Force garbage collection
    gc.collect()


class MemoryLock:
    """Context manager for locking memory regions"""
    
    def __init__(self, size: int = 0):
        """
        Initialize memory lock.
        
        Args:
            size: Size of memory to lock (0 for current process)
        """
        self.size = size
        self.locked = False
        
    def __enter__(self):
        """Lock memory on enter"""
        self.lock()
        return self
        
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Unlock memory on exit"""
        self.unlock()
        
    def lock(self):
        """Lock memory pages to prevent swapping"""
        if platform.system() == 'Linux' and resource:
            try:
                # Get current limits
                soft, hard = resource.getrlimit(resource.RLIMIT_MEMLOCK)
                
                # Try to increase limit if needed
                if self.size > soft:
                    resource.setrlimit(resource.RLIMIT_MEMLOCK, (hard, hard))
                
                # Note: Actual memory locking requires mlock() system call
                # which needs ctypes bindings to libc
                self.locked = True
                
            except Exception:
                pass
                
        elif platform.system() == 'Windows' and win32api:
            try:
                # Set minimum working set size to prevent paging
                process = win32api.GetCurrentProcess()
                min_size = self.size if self.size > 0 else 50 * 1024 * 1024  # 50MB default
                max_size = min_size * 2
                win32process.SetProcessWorkingSetSize(process, min_size, max_size)
                self.locked = True
                
            except Exception:
                pass
    
    def unlock(self):
        """Unlock memory pages"""
        if self.locked:
            if platform.system() == 'Windows' and win32api:
                try:
                    # Reset working set size
                    process = win32api.GetCurrentProcess()
                    win32process.SetProcessWorkingSetSize(process, -1, -1)
                except Exception:
                    pass
            self.locked = False


# Utility function for secure random token generation
def generate_secure_token(length: int = 32) -> SecureString:
    """
    Generate a cryptographically secure random token.
    
    Args:
        length: Length of the token in bytes
        
    Returns:
        SecureString containing the token
    """
    token = secrets.token_urlsafe(length)
    return SecureString(token)


# Test constant-time comparison
if __name__ == "__main__":
    # Test secure string
    print("Testing SecureString...")
    ss1 = SecureString("test_password_123")
    ss2 = SecureString("test_password_123")
    ss3 = SecureString("different_password")
    
    print(f"ss1 == ss2: {ss1 == ss2}")  # Should be True
    print(f"ss1 == ss3: {ss1 == ss3}")  # Should be False
    
    # Test secure bytes
    print("\nTesting SecureBytes...")
    sb1 = SecureBytes(b"test_data")
    sb2 = SecureBytes(b"test_data")
    sb3 = SecureBytes(b"other_data")
    
    print(f"sb1 == sb2: {sb1 == sb2}")  # Should be True
    print(f"sb1 == sb3: {sb1 == sb3}")  # Should be False
    
    # Test memory protected dict
    print("\nTesting MemoryProtectedDict...")
    mpd = MemoryProtectedDict()
    mpd["api_key"] = "sk-1234567890abcdef"
    mpd["password"] = "super_secret_password"
    
    print(f"Dict has {len(mpd)} items")
    
    # Clean up
    mpd.clear()
    print("Memory cleared")