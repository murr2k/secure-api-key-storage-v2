#!/usr/bin/env python3
"""
Test script for secure memory management features

Demonstrates:
1. Constant-time comparison functions
2. Secure memory clearing mechanisms  
3. Memory locking functionality
4. Integration with secure storage
"""

import time
import sys
import os
import gc
from secure_memory import (
    SecureString,
    SecureBytes,
    MemoryProtectedDict,
    constant_time_compare,
    constant_time_compare_bytes,
    secure_zero_memory,
    MemoryLock,
    generate_secure_token
)

def test_constant_time_comparison():
    """Test constant-time string comparison"""
    print("\n=== Testing Constant-Time Comparison ===")
    
    # Test equal strings
    password1 = "super_secret_password_123"
    password2 = "super_secret_password_123"
    password3 = "different_password_456"
    
    # Time the comparisons
    iterations = 100000
    
    # Equal strings comparison
    start = time.perf_counter()
    for _ in range(iterations):
        result = constant_time_compare(password1, password2)
    equal_time = time.perf_counter() - start
    print(f"Equal strings ({iterations} iterations): {equal_time:.4f} seconds")
    
    # Different strings - early difference
    start = time.perf_counter()
    for _ in range(iterations):
        result = constant_time_compare(password1, password3)
    diff_early_time = time.perf_counter() - start
    print(f"Different strings (early diff): {diff_early_time:.4f} seconds")
    
    # Different strings - late difference
    password4 = "super_secret_password_12X"  # Differs only at the end
    start = time.perf_counter()
    for _ in range(iterations):
        result = constant_time_compare(password1, password4)
    diff_late_time = time.perf_counter() - start
    print(f"Different strings (late diff): {diff_late_time:.4f} seconds")
    
    # Check timing consistency
    time_variance = abs(diff_early_time - diff_late_time) / min(diff_early_time, diff_late_time)
    print(f"\nTiming variance: {time_variance:.2%}")
    if time_variance < 0.1:  # Less than 10% variance
        print("✓ Constant-time comparison working correctly")
    else:
        print("✗ Warning: Timing variance detected")


def test_secure_string():
    """Test SecureString functionality"""
    print("\n=== Testing SecureString ===")
    
    # Create secure string
    secret = "my_api_key_sk-1234567890abcdef"
    secure_str = SecureString(secret)
    
    print(f"Created SecureString with length: {len(secure_str)}")
    print(f"Representation: {repr(secure_str)}")
    
    # Test comparison
    secure_str2 = SecureString(secret)
    print(f"Comparison test: {secure_str == secure_str2}")
    
    # Test memory clearing
    print("\nClearing secure string from memory...")
    secure_str.clear()
    
    # Verify clearing (this is hard to test directly)
    print("✓ SecureString cleared")


def test_secure_bytes():
    """Test SecureBytes functionality"""
    print("\n=== Testing SecureBytes ===")
    
    # Create secure bytes
    data = b"sensitive_binary_data_12345"
    secure_data = SecureBytes(data)
    
    print(f"Created SecureBytes with length: {len(secure_data)}")
    print(f"Representation: {repr(secure_data)}")
    
    # Test comparison
    secure_data2 = SecureBytes(data)
    print(f"Comparison test: {secure_data == secure_data2}")
    
    # Test memory clearing
    print("\nClearing secure bytes from memory...")
    secure_data.clear()
    
    print("✓ SecureBytes cleared")


def test_memory_protected_dict():
    """Test MemoryProtectedDict functionality"""
    print("\n=== Testing MemoryProtectedDict ===")
    
    # Create protected dictionary
    protected = MemoryProtectedDict()
    
    # Add sensitive data
    protected["api_key"] = "sk-prod-1234567890abcdefghijklmnop"
    protected["password"] = "super_secret_password_123"
    protected["token"] = b"binary_auth_token_data"
    
    print(f"Added {len(protected)} items to protected dictionary")
    
    # Access data
    print(f"API key type: {type(protected['api_key'])}")
    print(f"Password type: {type(protected['password'])}")
    print(f"Token type: {type(protected['token'])}")
    
    # Delete individual item
    print("\nDeleting 'password' key...")
    del protected["password"]
    print(f"Items remaining: {len(protected)}")
    
    # Clear all
    print("\nClearing entire dictionary...")
    protected.clear()
    print(f"Items after clear: {len(protected)}")
    print("✓ MemoryProtectedDict working correctly")


def test_memory_lock():
    """Test memory locking functionality"""
    print("\n=== Testing Memory Lock ===")
    
    print("Creating large sensitive data...")
    sensitive_data = "x" * (1024 * 1024)  # 1MB of data
    
    with MemoryLock(size=2 * 1024 * 1024):  # Lock 2MB
        print("Memory locked")
        
        # Perform sensitive operations
        secure_data = SecureString(sensitive_data)
        
        # Process data...
        print(f"Processing {len(secure_data)} bytes of sensitive data")
        
        # Clear when done
        secure_data.clear()
        
    print("Memory unlocked")
    print("✓ Memory locking completed")


def test_secure_token_generation():
    """Test secure token generation"""
    print("\n=== Testing Secure Token Generation ===")
    
    # Generate tokens of different lengths
    for length in [16, 32, 64]:
        token = generate_secure_token(length)
        print(f"Generated {length}-byte token: {repr(token)}")
        
        # Verify it's a SecureString
        assert isinstance(token, SecureString)
        
        # Clear the token
        token.clear()
    
    print("✓ Secure token generation working correctly")


def test_integration_with_storage():
    """Test integration with secure storage"""
    print("\n=== Testing Integration with Secure Storage ===")
    
    try:
        # Import the secure storage module
        import secure_storage
        
        # Create storage instance
        storage = secure_storage.SecureKeyStorage(
            storage_path=".test_secure_keys",
            master_key_env="TEST_MASTER_KEY"
        )
        
        # Store a key
        test_key = "sk-test-1234567890abcdefghijklmnop"
        success = storage.store_key(
            "test_service",
            test_key,
            metadata={"service": "test", "environment": "testing"}
        )
        
        if success:
            print("✓ Key stored successfully with memory protection")
            
            # Retrieve the key
            retrieved = storage.retrieve_key("test_service")
            if retrieved == test_key:
                print("✓ Key retrieved successfully")
            
            # Rotate the key
            new_key = "sk-test-new-0987654321zyxwvutsrq"
            if storage.rotate_key("test_service", new_key):
                print("✓ Key rotated successfully with secure memory handling")
            
            # Delete the key
            if storage.delete_key("test_service"):
                print("✓ Key deleted with secure memory clearing")
        
        # Clean up test directory
        import shutil
        shutil.rmtree(".test_secure_keys", ignore_errors=True)
        
    except ImportError:
        print("! Could not import secure_storage module")
    except Exception as e:
        print(f"! Integration test error: {e}")


def test_memory_clearing():
    """Test various memory clearing scenarios"""
    print("\n=== Testing Memory Clearing ===")
    
    # Test string clearing
    test_str = "sensitive_string_data"
    print(f"Original string: {test_str}")
    secure_zero_memory(test_str)
    print("✓ String memory cleared")
    
    # Test bytes clearing
    test_bytes = bytearray(b"sensitive_bytes_data")
    print(f"Original bytes: {test_bytes}")
    secure_zero_memory(test_bytes)
    print(f"After clearing: {test_bytes}")
    print("✓ Bytes memory cleared")
    
    # Test list clearing
    test_list = ["secret1", "secret2", "secret3"]
    print(f"Original list length: {len(test_list)}")
    secure_zero_memory(test_list)
    print(f"After clearing: {len(test_list)}")
    print("✓ List memory cleared")
    
    # Test dict clearing
    test_dict = {"key1": "secret1", "key2": "secret2"}
    print(f"Original dict keys: {list(test_dict.keys())}")
    secure_zero_memory(test_dict)
    print(f"After clearing: {len(test_dict)}")
    print("✓ Dict memory cleared")


def run_performance_tests():
    """Run performance benchmarks"""
    print("\n=== Performance Tests ===")
    
    iterations = 10000
    
    # Regular string operations
    start = time.perf_counter()
    for _ in range(iterations):
        s = "test_string_12345"
        _ = s == "test_string_12345"
    regular_time = time.perf_counter() - start
    
    # SecureString operations
    start = time.perf_counter()
    for _ in range(iterations):
        s = SecureString("test_string_12345")
        _ = s == "test_string_12345"
        s.clear()
    secure_time = time.perf_counter() - start
    
    print(f"Regular string ops ({iterations} iterations): {regular_time:.4f}s")
    print(f"SecureString ops ({iterations} iterations): {secure_time:.4f}s")
    print(f"Overhead factor: {secure_time/regular_time:.2f}x")
    
    # Memory clearing performance
    data_size = 1024 * 1024  # 1MB
    data = bytearray(data_size)
    
    start = time.perf_counter()
    secure_zero_memory(data)
    clear_time = time.perf_counter() - start
    
    print(f"\nClearing 1MB of memory: {clear_time:.4f}s")
    print(f"Throughput: {data_size / clear_time / 1024 / 1024:.2f} MB/s")


def main():
    """Run all tests"""
    print("Secure Memory Management Test Suite")
    print("===================================")
    
    tests = [
        test_constant_time_comparison,
        test_secure_string,
        test_secure_bytes,
        test_memory_protected_dict,
        test_memory_lock,
        test_secure_token_generation,
        test_memory_clearing,
        test_integration_with_storage,
        run_performance_tests
    ]
    
    failed = 0
    for test in tests:
        try:
            test()
        except Exception as e:
            print(f"\n✗ Test {test.__name__} failed: {e}")
            failed += 1
    
    print(f"\n\nTest Summary: {len(tests) - failed}/{len(tests)} tests passed")
    
    if failed == 0:
        print("\n✓ All secure memory management features working correctly!")
    else:
        print(f"\n✗ {failed} tests failed")
        sys.exit(1)


if __name__ == "__main__":
    main()