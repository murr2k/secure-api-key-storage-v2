#!/usr/bin/env python3
"""
Simple demonstration of secure memory features
"""

import os
import sys

# Add current directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from secure_memory import (
    SecureString,
    SecureBytes,
    MemoryProtectedDict,
    constant_time_compare,
    generate_secure_token
)
from secure_storage import SecureKeyStorage

def demo_secure_comparison():
    """Demonstrate constant-time comparison"""
    print("\n=== Constant-Time Comparison Demo ===")
    
    password1 = "my_secure_password_123"
    password2 = "my_secure_password_123"
    password3 = "wrong_password_456"
    
    # Safe comparison
    result1 = constant_time_compare(password1, password2)
    print(f"Password match (should be True): {result1}")
    
    result2 = constant_time_compare(password1, password3)
    print(f"Password mismatch (should be False): {result2}")
    
    print("✓ Constant-time comparison prevents timing attacks")

def demo_secure_string():
    """Demonstrate SecureString usage"""
    print("\n=== SecureString Demo ===")
    
    # Create a secure string for an API key
    api_key = SecureString("sk-prod-1234567890abcdefghijklmnop")
    print(f"Created SecureString with length: {len(api_key)}")
    print(f"Secure representation: {repr(api_key)}")
    
    # Use the API key
    print("Using API key for authentication...")
    # In real use: make_api_call(str(api_key))
    
    # Clear from memory when done
    api_key.clear()
    print("✓ API key securely cleared from memory")

def demo_memory_protected_dict():
    """Demonstrate MemoryProtectedDict usage"""
    print("\n=== MemoryProtectedDict Demo ===")
    
    # Store multiple sensitive values
    credentials = MemoryProtectedDict()
    
    credentials["github_token"] = "ghp_1234567890abcdefghijklmnop"
    credentials["api_key"] = "sk-ant-api03-1234567890"
    credentials["password"] = "super_secret_password_123"
    
    print(f"Stored {len(credentials)} sensitive credentials")
    
    # Access a credential
    github_token = str(credentials["github_token"])
    print(f"Retrieved GitHub token (length: {len(github_token)})")
    
    # Clear all credentials
    credentials.clear()
    print("✓ All credentials securely cleared from memory")

def demo_secure_token_generation():
    """Demonstrate secure token generation"""
    print("\n=== Secure Token Generation Demo ===")
    
    # Generate a secure token
    token = generate_secure_token(32)
    print(f"Generated secure token: {str(token)[:20]}...")
    print(f"Token type: {type(token)}")
    
    # Clear the token
    token.clear()
    print("✓ Token securely cleared from memory")

def demo_integration_with_storage():
    """Demonstrate integration with secure storage"""
    print("\n=== Integration with Secure Storage Demo ===")
    
    # Set up test environment
    os.environ["TEST_MASTER_KEY"] = "test_master_key_for_demo"
    
    # Create secure storage instance
    storage = SecureKeyStorage(
        storage_path=".demo_secure_keys",
        master_key_env="TEST_MASTER_KEY"
    )
    
    # Store an API key
    print("Storing API key with secure memory protection...")
    success = storage.store_key(
        "openai", 
        "sk-demo-1234567890abcdefghijklmnop",
        metadata={"service": "OpenAI", "environment": "production"}
    )
    
    if success:
        print("✓ API key stored securely")
        
        # Retrieve the key
        retrieved_key = storage.retrieve_key("openai")
        if retrieved_key:
            print(f"✓ Retrieved API key (length: {len(retrieved_key)})")
        
        # List keys without exposing values
        keys_list = storage.list_keys()
        print(f"✓ Found {len(keys_list)} stored keys")
        
        # Rotate the key
        new_key = "sk-demo-new-0987654321zyxwvutsrq"
        if storage.rotate_key("openai", new_key):
            print("✓ API key rotated with secure memory handling")
        
        # Delete the key
        if storage.delete_key("openai"):
            print("✓ API key deleted with secure memory clearing")
    
    # Clean up
    import shutil
    shutil.rmtree(".demo_secure_keys", ignore_errors=True)

def main():
    """Run all demonstrations"""
    print("Secure Memory Management Demonstration")
    print("=====================================")
    print("\nThis demo shows the key security features:")
    print("1. Constant-time comparison to prevent timing attacks")
    print("2. Secure memory clearing for sensitive data")
    print("3. Memory protection for API keys and passwords")
    
    demos = [
        demo_secure_comparison,
        demo_secure_string,
        demo_memory_protected_dict,
        demo_secure_token_generation,
        demo_integration_with_storage
    ]
    
    for demo in demos:
        try:
            demo()
        except Exception as e:
            print(f"\n✗ Demo {demo.__name__} failed: {e}")
    
    print("\n" + "="*50)
    print("✓ Secure memory management is now active!")
    print("\nKey improvements implemented:")
    print("- Timing attack prevention")
    print("- Automatic memory clearing")
    print("- Secure storage integration")
    print("- Memory locking support")

if __name__ == "__main__":
    main()