#!/usr/bin/env python3
"""
Quick validation script to ensure basic functionality
"""

import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))

from api_key_storage import APIKeyStorage
import tempfile
import shutil

def validate_basic_functionality():
    """Validate core functionality works"""
    print("API Key Storage System - Basic Validation")
    print("=" * 50)
    
    # Create temporary directory for testing
    test_dir = tempfile.mkdtemp()
    
    try:
        # Test 1: Initialize storage
        print("\n✓ Initializing storage system...")
        storage = APIKeyStorage(storage_path=test_dir, master_password="test123")
        
        # Test 2: Add a key
        print("✓ Adding test API key...")
        key_id = storage.add_api_key(
            service="test_service",
            api_key="test_api_key_12345",
            user="test_user",
            metadata={"env": "test"}
        )
        print(f"  Key ID: {key_id}")
        
        # Test 3: Retrieve the key
        print("✓ Retrieving API key...")
        retrieved = storage.get_api_key(key_id, "test_user")
        assert retrieved == "test_api_key_12345", "Key retrieval failed"
        print("  Key retrieved successfully")
        
        # Test 4: List keys
        print("✓ Listing keys...")
        keys = storage.list_keys("test_user")
        assert len(keys) == 1, "Key listing failed"
        print(f"  Found {len(keys)} key(s)")
        
        # Test 5: Check audit log
        print("✓ Checking audit log...")
        audit = storage.export_audit_log()
        assert "Added API key" in audit, "Audit logging failed"
        print("  Audit log working")
        
        # Test 6: Revoke key
        print("✓ Revoking key...")
        success = storage.revoke_key(key_id, "test_user")
        assert success, "Key revocation failed"
        
        # Verify revoked key can't be accessed
        revoked = storage.get_api_key(key_id, "test_user")
        assert revoked is None, "Revoked key still accessible"
        print("  Key successfully revoked")
        
        print("\n" + "="*50)
        print("✅ ALL BASIC TESTS PASSED!")
        print("="*50)
        print("\nThe API Key Storage System is working correctly.")
        print("\nTo run the full test suite, execute:")
        print("  python run_tests.py")
        print("\nTo use the interactive interface, run:")
        print("  python src/user_interface.py")
        
        return True
        
    except Exception as e:
        print(f"\n❌ ERROR: {str(e)}")
        print("\nPlease ensure all dependencies are installed:")
        print("  pip install -r requirements.txt")
        return False
        
    finally:
        # Clean up
        shutil.rmtree(test_dir)


if __name__ == "__main__":
    success = validate_basic_functionality()
    sys.exit(0 if success else 1)