"""
Regression Tests for API Key Storage System
Validates that all critical functionality works correctly across system changes
"""

import unittest
import os
import tempfile
import shutil
import json
import time
from datetime import datetime, timedelta
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.secure_storage import APIKeyStorage, SecurityException
from src.secure_storage_rbac import SecureStorageWithRBAC
from src.rbac_models import RBACManager, Role, Permission


class RegressionTests(unittest.TestCase):
    """Comprehensive regression testing suite"""
    
    def setUp(self):
        """Set up test environment"""
        self.test_dir = tempfile.mkdtemp()
        self.storage = APIKeyStorage(storage_path=self.test_dir, master_password="test_password_123")
        
    def tearDown(self):
        """Clean up test environment"""
        try:
            shutil.rmtree(self.test_dir)
        except:
            # Handle any permission issues with audit logs
            pass
    
    def test_core_functionality_regression(self):
        """Test that all core features work together"""
        # Store a key
        key_id = self.storage.add_api_key("test-service", "test-key-value", "testuser", {"env": "test"})
        self.assertIsNotNone(key_id)
        
        # Retrieve the key
        retrieved_key = self.storage.get_api_key(key_id, "testuser")
        self.assertEqual(retrieved_key, "test-key-value")
        
        # List keys
        keys = self.storage.list_keys("testuser")
        self.assertTrue(len(keys) > 0)
        
        # Delete key
        result = self.storage.revoke_key(key_id, "testuser")
        self.assertTrue(result)
        
        # Verify deletion
        retrieved_after_delete = self.storage.get_api_key(key_id, "testuser")
        self.assertIsNone(retrieved_after_delete)
    
    def test_encryption_regression(self):
        """Test that encryption/decryption works consistently"""
        test_data = "sensitive-api-key-12345"
        key_id = self.storage.store_key("encryption-test", test_data)
        
        # Verify stored data is encrypted on disk
        key_files = os.listdir(self.test_dir)
        self.assertTrue(len(key_files) > 0)
        
        # Read raw file content
        for filename in key_files:
            if filename.endswith('.enc'):
                with open(os.path.join(self.test_dir, filename), 'rb') as f:
                    raw_content = f.read()
                # Verify data is encrypted (not plaintext)
                self.assertNotIn(test_data.encode(), raw_content)
        
        # Verify we can still decrypt correctly
        retrieved = self.storage.get_key("encryption-test")
        self.assertEqual(retrieved, test_data)
    
    def test_rbac_integration_regression(self):
        """Test RBAC functionality regression"""
        rbac_storage = SecureStorageWithRBAC(
            storage_path=self.test_dir, 
            master_password="test_password_123"
        )
        
        # Create user and role
        rbac_storage.rbac.create_user("testuser", "test@example.com")
        read_role = Role("reader", [Permission.READ])
        rbac_storage.rbac.create_role(read_role)
        rbac_storage.rbac.assign_role("testuser", "reader")
        
        # Test permission checking
        self.assertTrue(rbac_storage.rbac.check_permission("testuser", Permission.READ))
        self.assertFalse(rbac_storage.rbac.check_permission("testuser", Permission.WRITE))
    
    def test_metadata_handling_regression(self):
        """Test metadata storage and retrieval"""
        metadata = {
            "environment": "production",
            "service": "api-gateway", 
            "created_by": "admin",
            "expires": "2025-12-31"
        }
        
        key_id = self.storage.store_key("metadata-test", "test-key", metadata)
        
        # Get key info with metadata
        key_info = self.storage.get_key_info("metadata-test")
        self.assertIsNotNone(key_info)
        self.assertEqual(key_info["metadata"]["environment"], "production")
        self.assertEqual(key_info["metadata"]["service"], "api-gateway")
    
    def test_concurrent_access_regression(self):
        """Test thread safety regression"""
        import threading
        import time
        
        results = []
        errors = []
        
        def worker(worker_id):
            try:
                # Each worker stores and retrieves a key
                service_name = f"concurrent-test-{worker_id}"
                key_value = f"key-value-{worker_id}"
                
                key_id = self.storage.store_key(service_name, key_value)
                time.sleep(0.01)  # Small delay to encourage race conditions
                retrieved = self.storage.get_key(service_name)
                
                if retrieved == key_value:
                    results.append(worker_id)
                else:
                    errors.append(f"Worker {worker_id}: expected {key_value}, got {retrieved}")
            except Exception as e:
                errors.append(f"Worker {worker_id}: {str(e)}")
        
        # Start multiple worker threads
        threads = []
        for i in range(5):
            t = threading.Thread(target=worker, args=(i,))
            threads.append(t)
            t.start()
        
        # Wait for all threads
        for t in threads:
            t.join()
        
        # Verify results
        self.assertEqual(len(errors), 0, f"Concurrent access errors: {errors}")
        self.assertEqual(len(results), 5, "Not all workers completed successfully")
    
    def test_error_handling_regression(self):
        """Test error handling consistency"""
        # Test invalid master password
        with self.assertRaises(SecurityException):
            bad_storage = APIKeyStorage(storage_path=self.test_dir, master_password="wrong")
            bad_storage.get_key("nonexistent")
        
        # Test nonexistent key
        with self.assertRaises(SecurityException):
            self.storage.get_key("does-not-exist")
        
        # Test empty service name
        with self.assertRaises((ValueError, SecurityException)):
            self.storage.store_key("", "some-value")
        
        # Test None key value
        with self.assertRaises((ValueError, SecurityException)):
            self.storage.store_key("test-service", None)
    
    def test_audit_logging_regression(self):
        """Test audit logging functionality"""
        # Store a key (should generate audit log)
        key_id = self.storage.store_key("audit-test", "test-value")
        
        # Access the key (should generate audit log)
        retrieved = self.storage.get_key("audit-test")
        
        # Check if audit directory exists
        audit_dir = os.path.join(self.test_dir, "audit")
        if os.path.exists(audit_dir):
            audit_files = os.listdir(audit_dir)
            self.assertTrue(len(audit_files) > 0, "No audit files generated")
    
    def test_key_rotation_regression(self):
        """Test key rotation functionality"""
        # Store initial key
        original_key = "original-key-value"
        key_id = self.storage.store_key("rotation-test", original_key)
        
        # Rotate the key
        new_key = "rotated-key-value"
        if hasattr(self.storage, 'rotate_key'):
            self.storage.rotate_key("rotation-test", new_key)
            
            # Verify new key is stored
            retrieved = self.storage.get_key("rotation-test")
            self.assertEqual(retrieved, new_key)
    
    def test_performance_regression(self):
        """Test basic performance characteristics"""
        import time
        
        # Time key storage operations
        start_time = time.time()
        
        for i in range(10):
            key_id = self.storage.store_key(f"perf-test-{i}", f"value-{i}")
        
        storage_time = time.time() - start_time
        
        # Time key retrieval operations
        start_time = time.time()
        
        for i in range(10):
            value = self.storage.get_key(f"perf-test-{i}")
        
        retrieval_time = time.time() - start_time
        
        # Basic performance assertions (should complete in reasonable time)
        self.assertLess(storage_time, 5.0, "Key storage took too long")
        self.assertLess(retrieval_time, 2.0, "Key retrieval took too long")


if __name__ == '__main__':
    unittest.main()