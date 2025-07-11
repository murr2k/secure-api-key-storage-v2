#!/usr/bin/env python3
"""
Test suite for the Secure Key Manager

Demonstrates and tests all key functionality.
"""

import unittest
import tempfile
import shutil
import os
from pathlib import Path
import json
from key_manager_lib import KeyManager, KeyManagerError, AuthenticationError, KeyNotFoundError


class TestKeyManager(unittest.TestCase):
    """Test cases for KeyManager functionality."""
    
    def setUp(self):
        """Set up test environment."""
        # Create temporary directory for test configs
        self.test_dir = tempfile.mkdtemp()
        self.original_home = os.environ.get('HOME')
        os.environ['HOME'] = self.test_dir
        
        # Initialize key manager
        self.master_password = "test_password_123"
        self.km = KeyManager(master_password=self.master_password)
        self.km.initialize(self.master_password)
    
    def tearDown(self):
        """Clean up test environment."""
        # Restore original HOME
        if self.original_home:
            os.environ['HOME'] = self.original_home
        else:
            del os.environ['HOME']
        
        # Remove test directory
        shutil.rmtree(self.test_dir)
    
    def test_initialization(self):
        """Test key manager initialization."""
        self.assertTrue(self.km.is_initialized())
        
        # Test password requirements
        with self.assertRaises(ValueError):
            new_km = KeyManager()
            new_km.initialize("short")  # Too short
    
    def test_add_and_get_key(self):
        """Test adding and retrieving keys."""
        # Add a key
        success = self.km.add_key("github", "personal", "ghp_test123")
        self.assertTrue(success)
        
        # Retrieve the key
        key_value = self.km.get_key("github", "personal")
        self.assertEqual(key_value, "ghp_test123")
        
        # Test non-existent key
        with self.assertRaises(KeyNotFoundError):
            self.km.get_key("github", "nonexistent")
    
    def test_add_key_with_metadata(self):
        """Test adding keys with metadata."""
        metadata = {
            "environment": "production",
            "created_by": "test_user",
            "expires": "2024-12-31"
        }
        
        success = self.km.add_key("aws", "prod-key", "AKIATEST123", metadata)
        self.assertTrue(success)
        
        # Verify key exists
        key_value = self.km.get_key("aws", "prod-key")
        self.assertEqual(key_value, "AKIATEST123")
    
    def test_remove_key(self):
        """Test removing keys."""
        # Add a key
        self.km.add_key("test", "temp", "temp123")
        
        # Remove it
        success = self.km.remove_key("test", "temp", confirm=False)
        self.assertTrue(success)
        
        # Verify it's gone
        with self.assertRaises(KeyNotFoundError):
            self.km.get_key("test", "temp")
        
        # Test removing non-existent key
        success = self.km.remove_key("test", "nonexistent", confirm=False)
        self.assertFalse(success)
    
    def test_update_key(self):
        """Test updating keys."""
        # Add a key
        self.km.add_key("github", "ci", "old_token")
        
        # Update it
        success = self.km.update_key("github", "ci", "new_token")
        self.assertTrue(success)
        
        # Verify update
        key_value = self.km.get_key("github", "ci")
        self.assertEqual(key_value, "new_token")
    
    def test_rotate_key(self):
        """Test key rotation."""
        # Add a key
        self.km.add_key("api", "key1", "original")
        
        # Rotate with specific value
        new_value = self.km.rotate_key("api", "key1", "rotated")
        self.assertEqual(new_value, "rotated")
        
        # Verify rotation
        key_value = self.km.get_key("api", "key1")
        self.assertEqual(key_value, "rotated")
        
        # Rotate with auto-generated value
        auto_value = self.km.rotate_key("api", "key1")
        self.assertIsNotNone(auto_value)
        self.assertNotEqual(auto_value, "rotated")
        self.assertTrue(len(auto_value) > 20)  # Should be a decent length
    
    def test_list_services(self):
        """Test listing services."""
        # Add keys for multiple services
        self.km.add_key("github", "personal", "token1")
        self.km.add_key("github", "work", "token2")
        self.km.add_key("aws", "access", "key1")
        self.km.add_key("aws", "secret", "key2")
        self.km.add_key("openai", "api-key", "sk-test")
        
        # List services
        services = self.km.list_services()
        
        # Verify
        self.assertEqual(len(services), 3)
        service_names = [s['name'] for s in services]
        self.assertIn('github', service_names)
        self.assertIn('aws', service_names)
        self.assertIn('openai', service_names)
        
        # Check key counts
        github_service = next(s for s in services if s['name'] == 'github')
        self.assertEqual(len(github_service['keys']), 2)
        self.assertIn('personal', github_service['keys'])
        self.assertIn('work', github_service['keys'])
    
    def test_backup_and_restore(self):
        """Test backup and restore functionality."""
        # Add some keys
        self.km.add_key("service1", "key1", "value1")
        self.km.add_key("service2", "key2", "value2")
        
        # Create backup
        backup_path = self.km.backup("test_backup")
        self.assertTrue(Path(backup_path).exists())
        
        # Modify keys
        self.km.remove_key("service1", "key1", confirm=False)
        self.km.add_key("service3", "key3", "value3")
        
        # Verify current state
        with self.assertRaises(KeyNotFoundError):
            self.km.get_key("service1", "key1")
        self.assertEqual(self.km.get_key("service3", "key3"), "value3")
        
        # Restore
        success = self.km.restore("test_backup")
        self.assertTrue(success)
        
        # Verify restoration
        self.assertEqual(self.km.get_key("service1", "key1"), "value1")
        self.assertEqual(self.km.get_key("service2", "key2"), "value2")
        with self.assertRaises(KeyNotFoundError):
            self.km.get_key("service3", "key3")
    
    def test_list_backups(self):
        """Test listing backups."""
        # Create multiple backups
        self.km.backup("backup1")
        self.km.backup("backup2")
        self.km.backup("backup3")
        
        # List backups
        backups = self.km.list_backups()
        
        # Verify
        self.assertGreaterEqual(len(backups), 3)
        backup_names = [b['name'] for b in backups]
        self.assertIn('backup1', backup_names)
        self.assertIn('backup2', backup_names)
        self.assertIn('backup3', backup_names)
    
    def test_search_keys(self):
        """Test searching for keys."""
        # Add various keys
        self.km.add_key("github", "personal-token", "value1")
        self.km.add_key("github", "work-token", "value2")
        self.km.add_key("gitlab", "personal-key", "value3")
        self.km.add_key("aws", "prod-access", "value4")
        
        # Search by service name
        results = self.km.search_keys("git")
        self.assertEqual(len(results), 3)  # github (2) + gitlab (1)
        
        # Search by key name
        results = self.km.search_keys("personal")
        self.assertEqual(len(results), 2)  # personal-token + personal-key
        
        # Search for specific term
        results = self.km.search_keys("prod")
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]['service'], 'aws')
        self.assertEqual(results[0]['key_name'], 'prod-access')
    
    def test_bulk_operations(self):
        """Test bulk add operations."""
        keys_to_add = [
            {
                'service': 'stripe',
                'key_name': 'test',
                'value': 'sk_test_123',
                'metadata': {'environment': 'test'}
            },
            {
                'service': 'stripe',
                'key_name': 'live',
                'value': 'sk_live_456',
                'metadata': {'environment': 'production'}
            },
            {
                'service': 'sendgrid',
                'key_name': 'api',
                'value': 'SG.abc123'
            }
        ]
        
        results = self.km.bulk_add(keys_to_add)
        
        # Verify all succeeded
        self.assertTrue(all(results.values()))
        
        # Verify keys exist
        self.assertEqual(self.km.get_key('stripe', 'test'), 'sk_test_123')
        self.assertEqual(self.km.get_key('stripe', 'live'), 'sk_live_456')
        self.assertEqual(self.km.get_key('sendgrid', 'api'), 'SG.abc123')
    
    def test_export_env(self):
        """Test environment variable export."""
        # Add keys
        self.km.add_key('github', 'token', 'ghp_123')
        self.km.add_key('aws', 'access-key', 'AKIA123')
        self.km.add_key('aws', 'secret-key', 'secret123')
        
        # Define mappings
        mappings = {
            'GITHUB_TOKEN': ('github', 'token'),
            'AWS_ACCESS_KEY_ID': ('aws', 'access-key'),
            'AWS_SECRET_ACCESS_KEY': ('aws', 'secret-key'),
            'NONEXISTENT': ('fake', 'key')
        }
        
        # Export
        env_vars = self.km.export_env(mappings)
        
        # Verify
        self.assertEqual(len(env_vars), 3)  # Only 3 should succeed
        self.assertEqual(env_vars['GITHUB_TOKEN'], 'ghp_123')
        self.assertEqual(env_vars['AWS_ACCESS_KEY_ID'], 'AKIA123')
        self.assertEqual(env_vars['AWS_SECRET_ACCESS_KEY'], 'secret123')
        self.assertNotIn('NONEXISTENT', env_vars)
        
        # Verify environment variables were set
        self.assertEqual(os.environ['GITHUB_TOKEN'], 'ghp_123')
    
    def test_temporary_key(self):
        """Test temporary key context manager."""
        # Use temporary key
        with self.km.temporary_key('temp_service', 'temp_key', 'temp_value') as key:
            # Key should exist
            self.assertEqual(key, 'temp_value')
            self.assertEqual(self.km.get_key('temp_service', 'temp_key'), 'temp_value')
        
        # Key should be removed after context
        with self.assertRaises(KeyNotFoundError):
            self.km.get_key('temp_service', 'temp_key')
    
    def test_authentication_failure(self):
        """Test authentication with wrong password."""
        wrong_km = KeyManager(master_password="wrong_password")
        
        with self.assertRaises(AuthenticationError):
            wrong_km.list_services()
    
    def test_concurrent_access(self):
        """Test concurrent access to keys."""
        # This is a simple test - in production you'd want more robust testing
        import threading
        
        results = []
        
        def add_keys(service_name):
            for i in range(5):
                try:
                    self.km.add_key(service_name, f"key{i}", f"value{i}")
                    results.append(True)
                except Exception:
                    results.append(False)
        
        # Create threads
        threads = []
        for i in range(3):
            t = threading.Thread(target=add_keys, args=(f"service{i}",))
            threads.append(t)
            t.start()
        
        # Wait for completion
        for t in threads:
            t.join()
        
        # Verify results
        self.assertEqual(len(results), 15)  # 3 threads * 5 keys each
        self.assertTrue(all(results))  # All should succeed


class TestQuickFunctions(unittest.TestCase):
    """Test quick access functions."""
    
    def setUp(self):
        """Set up test environment."""
        self.test_dir = tempfile.mkdtemp()
        self.original_home = os.environ.get('HOME')
        os.environ['HOME'] = self.test_dir
        
        # Initialize and add a test key
        self.password = "test_pass_123"
        km = KeyManager(master_password=self.password)
        km.initialize(self.password)
        km.add_key("test", "key", "value123")
    
    def tearDown(self):
        """Clean up test environment."""
        if self.original_home:
            os.environ['HOME'] = self.original_home
        else:
            del os.environ['HOME']
        shutil.rmtree(self.test_dir)
    
    def test_quick_get(self):
        """Test quick_get function."""
        from key_manager_lib import quick_get
        
        # Test with password
        value = quick_get("test", "key", self.password)
        self.assertEqual(value, "value123")
        
        # Test with wrong password
        value = quick_get("test", "key", "wrong")
        self.assertIsNone(value)
        
        # Test non-existent key
        value = quick_get("test", "nonexistent", self.password)
        self.assertIsNone(value)
    
    def test_quick_add(self):
        """Test quick_add function."""
        from key_manager_lib import quick_add
        
        # Test adding a key
        success = quick_add("new_service", "new_key", "new_value", self.password)
        self.assertTrue(success)
        
        # Verify it was added
        km = KeyManager(master_password=self.password)
        value = km.get_key("new_service", "new_key")
        self.assertEqual(value, "new_value")


def run_demo():
    """Run a demonstration of key manager features."""
    print("=" * 60)
    print("Secure Key Manager - Feature Demonstration")
    print("=" * 60)
    
    # Create temporary environment
    test_dir = tempfile.mkdtemp()
    original_home = os.environ.get('HOME')
    os.environ['HOME'] = test_dir
    
    try:
        # Initialize
        print("\n1. Initializing Key Manager...")
        km = KeyManager(master_password="demo_password_123")
        km.initialize("demo_password_123")
        print("✓ Initialized successfully")
        
        # Add keys
        print("\n2. Adding API keys...")
        km.add_key("github", "personal", "ghp_demoToken123", {"scope": "repo"})
        km.add_key("aws", "access-key", "AKIADEMO123")
        km.add_key("aws", "secret-key", "demoSecret456")
        km.add_key("openai", "api-key", "sk-demoKey789")
        print("✓ Added 4 keys across 3 services")
        
        # List services
        print("\n3. Listing services...")
        services = km.list_services()
        for service in services:
            print(f"  - {service['name']}: {', '.join(service['keys'])}")
        
        # Search
        print("\n4. Searching for keys...")
        results = km.search_keys("key")
        print(f"  Found {len(results)} keys matching 'key'")
        
        # Backup
        print("\n5. Creating backup...")
        backup_path = km.backup("demo_backup")
        print(f"  ✓ Backup created: {backup_path}")
        
        # Rotate key
        print("\n6. Rotating a key...")
        new_token = km.rotate_key("github", "personal")
        print(f"  ✓ Rotated GitHub token (new length: {len(new_token)})")
        
        # Export environment variables
        print("\n7. Exporting to environment variables...")
        env_vars = km.export_env({
            'GITHUB_TOKEN': ('github', 'personal'),
            'AWS_ACCESS_KEY_ID': ('aws', 'access-key')
        })
        print(f"  ✓ Exported {len(env_vars)} variables")
        
        print("\n✓ Demo completed successfully!")
        
    finally:
        # Cleanup
        if original_home:
            os.environ['HOME'] = original_home
        else:
            del os.environ['HOME']
        shutil.rmtree(test_dir)


if __name__ == '__main__':
    import sys
    
    if len(sys.argv) > 1 and sys.argv[1] == 'demo':
        run_demo()
    else:
        unittest.main()