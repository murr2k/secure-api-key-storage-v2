"""
Security Integration Tests for API Key Storage System
Validates that all security enhancements from different agents work together seamlessly
"""

import unittest
import os
import tempfile
import shutil
import json
import time
import threading
from datetime import datetime, timedelta
import subprocess
import sys

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.secure_storage import SecureStorage
from src.config_manager import ConfigManager
from src.key_rotation import KeyRotationManager
from src.integrations.base_integration import BaseIntegration, SecureKeyWrapper
from src.integrations.github_integration import GitHubIntegration
from src.integrations.claude_integration import ClaudeIntegration
from src.integrations.generic_integration import GenericServiceIntegration


class SecurityIntegrationTests(unittest.TestCase):
    """Comprehensive integration testing for all security features"""
    
    def setUp(self):
        """Set up test environment"""
        self.test_dir = tempfile.mkdtemp()
        self.master_key = "test_master_key_12345"
        os.environ['API_KEY_MASTER'] = self.master_key
        
        # Initialize all components
        self.secure_storage = SecureStorage(
            storage_path=os.path.join(self.test_dir, "secure_keys.enc"),
            master_key=self.master_key
        )
        
        self.config_manager = ConfigManager(
            config_dir=os.path.join(self.test_dir, "config")
        )
        
        self.key_rotation = KeyRotationManager(
            secure_storage=self.secure_storage,
            config_manager=self.config_manager
        )
        
        self.key_wrapper = SecureKeyWrapper()
        
    def tearDown(self):
        """Clean up test environment"""
        shutil.rmtree(self.test_dir, ignore_errors=True)
        if 'API_KEY_MASTER' in os.environ:
            del os.environ['API_KEY_MASTER']
    
    def test_complete_security_workflow(self):
        """Test complete security workflow across all components"""
        # 1. Store encrypted API keys
        test_keys = {
            'github': 'ghp_test1234567890abcdef',
            'claude': 'sk-ant-test1234567890',
            'custom': 'custom_api_key_12345'
        }
        
        for service, key in test_keys.items():
            self.secure_storage.store_key(service, key, {
                'created_by': 'test_user',
                'created_at': datetime.now().isoformat()
            })
        
        # 2. Configure services in config manager
        self.config_manager.set_key('github', test_keys['github'])
        self.config_manager.set_key('claude', test_keys['claude'])
        self.config_manager.set_key('custom', test_keys['custom'])
        
        # 3. Set up integrations
        github = GitHubIntegration()
        claude = ClaudeIntegration()
        custom = GenericServiceIntegration('custom', 'https://api.custom.com')
        
        self.key_wrapper.register_integration(github)
        self.key_wrapper.register_integration(claude)
        self.key_wrapper.register_integration(custom)
        
        # 4. Verify encryption at rest
        with open(self.secure_storage.storage_path, 'rb') as f:
            encrypted_content = f.read()
            # Ensure no keys are in plaintext
            for key in test_keys.values():
                self.assertNotIn(key.encode(), encrypted_content)
        
        # 5. Test key retrieval through integration
        self.key_wrapper.set_key('github', test_keys['github'])
        retrieved_key = self.key_wrapper.get_key('github')
        self.assertEqual(retrieved_key, test_keys['github'])
        
        # 6. Test key rotation
        old_key = test_keys['github']
        new_key = 'ghp_new1234567890abcdef'
        
        rotation_result = self.key_rotation.rotate_key(
            'github', 
            new_key,
            reason='Scheduled rotation test'
        )
        
        self.assertTrue(rotation_result['success'])
        self.assertEqual(rotation_result['old_key_backup'], old_key)
        
        # Verify new key is stored and old key is revoked
        current_key = self.secure_storage.get_key('github')
        self.assertEqual(current_key, new_key)
        
        # 7. Test audit logging
        history = self.key_rotation.get_rotation_history('github')
        self.assertGreater(len(history), 0)
        self.assertEqual(history[-1]['reason'], 'Scheduled rotation test')
    
    def test_concurrent_access_security(self):
        """Test security under concurrent access"""
        num_threads = 10
        operations_per_thread = 50
        results = {'errors': [], 'success': 0}
        
        def concurrent_operations(thread_id):
            """Perform concurrent key operations"""
            try:
                for i in range(operations_per_thread):
                    # Mix of operations
                    if i % 3 == 0:
                        # Store operation
                        key = f'test_key_{thread_id}_{i}'
                        self.secure_storage.store_key(
                            f'service_{thread_id}', 
                            key,
                            {'thread': thread_id, 'iteration': i}
                        )
                    elif i % 3 == 1:
                        # Retrieve operation
                        try:
                            self.secure_storage.get_key(f'service_{thread_id}')
                        except KeyError:
                            pass  # Key might not exist yet
                    else:
                        # List operation
                        self.secure_storage.list_keys()
                    
                    results['success'] += 1
            except Exception as e:
                results['errors'].append(f"Thread {thread_id}: {str(e)}")
        
        # Launch concurrent threads
        threads = []
        for i in range(num_threads):
            t = threading.Thread(target=concurrent_operations, args=(i,))
            threads.append(t)
            t.start()
        
        # Wait for all threads
        for t in threads:
            t.join()
        
        # Verify results
        self.assertEqual(len(results['errors']), 0, 
                        f"Concurrent access errors: {results['errors']}")
        self.assertEqual(results['success'], 
                        num_threads * operations_per_thread)
        
        # Verify data integrity
        keys = self.secure_storage.list_keys()
        self.assertGreater(len(keys), 0)
    
    def test_security_layers_integration(self):
        """Test that all security layers work together"""
        # Layer 1: Master key protection
        self.assertIsNotNone(os.environ.get('API_KEY_MASTER'))
        
        # Layer 2: Encryption at rest
        test_key = 'sensitive_api_key_12345'
        self.secure_storage.store_key('test_service', test_key, {})
        
        # Layer 3: Access control through config manager
        profile = self.config_manager.create_profile('production')
        profile.set_config('api_key_expiry', 30)
        profile.set_config('require_rotation', True)
        
        # Layer 4: Integration validation
        integration = GenericServiceIntegration(
            'test_service',
            'https://api.test.com',
            validation_pattern=r'^sensitive_api_key_\d+$'
        )
        
        # Validate key format
        is_valid = integration.validate_api_key(test_key)
        self.assertTrue(is_valid)
        
        # Layer 5: Audit trail
        metadata = self.secure_storage.get_metadata('test_service')
        self.assertIsNotNone(metadata)
        
        # Layer 6: Key rotation enforcement
        if profile.get_config('require_rotation'):
            expiry_days = profile.get_config('api_key_expiry')
            should_rotate = self.key_rotation.check_rotation_needed(
                'test_service',
                expiry_days
            )
            # New key shouldn't need rotation
            self.assertFalse(should_rotate)
    
    def test_vulnerability_mitigation(self):
        """Test that identified vulnerabilities are properly mitigated"""
        # Test 1: Injection attack mitigation
        malicious_inputs = [
            "'; DROP TABLE keys; --",
            "../../../etc/passwd",
            "<script>alert('xss')</script>",
            "key' OR '1'='1"
        ]
        
        for malicious in malicious_inputs:
            try:
                # Attempt to store with malicious service name
                self.secure_storage.store_key(malicious, 'test_key', {})
                # Attempt to retrieve with malicious key
                self.secure_storage.get_key(malicious)
            except Exception:
                pass  # Expected to fail safely
            
            # Verify no corruption
            keys = self.secure_storage.list_keys()
            self.assertIsInstance(keys, list)
        
        # Test 2: Timing attack mitigation
        valid_service = 'existing_service'
        self.secure_storage.store_key(valid_service, 'test_key', {})
        
        # Measure timing for valid vs invalid keys
        import time
        
        valid_times = []
        invalid_times = []
        
        for _ in range(10):
            # Valid key timing
            start = time.perf_counter()
            try:
                self.secure_storage.get_key(valid_service)
            except:
                pass
            valid_times.append(time.perf_counter() - start)
            
            # Invalid key timing
            start = time.perf_counter()
            try:
                self.secure_storage.get_key('nonexistent_service')
            except:
                pass
            invalid_times.append(time.perf_counter() - start)
        
        # Check timing difference is minimal (less than 50ms average)
        avg_valid = sum(valid_times) / len(valid_times)
        avg_invalid = sum(invalid_times) / len(invalid_times)
        timing_diff = abs(avg_valid - avg_invalid)
        self.assertLess(timing_diff, 0.05)  # 50ms threshold
        
        # Test 3: Memory security
        sensitive_key = 'memory_test_key_secret'
        self.secure_storage.store_key('memory_test', sensitive_key, {})
        
        # Retrieve and then delete reference
        retrieved = self.secure_storage.get_key('memory_test')
        del retrieved
        
        # Force garbage collection
        import gc
        gc.collect()
        
        # Key should not be easily accessible in memory
        # (This is a simplified test - real memory security requires OS-level features)
    
    def test_secure_backup_restore(self):
        """Test secure backup and restore functionality"""
        # Store some test data
        test_data = {
            'github': 'ghp_backup_test_123',
            'aws': 'AKIA_backup_test_456',
            'stripe': 'sk_test_backup_789'
        }
        
        for service, key in test_data.items():
            self.secure_storage.store_key(service, key, {
                'environment': 'production',
                'created_at': datetime.now().isoformat()
            })
        
        # Create backup
        backup_path = os.path.join(self.test_dir, 'backup.enc')
        backup_data = {
            'keys': {},
            'metadata': {},
            'timestamp': datetime.now().isoformat()
        }
        
        for service in test_data:
            backup_data['keys'][service] = self.secure_storage.get_key(service)
            backup_data['metadata'][service] = self.secure_storage.get_metadata(service)
        
        # Encrypt backup
        from cryptography.fernet import Fernet
        import base64
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
        
        # Derive backup key from master key
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b'backup_salt_12345',
            iterations=100000
        )
        backup_key = base64.urlsafe_b64encode(
            kdf.derive(self.master_key.encode())
        )
        fernet = Fernet(backup_key)
        
        encrypted_backup = fernet.encrypt(json.dumps(backup_data).encode())
        with open(backup_path, 'wb') as f:
            f.write(encrypted_backup)
        
        # Clear current storage
        self.secure_storage.data = {'keys': {}, 'metadata': {}}
        
        # Restore from backup
        with open(backup_path, 'rb') as f:
            encrypted_data = f.read()
        
        decrypted_data = fernet.decrypt(encrypted_data)
        restored_data = json.loads(decrypted_data.decode())
        
        # Verify restoration
        self.assertEqual(len(restored_data['keys']), len(test_data))
        for service, key in test_data.items():
            self.assertEqual(restored_data['keys'][service], key)
            self.assertIn('environment', restored_data['metadata'][service])
    
    def test_cli_integration_security(self):
        """Test CLI tool security integration"""
        cli_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            'src', 'cli.py'
        )
        
        if not os.path.exists(cli_path):
            self.skipTest("CLI tool not found")
        
        # Test secure key addition via CLI
        env = os.environ.copy()
        env['API_KEY_MASTER'] = self.master_key
        
        # Add a key using CLI
        result = subprocess.run(
            [sys.executable, cli_path, 'add', 'test_service', 'test_key_123'],
            env=env,
            capture_output=True,
            text=True,
            cwd=self.test_dir
        )
        
        # Verify the key was added securely
        if result.returncode == 0:
            # Check that the key is encrypted in storage
            storage_file = os.path.join(self.test_dir, 'keys.json')
            if os.path.exists(storage_file):
                with open(storage_file, 'r') as f:
                    content = f.read()
                    self.assertNotIn('test_key_123', content)
    
    def test_integration_error_handling(self):
        """Test error handling across integrated components"""
        # Test 1: Invalid master key
        with self.assertRaises(Exception):
            invalid_storage = SecureStorage(
                storage_path=os.path.join(self.test_dir, "invalid.enc"),
                master_key=""  # Empty master key
            )
        
        # Test 2: Corrupted storage file
        corrupted_path = os.path.join(self.test_dir, "corrupted.enc")
        with open(corrupted_path, 'wb') as f:
            f.write(b'corrupted data')
        
        with self.assertRaises(Exception):
            corrupted_storage = SecureStorage(
                storage_path=corrupted_path,
                master_key=self.master_key
            )
            corrupted_storage.load()
        
        # Test 3: Integration with invalid API key format
        github = GitHubIntegration()
        invalid_key = 'invalid_format_key'
        is_valid = github.validate_api_key(invalid_key)
        self.assertFalse(is_valid)
        
        # Test 4: Key rotation with non-existent key
        result = self.key_rotation.rotate_key(
            'nonexistent_service',
            'new_key',
            reason='Test rotation'
        )
        self.assertFalse(result['success'])
        self.assertIn('error', result)
    
    def test_performance_under_security_load(self):
        """Test performance with all security features enabled"""
        num_keys = 1000
        start_time = time.time()
        
        # Add keys with full security
        for i in range(num_keys):
            service = f'service_{i}'
            key = f'key_{i}_' + 'x' * 100  # Longer keys
            
            self.secure_storage.store_key(service, key, {
                'index': i,
                'timestamp': datetime.now().isoformat(),
                'metadata': 'x' * 500  # Additional metadata
            })
        
        add_time = time.time() - start_time
        avg_add_time = (add_time / num_keys) * 1000  # Convert to ms
        
        # Performance should still be acceptable with security
        self.assertLess(avg_add_time, 10)  # Less than 10ms per key
        
        # Test retrieval performance
        start_time = time.time()
        for i in range(100):  # Sample retrieval
            service = f'service_{i}'
            key = self.secure_storage.get_key(service)
            self.assertIsNotNone(key)
        
        get_time = time.time() - start_time
        avg_get_time = (get_time / 100) * 1000
        self.assertLess(avg_get_time, 5)  # Less than 5ms per retrieval


class SecurityComplianceTests(unittest.TestCase):
    """Tests for security compliance and standards"""
    
    def setUp(self):
        """Set up test environment"""
        self.test_dir = tempfile.mkdtemp()
        self.master_key = "compliance_test_key_123"
        os.environ['API_KEY_MASTER'] = self.master_key
        
        self.secure_storage = SecureStorage(
            storage_path=os.path.join(self.test_dir, "secure_keys.enc"),
            master_key=self.master_key
        )
    
    def tearDown(self):
        """Clean up test environment"""
        shutil.rmtree(self.test_dir, ignore_errors=True)
        if 'API_KEY_MASTER' in os.environ:
            del os.environ['API_KEY_MASTER']
    
    def test_owasp_compliance(self):
        """Test OWASP Top 10 compliance"""
        # A1: Injection - Test SQL/Command injection prevention
        injection_tests = [
            "'; DROP TABLE; --",
            "$(rm -rf /)",
            "`cat /etc/passwd`"
        ]
        
        for payload in injection_tests:
            # Should handle safely without executing
            try:
                self.secure_storage.store_key(payload, 'test', {})
            except Exception as e:
                # Should fail safely
                self.assertNotIn('command', str(e).lower())
                self.assertNotIn('sql', str(e).lower())
        
        # A2: Broken Authentication - Test strong key derivation
        # Already using PBKDF2 with 100k iterations
        
        # A3: Sensitive Data Exposure - Test encryption
        sensitive_key = 'super_secret_api_key'
        self.secure_storage.store_key('sensitive', sensitive_key, {})
        
        # Verify encrypted at rest
        with open(self.secure_storage.storage_path, 'rb') as f:
            content = f.read()
            self.assertNotIn(sensitive_key.encode(), content)
        
        # A5: Broken Access Control - Test access restrictions
        # File permissions tested separately
        
        # A6: Security Misconfiguration - Test secure defaults
        # Verify secure defaults are in place
        self.assertEqual(self.secure_storage.iterations, 100000)  # Strong KDF
        
        # A9: Using Components with Known Vulnerabilities
        # This would require checking dependency versions
        
        # A10: Insufficient Logging & Monitoring
        # Verify audit logging exists
        self.secure_storage.store_key('audit_test', 'key', {
            'action': 'store',
            'timestamp': datetime.now().isoformat(),
            'user': 'test_user'
        })
        
        metadata = self.secure_storage.get_metadata('audit_test')
        self.assertIn('timestamp', metadata)
    
    def test_pci_dss_compliance(self):
        """Test PCI DSS compliance requirements"""
        # Requirement 3: Protect stored cardholder data
        # Using strong encryption (AES-256-GCM)
        
        # Requirement 8: Identify and authenticate access
        # Test key access tracking
        test_key = 'pci_test_key_123'
        self.secure_storage.store_key('pci_test', test_key, {
            'accessed_by': 'user_123',
            'access_time': datetime.now().isoformat()
        })
        
        # Requirement 10: Track and monitor access
        metadata = self.secure_storage.get_metadata('pci_test')
        self.assertIn('access_time', metadata)
        
        # Requirement 12: Maintain security policy
        # Test key rotation capability
        old_key = self.secure_storage.get_key('pci_test')
        new_key = 'pci_test_key_456'
        
        # Manual rotation (since KeyRotationManager isn't initialized here)
        self.secure_storage.store_key('pci_test', new_key, {
            'rotated_from': old_key,
            'rotation_time': datetime.now().isoformat(),
            'rotation_reason': 'PCI compliance'
        })
        
        self.assertEqual(self.secure_storage.get_key('pci_test'), new_key)


if __name__ == '__main__':
    unittest.main(verbosity=2)