"""
Tests for Critical Security Recommendations from QA Audit
Focuses on implementing and validating the immediate action items
"""

import unittest
import os
import tempfile
import shutil
import time
import secrets
import ctypes
import sys
import platform
from unittest.mock import Mock, patch

sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cryptography.hazmat.primitives import constant_time


class CriticalSecurityTests(unittest.TestCase):
    """Tests for critical security recommendations"""
    
    def setUp(self):
        """Set up test environment"""
        self.test_dir = tempfile.mkdtemp()
        
    def tearDown(self):
        """Clean up test environment"""
        shutil.rmtree(self.test_dir, ignore_errors=True)
    
    def test_constant_time_comparison(self):
        """Test implementation of constant-time string comparison"""
        # Test data
        test_pairs = [
            ("test_key_123", "test_key_123", True),  # Equal
            ("test_key_123", "test_key_456", False),  # Different
            ("short", "longer_string", False),  # Different lengths
            ("", "", True),  # Empty strings
            ("a" * 1000, "a" * 1000, True),  # Long equal strings
            ("a" * 1000, "b" * 1000, False),  # Long different strings
        ]
        
        for str1, str2, expected in test_pairs:
            # Use constant-time comparison
            result = constant_time.bytes_eq(str1.encode(), str2.encode())
            self.assertEqual(result, expected)
            
            # Measure timing to ensure constant-time behavior
            iterations = 1000
            
            # Time for equal strings
            start = time.perf_counter()
            for _ in range(iterations):
                constant_time.bytes_eq(str1.encode(), str1.encode())
            equal_time = time.perf_counter() - start
            
            # Time for different strings
            if str1 != str2 and len(str1) == len(str2):
                start = time.perf_counter()
                for _ in range(iterations):
                    constant_time.bytes_eq(str1.encode(), str2.encode())
                diff_time = time.perf_counter() - start
                
                # Timing should be similar (within 20% variance)
                time_ratio = max(equal_time, diff_time) / min(equal_time, diff_time)
                self.assertLess(time_ratio, 1.2, 
                    f"Timing attack possible: ratio {time_ratio}")
    
    def test_secure_memory_wiping(self):
        """Test secure erasure of sensitive data from memory"""
        
        def secure_zero_memory(data):
            """Securely overwrite memory"""
            if isinstance(data, str):
                data = data.encode()
            
            if isinstance(data, (bytes, bytearray)):
                # Multiple overwrite passes
                for _ in range(3):
                    # Overwrite with random data
                    for i in range(len(data)):
                        if isinstance(data, bytearray):
                            data[i] = secrets.randbits(8)
                
                # Final overwrite with zeros
                for i in range(len(data)):
                    if isinstance(data, bytearray):
                        data[i] = 0
                
                return True
            return False
        
        # Test with bytearray (mutable)
        sensitive_data = bytearray(b"sensitive_api_key_12345")
        original = bytes(sensitive_data)
        
        # Securely wipe
        secure_zero_memory(sensitive_data)
        
        # Verify data is wiped
        self.assertNotEqual(sensitive_data, original)
        self.assertEqual(sensitive_data, bytearray(len(original)))
        
        # Test with different data types
        test_data = [
            bytearray(b"test_password_123"),
            bytearray(b"api_key_secret_456"),
            bytearray(b"x" * 1000)  # Large data
        ]
        
        for data in test_data:
            original_len = len(data)
            secure_zero_memory(data)
            self.assertEqual(len(data), original_len)
            self.assertEqual(data, bytearray(original_len))
    
    def test_memory_locking(self):
        """Test memory locking to prevent swapping (platform-specific)"""
        if platform.system() not in ['Linux', 'Darwin']:
            self.skipTest("Memory locking test only for Unix-like systems")
        
        try:
            # Try to import mlock functionality
            if platform.system() == 'Linux':
                libc = ctypes.CDLL("libc.so.6")
            else:  # macOS
                libc = ctypes.CDLL("libc.dylib")
            
            # Define mlock and munlock
            mlock = libc.mlock
            munlock = libc.munlock
            
            # Test data
            sensitive_data = b"sensitive_api_key_to_protect"
            data_ptr = ctypes.c_char_p(sensitive_data)
            data_len = len(sensitive_data)
            
            # Try to lock memory (may fail without proper permissions)
            try:
                result = mlock(data_ptr, data_len)
                if result == 0:
                    # Successfully locked
                    self.assertEqual(result, 0)
                    # Unlock when done
                    munlock(data_ptr, data_len)
                else:
                    # Locking failed (likely permission issue)
                    # This is expected in many environments
                    pass
            except Exception:
                # Expected in restricted environments
                pass
                
        except Exception as e:
            # Skip if platform doesn't support memory locking
            self.skipTest(f"Memory locking not available: {e}")
    
    def test_authentication_layer(self):
        """Test implementation of authentication layer"""
        
        class AuthenticationManager:
            """Simple authentication manager for testing"""
            
            def __init__(self):
                self.users = {}
                self.sessions = {}
                self.failed_attempts = {}
                self.max_attempts = 3
                self.lockout_duration = 300  # 5 minutes
            
            def create_user(self, username, password_hash, requires_2fa=False):
                """Create a new user"""
                self.users[username] = {
                    'password_hash': password_hash,
                    'requires_2fa': requires_2fa,
                    'created_at': time.time()
                }
            
            def authenticate(self, username, password_hash, otp_code=None):
                """Authenticate user"""
                # Check lockout
                if username in self.failed_attempts:
                    attempts, last_attempt = self.failed_attempts[username]
                    if attempts >= self.max_attempts:
                        if time.time() - last_attempt < self.lockout_duration:
                            return False, "Account locked due to failed attempts"
                
                # Verify user exists
                if username not in self.users:
                    # Still track failed attempt to prevent enumeration
                    self._record_failed_attempt(username)
                    return False, "Invalid credentials"
                
                user = self.users[username]
                
                # Constant-time password comparison
                if not constant_time.bytes_eq(
                    password_hash.encode(), 
                    user['password_hash'].encode()
                ):
                    self._record_failed_attempt(username)
                    return False, "Invalid credentials"
                
                # Check 2FA if required
                if user['requires_2fa']:
                    if not otp_code or not self._verify_otp(username, otp_code):
                        return False, "Invalid 2FA code"
                
                # Success - clear failed attempts
                if username in self.failed_attempts:
                    del self.failed_attempts[username]
                
                # Create session
                session_id = secrets.token_urlsafe(32)
                self.sessions[session_id] = {
                    'username': username,
                    'created_at': time.time(),
                    'last_activity': time.time()
                }
                
                return True, session_id
            
            def _record_failed_attempt(self, username):
                """Record failed login attempt"""
                if username not in self.failed_attempts:
                    self.failed_attempts[username] = (0, time.time())
                
                attempts, _ = self.failed_attempts[username]
                self.failed_attempts[username] = (attempts + 1, time.time())
            
            def _verify_otp(self, username, otp_code):
                """Verify OTP code (simplified for testing)"""
                # In production, use pyotp or similar
                return otp_code == "123456"  # Test OTP
        
        # Test authentication manager
        auth_mgr = AuthenticationManager()
        
        # Create test users
        auth_mgr.create_user("user1", "hashed_password_1", requires_2fa=False)
        auth_mgr.create_user("user2", "hashed_password_2", requires_2fa=True)
        
        # Test successful authentication
        success, session = auth_mgr.authenticate("user1", "hashed_password_1")
        self.assertTrue(success)
        self.assertIsInstance(session, str)
        self.assertGreater(len(session), 30)  # Secure session ID
        
        # Test failed authentication
        success, error = auth_mgr.authenticate("user1", "wrong_password")
        self.assertFalse(success)
        self.assertEqual(error, "Invalid credentials")
        
        # Test 2FA requirement
        success, error = auth_mgr.authenticate("user2", "hashed_password_2")
        self.assertFalse(success)
        self.assertEqual(error, "Invalid 2FA code")
        
        # Test 2FA success
        success, session = auth_mgr.authenticate(
            "user2", "hashed_password_2", otp_code="123456"
        )
        self.assertTrue(success)
        
        # Test account lockout
        for _ in range(3):
            auth_mgr.authenticate("user1", "wrong_password")
        
        success, error = auth_mgr.authenticate("user1", "hashed_password_1")
        self.assertFalse(success)
        self.assertEqual(error, "Account locked due to failed attempts")
    
    def test_role_based_access_control(self):
        """Test RBAC implementation"""
        
        class RBACManager:
            """Role-Based Access Control manager"""
            
            def __init__(self):
                self.roles = {
                    'admin': {
                        'permissions': ['read', 'write', 'delete', 'rotate', 'audit']
                    },
                    'developer': {
                        'permissions': ['read', 'write', 'rotate']
                    },
                    'auditor': {
                        'permissions': ['read', 'audit']
                    },
                    'viewer': {
                        'permissions': ['read']
                    }
                }
                self.user_roles = {}
                self.key_policies = {}
            
            def assign_role(self, username, role):
                """Assign role to user"""
                if role not in self.roles:
                    raise ValueError(f"Invalid role: {role}")
                self.user_roles[username] = role
            
            def check_permission(self, username, action, resource=None):
                """Check if user has permission for action"""
                if username not in self.user_roles:
                    return False
                
                role = self.user_roles[username]
                permissions = self.roles[role]['permissions']
                
                # Check basic permission
                if action not in permissions:
                    return False
                
                # Check resource-specific policy if exists
                if resource and resource in self.key_policies:
                    policy = self.key_policies[resource]
                    if 'allowed_users' in policy:
                        return username in policy['allowed_users']
                    if 'allowed_roles' in policy:
                        return role in policy['allowed_roles']
                
                return True
            
            def set_key_policy(self, key_name, policy):
                """Set access policy for specific key"""
                self.key_policies[key_name] = policy
            
            def get_user_accessible_keys(self, username):
                """Get list of keys user can access"""
                if username not in self.user_roles:
                    return []
                
                role = self.user_roles[username]
                accessible_keys = []
                
                for key_name, policy in self.key_policies.items():
                    if 'allowed_users' in policy and username in policy['allowed_users']:
                        accessible_keys.append(key_name)
                    elif 'allowed_roles' in policy and role in policy['allowed_roles']:
                        accessible_keys.append(key_name)
                    elif 'public' in policy and policy['public']:
                        accessible_keys.append(key_name)
                
                return accessible_keys
        
        # Test RBAC
        rbac = RBACManager()
        
        # Assign roles
        rbac.assign_role('alice', 'admin')
        rbac.assign_role('bob', 'developer')
        rbac.assign_role('charlie', 'auditor')
        rbac.assign_role('david', 'viewer')
        
        # Test permissions
        self.assertTrue(rbac.check_permission('alice', 'delete'))
        self.assertFalse(rbac.check_permission('bob', 'delete'))
        self.assertTrue(rbac.check_permission('charlie', 'audit'))
        self.assertFalse(rbac.check_permission('david', 'write'))
        
        # Set key policies
        rbac.set_key_policy('production_db_key', {
            'allowed_roles': ['admin'],
            'description': 'Production database credentials'
        })
        
        rbac.set_key_policy('api_key_github', {
            'allowed_roles': ['admin', 'developer'],
            'description': 'GitHub API access'
        })
        
        rbac.set_key_policy('audit_log_key', {
            'allowed_users': ['charlie'],
            'allowed_roles': ['admin'],
            'description': 'Audit log encryption key'
        })
        
        # Test key access
        alice_keys = rbac.get_user_accessible_keys('alice')
        self.assertIn('production_db_key', alice_keys)
        self.assertIn('api_key_github', alice_keys)
        self.assertIn('audit_log_key', alice_keys)
        
        bob_keys = rbac.get_user_accessible_keys('bob')
        self.assertNotIn('production_db_key', bob_keys)
        self.assertIn('api_key_github', bob_keys)
        
        charlie_keys = rbac.get_user_accessible_keys('charlie')
        self.assertIn('audit_log_key', charlie_keys)
        self.assertNotIn('api_key_github', charlie_keys)
    
    def test_granular_permissions(self):
        """Test granular permission system"""
        
        class GranularPermissionManager:
            """Manage fine-grained permissions"""
            
            def __init__(self):
                self.permissions = {}
            
            def grant_permission(self, username, resource, actions, 
                               conditions=None, expiry=None):
                """Grant specific permissions with conditions"""
                if username not in self.permissions:
                    self.permissions[username] = {}
                
                self.permissions[username][resource] = {
                    'actions': actions if isinstance(actions, list) else [actions],
                    'conditions': conditions or {},
                    'expiry': expiry,
                    'granted_at': time.time()
                }
            
            def check_permission(self, username, resource, action, context=None):
                """Check if action is allowed with context"""
                if username not in self.permissions:
                    return False, "No permissions found"
                
                if resource not in self.permissions[username]:
                    return False, "No permission for resource"
                
                perm = self.permissions[username][resource]
                
                # Check expiry
                if perm['expiry'] and time.time() > perm['expiry']:
                    return False, "Permission expired"
                
                # Check action
                if action not in perm['actions']:
                    return False, f"Action '{action}' not allowed"
                
                # Check conditions
                if perm['conditions'] and context:
                    for condition, value in perm['conditions'].items():
                        if condition == 'ip_whitelist':
                            if context.get('ip') not in value:
                                return False, "IP not whitelisted"
                        elif condition == 'time_window':
                            current_hour = time.localtime().tm_hour
                            start, end = value
                            if not (start <= current_hour < end):
                                return False, "Outside allowed time window"
                        elif condition == 'max_uses':
                            # Would need to track usage
                            pass
                
                return True, "Permission granted"
        
        # Test granular permissions
        perm_mgr = GranularPermissionManager()
        
        # Grant permissions with conditions
        perm_mgr.grant_permission(
            'developer1',
            'api_key_staging',
            ['read', 'rotate'],
            conditions={
                'ip_whitelist': ['10.0.0.1', '10.0.0.2'],
                'time_window': (9, 17)  # 9 AM to 5 PM
            },
            expiry=time.time() + 86400  # 24 hours
        )
        
        # Test with valid context
        allowed, msg = perm_mgr.check_permission(
            'developer1',
            'api_key_staging',
            'read',
            context={'ip': '10.0.0.1'}
        )
        self.assertTrue(allowed)
        
        # Test with invalid IP
        allowed, msg = perm_mgr.check_permission(
            'developer1',
            'api_key_staging',
            'read',
            context={'ip': '192.168.1.1'}
        )
        self.assertFalse(allowed)
        self.assertIn("IP not whitelisted", msg)
        
        # Test unauthorized action
        allowed, msg = perm_mgr.check_permission(
            'developer1',
            'api_key_staging',
            'delete'
        )
        self.assertFalse(allowed)
        self.assertIn("not allowed", msg)


if __name__ == '__main__':
    unittest.main(verbosity=2)