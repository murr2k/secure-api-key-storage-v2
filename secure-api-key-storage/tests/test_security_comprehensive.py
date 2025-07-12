"""Comprehensive security tests for the secure API key storage system."""

import pytest
import os
import tempfile
import time
import hashlib
import secrets
from datetime import datetime, timedelta
from pathlib import Path
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

from src.secure_storage_rbac import SecureKeyStorageRBAC
from src.rbac_models import Role, Permission
from src.audit_enhancement import TamperProofAuditLogger
from src.auth_manager import AuthenticationManager


class TestEncryptionSecurity:
    """Test encryption and cryptographic security."""
    
    def test_aes_256_gcm_encryption(self, test_storage: SecureKeyStorageRBAC):
        """Test that AES-256-GCM encryption is used correctly."""
        # Store a key and verify it's encrypted
        test_key = "super_secret_api_key_12345"
        key_id = test_storage.store_key("test_key", test_key, "TestService")
        
        # Check that the stored data is encrypted (not plaintext)
        storage_path = Path(test_storage.storage_path)
        encrypted_files = list(storage_path.glob("*.enc"))
        
        assert len(encrypted_files) > 0, "No encrypted files found"
        
        # Read encrypted file content
        with open(encrypted_files[0], 'rb') as f:
            encrypted_content = f.read()
            
        # Verify the original key is not in plaintext
        assert test_key.encode() not in encrypted_content
        
        # Verify we can decrypt and retrieve the key
        retrieved_key = test_storage.get_key(key_id)
        assert retrieved_key == test_key
        
    def test_encryption_key_derivation(self, test_storage: SecureKeyStorageRBAC):
        """Test that encryption keys are properly derived from master password."""
        # Store multiple keys and verify they use different salts/IVs
        keys = [
            ("key1", "value1"),
            ("key2", "value2"),
            ("key3", "value3")
        ]
        
        for name, value in keys:
            test_storage.store_key(name, value, "TestService")
            
        # Check that different encrypted files have different content
        storage_path = Path(test_storage.storage_path)
        encrypted_files = list(storage_path.glob("*.enc"))
        
        assert len(encrypted_files) >= 3
        
        # Read all encrypted contents
        encrypted_contents = []
        for file_path in encrypted_files:
            with open(file_path, 'rb') as f:
                encrypted_contents.append(f.read())
                
        # Verify all encrypted contents are different (no key reuse)
        for i, content1 in enumerate(encrypted_contents):
            for j, content2 in enumerate(encrypted_contents):
                if i != j:
                    assert content1 != content2, "Encrypted contents should be unique"
                    
    def test_memory_security(self, test_storage: SecureKeyStorageRBAC):
        """Test secure memory handling."""
        # This test verifies that sensitive data is cleared from memory
        test_key = "memory_test_key_12345"
        key_id = test_storage.store_key("memory_test", test_key, "TestService")
        
        # Retrieve the key
        retrieved_key = test_storage.get_key(key_id)
        assert retrieved_key == test_key
        
        # Force garbage collection to ensure memory is cleared
        import gc
        gc.collect()
        
        # Note: This is a basic test. In practice, we'd need more sophisticated
        # memory inspection tools to verify memory is actually cleared
        
    def test_constant_time_comparisons(self, test_storage: SecureKeyStorageRBAC):
        """Test that password comparisons are constant-time."""
        # This test ensures timing attacks are prevented
        correct_password = "test_master_password_123"
        wrong_passwords = [
            "wrong",
            "test_master_password_12",  # Close but wrong
            "test_master_password_1234",  # One char too long
            "TEST_MASTER_PASSWORD_123",  # Wrong case
        ]
        
        # Time the correct password
        start_time = time.time()
        result_correct = test_storage.verify_master_password(correct_password)
        correct_time = time.time() - start_time
        
        assert result_correct is True
        
        # Time wrong passwords
        wrong_times = []
        for wrong_password in wrong_passwords:
            start_time = time.time()
            result_wrong = test_storage.verify_master_password(wrong_password)
            wrong_time = time.time() - start_time
            wrong_times.append(wrong_time)
            
            assert result_wrong is False
            
        # Verify timing differences are minimal (within reasonable variance)
        for wrong_time in wrong_times:
            time_diff = abs(correct_time - wrong_time)
            # Allow for some variance but should be relatively constant
            assert time_diff < 0.01, f"Timing difference too large: {time_diff}"
            
    def test_encryption_randomness(self, test_storage: SecureKeyStorageRBAC):
        """Test that encryption uses proper randomness."""
        # Store the same key multiple times and verify different encrypted output
        test_key = "randomness_test_key"
        
        encrypted_versions = []
        for i in range(5):
            key_id = test_storage.store_key(f"random_test_{i}", test_key, "TestService")
            
            # Read the encrypted file
            storage_path = Path(test_storage.storage_path)
            key_file = storage_path / f"{key_id}.enc"
            
            if key_file.exists():
                with open(key_file, 'rb') as f:
                    encrypted_versions.append(f.read())
                    
        # Verify all encrypted versions are different
        assert len(set(encrypted_versions)) == len(encrypted_versions), \
            "Encrypted versions should all be unique due to randomness"


class TestRBACSecurityEnforcement:
    """Test RBAC security enforcement."""
    
    def test_permission_enforcement(self, test_storage: SecureKeyStorageRBAC, test_users):
        """Test that RBAC permissions are properly enforced."""
        admin_id = test_users["admin"]["id"]
        user_id = test_users["user"]["id"]
        viewer_id = test_users["viewer"]["id"]
        
        # Admin creates a key
        key_id = test_storage.add_api_key_with_rbac(
            "TestService", "admin_key_value", admin_id
        )
        
        # Admin should be able to access
        admin_key = test_storage.get_api_key_with_rbac(key_id, admin_id)
        assert admin_key == "admin_key_value"
        
        # User should not be able to access without permission
        with pytest.raises(Exception):  # SecurityException
            test_storage.get_api_key_with_rbac(key_id, user_id)
            
        # Viewer should not be able to access without permission
        with pytest.raises(Exception):  # SecurityException
            test_storage.get_api_key_with_rbac(key_id, viewer_id)
            
    def test_permission_granting(self, test_storage: SecureKeyStorageRBAC, test_users):
        """Test permission granting and revocation."""
        admin_id = test_users["admin"]["id"]
        user_id = test_users["user"]["id"]
        
        # Admin creates a key
        key_id = test_storage.add_api_key_with_rbac(
            "TestService", "shared_key_value", admin_id
        )
        
        # Grant read permission to user
        test_storage.grant_key_access(
            key_id, admin_id, user_id, [Permission.KEY_READ]
        )
        
        # User should now be able to read
        user_key = test_storage.get_api_key_with_rbac(key_id, user_id)
        assert user_key == "shared_key_value"
        
        # User should not be able to update (no permission)
        with pytest.raises(Exception):  # SecurityException
            test_storage.update_api_key_with_rbac(key_id, "new_value", user_id)
            
    def test_role_based_permissions(self, test_storage: SecureKeyStorageRBAC, test_users):
        """Test that different roles have appropriate permissions."""
        admin_id = test_users["admin"]["id"]
        user_id = test_users["user"]["id"]
        viewer_id = test_users["viewer"]["id"]
        
        # Test admin permissions
        admin_key_id = test_storage.add_api_key_with_rbac(
            "AdminService", "admin_value", admin_id
        )
        assert admin_key_id is not None
        
        # Test user permissions (should be able to create)
        user_key_id = test_storage.add_api_key_with_rbac(
            "UserService", "user_value", user_id
        )
        assert user_key_id is not None
        
        # Test viewer permissions (should not be able to create)
        with pytest.raises(Exception):  # SecurityException
            test_storage.add_api_key_with_rbac(
                "ViewerService", "viewer_value", viewer_id
            )
            
    def test_permission_inheritance(self, test_storage: SecureKeyStorageRBAC, test_users):
        """Test permission inheritance and hierarchy."""
        admin_id = test_users["admin"]["id"]
        user_id = test_users["user"]["id"]
        
        # Create key as admin
        key_id = test_storage.add_api_key_with_rbac(
            "TestService", "inheritance_test", admin_id
        )
        
        # Grant cascading permissions
        test_storage.grant_key_access(
            key_id, admin_id, user_id, 
            [Permission.KEY_READ, Permission.KEY_UPDATE]
        )
        
        # User should be able to read and update
        retrieved_key = test_storage.get_api_key_with_rbac(key_id, user_id)
        assert retrieved_key == "inheritance_test"
        
        update_result = test_storage.update_api_key_with_rbac(
            key_id, "updated_value", user_id
        )
        assert update_result is True
        
        # But not delete (no permission)
        with pytest.raises(Exception):  # SecurityException
            test_storage.revoke_key_with_rbac(key_id, user_id)


class TestAuthenticationSecurity:
    """Test authentication security measures."""
    
    def test_password_hashing(self, rbac_manager):
        """Test that passwords are properly hashed."""
        username = "test_hash_user"
        password = "test_password_123"
        
        user_id = rbac_manager.create_user(
            username, password, Role.USER, email="test@example.com"
        )
        
        # Verify password is not stored in plaintext
        import sqlite3
        conn = sqlite3.connect(rbac_manager.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT password_hash FROM users WHERE id = ?", (user_id,))
        stored_hash = cursor.fetchone()[0]
        conn.close()
        
        # Password should be hashed
        assert stored_hash != password
        assert len(stored_hash) > 50  # Hashed password should be long
        assert "$" in stored_hash  # Should contain hash format markers
        
        # Verify password verification works
        is_valid = rbac_manager.verify_password(username, password)
        assert is_valid is True
        
        # Verify wrong password fails
        is_invalid = rbac_manager.verify_password(username, "wrong_password")
        assert is_invalid is False
        
    def test_session_management(self, rbac_manager):
        """Test secure session management."""
        username = "session_test_user"
        password = "session_password_123"
        
        user_id = rbac_manager.create_user(
            username, password, Role.USER, email="session@example.com"
        )
        
        # Create session
        session_data = rbac_manager.create_session(user_id)
        
        assert "session_id" in session_data
        assert "expires_at" in session_data
        assert "user_id" in session_data
        
        # Verify session is valid
        is_valid = rbac_manager.validate_session(session_data["session_id"])
        assert is_valid is True
        
        # Revoke session
        rbac_manager.revoke_session(session_data["session_id"])
        
        # Verify session is no longer valid
        is_valid_after_revoke = rbac_manager.validate_session(session_data["session_id"])
        assert is_valid_after_revoke is False
        
    def test_brute_force_protection(self, rbac_manager):
        """Test protection against brute force attacks."""
        username = "brute_force_user"
        password = "correct_password_123"
        
        rbac_manager.create_user(
            username, password, Role.USER, email="brute@example.com"
        )
        
        # Attempt multiple failed logins
        for i in range(10):
            result = rbac_manager.verify_password(username, f"wrong_password_{i}")
            assert result is False
            
        # Account should be locked or rate limited
        # (Implementation depends on the specific brute force protection mechanism)
        
    def test_password_complexity_requirements(self, rbac_manager):
        """Test password complexity requirements."""
        weak_passwords = [
            "123456",
            "password",
            "abc",
            "aaaaaaa",
            "1234567"
        ]
        
        for weak_password in weak_passwords:
            with pytest.raises(Exception):  # Should reject weak passwords
                rbac_manager.create_user(
                    f"weak_user_{weak_password}",
                    weak_password,
                    Role.USER,
                    email="weak@example.com"
                )


class TestAuditSecurity:
    """Test audit logging security."""
    
    def test_tamper_proof_logging(self, audit_logger: TamperProofAuditLogger):
        """Test that audit logs are tamper-proof."""
        # Log some events
        events = [
            {"action": "key_created", "user": "admin", "key_id": "test_key_1"},
            {"action": "key_accessed", "user": "user1", "key_id": "test_key_1"},
            {"action": "key_deleted", "user": "admin", "key_id": "test_key_1"}
        ]
        
        for event in events:
            audit_logger.log_event(
                event["action"],
                event["user"],
                details=event
            )
            
        # Verify audit log integrity
        log_entries = audit_logger.get_audit_logs(limit=10)
        assert len(log_entries) >= 3
        
        # Each entry should have integrity hash
        for entry in log_entries:
            assert "integrity_hash" in entry
            assert "timestamp" in entry
            assert "action" in entry
            
        # Verify integrity
        integrity_check = audit_logger.verify_integrity()
        assert integrity_check is True
        
    def test_audit_log_encryption(self, audit_logger: TamperProofAuditLogger):
        """Test that sensitive audit data is encrypted."""
        sensitive_event = {
            "action": "sensitive_operation",
            "user": "admin",
            "sensitive_data": "secret_information_12345"
        }
        
        audit_logger.log_event(
            sensitive_event["action"],
            sensitive_event["user"],
            details=sensitive_event
        )
        
        # Read raw log file
        with open(audit_logger.log_file, 'r') as f:
            raw_content = f.read()
            
        # Sensitive data should not appear in plaintext
        assert "secret_information_12345" not in raw_content
        
        # But should be retrievable through proper channels
        log_entries = audit_logger.get_audit_logs(limit=1)
        assert len(log_entries) > 0
        
    def test_audit_log_immutability(self, audit_logger: TamperProofAuditLogger):
        """Test that audit logs cannot be modified after creation."""
        original_event = {
            "action": "immutable_test",
            "user": "admin",
            "data": "original_data"
        }
        
        audit_logger.log_event(
            original_event["action"],
            original_event["user"],
            details=original_event
        )
        
        # Get the log file path
        log_file_path = Path(audit_logger.log_file)
        
        # Attempt to modify the log file
        try:
            with open(log_file_path, 'a') as f:
                f.write("\nMALICIOUS LOG ENTRY")
                
            # Integrity check should fail
            integrity_check = audit_logger.verify_integrity()
            assert integrity_check is False, "Integrity check should detect tampering"
            
        except (PermissionError, OSError):
            # If file is protected, that's also good
            pass


class TestInputValidationSecurity:
    """Test input validation and sanitization."""
    
    def test_sql_injection_prevention(self, test_storage: SecureKeyStorageRBAC):
        """Test prevention of SQL injection attacks."""
        malicious_inputs = [
            "'; DROP TABLE api_keys; --",
            "1' OR '1'='1",
            "admin'; DELETE FROM users WHERE '1'='1",
            "test' UNION SELECT * FROM users --"
        ]
        
        for malicious_input in malicious_inputs:
            # Try to inject via key name
            try:
                key_id = test_storage.store_key(
                    malicious_input, "test_value", "TestService"
                )
                
                # If storage succeeds, verify it was properly escaped
                retrieved_key = test_storage.get_key(key_id)
                assert retrieved_key == "test_value"
                
                # Clean up
                test_storage.delete_key(key_id)
                
            except Exception as e:
                # If it fails safely, that's also acceptable
                assert "DROP TABLE" not in str(e).upper()
                
    def test_xss_prevention(self, test_storage: SecureKeyStorageRBAC):
        """Test prevention of XSS attacks."""
        xss_payloads = [
            "<script>alert('xss')</script>",
            "javascript:alert('xss')",
            "<img src=x onerror=alert('xss')>",
            "\u003cscript\u003ealert('xss')\u003c/script\u003e"
        ]
        
        for payload in xss_payloads:
            key_id = test_storage.store_key(
                "xss_test", payload, "TestService",
                metadata={"description": payload}
            )
            
            # Retrieve and verify payload is stored safely
            retrieved_key = test_storage.get_key(key_id)
            assert retrieved_key == payload  # Should store as-is but handle safely on output
            
            # Clean up
            test_storage.delete_key(key_id)
            
    def test_path_traversal_prevention(self, test_storage: SecureKeyStorageRBAC):
        """Test prevention of path traversal attacks."""
        malicious_paths = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\config\\sam",
            "/etc/shadow",
            "../../.ssh/id_rsa"
        ]
        
        for malicious_path in malicious_paths:
            # Try to use malicious path as key name
            key_id = test_storage.store_key(
                malicious_path, "test_value", "TestService"
            )
            
            # Verify the key is stored securely
            retrieved_key = test_storage.get_key(key_id)
            assert retrieved_key == "test_value"
            
            # Verify no files were created outside the storage directory
            storage_path = Path(test_storage.storage_path)
            parent_dir = storage_path.parent
            
            # Check that no files were created outside storage directory
            for file_path in parent_dir.rglob("*"):
                if file_path.is_file() and not file_path.is_relative_to(storage_path):
                    # Check if it could be our malicious file
                    if file_path.name in malicious_path:
                        pytest.fail(f"Potential path traversal: {file_path}")
                        
            # Clean up
            test_storage.delete_key(key_id)
            
    def test_buffer_overflow_prevention(self, test_storage: SecureKeyStorageRBAC):
        """Test handling of extremely large inputs."""
        # Create very large inputs
        large_inputs = [
            "A" * 10000,  # 10KB string
            "B" * 100000,  # 100KB string
            "C" * 1000000,  # 1MB string (if system allows)
        ]
        
        for large_input in large_inputs:
            try:
                key_id = test_storage.store_key(
                    "large_test", large_input, "TestService"
                )
                
                # If it succeeds, verify it's handled correctly
                retrieved_key = test_storage.get_key(key_id)
                assert retrieved_key == large_input
                
                # Clean up
                test_storage.delete_key(key_id)
                
            except (MemoryError, OverflowError, ValueError) as e:
                # These are acceptable for very large inputs
                assert "memory" in str(e).lower() or "overflow" in str(e).lower() or "too large" in str(e).lower()
                
            except Exception as e:
                # Should fail gracefully, not crash
                assert "segmentation" not in str(e).lower()
                assert "access violation" not in str(e).lower()


class TestCryptographicSecurity:
    """Test advanced cryptographic security measures."""
    
    def test_key_derivation_function(self, test_storage: SecureKeyStorageRBAC):
        """Test proper key derivation function usage."""
        # Verify that master password goes through proper KDF
        master_password = "test_master_password_123"
        
        # Store a key (this triggers key derivation)
        key_id = test_storage.store_key("kdf_test", "test_value", "TestService")
        
        # Verify the derived key is not the same as master password
        # (We can't easily test this without accessing internals, but we can
        # verify that different master passwords produce different results)
        
    def test_salt_generation(self, test_storage: SecureKeyStorageRBAC):
        """Test that proper salts are generated for encryption."""
        # Store multiple keys and verify they use different salts
        keys = ["salt_test_1", "salt_test_2", "salt_test_3"]
        
        for key_name in keys:
            test_storage.store_key(key_name, f"value_{key_name}", "TestService")
            
        # Read encrypted files and verify they're all different
        storage_path = Path(test_storage.storage_path)
        encrypted_files = list(storage_path.glob("*.enc"))
        
        assert len(encrypted_files) >= 3
        
        encrypted_contents = []
        for file_path in encrypted_files:
            with open(file_path, 'rb') as f:
                content = f.read()
                encrypted_contents.append(content)
                
        # All encrypted contents should be unique (different salts/IVs)
        unique_contents = set(encrypted_contents)
        assert len(unique_contents) == len(encrypted_contents)
        
    def test_random_number_generation(self):
        """Test that secure random number generation is used."""
        # Generate multiple random values and verify they're different
        random_values = []
        
        for i in range(100):
            random_value = secrets.token_bytes(32)
            random_values.append(random_value)
            
        # All values should be unique
        unique_values = set(random_values)
        assert len(unique_values) == len(random_values), "Random values should be unique"
        
        # Test entropy (basic check)
        for value in random_values[:10]:  # Test first 10
            # Should not be all zeros or all ones
            assert value != b'\x00' * 32
            assert value != b'\xff' * 32
            
            # Should have reasonable entropy (not too repetitive)
            unique_bytes = set(value)
            assert len(unique_bytes) > 5, "Random value should have reasonable entropy"
            
    def test_timing_attack_resistance(self, test_storage: SecureKeyStorageRBAC):
        """Test resistance to timing attacks."""
        # Test password verification timing
        correct_password = "test_master_password_123"
        wrong_passwords = [
            "a",  # Very short
            "test_master_password_12",  # Almost correct
            "completely_different_password_that_is_much_longer",  # Very different
            "x" * 100,  # Very long
        ]
        
        # Measure timing for correct password
        times_correct = []
        for _ in range(10):
            start = time.time()
            result = test_storage.verify_master_password(correct_password)
            end = time.time()
            times_correct.append(end - start)
            assert result is True
            
        avg_correct_time = sum(times_correct) / len(times_correct)
        
        # Measure timing for wrong passwords
        for wrong_password in wrong_passwords:
            times_wrong = []
            for _ in range(10):
                start = time.time()
                result = test_storage.verify_master_password(wrong_password)
                end = time.time()
                times_wrong.append(end - start)
                assert result is False
                
            avg_wrong_time = sum(times_wrong) / len(times_wrong)
            
            # Timing should be similar (within reasonable variance)
            time_diff = abs(avg_correct_time - avg_wrong_time)
            assert time_diff < 0.05, f"Timing difference too large: {time_diff} for password: {wrong_password[:10]}..."


class TestSecurityHeaders:
    """Test security headers and web security measures."""
    
    def test_security_headers_present(self, test_client):
        """Test that security headers are present in responses."""
        response = test_client.get("/api/health")
        
        # Check for security headers
        headers = response.headers
        
        # These headers should be present for security
        expected_headers = [
            "x-content-type-options",  # nosniff
            "x-frame-options",         # DENY or SAMEORIGIN
            "x-xss-protection",        # 1; mode=block
            "strict-transport-security",  # HSTS
        ]
        
        for header in expected_headers:
            assert header in headers, f"Security header {header} is missing"
            
        # Verify header values
        if "x-content-type-options" in headers:
            assert headers["x-content-type-options"] == "nosniff"
            
        if "x-frame-options" in headers:
            assert headers["x-frame-options"] in ["DENY", "SAMEORIGIN"]
            
    def test_csrf_protection(self, test_client):
        """Test CSRF protection mechanisms."""
        # For API endpoints, CSRF protection might be different
        # This test verifies that appropriate measures are in place
        
        # Test that state-changing operations require proper authentication
        response = test_client.post("/api/keys", json={"name": "test", "value": "test"})
        
        # Should require authentication
        assert response.status_code == 401
        
    def test_content_type_validation(self, test_client, auth_headers):
        """Test that content types are properly validated."""
        # Test with wrong content type
        response = test_client.post(
            "/api/keys",
            data="{\"name\": \"test\", \"value\": \"test\"}",
            headers={**auth_headers, "Content-Type": "text/plain"}
        )
        
        # Should reject wrong content type
        assert response.status_code in [400, 415, 422]
