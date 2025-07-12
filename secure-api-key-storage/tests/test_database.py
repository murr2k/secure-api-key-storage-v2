"""Database tests for the secure API key storage system."""

import pytest
import sqlite3
import tempfile
import os
from pathlib import Path
from datetime import datetime, timedelta

from src.rbac_models import RBACManager, Role, Permission


class TestDatabaseConnections:
    """Test database connection and basic operations."""
    
    def test_database_creation(self, test_dir: Path):
        """Test that database files are created properly."""
        db_path = test_dir / "test.db"
        rbac_manager = RBACManager(db_path=str(db_path))
        
        # Database file should be created
        assert db_path.exists()
        assert db_path.is_file()
        
        # Should be a valid SQLite database
        conn = sqlite3.connect(str(db_path))
        cursor = conn.cursor()
        
        # Test basic query
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
        tables = cursor.fetchall()
        conn.close()
        
        # Should have RBAC tables
        table_names = [table[0] for table in tables]
        expected_tables = ['users', 'key_policies', 'audit_logs']
        
        for expected_table in expected_tables:
            assert expected_table in table_names, f"Table {expected_table} not found"
            
    def test_database_permissions(self, test_dir: Path):
        """Test database file permissions are secure."""
        db_path = test_dir / "secure_test.db"
        rbac_manager = RBACManager(db_path=str(db_path))
        
        # Check file permissions (should be readable/writable only by owner)
        stat = db_path.stat()
        mode = oct(stat.st_mode)[-3:]
        
        # On Unix systems, should be 600 (owner read/write only)
        # On Windows, this test might be skipped
        if os.name == 'posix':
            assert mode in ['600', '640'], f"Database file permissions too open: {mode}"
            
    def test_concurrent_connections(self, rbac_manager: RBACManager):
        """Test handling of concurrent database connections."""
        # Create multiple connections simultaneously
        connections = []
        
        try:
            for i in range(10):
                conn = sqlite3.connect(rbac_manager.db_path)
                connections.append(conn)
                
                # Test basic operation on each connection
                cursor = conn.cursor()
                cursor.execute("SELECT COUNT(*) FROM users")
                count = cursor.fetchone()[0]
                assert isinstance(count, int)
                
        finally:
            # Clean up connections
            for conn in connections:
                conn.close()
                
    def test_database_integrity_constraints(self, rbac_manager: RBACManager):
        """Test database integrity constraints."""
        # Test unique constraints
        user_id1 = rbac_manager.create_user(
            "unique_test_user", "password123", Role.USER, "unique@test.com"
        )
        
        # Should not be able to create another user with same username
        with pytest.raises(Exception):  # Should raise integrity error
            rbac_manager.create_user(
                "unique_test_user", "password456", Role.USER, "different@test.com"
            )
            
        # Should not be able to create another user with same email
        with pytest.raises(Exception):  # Should raise integrity error
            rbac_manager.create_user(
                "different_user", "password789", Role.USER, "unique@test.com"
            )
            
    def test_foreign_key_constraints(self, rbac_manager: RBACManager):
        """Test foreign key constraints are enforced."""
        # Create a user
        user_id = rbac_manager.create_user(
            "fk_test_user", "password123", Role.USER, "fk@test.com"
        )
        
        # Grant access to a key
        rbac_manager.grant_key_access("test_key", user_id, [Permission.KEY_READ])
        
        # Try to grant access with invalid user_id
        with pytest.raises(Exception):  # Should raise foreign key error
            rbac_manager.grant_key_access("test_key2", 99999, [Permission.KEY_READ])


class TestUserManagement:
    """Test user management database operations."""
    
    def test_user_creation(self, rbac_manager: RBACManager):
        """Test user creation in database."""
        username = "test_db_user"
        password = "secure_password_123"
        email = "test@example.com"
        metadata = {"department": "Engineering", "team": "Backend"}
        
        user_id = rbac_manager.create_user(
            username, password, Role.USER, email, metadata
        )
        
        assert isinstance(user_id, int)
        assert user_id > 0
        
        # Verify user was created in database
        conn = sqlite3.connect(rbac_manager.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
        user_row = cursor.fetchone()
        conn.close()
        
        assert user_row is not None
        assert user_row["username"] == username
        assert user_row["email"] == email
        assert user_row["role"] == Role.USER.value
        assert user_row["password_hash"] != password  # Should be hashed
        
    def test_user_retrieval(self, rbac_manager: RBACManager):
        """Test retrieving user information from database."""
        username = "retrieve_test_user"
        password = "password123"
        
        user_id = rbac_manager.create_user(
            username, password, Role.ADMIN, "retrieve@test.com"
        )
        
        # Retrieve user by ID
        user_data = rbac_manager.get_user_by_id(user_id)
        
        assert user_data is not None
        assert user_data["username"] == username
        assert user_data["role"] == Role.ADMIN.value
        
        # Retrieve user by username
        user_data_by_name = rbac_manager.get_user_by_username(username)
        
        assert user_data_by_name is not None
        assert user_data_by_name["id"] == user_id
        
    def test_user_update(self, rbac_manager: RBACManager):
        """Test updating user information."""
        username = "update_test_user"
        user_id = rbac_manager.create_user(
            username, "password123", Role.USER, "update@test.com"
        )
        
        # Update user role
        rbac_manager.update_user_role(user_id, Role.ADMIN)
        
        # Verify update
        user_data = rbac_manager.get_user_by_id(user_id)
        assert user_data["role"] == Role.ADMIN.value
        
        # Update user metadata
        new_metadata = {"updated": True, "timestamp": datetime.now().isoformat()}
        rbac_manager.update_user_metadata(user_id, new_metadata)
        
        # Verify metadata update
        updated_user = rbac_manager.get_user_by_id(user_id)
        assert "updated" in updated_user.get("metadata", {})
        
    def test_user_deletion(self, rbac_manager: RBACManager):
        """Test user deletion from database."""
        username = "delete_test_user"
        user_id = rbac_manager.create_user(
            username, "password123", Role.USER, "delete@test.com"
        )
        
        # Verify user exists
        user_data = rbac_manager.get_user_by_id(user_id)
        assert user_data is not None
        
        # Delete user
        rbac_manager.delete_user(user_id)
        
        # Verify user is deleted
        deleted_user = rbac_manager.get_user_by_id(user_id)
        assert deleted_user is None
        
    def test_user_listing(self, rbac_manager: RBACManager):
        """Test listing users with pagination."""
        # Create multiple users
        user_ids = []
        for i in range(15):
            user_id = rbac_manager.create_user(
                f"list_user_{i}",
                f"password_{i}",
                Role.USER,
                f"list_{i}@test.com"
            )
            user_ids.append(user_id)
            
        # Test listing with pagination
        users_page1 = rbac_manager.list_users(limit=10, offset=0)
        assert len(users_page1) <= 10
        
        users_page2 = rbac_manager.list_users(limit=10, offset=10)
        assert len(users_page2) >= 5  # Should have remaining users
        
        # Test total count
        total_users = rbac_manager.count_users()
        assert total_users >= 15


class TestKeyPolicyManagement:
    """Test key policy database operations."""
    
    def test_key_policy_creation(self, rbac_manager: RBACManager):
        """Test creating key access policies."""
        # Create a user first
        user_id = rbac_manager.create_user(
            "policy_user", "password123", Role.USER, "policy@test.com"
        )
        
        key_id = "test_policy_key"
        permissions = [Permission.KEY_READ, Permission.KEY_UPDATE]
        
        # Grant key access
        rbac_manager.grant_key_access(key_id, user_id, permissions)
        
        # Verify policy was created
        conn = sqlite3.connect(rbac_manager.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        cursor.execute(
            "SELECT * FROM key_policies WHERE key_id = ? AND user_id = ?",
            (key_id, user_id)
        )
        policy_row = cursor.fetchone()
        conn.close()
        
        assert policy_row is not None
        assert policy_row["key_id"] == key_id
        assert policy_row["user_id"] == user_id
        
        # Verify permissions are stored correctly
        import json
        stored_permissions = json.loads(policy_row["permissions"])
        expected_permissions = [p.value for p in permissions]
        assert set(stored_permissions) == set(expected_permissions)
        
    def test_key_policy_retrieval(self, rbac_manager: RBACManager):
        """Test retrieving key access policies."""
        user_id = rbac_manager.create_user(
            "retrieve_policy_user", "password123", Role.USER, "rpolicy@test.com"
        )
        
        key_id = "retrieve_policy_key"
        permissions = [Permission.KEY_READ]
        
        rbac_manager.grant_key_access(key_id, user_id, permissions)
        
        # Test checking specific permission
        has_read = rbac_manager.check_permission(user_id, Permission.KEY_READ, key_id)
        assert has_read is True
        
        has_delete = rbac_manager.check_permission(user_id, Permission.KEY_DELETE, key_id)
        assert has_delete is False
        
        # Test getting user's accessible keys
        accessible_keys = rbac_manager.get_user_accessible_keys(user_id)
        assert key_id in accessible_keys
        
    def test_key_policy_update(self, rbac_manager: RBACManager):
        """Test updating key access policies."""
        user_id = rbac_manager.create_user(
            "update_policy_user", "password123", Role.USER, "upolicy@test.com"
        )
        
        key_id = "update_policy_key"
        
        # Initially grant read permission
        rbac_manager.grant_key_access(key_id, user_id, [Permission.KEY_READ])
        
        # Verify initial permission
        has_read = rbac_manager.check_permission(user_id, Permission.KEY_READ, key_id)
        assert has_read is True
        
        has_update = rbac_manager.check_permission(user_id, Permission.KEY_UPDATE, key_id)
        assert has_update is False
        
        # Update permissions to include update
        rbac_manager.grant_key_access(
            key_id, user_id, [Permission.KEY_READ, Permission.KEY_UPDATE]
        )
        
        # Verify updated permissions
        has_update_after = rbac_manager.check_permission(user_id, Permission.KEY_UPDATE, key_id)
        assert has_update_after is True
        
    def test_key_policy_revocation(self, rbac_manager: RBACManager):
        """Test revoking key access policies."""
        user_id = rbac_manager.create_user(
            "revoke_policy_user", "password123", Role.USER, "revoke@test.com"
        )
        
        key_id = "revoke_policy_key"
        
        # Grant access
        rbac_manager.grant_key_access(key_id, user_id, [Permission.KEY_READ])
        
        # Verify access
        has_access = rbac_manager.check_permission(user_id, Permission.KEY_READ, key_id)
        assert has_access is True
        
        # Revoke access
        rbac_manager.revoke_key_access(key_id, user_id)
        
        # Verify access is revoked
        has_access_after = rbac_manager.check_permission(user_id, Permission.KEY_READ, key_id)
        assert has_access_after is False
        
    def test_key_policy_expiration(self, rbac_manager: RBACManager):
        """Test key policy expiration."""
        user_id = rbac_manager.create_user(
            "expire_policy_user", "password123", Role.USER, "expire@test.com"
        )
        
        key_id = "expire_policy_key"
        
        # Grant access with short expiration
        expires_at = datetime.now() + timedelta(seconds=1)
        rbac_manager.grant_key_access(
            key_id, user_id, [Permission.KEY_READ], expires_at=expires_at
        )
        
        # Verify access initially
        has_access = rbac_manager.check_permission(user_id, Permission.KEY_READ, key_id)
        assert has_access is True
        
        # Wait for expiration
        import time
        time.sleep(2)
        
        # Verify access is expired
        has_access_after = rbac_manager.check_permission(user_id, Permission.KEY_READ, key_id)
        assert has_access_after is False


class TestAuditLogDatabase:
    """Test audit log database operations."""
    
    def test_audit_log_creation(self, rbac_manager: RBACManager):
        """Test creating audit log entries."""
        user_id = rbac_manager.create_user(
            "audit_user", "password123", Role.USER, "audit@test.com"
        )
        
        # Create audit log entry
        rbac_manager.log_audit_event(
            user_id=user_id,
            action="test_action",
            resource_type="key",
            resource_id="test_key",
            success=True,
            details={"test": "data"}
        )
        
        # Verify audit log was created
        conn = sqlite3.connect(rbac_manager.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        cursor.execute(
            "SELECT * FROM audit_logs WHERE user_id = ? AND action = ?",
            (user_id, "test_action")
        )
        audit_row = cursor.fetchone()
        conn.close()
        
        assert audit_row is not None
        assert audit_row["action"] == "test_action"
        assert audit_row["resource_type"] == "key"
        assert audit_row["resource_id"] == "test_key"
        assert audit_row["success"] == 1  # SQLite boolean
        
    def test_audit_log_retrieval(self, rbac_manager: RBACManager):
        """Test retrieving audit log entries."""
        user_id = rbac_manager.create_user(
            "retrieve_audit_user", "password123", Role.USER, "raudit@test.com"
        )
        
        # Create multiple audit entries
        actions = ["action1", "action2", "action3"]
        for action in actions:
            rbac_manager.log_audit_event(
                user_id=user_id,
                action=action,
                resource_type="key",
                resource_id=f"key_{action}",
                success=True
            )
            
        # Retrieve audit logs
        audit_logs = rbac_manager.get_audit_logs(limit=10)
        
        assert len(audit_logs) >= 3
        
        # Check that our actions are in the logs
        log_actions = [log["action"] for log in audit_logs]
        for action in actions:
            assert action in log_actions
            
    def test_audit_log_filtering(self, rbac_manager: RBACManager):
        """Test filtering audit logs by various criteria."""
        user_id = rbac_manager.create_user(
            "filter_audit_user", "password123", Role.USER, "faudit@test.com"
        )
        
        # Create audit entries with different criteria
        rbac_manager.log_audit_event(
            user_id=user_id,
            action="key_create",
            resource_type="key",
            resource_id="filter_key1",
            success=True
        )
        
        rbac_manager.log_audit_event(
            user_id=user_id,
            action="key_read",
            resource_type="key",
            resource_id="filter_key2",
            success=False
        )
        
        # Filter by action
        create_logs = rbac_manager.get_audit_logs(
            action="key_create", limit=10
        )
        assert len(create_logs) >= 1
        assert all(log["action"] == "key_create" for log in create_logs)
        
        # Filter by success status
        failed_logs = rbac_manager.get_audit_logs(
            success=False, limit=10
        )
        assert len(failed_logs) >= 1
        assert all(log["success"] is False for log in failed_logs)
        
    def test_audit_log_retention(self, rbac_manager: RBACManager):
        """Test audit log retention and cleanup."""
        user_id = rbac_manager.create_user(
            "retention_user", "password123", Role.USER, "retention@test.com"
        )
        
        # Create old audit entries (simulate by modifying timestamp)
        old_timestamp = datetime.now() - timedelta(days=400)  # Very old
        
        conn = sqlite3.connect(rbac_manager.db_path)
        cursor = conn.cursor()
        
        # Insert old audit entry directly
        cursor.execute(
            "INSERT INTO audit_logs (user_id, username, action, resource_type, resource_id, success, timestamp, details) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (user_id, "retention_user", "old_action", "key", "old_key", True, old_timestamp.isoformat(), "{}")
        )
        conn.commit()
        conn.close()
        
        # Test cleanup of old entries (if implemented)
        if hasattr(rbac_manager, 'cleanup_old_audit_logs'):
            rbac_manager.cleanup_old_audit_logs(retention_days=365)
            
            # Verify old entries are removed
            remaining_logs = rbac_manager.get_audit_logs(action="old_action")
            assert len(remaining_logs) == 0


class TestDatabaseMigrations:
    """Test database schema migrations."""
    
    def test_schema_version_tracking(self, test_dir: Path):
        """Test that database schema version is tracked."""
        db_path = test_dir / "migration_test.db"
        rbac_manager = RBACManager(db_path=str(db_path))
        
        # Check if schema version is tracked
        conn = sqlite3.connect(str(db_path))
        cursor = conn.cursor()
        
        # Look for version tracking table or metadata
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='schema_version';")
        version_table = cursor.fetchone()
        
        # If schema versioning is implemented
        if version_table:
            cursor.execute("SELECT version FROM schema_version ORDER BY applied_at DESC LIMIT 1;")
            current_version = cursor.fetchone()
            assert current_version is not None
            assert isinstance(current_version[0], (int, str))
            
        conn.close()
        
    def test_backward_compatibility(self, test_dir: Path):
        """Test backward compatibility with older database schemas."""
        # This test would verify that newer code can work with older database schemas
        # Implementation depends on the specific migration strategy used
        pass


class TestDatabaseSecurity:
    """Test database security measures."""
    
    def test_sql_injection_prevention(self, rbac_manager: RBACManager):
        """Test prevention of SQL injection in database operations."""
        malicious_inputs = [
            "'; DROP TABLE users; --",
            "admin' OR '1'='1",
            "test'; DELETE FROM key_policies WHERE '1'='1; --"
        ]
        
        for malicious_input in malicious_inputs:
            # Try to inject via username
            try:
                user_id = rbac_manager.create_user(
                    malicious_input, "password123", Role.USER, "inject@test.com"
                )
                
                # If creation succeeds, verify it was properly escaped
                user_data = rbac_manager.get_user_by_id(user_id)
                assert user_data["username"] == malicious_input  # Should be stored as-is
                
                # Verify no SQL injection occurred (tables still exist)
                conn = sqlite3.connect(rbac_manager.db_path)
                cursor = conn.cursor()
                cursor.execute("SELECT COUNT(*) FROM users")
                user_count = cursor.fetchone()[0]
                assert user_count > 0  # Users table should still exist and have data
                conn.close()
                
            except Exception as e:
                # If it fails safely, that's also acceptable
                assert "DROP TABLE" not in str(e).upper()
                
    def test_database_encryption(self, test_dir: Path):
        """Test database encryption if implemented."""
        db_path = test_dir / "encrypted_test.db"
        rbac_manager = RBACManager(db_path=str(db_path))
        
        # Create some test data
        user_id = rbac_manager.create_user(
            "encryption_test", "password123", Role.USER, "encrypt@test.com"
        )
        
        # If database encryption is implemented, verify sensitive data is not in plaintext
        with open(db_path, 'rb') as f:
            raw_content = f.read()
            
        # Password should not appear in plaintext in the database file
        assert b"password123" not in raw_content
        assert b"encrypt@test.com" not in raw_content  # Email might be encrypted too
        
    def test_connection_security(self, rbac_manager: RBACManager):
        """Test database connection security settings."""
        conn = sqlite3.connect(rbac_manager.db_path)
        cursor = conn.cursor()
        
        # Test that foreign keys are enabled (security constraint)
        cursor.execute("PRAGMA foreign_keys;")
        fk_status = cursor.fetchone()[0]
        assert fk_status == 1, "Foreign keys should be enabled for referential integrity"
        
        # Test other security-related pragmas
        cursor.execute("PRAGMA journal_mode;")
        journal_mode = cursor.fetchone()[0]
        # WAL mode is generally more secure and performant
        assert journal_mode.upper() in ['WAL', 'DELETE'], f"Unexpected journal mode: {journal_mode}"
        
        conn.close()


class TestDatabasePerformance:
    """Test database performance and optimization."""
    
    def test_query_performance(self, rbac_manager: RBACManager, performance_timer):
        """Test that database queries perform within acceptable limits."""
        # Create test data
        user_ids = []
        for i in range(100):
            user_id = rbac_manager.create_user(
                f"perf_user_{i}", f"password_{i}", Role.USER, f"perf_{i}@test.com"
            )
            user_ids.append(user_id)
            
        # Test user lookup performance
        performance_timer.start()
        for user_id in user_ids[:10]:  # Test first 10
            user_data = rbac_manager.get_user_by_id(user_id)
            assert user_data is not None
        performance_timer.stop()
        
        # Should complete quickly
        assert performance_timer.elapsed < 1.0, f"User lookups too slow: {performance_timer.elapsed}s"
        
    def test_index_usage(self, rbac_manager: RBACManager):
        """Test that proper database indexes are in place."""
        conn = sqlite3.connect(rbac_manager.db_path)
        cursor = conn.cursor()
        
        # Check for indexes on commonly queried columns
        cursor.execute("SELECT name FROM sqlite_master WHERE type='index';")
        indexes = [row[0] for row in cursor.fetchall()]
        
        # Should have indexes on key columns
        expected_index_patterns = [
            "username",  # For user lookups
            "email",     # For email lookups
            "key_id",    # For key policy lookups
            "user_id"    # For foreign key relationships
        ]
        
        for pattern in expected_index_patterns:
            # Check if any index name contains the pattern
            matching_indexes = [idx for idx in indexes if pattern.lower() in idx.lower()]
            assert len(matching_indexes) > 0, f"No index found for {pattern}"
            
        conn.close()
        
    def test_bulk_operations(self, rbac_manager: RBACManager, performance_timer):
        """Test performance of bulk database operations."""
        # Test bulk user creation
        performance_timer.start()
        user_ids = []
        for i in range(50):
            user_id = rbac_manager.create_user(
                f"bulk_user_{i}", f"password_{i}", Role.USER, f"bulk_{i}@test.com"
            )
            user_ids.append(user_id)
        performance_timer.stop()
        
        # Should complete in reasonable time
        assert performance_timer.elapsed < 5.0, f"Bulk operations too slow: {performance_timer.elapsed}s"
        
        # Test bulk retrieval
        performance_timer.start()
        all_users = rbac_manager.list_users(limit=100)
        performance_timer.stop()
        
        assert len(all_users) >= 50
        assert performance_timer.elapsed < 2.0, f"Bulk retrieval too slow: {performance_timer.elapsed}s"


class TestDatabaseBackupRestore:
    """Test database backup and restore functionality."""
    
    def test_database_backup(self, rbac_manager: RBACManager, test_dir: Path):
        """Test creating database backups."""
        # Create test data
        user_id = rbac_manager.create_user(
            "backup_user", "password123", Role.USER, "backup@test.com"
        )
        
        rbac_manager.grant_key_access("backup_key", user_id, [Permission.KEY_READ])
        
        # Create backup
        backup_path = test_dir / "backup.db"
        
        if hasattr(rbac_manager, 'create_backup'):
            rbac_manager.create_backup(str(backup_path))
            
            # Verify backup file exists
            assert backup_path.exists()
            
            # Verify backup contains data
            backup_conn = sqlite3.connect(str(backup_path))
            cursor = backup_conn.cursor()
            
            cursor.execute("SELECT COUNT(*) FROM users")
            user_count = cursor.fetchone()[0]
            assert user_count > 0
            
            backup_conn.close()
            
    def test_database_restore(self, test_dir: Path):
        """Test restoring database from backup."""
        # This test would verify that a database can be restored from backup
        # Implementation depends on the specific backup/restore strategy
        pass
