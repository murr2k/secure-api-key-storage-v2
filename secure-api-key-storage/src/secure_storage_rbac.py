"""
Enhanced Secure API Key Storage with RBAC Integration
Extends the existing storage system with role-based access control
"""

import os
import json
from typing import Dict, Optional, List, Tuple, Any
from datetime import datetime

from .secure_storage import APIKeyStorage, SecurityException
from .rbac_models import RBACManager, Role, Permission


class SecureStorageWithRBAC(APIKeyStorage):
    """Enhanced API Key Storage with integrated RBAC"""

    def __init__(
        self,
        storage_path: str = "./keys",
        master_password: Optional[str] = None,
        rbac_db_path: str = "./rbac.db",
    ):
        super().__init__(storage_path, master_password)
        self.rbac = RBACManager(rbac_db_path)
        self.default_user_id = 1  # Default admin user ID

        # Create default admin user if none exists
        self._ensure_admin_user()

    def _ensure_admin_user(self):
        """Ensure at least one admin user exists"""
        try:
            # Check if admin exists
            conn = self.rbac.db.db_path
            import sqlite3

            db_conn = sqlite3.connect(conn)
            cursor = db_conn.cursor()
            cursor.execute("SELECT COUNT(*) FROM users WHERE role = ?", (Role.ADMIN.value,))
            admin_count = cursor.fetchone()[0]
            db_conn.close()

            if admin_count == 0:
                # Create default admin
                admin_password = os.environ.get("DEFAULT_ADMIN_PASSWORD", "admin123")
                self.rbac.create_user(
                    "admin",
                    admin_password,
                    Role.ADMIN,
                    email="admin@localhost",
                    metadata={"created_by": "system", "is_default": True},
                )
                print("Created default admin user (username: admin)")
        except Exception as e:
            print(f"Warning: Could not ensure admin user: {e}")

    def add_api_key_with_rbac(
        self,
        service: str,
        api_key: str,
        user_id: int,
        metadata: Optional[Dict] = None,
        shared_with: Optional[List[Tuple[int, List[Permission]]]] = None,
    ) -> str:
        """Add API key with RBAC permissions"""
        # Check if user has permission to create keys
        if not self.rbac.check_permission(user_id, Permission.KEY_CREATE):
            raise SecurityException("User does not have permission to create keys")

        # Get username for audit
        import sqlite3

        conn = sqlite3.connect(self.rbac.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT username FROM users WHERE id = ?", (user_id,))
        username = cursor.fetchone()[0]
        conn.close()

        # Add the key using parent method
        key_id = super().add_api_key(service, api_key, username, metadata)

        # Grant owner full permissions
        owner_permissions = [
            Permission.KEY_READ,
            Permission.KEY_UPDATE,
            Permission.KEY_DELETE,
            Permission.KEY_ROTATE,
        ]
        self.rbac.grant_key_access(key_id, user_id, owner_permissions)

        # Grant permissions to shared users if specified
        if shared_with:
            for shared_user_id, permissions in shared_with:
                self.rbac.grant_key_access(key_id, shared_user_id, permissions)

        return key_id

    def store_key(self, name: str, value: str, service: Optional[str] = None, metadata: Optional[Dict] = None) -> str:
        """Store an API key (wrapper for compatibility with dashboard API)"""
        # For dashboard compatibility, use default admin user
        full_metadata = metadata or {}
        if service:
            full_metadata['service'] = service
        full_metadata['name'] = name
        
        return self.add_api_key_with_rbac(
            service=service or name,
            api_key=value,
            user_id=self.default_user_id,
            metadata=full_metadata
        )

    def list_keys(self) -> List[Dict[str, Any]]:
        """List all API keys (wrapper for compatibility)"""
        # Use parent method to get all keys (pass 'admin' as user)
        keys = super().list_keys('admin')
        
        # Format for dashboard compatibility
        formatted_keys = []
        for key in keys:
            formatted_key = {
                'id': key['key_id'],  # Use key_id from parent class
                'name': key.get('metadata', {}).get('name', key.get('service', 'Unknown')),
                'service': key.get('service'),
                'description': key.get('metadata', {}).get('description'),
                'created_at': key.get('metadata', {}).get('created_at', key.get('created_at')),
                'updated_at': key.get('metadata', {}).get('updated_at', key.get('created_at')),
                'last_accessed': key.get('last_accessed'),
                'rotation_due': key.get('metadata', {}).get('rotation_due')
            }
            formatted_keys.append(formatted_key)
        
        return formatted_keys

    def get_key(self, key_id: str) -> Optional[str]:
        """Get an API key value (wrapper for compatibility)"""
        # For dashboard compatibility, use default admin user
        return self.get_api_key_with_rbac(key_id, self.default_user_id)

    def delete_key(self, key_id: str) -> bool:
        """Delete an API key (wrapper for compatibility)"""
        # For dashboard compatibility, use default admin user
        return self.revoke_key_with_rbac(key_id, self.default_user_id)

    def rotate_key(self, key_id: str) -> str:
        """Rotate an API key (wrapper for compatibility)"""
        # For dashboard compatibility, use default admin user
        # Generate a new key value
        import secrets
        new_key = secrets.token_urlsafe(32)
        success = self.rotate_key_with_rbac(key_id, new_key, self.default_user_id)
        if success:
            return new_key
        else:
            raise Exception("Key rotation failed")
    
    def update_key(self, key_id: str, new_value: str) -> bool:
        """Update an API key (wrapper for compatibility)"""
        # For dashboard compatibility, use default admin user
        return self.update_api_key_with_rbac(key_id, new_value, self.default_user_id)
    
    def verify_master_password(self, password: str) -> bool:
        """Verify the master password"""
        # Use the parent class's master password verification
        # This should match the master password used during initialization
        master_password = os.environ.get("MASTER_PASSWORD") or os.environ.get("API_KEY_MASTER")
        if not master_password:
            return False
        return password == master_password

    def get_api_key_with_rbac(self, key_id: str, user_id: int) -> Optional[str]:
        """Get API key with RBAC check"""
        # Check if user has permission to read this key
        if not self.rbac.check_permission(user_id, Permission.KEY_READ, key_id):
            self._log_audit(
                "WARNING", f"Unauthorized access attempt to key: {key_id}", f"user_id:{user_id}"
            )
            raise SecurityException("Access denied: insufficient permissions")

        # Get username for audit
        import sqlite3

        conn = sqlite3.connect(self.rbac.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT username FROM users WHERE id = ?", (user_id,))
        username = cursor.fetchone()[0]
        conn.close()

        return super().get_api_key(key_id, username)

    def update_api_key_with_rbac(self, key_id: str, new_api_key: str, user_id: int) -> bool:
        """Update API key with RBAC check"""
        # Check if user has permission to update this key
        if not self.rbac.check_permission(user_id, Permission.KEY_UPDATE, key_id):
            raise SecurityException("Access denied: insufficient permissions")

        if key_id not in self.keys_data:
            return False

        # Update the key
        self.keys_data[key_id]["api_key"] = new_api_key
        self.keys_data[key_id]["updated_at"] = datetime.now().isoformat()
        self._save_keys()

        # Log the update
        import sqlite3

        conn = sqlite3.connect(self.rbac.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT username FROM users WHERE id = ?", (user_id,))
        username = cursor.fetchone()[0]
        conn.close()

        self._log_audit("INFO", f"Updated API key: {key_id}", username)
        return True

    def revoke_key_with_rbac(self, key_id: str, user_id: int) -> bool:
        """Revoke API key with RBAC check"""
        # Check if user has permission to delete this key
        if not self.rbac.check_permission(user_id, Permission.KEY_DELETE, key_id):
            raise SecurityException("Access denied: insufficient permissions")

        # Get username for audit
        import sqlite3

        conn = sqlite3.connect(self.rbac.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT username FROM users WHERE id = ?", (user_id,))
        username = cursor.fetchone()[0]
        conn.close()

        return super().revoke_key(key_id, username)

    def rotate_key_with_rbac(self, key_id: str, new_api_key: str, user_id: int) -> bool:
        """Rotate API key with RBAC check"""
        # Check if user has permission to rotate this key
        if not self.rbac.check_permission(user_id, Permission.KEY_ROTATE, key_id):
            raise SecurityException("Access denied: insufficient permissions")

        # Get username for audit
        import sqlite3

        conn = sqlite3.connect(self.rbac.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT username FROM users WHERE id = ?", (user_id,))
        username = cursor.fetchone()[0]
        conn.close()

        return super().rotate_key(key_id, new_api_key, username)

    def list_keys_with_rbac(self, user_id: int, include_inactive: bool = False) -> List[Dict]:
        """List keys accessible to the user"""
        # Check if user has permission to list keys
        if not self.rbac.check_permission(user_id, Permission.KEY_LIST):
            raise SecurityException("Access denied: insufficient permissions")

        # Get user's accessible keys
        accessible_keys = self.rbac.get_user_accessible_keys(user_id)

        # Get username for audit
        import sqlite3

        conn = sqlite3.connect(self.rbac.db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT username, role FROM users WHERE id = ?", (user_id,))
        username, role = cursor.fetchone()
        conn.close()

        all_keys = super().list_keys(username, include_inactive)

        # Filter based on access
        if accessible_keys == ["*"]:  # Admin has access to all
            return all_keys

        # Filter to only accessible keys
        filtered_keys = []
        for key in all_keys:
            if key["key_id"] in accessible_keys:
                filtered_keys.append(key)
            # Also include keys created by the user
            elif key.get("user") == username:
                filtered_keys.append(key)

        return filtered_keys

    def grant_key_access(
        self,
        key_id: str,
        granting_user_id: int,
        target_user_id: int,
        permissions: List[Permission],
        expires_at: Optional[datetime] = None,
    ):
        """Grant access to a key to another user"""
        # Check if granting user has permission to manage this key
        if not self.rbac.check_permission(granting_user_id, Permission.KEY_UPDATE, key_id):
            raise SecurityException("Access denied: cannot grant access to this key")

        # Verify the key exists
        if key_id not in self.keys_data:
            raise ValueError(f"Key {key_id} not found")

        # Grant access
        self.rbac.grant_key_access(key_id, target_user_id, permissions, expires_at=expires_at)

        # Log the grant
        self._log_audit(
            "INFO",
            f"Access granted for key {key_id} to user {target_user_id}",
            f"user_id:{granting_user_id}",
        )

    def revoke_key_access(self, key_id: str, revoking_user_id: int, target_user_id: int):
        """Revoke access to a key from another user"""
        # Check if revoking user has permission to manage this key
        if not self.rbac.check_permission(revoking_user_id, Permission.KEY_UPDATE, key_id):
            raise SecurityException("Access denied: cannot revoke access to this key")

        # Revoke access
        self.rbac.revoke_key_access(key_id, target_user_id)

        # Log the revocation
        self._log_audit(
            "INFO",
            f"Access revoked for key {key_id} from user {target_user_id}",
            f"user_id:{revoking_user_id}",
        )

    def get_key_access_list(self, key_id: str, requesting_user_id: int) -> List[Dict]:
        """Get list of users with access to a key"""
        # Check if user can read this key
        if not self.rbac.check_permission(requesting_user_id, Permission.KEY_READ, key_id):
            raise SecurityException("Access denied: cannot view access list for this key")

        import sqlite3

        conn = sqlite3.connect(self.rbac.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        # Get all users with access to this key
        cursor.execute(
            """
            SELECT u.id, u.username, u.role, kp.permissions, kp.created_at, kp.expires_at
            FROM key_policies kp
            JOIN users u ON kp.user_id = u.id
            WHERE kp.key_id = ?
            ORDER BY kp.created_at DESC
        """,
            (key_id,),
        )

        access_list = []
        for row in cursor.fetchall():
            access_list.append(
                {
                    "user_id": row["id"],
                    "username": row["username"],
                    "role": row["role"],
                    "permissions": json.loads(row["permissions"]),
                    "granted_at": row["created_at"],
                    "expires_at": row["expires_at"],
                }
            )

        conn.close()
        return access_list

    def export_audit_log_with_rbac(self, user_id: int) -> str:
        """Export audit log with RBAC check"""
        # Check if user has permission to read audit logs
        if not self.rbac.check_permission(user_id, Permission.AUDIT_READ):
            raise SecurityException("Access denied: insufficient permissions to read audit logs")

        # Get both storage and RBAC audit logs
        storage_logs = super().export_audit_log()
        rbac_logs = self.rbac.get_audit_logs(limit=1000)

        # Combine logs
        combined_log = "=== Storage Audit Log ===\\n" + storage_logs + "\\n\\n"
        combined_log += "=== RBAC Audit Log ===\\n"

        for log in rbac_logs:
            combined_log += f"[{log['timestamp']}] [{log['action']}] "
            combined_log += f"User: {log['username'] or log['user_id']} "
            if log["resource_type"] and log["resource_id"]:
                combined_log += f"Resource: {log['resource_type']}:{log['resource_id']} "
            combined_log += f"Success: {log['success']}\\n"

        return combined_log


# Create convenience class that combines all functionality
class SecureKeyStorageRBAC(SecureStorageWithRBAC):
    """Main class for secure key storage with RBAC"""

    def __init__(
        self,
        storage_path: str = "./keys",
        master_password: Optional[str] = None,
        rbac_db_path: str = "./rbac.db",
    ):
        super().__init__(storage_path, master_password, rbac_db_path)

        # Additional initialization if needed
        self._init_default_policies()

    def _init_default_policies(self):
        """Initialize any default access policies"""
        # Can be extended to set up default sharing policies, etc.
        pass


# Export main class
__all__ = ["SecureKeyStorageRBAC", "SecureStorageWithRBAC"]
