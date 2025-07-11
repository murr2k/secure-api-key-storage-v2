"""
Role-Based Access Control (RBAC) Models and Database Schema
Implements user roles, permissions, and access policies for secure API key management
"""

import sqlite3
import os
import json
from datetime import datetime
from typing import Dict, List, Optional, Tuple
from enum import Enum
import hashlib


class Role(Enum):
    """User roles with hierarchical permissions"""

    ADMIN = "admin"  # Full system access
    USER = "user"  # Create, read, update own keys
    VIEWER = "viewer"  # Read-only access to assigned keys


class Permission(Enum):
    """Granular permissions for key operations"""

    # Key management permissions
    KEY_CREATE = "key:create"
    KEY_READ = "key:read"
    KEY_UPDATE = "key:update"
    KEY_DELETE = "key:delete"
    KEY_ROTATE = "key:rotate"
    KEY_LIST = "key:list"
    KEY_EXPORT = "key:export"

    # User management permissions
    USER_CREATE = "user:create"
    USER_READ = "user:read"
    USER_UPDATE = "user:update"
    USER_DELETE = "user:delete"
    USER_LIST = "user:list"

    # Audit permissions
    AUDIT_READ = "audit:read"
    AUDIT_EXPORT = "audit:export"

    # Policy management permissions
    POLICY_CREATE = "policy:create"
    POLICY_READ = "policy:read"
    POLICY_UPDATE = "policy:update"
    POLICY_DELETE = "policy:delete"

    # System permissions
    SYSTEM_CONFIG = "system:config"
    SYSTEM_BACKUP = "system:backup"


# Role permission mappings
ROLE_PERMISSIONS = {
    Role.ADMIN: {
        # Admin has all permissions
        Permission.KEY_CREATE,
        Permission.KEY_READ,
        Permission.KEY_UPDATE,
        Permission.KEY_DELETE,
        Permission.KEY_ROTATE,
        Permission.KEY_LIST,
        Permission.KEY_EXPORT,
        Permission.USER_CREATE,
        Permission.USER_READ,
        Permission.USER_UPDATE,
        Permission.USER_DELETE,
        Permission.USER_LIST,
        Permission.AUDIT_READ,
        Permission.AUDIT_EXPORT,
        Permission.POLICY_CREATE,
        Permission.POLICY_READ,
        Permission.POLICY_UPDATE,
        Permission.POLICY_DELETE,
        Permission.SYSTEM_CONFIG,
        Permission.SYSTEM_BACKUP,
    },
    Role.USER: {
        # Users can manage their own keys
        Permission.KEY_CREATE,
        Permission.KEY_READ,
        Permission.KEY_UPDATE,
        Permission.KEY_ROTATE,
        Permission.KEY_LIST,
        Permission.AUDIT_READ,
    },
    Role.VIEWER: {
        # Viewers have read-only access
        Permission.KEY_READ,
        Permission.KEY_LIST,
        Permission.AUDIT_READ,
    },
}


class RBACDatabase:
    """Database handler for RBAC system"""

    def __init__(self, db_path: str = "./rbac.db"):
        self.db_path = db_path
        self.init_database()

    def init_database(self):
        """Initialize RBAC database schema"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # Users table
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                role TEXT NOT NULL,
                email TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_login TIMESTAMP,
                is_active BOOLEAN DEFAULT 1,
                metadata TEXT
            )
        """
        )

        # Key access policies table
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS key_policies (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                key_id TEXT NOT NULL,
                user_id INTEGER,
                permissions TEXT NOT NULL,
                conditions TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )
        """
        )

        # Access tokens table (for session management)
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS access_tokens (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                token_hash TEXT UNIQUE NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                expires_at TIMESTAMP NOT NULL,
                is_revoked BOOLEAN DEFAULT 0,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            )
        """
        )

        # Audit log table with RBAC context
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS rbac_audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                user_id INTEGER,
                username TEXT,
                action TEXT NOT NULL,
                resource_type TEXT,
                resource_id TEXT,
                permission_used TEXT,
                success BOOLEAN,
                ip_address TEXT,
                details TEXT
            )
        """
        )

        # Create indexes for performance
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_users_username ON users(username)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_key_policies_key ON key_policies(key_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_key_policies_user ON key_policies(user_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_tokens_hash ON access_tokens(token_hash)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_audit_user ON rbac_audit_log(user_id)")
        cursor.execute(
            "CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON rbac_audit_log(timestamp)"
        )

        conn.commit()
        conn.close()

        # Set restrictive permissions on database file
        os.chmod(self.db_path, 0o600)


class RBACManager:
    """Main RBAC management class"""

    def __init__(self, db_path: str = "./rbac.db"):
        self.db = RBACDatabase(db_path)
        self.db_path = db_path

    def create_user(
        self,
        username: str,
        password: str,
        role: Role,
        email: Optional[str] = None,
        metadata: Optional[Dict] = None,
    ) -> int:
        """Create a new user with specified role"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # Hash password with salt
        password_hash = self._hash_password(password)

        try:
            cursor.execute(
                """
                INSERT INTO users (username, password_hash, role, email, metadata)
                VALUES (?, ?, ?, ?, ?)
            """,
                (
                    username,
                    password_hash,
                    role.value,
                    email,
                    json.dumps(metadata) if metadata else None,
                ),
            )

            user_id = cursor.lastrowid
            conn.commit()

            # Log user creation
            self._log_audit(
                user_id,
                username,
                "user_created",
                "user",
                str(user_id),
                None,
                True,
                details={"role": role.value},
            )

            return user_id

        except sqlite3.IntegrityError:
            raise ValueError(f"User '{username}' already exists")
        finally:
            conn.close()

    def authenticate_user(self, username: str, password: str) -> Optional[Tuple[int, Role]]:
        """Authenticate user and return user ID and role"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT id, password_hash, role, is_active FROM users WHERE username = ?
        """,
            (username,),
        )

        result = cursor.fetchone()
        if not result:
            self._log_audit(
                None,
                username,
                "login_failed",
                "auth",
                None,
                None,
                False,
                details={"reason": "user_not_found"},
            )
            return None

        user_id, stored_hash, role_str, is_active = result

        if not is_active:
            self._log_audit(
                user_id,
                username,
                "login_failed",
                "auth",
                None,
                None,
                False,
                details={"reason": "user_inactive"},
            )
            return None

        # Verify password
        if not self._verify_password(password, stored_hash):
            self._log_audit(
                user_id,
                username,
                "login_failed",
                "auth",
                None,
                None,
                False,
                details={"reason": "invalid_password"},
            )
            return None

        # Update last login
        cursor.execute(
            """
            UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?
        """,
            (user_id,),
        )
        conn.commit()
        conn.close()

        role = Role(role_str)
        self._log_audit(
            user_id, username, "login_success", "auth", None, None, True, details={"role": role_str}
        )

        return user_id, role

    def check_permission(
        self, user_id: int, permission: Permission, key_id: Optional[str] = None
    ) -> bool:
        """Check if user has permission for an action"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # Get user role
        cursor.execute("SELECT role, username FROM users WHERE id = ?", (user_id,))
        result = cursor.fetchone()
        if not result:
            return False

        role_str, username = result
        role = Role(role_str)

        # Check role-based permissions
        if permission in ROLE_PERMISSIONS.get(role, set()):
            # For key-specific operations, check additional policies
            if key_id and permission in [
                Permission.KEY_READ,
                Permission.KEY_UPDATE,
                Permission.KEY_DELETE,
                Permission.KEY_ROTATE,
            ]:
                # Check if there are specific policies for this key
                has_access = self._check_key_policy(user_id, key_id, permission)
                if has_access is not None:
                    self._log_audit(
                        user_id,
                        username,
                        f"permission_check_{permission.value}",
                        "key",
                        key_id,
                        permission.value,
                        has_access,
                    )
                    return has_access

            conn.close()
            return True

        # Check individual key policies
        if key_id:
            has_access = self._check_key_policy(user_id, key_id, permission)
            if has_access:
                self._log_audit(
                    user_id,
                    username,
                    f"permission_check_{permission.value}",
                    "key",
                    key_id,
                    permission.value,
                    True,
                )
                conn.close()
                return True

        self._log_audit(
            user_id,
            username,
            f"permission_denied_{permission.value}",
            "key" if key_id else "system",
            key_id,
            permission.value,
            False,
        )
        conn.close()
        return False

    def grant_key_access(
        self,
        key_id: str,
        user_id: int,
        permissions: List[Permission],
        conditions: Optional[Dict] = None,
        expires_at: Optional[datetime] = None,
    ):
        """Grant specific permissions to a user for a key"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        perm_list = [p.value for p in permissions]

        cursor.execute(
            """
            INSERT INTO key_policies (key_id, user_id, permissions, conditions, expires_at)
            VALUES (?, ?, ?, ?, ?)
        """,
            (
                key_id,
                user_id,
                json.dumps(perm_list),
                json.dumps(conditions) if conditions else None,
                expires_at,
            ),
        )

        conn.commit()
        conn.close()

        self._log_audit(
            user_id,
            None,
            "key_access_granted",
            "key",
            key_id,
            None,
            True,
            details={"permissions": perm_list},
        )

    def revoke_key_access(self, key_id: str, user_id: int):
        """Revoke all permissions for a user on a key"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute(
            """
            DELETE FROM key_policies WHERE key_id = ? AND user_id = ?
        """,
            (key_id, user_id),
        )

        affected = cursor.rowcount
        conn.commit()
        conn.close()

        if affected > 0:
            self._log_audit(user_id, None, "key_access_revoked", "key", key_id, None, True)

    def get_user_accessible_keys(self, user_id: int) -> List[str]:
        """Get list of keys accessible to a user"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # Get user role
        cursor.execute("SELECT role FROM users WHERE id = ?", (user_id,))
        result = cursor.fetchone()
        if not result:
            return []

        role = Role(result[0])

        # Admins can access all keys
        if role == Role.ADMIN:
            conn.close()
            return ["*"]  # Special marker for all keys

        # Get keys with specific policies
        cursor.execute(
            """
            SELECT DISTINCT key_id FROM key_policies
            WHERE user_id = ? AND (expires_at IS NULL OR expires_at > CURRENT_TIMESTAMP)
        """,
            (user_id,),
        )

        keys = [row[0] for row in cursor.fetchall()]
        conn.close()

        return keys

    def _check_key_policy(
        self, user_id: int, key_id: str, permission: Permission
    ) -> Optional[bool]:
        """Check if user has specific permission for a key based on policies"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT permissions, conditions, expires_at FROM key_policies
            WHERE key_id = ? AND user_id = ?
            AND (expires_at IS NULL OR expires_at > CURRENT_TIMESTAMP)
        """,
            (key_id, user_id),
        )

        for row in cursor.fetchall():
            permissions_json, conditions_json, expires_at = row
            permissions = json.loads(permissions_json)

            if permission.value in permissions:
                # Check conditions if any
                if conditions_json:
                    conditions = json.loads(conditions_json)
                    if not self._evaluate_conditions(conditions):
                        continue

                conn.close()
                return True

        conn.close()
        return None

    def _evaluate_conditions(self, conditions: Dict) -> bool:
        """Evaluate access conditions (time-based, IP-based, etc.)"""
        # Implement condition evaluation logic
        # For now, return True (no conditions implemented yet)
        return True

    def _hash_password(self, password: str) -> str:
        """Hash password with salt"""
        salt = os.urandom(32)
        pwdhash = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 100000)
        return salt.hex() + pwdhash.hex()

    def _verify_password(self, password: str, stored_hash: str) -> bool:
        """Verify password against stored hash"""
        salt = bytes.fromhex(stored_hash[:64])
        stored_pwdhash = stored_hash[64:]
        pwdhash = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 100000)
        return pwdhash.hex() == stored_pwdhash

    def _log_audit(
        self,
        user_id: Optional[int],
        username: Optional[str],
        action: str,
        resource_type: Optional[str],
        resource_id: Optional[str],
        permission_used: Optional[str],
        success: bool,
        ip_address: Optional[str] = None,
        details: Optional[Dict] = None,
    ):
        """Log RBAC audit event"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute(
            """
            INSERT INTO rbac_audit_log
            (user_id, username, action, resource_type, resource_id, permission_used,
             success, ip_address, details)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
            (
                user_id,
                username,
                action,
                resource_type,
                resource_id,
                permission_used,
                success,
                ip_address,
                json.dumps(details) if details else None,
            ),
        )

        conn.commit()
        conn.close()

    def get_audit_logs(self, user_id: Optional[int] = None, limit: int = 100) -> List[Dict]:
        """Get RBAC audit logs"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()

        if user_id:
            cursor.execute(
                """
                SELECT * FROM rbac_audit_log
                WHERE user_id = ?
                ORDER BY timestamp DESC LIMIT ?
            """,
                (user_id, limit),
            )
        else:
            cursor.execute(
                """
                SELECT * FROM rbac_audit_log
                ORDER BY timestamp DESC LIMIT ?
            """,
                (limit,),
            )

        logs = []
        for row in cursor.fetchall():
            log_dict = dict(row)
            if log_dict.get("details"):
                log_dict["details"] = json.loads(log_dict["details"])
            logs.append(log_dict)

        conn.close()
        return logs


# Export for use in other modules
__all__ = ["Role", "Permission", "ROLE_PERMISSIONS", "RBACManager"]
