"""
Enhanced Authentication Manager with Multi-Factor Support

This module provides comprehensive authentication including:
- User management with secure password storage
- Two-factor authentication (2FA) using TOTP
- Certificate-based authentication
- Session management and audit logging
"""

import os
import json
import base64
import hashlib
import secrets
import sqlite3
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional, Dict, List, Any
from cryptography.hazmat.backends import default_backend
from cryptography.x509 import load_pem_x509_certificate
from passlib.context import CryptContext
import pyotp
import qrcode
from io import BytesIO
import jwt
from jose import JWTError


class AuthenticationManager:
    """Manages user authentication with multiple authentication methods."""

    def __init__(self, db_path: Optional[Path] = None):
        """Initialize the authentication manager."""
        self.db_path = db_path or Path.home() / ".secure-keys" / "auth.db"
        self.db_path.parent.mkdir(exist_ok=True, parents=True)

        # Password hashing context
        self.pwd_context = CryptContext(
            schemes=["argon2", "bcrypt"],
            deprecated="auto",
            argon2__memory_cost=65536,
            argon2__time_cost=3,
            argon2__parallelism=4,
        )

        # JWT configuration
        self.jwt_secret = os.environ.get("JWT_SECRET_KEY", secrets.token_urlsafe(32))
        self.jwt_algorithm = "HS256"
        self.access_token_expire_minutes = 15
        self.refresh_token_expire_days = 7

        # Certificate store
        self.cert_store_path = self.db_path.parent / "certificates"
        self.cert_store_path.mkdir(exist_ok=True)

        # Initialize database
        self._init_database()

    def _init_database(self):
        """Initialize the authentication database."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()

            # Users table
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    email TEXT UNIQUE,
                    is_active BOOLEAN DEFAULT 1,
                    is_admin BOOLEAN DEFAULT 0,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_login TIMESTAMP,
                    failed_attempts INTEGER DEFAULT 0,
                    locked_until TIMESTAMP,
                    require_2fa BOOLEAN DEFAULT 0,
                    totp_secret TEXT,
                    backup_codes TEXT,
                    certificate_subject TEXT,
                    certificate_fingerprint TEXT
                )
            """
            )

            # Authentication sessions table
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS sessions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    session_token TEXT UNIQUE NOT NULL,
                    ip_address TEXT,
                    user_agent TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    expires_at TIMESTAMP NOT NULL,
                    is_active BOOLEAN DEFAULT 1,
                    FOREIGN KEY (user_id) REFERENCES users (id)
                )
            """
            )

            # Audit log table
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS auth_audit_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER,
                    action TEXT NOT NULL,
                    ip_address TEXT,
                    user_agent TEXT,
                    success BOOLEAN,
                    details TEXT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users (id)
                )
            """
            )

            # Create indexes
            cursor.execute(
                "CREATE INDEX IF NOT EXISTS idx_sessions_token ON sessions(session_token)"
            )
            cursor.execute(
                "CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at)"
            )
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_audit_user ON auth_audit_log(user_id)")
            cursor.execute(
                "CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON auth_audit_log(timestamp)"
            )

            conn.commit()

    # User Management

    def create_user(
        self,
        username: str,
        password: str,
        email: Optional[str] = None,
        is_admin: bool = False,
        require_2fa: bool = True,
    ) -> Dict[str, Any]:
        """Create a new user account."""
        # Validate password strength
        if len(password) < 12:
            raise ValueError("Password must be at least 12 characters long")

        # Hash password
        password_hash = self.pwd_context.hash(password)

        # Generate TOTP secret if 2FA is required
        totp_secret = None
        if require_2fa:
            totp_secret = pyotp.random_base32()

        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute(
                    """
                    INSERT INTO users (username, password_hash, email, is_admin,
                                     require_2fa, totp_secret)
                    VALUES (?, ?, ?, ?, ?, ?)
                """,
                    (username, password_hash, email, is_admin, require_2fa, totp_secret),
                )

                user_id = cursor.lastrowid

                self._log_audit(user_id, "user_created", True, {"username": username})

                return {
                    "user_id": user_id,
                    "username": username,
                    "email": email,
                    "is_admin": is_admin,
                    "require_2fa": require_2fa,
                    "totp_secret": totp_secret,
                }
        except sqlite3.IntegrityError:
            raise ValueError(f"User '{username}' already exists")

    def update_password(self, username: str, old_password: str, new_password: str) -> bool:
        """Update user password."""
        user = self._get_user_by_username(username)
        if not user:
            return False

        # Verify old password
        if not self.pwd_context.verify(old_password, user["password_hash"]):
            self._log_audit(
                user["id"], "password_change_failed", False, {"reason": "invalid_old_password"}
            )
            return False

        # Validate new password
        if len(new_password) < 12:
            raise ValueError("Password must be at least 12 characters long")

        # Update password
        new_hash = self.pwd_context.hash(new_password)

        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                UPDATE users SET password_hash = ?, updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
            """,
                (new_hash, user["id"]),
            )

            # Invalidate all sessions
            cursor.execute("UPDATE sessions SET is_active = 0 WHERE user_id = ?", (user["id"],))

            self._log_audit(user["id"], "password_changed", True)

        return True

    # Authentication Methods

    def authenticate_password(
        self, username: str, password: str, ip_address: Optional[str] = None
    ) -> Dict[str, Any]:
        """Authenticate user with username and password."""
        user = self._get_user_by_username(username)

        if not user:
            self._log_audit(
                None,
                "login_failed",
                False,
                {"username": username, "reason": "user_not_found"},
                ip_address,
            )
            raise ValueError("Invalid username or password")

        # Check if account is locked
        if user["locked_until"] and datetime.now() < datetime.fromisoformat(user["locked_until"]):
            self._log_audit(
                user["id"], "login_failed", False, {"reason": "account_locked"}, ip_address
            )
            raise ValueError("Account is temporarily locked")

        # Verify password
        if not self.pwd_context.verify(password, user["password_hash"]):
            self._handle_failed_login(user["id"], ip_address)
            raise ValueError("Invalid username or password")

        # Reset failed attempts
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                UPDATE users SET failed_attempts = 0, locked_until = NULL,
                       last_login = CURRENT_TIMESTAMP
                WHERE id = ?
            """,
                (user["id"],),
            )

        self._log_audit(user["id"], "password_auth_success", True, ip_address=ip_address)

        return {
            "user_id": user["id"],
            "username": user["username"],
            "is_admin": user["is_admin"],
            "require_2fa": user["require_2fa"],
            "totp_configured": bool(user["totp_secret"]),
        }

    def setup_2fa(self, user_id: int) -> Dict[str, Any]:
        """Set up 2FA for a user."""
        user = self._get_user_by_id(user_id)
        if not user:
            raise ValueError("User not found")

        # Generate new TOTP secret
        totp_secret = pyotp.random_base32()

        # Generate backup codes
        backup_codes = [secrets.token_hex(4) for _ in range(10)]
        backup_codes_hash = [self.pwd_context.hash(code) for code in backup_codes]

        # Update user
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                UPDATE users SET totp_secret = ?, backup_codes = ?, require_2fa = 1
                WHERE id = ?
            """,
                (totp_secret, json.dumps(backup_codes_hash), user_id),
            )

        # Generate QR code
        totp_uri = pyotp.totp.TOTP(totp_secret).provisioning_uri(
            name=user["username"], issuer_name="Secure API Key Storage"
        )

        qr = qrcode.QRCode(version=1, box_size=10, border=5)
        qr.add_data(totp_uri)
        qr.make(fit=True)

        img = qr.make_image(fill_color="black", back_color="white")
        buffer = BytesIO()
        img.save(buffer, format="PNG")
        qr_code_data = base64.b64encode(buffer.getvalue()).decode()

        self._log_audit(user_id, "2fa_setup", True)

        return {"totp_secret": totp_secret, "qr_code": qr_code_data, "backup_codes": backup_codes}

    def verify_2fa(self, user_id: int, totp_code: str) -> bool:
        """Verify 2FA TOTP code."""
        user = self._get_user_by_id(user_id)
        if not user or not user["totp_secret"]:
            return False

        totp = pyotp.TOTP(user["totp_secret"])

        # Allow for time drift (30 second window)
        is_valid = totp.verify(totp_code, valid_window=1)

        self._log_audit(user_id, "2fa_verification", is_valid, {"method": "totp"})

        return is_valid

    def verify_backup_code(self, user_id: int, backup_code: str) -> bool:
        """Verify and consume a backup code."""
        user = self._get_user_by_id(user_id)
        if not user or not user["backup_codes"]:
            return False

        backup_codes_hash = json.loads(user["backup_codes"])

        # Check each hashed backup code
        for i, code_hash in enumerate(backup_codes_hash):
            if self.pwd_context.verify(backup_code, code_hash):
                # Remove used code
                backup_codes_hash.pop(i)

                with sqlite3.connect(self.db_path) as conn:
                    cursor = conn.cursor()
                    cursor.execute(
                        """
                        UPDATE users SET backup_codes = ?
                        WHERE id = ?
                    """,
                        (json.dumps(backup_codes_hash), user_id),
                    )

                self._log_audit(user_id, "2fa_verification", True, {"method": "backup_code"})
                return True

        self._log_audit(user_id, "2fa_verification", False, {"method": "backup_code"})
        return False

    def setup_certificate_auth(self, user_id: int, certificate_pem: str) -> Dict[str, Any]:
        """Set up certificate-based authentication for a user."""
        user = self._get_user_by_id(user_id)
        if not user:
            raise ValueError("User not found")

        # Load and validate certificate
        try:
            cert = load_pem_x509_certificate(certificate_pem.encode(), default_backend())
        except Exception as e:
            raise ValueError(f"Invalid certificate: {e}")

        # Extract certificate information
        subject = cert.subject.rfc4514_string()
        fingerprint = hashlib.sha256(cert.public_key_bytes_raw).hexdigest()

        # Store certificate
        cert_path = self.cert_store_path / f"{user_id}_{fingerprint}.pem"
        with open(cert_path, "w") as f:
            f.write(certificate_pem)

        # Update user record
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                UPDATE users SET certificate_subject = ?, certificate_fingerprint = ?
                WHERE id = ?
            """,
                (subject, fingerprint, user_id),
            )

        self._log_audit(user_id, "certificate_setup", True, {"fingerprint": fingerprint})

        return {
            "subject": subject,
            "fingerprint": fingerprint,
            "not_before": cert.not_valid_before_utc.isoformat(),
            "not_after": cert.not_valid_after_utc.isoformat(),
        }

    def authenticate_certificate(
        self, certificate_pem: str, ip_address: Optional[str] = None
    ) -> Dict[str, Any]:
        """Authenticate user with client certificate."""
        try:
            cert = load_pem_x509_certificate(certificate_pem.encode(), default_backend())
        except Exception as e:
            self._log_audit(
                None,
                "certificate_auth_failed",
                False,
                {"reason": "invalid_certificate"},
                ip_address,
            )
            raise ValueError(f"Invalid certificate: {e}")

        # Check certificate validity
        now = datetime.now()
        if now < cert.not_valid_before_utc.replace(
            tzinfo=None
        ) or now > cert.not_valid_after_utc.replace(tzinfo=None):
            self._log_audit(
                None,
                "certificate_auth_failed",
                False,
                {"reason": "expired_certificate"},
                ip_address,
            )
            raise ValueError("Certificate is not valid")

        # Calculate fingerprint
        fingerprint = hashlib.sha256(cert.public_key_bytes_raw).hexdigest()

        # Find user by certificate
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT id, username, is_admin FROM users
                WHERE certificate_fingerprint = ? AND is_active = 1
            """,
                (fingerprint,),
            )

            row = cursor.fetchone()
            if not row:
                self._log_audit(
                    None,
                    "certificate_auth_failed",
                    False,
                    {"reason": "certificate_not_found", "fingerprint": fingerprint},
                    ip_address,
                )
                raise ValueError("Certificate not registered")

            user_id, username, is_admin = row

            # Update last login
            cursor.execute(
                "UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?", (user_id,)
            )

        self._log_audit(
            user_id, "certificate_auth_success", True, {"fingerprint": fingerprint}, ip_address
        )

        return {
            "user_id": user_id,
            "username": username,
            "is_admin": is_admin,
            "auth_method": "certificate",
        }

    # Session Management

    def create_session(
        self, user_id: int, ip_address: Optional[str] = None, user_agent: Optional[str] = None
    ) -> Dict[str, str]:
        """Create a new authenticated session."""
        # Generate tokens
        session_token = secrets.token_urlsafe(32)

        # Create JWT tokens
        access_token = self._create_jwt_token(user_id, "access", self.access_token_expire_minutes)
        refresh_token = self._create_jwt_token(
            user_id, "refresh", self.refresh_token_expire_days * 24 * 60
        )

        # Store session
        expires_at = datetime.now() + timedelta(days=self.refresh_token_expire_days)

        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO sessions (user_id, session_token, ip_address, user_agent, expires_at)
                VALUES (?, ?, ?, ?, ?)
            """,
                (user_id, session_token, ip_address, user_agent, expires_at),
            )

        self._log_audit(user_id, "session_created", True, ip_address=ip_address)

        return {
            "session_token": session_token,
            "access_token": access_token,
            "refresh_token": refresh_token,
        }

    def validate_session(self, session_token: str) -> Optional[Dict[str, Any]]:
        """Validate a session token."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                SELECT s.user_id, s.expires_at, u.username, u.is_admin
                FROM sessions s
                JOIN users u ON s.user_id = u.id
                WHERE s.session_token = ? AND s.is_active = 1 AND u.is_active = 1
            """,
                (session_token,),
            )

            row = cursor.fetchone()
            if not row:
                return None

            user_id, expires_at, username, is_admin = row

            # Check expiration
            if datetime.now() > datetime.fromisoformat(expires_at):
                cursor.execute(
                    "UPDATE sessions SET is_active = 0 WHERE session_token = ?", (session_token,)
                )
                return None

            return {"user_id": user_id, "username": username, "is_admin": is_admin}

    def invalidate_session(self, session_token: str):
        """Invalidate a session."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                "UPDATE sessions SET is_active = 0 WHERE session_token = ?", (session_token,)
            )

    def invalidate_all_user_sessions(self, user_id: int):
        """Invalidate all sessions for a user."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("UPDATE sessions SET is_active = 0 WHERE user_id = ?", (user_id,))

        self._log_audit(user_id, "all_sessions_invalidated", True)

    # JWT Token Management

    def _create_jwt_token(self, user_id: int, token_type: str, expire_minutes: int) -> str:
        """Create a JWT token."""
        user = self._get_user_by_id(user_id)
        if not user:
            raise ValueError("User not found")

        expire = datetime.utcnow() + timedelta(minutes=expire_minutes)

        payload = {
            "sub": user["username"],
            "user_id": user_id,
            "is_admin": user["is_admin"],
            "type": token_type,
            "exp": expire,
        }

        return jwt.encode(payload, self.jwt_secret, algorithm=self.jwt_algorithm)

    def validate_jwt_token(
        self, token: str, expected_type: str = "access"
    ) -> Optional[Dict[str, Any]]:
        """Validate a JWT token."""
        try:
            payload = jwt.decode(token, self.jwt_secret, algorithms=[self.jwt_algorithm])

            if payload.get("type") != expected_type:
                return None

            return {
                "user_id": payload.get("user_id"),
                "username": payload.get("sub"),
                "is_admin": payload.get("is_admin", False),
            }
        except (JWTError, KeyError):
            return None

    def refresh_access_token(self, refresh_token: str) -> Optional[str]:
        """Refresh an access token using a refresh token."""
        token_data = self.validate_jwt_token(refresh_token, "refresh")
        if not token_data:
            return None

        # Create new access token
        return self._create_jwt_token(
            token_data["user_id"], "access", self.access_token_expire_minutes
        )

    # Helper Methods

    def _get_user_by_username(self, username: str) -> Optional[Dict[str, Any]]:
        """Get user by username."""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
            row = cursor.fetchone()
            return dict(row) if row else None

    def _get_user_by_id(self, user_id: int) -> Optional[Dict[str, Any]]:
        """Get user by ID."""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
            row = cursor.fetchone()
            return dict(row) if row else None

    def _handle_failed_login(self, user_id: int, ip_address: Optional[str] = None):
        """Handle failed login attempt."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()

            # Increment failed attempts
            cursor.execute(
                """
                UPDATE users SET failed_attempts = failed_attempts + 1
                WHERE id = ?
            """,
                (user_id,),
            )

            # Check if we should lock the account
            cursor.execute("SELECT failed_attempts FROM users WHERE id = ?", (user_id,))
            failed_attempts = cursor.fetchone()[0]

            if failed_attempts >= 5:
                # Lock account for 30 minutes
                locked_until = datetime.now() + timedelta(minutes=30)
                cursor.execute(
                    """
                    UPDATE users SET locked_until = ?
                    WHERE id = ?
                """,
                    (locked_until.isoformat(), user_id),
                )

                self._log_audit(
                    user_id,
                    "account_locked",
                    True,
                    {"failed_attempts": failed_attempts},
                    ip_address,
                )
            else:
                self._log_audit(
                    user_id, "login_failed", False, {"failed_attempts": failed_attempts}, ip_address
                )

    def _log_audit(
        self,
        user_id: Optional[int],
        action: str,
        success: bool,
        details: Optional[Dict[str, Any]] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
    ):
        """Log an authentication audit event."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO auth_audit_log (user_id, action, ip_address,
                                           user_agent, success, details)
                VALUES (?, ?, ?, ?, ?, ?)
            """,
                (
                    user_id,
                    action,
                    ip_address,
                    user_agent,
                    success,
                    json.dumps(details) if details else None,
                ),
            )

    def get_audit_logs(
        self, user_id: Optional[int] = None, limit: int = 100
    ) -> List[Dict[str, Any]]:
        """Get authentication audit logs."""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

            if user_id:
                cursor.execute(
                    """
                    SELECT * FROM auth_audit_log
                    WHERE user_id = ?
                    ORDER BY timestamp DESC
                    LIMIT ?
                """,
                    (user_id, limit),
                )
            else:
                cursor.execute(
                    """
                    SELECT * FROM auth_audit_log
                    ORDER BY timestamp DESC
                    LIMIT ?
                """,
                    (limit,),
                )

            return [dict(row) for row in cursor.fetchall()]

    def cleanup_expired_sessions(self):
        """Clean up expired sessions."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                UPDATE sessions SET is_active = 0
                WHERE expires_at < CURRENT_TIMESTAMP AND is_active = 1
            """
            )

            affected = cursor.rowcount
            if affected > 0:
                print(f"Cleaned up {affected} expired sessions")
