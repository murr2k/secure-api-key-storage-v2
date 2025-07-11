"""
Secure API Key Storage System
Implements encryption, secure storage, and access control for API keys
"""

import os
import json
import hashlib
import secrets
from datetime import datetime, timedelta
from typing import Dict, Optional, List, Tuple, Any
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import base64

# Import enhanced audit system
try:
    from .audit_enhancement import (
        TamperProofAuditLogger,
        RotationPolicyEnforcer,
        SecurityEventMonitor,
        EventType,
        EventSeverity,
        RetentionPolicy,
        RotationPolicy,
    )

    AUDIT_ENHANCEMENT_AVAILABLE = True
except ImportError:
    AUDIT_ENHANCEMENT_AVAILABLE = False


class SecurityException(Exception):
    """Custom exception for security-related errors"""

    pass


class APIKeyStorage:
    """Secure API Key Storage with encryption and access control"""

    def __init__(
        self,
        storage_path: str = "./keys",
        master_password: Optional[str] = None,
        enable_enhanced_audit: bool = True,
        retention_policy: Optional["RetentionPolicy"] = None,
        rotation_policy: Optional["RotationPolicy"] = None,
    ):
        self.storage_path = storage_path
        self.keys_file = os.path.join(storage_path, "encrypted_keys.json")
        self.audit_log = os.path.join(storage_path, "audit.log")

        # Create storage directory if it doesn't exist
        os.makedirs(storage_path, exist_ok=True)

        # Initialize enhanced audit system if available
        self.enhanced_audit = None
        self.rotation_enforcer = None
        self.security_monitor = None

        if enable_enhanced_audit and AUDIT_ENHANCEMENT_AVAILABLE:
            try:
                self.enhanced_audit = TamperProofAuditLogger(
                    audit_dir=os.path.join(storage_path, "audit"), retention_policy=retention_policy
                )
                self.rotation_enforcer = RotationPolicyEnforcer(
                    audit_logger=self.enhanced_audit, rotation_policy=rotation_policy
                )
                self.security_monitor = SecurityEventMonitor(self.enhanced_audit)
            except Exception as e:
                print(f"Warning: Failed to initialize enhanced audit system: {e}")
                self.enhanced_audit = None

        # Initialize encryption
        self._init_encryption(master_password)

        # Load existing keys
        self.keys_data = self._load_keys()

    def _init_encryption(self, master_password: Optional[str] = None):
        """Initialize encryption using master password or generated key"""
        if master_password:
            # Derive key from password using PBKDF2
            salt = b"stable_salt_for_demo"  # In production, use random salt stored separately
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
                backend=default_backend(),
            )
            key = base64.urlsafe_b64encode(kdf.derive(master_password.encode()))
            self.cipher = Fernet(key)
        else:
            # Generate new key
            key_file = os.path.join(self.storage_path, ".master_key")
            if os.path.exists(key_file):
                with open(key_file, "rb") as f:
                    key = f.read()
            else:
                key = Fernet.generate_key()
                with open(key_file, "wb") as f:
                    f.write(key)
                # Set restrictive permissions
                os.chmod(key_file, 0o600)
            self.cipher = Fernet(key)

    def _load_keys(self) -> Dict:
        """Load encrypted keys from storage"""
        if os.path.exists(self.keys_file):
            try:
                with open(self.keys_file, "r") as f:
                    encrypted_data = json.load(f)
                # Decrypt the data
                decrypted_data = {}
                for key, value in encrypted_data.items():
                    decrypted_data[key] = json.loads(self.cipher.decrypt(value.encode()).decode())
                return decrypted_data
            except Exception as e:
                self._log_audit("ERROR", f"Failed to load keys: {str(e)}")
                raise SecurityException(f"Failed to decrypt keys: {str(e)}")
        return {}

    def _save_keys(self):
        """Save encrypted keys to storage"""
        encrypted_data = {}
        for key, value in self.keys_data.items():
            encrypted_data[key] = self.cipher.encrypt(json.dumps(value).encode()).decode()

        with open(self.keys_file, "w") as f:
            json.dump(encrypted_data, f, indent=2)

        # Set restrictive permissions
        os.chmod(self.keys_file, 0o600)

    def _log_audit(
        self,
        level: str,
        message: str,
        user: str = "system",
        key_id: Optional[str] = None,
        service: Optional[str] = None,
        event_type: Optional["EventType"] = None,
        details: Optional[Dict] = None,
    ):
        """Log security audit events"""
        # Use enhanced audit if available
        if self.enhanced_audit:
            # Map level to severity
            severity_map = {
                "INFO": EventSeverity.INFO,
                "WARNING": EventSeverity.WARNING,
                "ERROR": EventSeverity.ERROR,
                "CRITICAL": EventSeverity.CRITICAL,
            }
            severity = severity_map.get(level, EventSeverity.INFO)

            # Map or use provided event type
            if not event_type:
                # Infer event type from message
                if "Added API key" in message:
                    event_type = EventType.KEY_CREATED
                elif "Accessed API key" in message:
                    event_type = EventType.KEY_ACCESSED
                elif "Revoked API key" in message:
                    event_type = EventType.KEY_REVOKED
                elif "Rotated key" in message:
                    event_type = EventType.KEY_ROTATED
                elif "Failed to" in message:
                    event_type = EventType.SYSTEM_ERROR
                else:
                    event_type = EventType.KEY_ACCESSED  # Default

            # Log to enhanced audit system
            self.enhanced_audit.log_event(
                event_type=event_type,
                severity=severity,
                user_id=user,
                key_id=key_id,
                service=service,
                details=details or {"message": message},
            )

        # Also log to traditional file
        timestamp = datetime.now().isoformat()
        log_entry = f"[{timestamp}] [{level}] [{user}] {message}\n"

        with open(self.audit_log, "a") as f:
            f.write(log_entry)

    def add_api_key(
        self, service: str, api_key: str, user: str, metadata: Optional[Dict] = None
    ) -> str:
        """Add new API key with encryption"""
        # Validate inputs
        if not service or not api_key or not user:
            raise ValueError("Service, API key, and user are required")

        # Generate unique ID
        key_id = hashlib.sha256(f"{service}_{user}_{secrets.token_hex(8)}".encode()).hexdigest()[
            :16
        ]

        # Store encrypted key data
        key_data = {
            "service": service,
            "api_key": api_key,
            "user": user,
            "created_at": datetime.now().isoformat(),
            "last_accessed": None,
            "access_count": 0,
            "metadata": metadata or {},
            "active": True,
        }

        self.keys_data[key_id] = key_data
        self._save_keys()

        # Register with rotation enforcer
        if self.rotation_enforcer:
            self.rotation_enforcer.register_key(key_id, service, datetime.now())

        self._log_audit(
            "INFO",
            f"Added API key for service: {service}",
            user,
            key_id=key_id,
            service=service,
            event_type=EventType.KEY_CREATED,
        )

        return key_id

    def get_api_key(self, key_id: str, user: str) -> Optional[str]:
        """Retrieve API key with access control"""
        if key_id not in self.keys_data:
            self._log_audit(
                "WARNING",
                f"Attempted to access non-existent key: {key_id}",
                user,
                key_id=key_id,
                event_type=EventType.AUTH_FAILURE,
            )

            # Check security monitor
            if self.security_monitor:
                self.security_monitor.check_event(EventType.AUTH_FAILURE, user, key_id)

            return None

        key_data = self.keys_data[key_id]
        service = key_data.get("service")

        # Check rotation policy enforcement
        if self.rotation_enforcer:
            is_valid, message = self.rotation_enforcer.check_key_validity(key_id)
            if not is_valid:
                self._log_audit(
                    "ERROR",
                    f"Key blocked by rotation policy: {message}",
                    user,
                    key_id=key_id,
                    service=service,
                    event_type=EventType.POLICY_VIOLATION,
                )
                return None
            elif message:  # Warning message
                self._log_audit("WARNING", message, user, key_id=key_id, service=service)

        # Check if key is active
        if not key_data.get("active", True):
            self._log_audit(
                "WARNING",
                f"Attempted to access inactive key: {key_id}",
                user,
                key_id=key_id,
                service=service,
                event_type=EventType.AUTH_FAILURE,
            )
            return None

        # Update access metadata
        key_data["last_accessed"] = datetime.now().isoformat()
        key_data["access_count"] += 1
        self._save_keys()

        self._log_audit(
            "INFO",
            f"Accessed API key: {key_id}",
            user,
            key_id=key_id,
            service=service,
            event_type=EventType.KEY_ACCESSED,
        )

        # Check security monitor for anomalies
        if self.security_monitor:
            self.security_monitor.check_event(EventType.KEY_ACCESSED, user, key_id)

        return key_data["api_key"]

    def revoke_key(self, key_id: str, user: str) -> bool:
        """Revoke an API key"""
        if key_id not in self.keys_data:
            return False

        self.keys_data[key_id]["active"] = False
        self.keys_data[key_id]["revoked_at"] = datetime.now().isoformat()
        self.keys_data[key_id]["revoked_by"] = user
        self._save_keys()

        self._log_audit(
            "WARNING",
            f"Revoked API key: {key_id}",
            user,
            key_id=key_id,
            service=self.keys_data[key_id].get("service"),
            event_type=EventType.KEY_REVOKED,
        )

        return True

    def list_keys(self, user: str, include_inactive: bool = False) -> List[Dict]:
        """List API keys (without exposing actual keys)"""
        keys_list = []

        for key_id, key_data in self.keys_data.items():
            if not include_inactive and not key_data.get("active", True):
                continue

            # Return metadata without actual API key
            safe_data = {
                "key_id": key_id,
                "service": key_data["service"],
                "user": key_data["user"],
                "created_at": key_data["created_at"],
                "last_accessed": key_data.get("last_accessed"),
                "access_count": key_data.get("access_count", 0),
                "active": key_data.get("active", True),
                "metadata": key_data.get("metadata", {}),
            }
            keys_list.append(safe_data)

        self._log_audit("INFO", f"Listed {len(keys_list)} keys", user)

        return keys_list

    def rotate_key(self, key_id: str, new_api_key: str, user: str) -> bool:
        """Rotate an existing API key"""
        if key_id not in self.keys_data:
            return False

        old_key_data = self.keys_data[key_id].copy()

        # Create new key entry
        new_key_id = self.add_api_key(
            service=old_key_data["service"],
            api_key=new_api_key,
            user=user,
            metadata={
                **old_key_data.get("metadata", {}),
                "rotated_from": key_id,
                "rotation_date": datetime.now().isoformat(),
            },
        )

        # Revoke old key
        self.revoke_key(key_id, user)

        # Update rotation enforcer
        if self.rotation_enforcer:
            self.rotation_enforcer.update_rotation(new_key_id, datetime.now())

        self._log_audit(
            "INFO",
            f"Rotated key {key_id} to {new_key_id}",
            user,
            key_id=key_id,
            service=old_key_data["service"],
            event_type=EventType.KEY_ROTATED,
            details={"old_key_id": key_id, "new_key_id": new_key_id},
        )

        return True

    def export_audit_log(self) -> str:
        """Export audit log for security review"""
        if os.path.exists(self.audit_log):
            with open(self.audit_log, "r") as f:
                return f.read()
        return ""

    def check_key_expiry(self, days: int = 90) -> List[Dict]:
        """Check for keys that should be rotated based on age"""
        expiry_date = datetime.now() - timedelta(days=days)
        expired_keys = []

        for key_id, key_data in self.keys_data.items():
            if not key_data.get("active", True):
                continue

            created_at = datetime.fromisoformat(key_data["created_at"])
            if created_at < expiry_date:
                expired_keys.append(
                    {
                        "key_id": key_id,
                        "service": key_data["service"],
                        "created_at": key_data["created_at"],
                        "days_old": (datetime.now() - created_at).days,
                    }
                )

        return expired_keys

    def verify_audit_integrity(
        self, start_date: Optional[datetime] = None, end_date: Optional[datetime] = None
    ) -> Tuple[bool, List[str]]:
        """Verify integrity of audit logs using cryptographic signatures"""
        if self.enhanced_audit:
            return self.enhanced_audit.verify_integrity(start_date, end_date)
        else:
            return False, ["Enhanced audit system not available"]

    def get_security_status(self) -> Dict[str, Any]:
        """Get comprehensive security status including audit and rotation info"""
        status = {
            "enhanced_audit_enabled": self.enhanced_audit is not None,
            "total_keys": len(self.keys_data),
            "active_keys": len([k for k, v in self.keys_data.items() if v.get("active", True)]),
            "expired_keys": len(self.check_key_expiry()),
        }

        # Add rotation status if available
        if self.rotation_enforcer:
            status["rotation_enforcement"] = self.rotation_enforcer.get_rotation_status()

        # Add security summary if available
        if self.security_monitor:
            status["security_summary"] = self.security_monitor.get_security_summary(hours=24)

        # Add audit integrity status
        if self.enhanced_audit:
            is_valid, issues = self.verify_audit_integrity()
            status["audit_integrity"] = {
                "valid": is_valid,
                "issues_count": len(issues),
                "last_check": datetime.now().isoformat(),
            }

        return status

    def enforce_retention_policies(self):
        """Enforce audit log retention policies"""
        if self.enhanced_audit:
            self.enhanced_audit.enforce_retention_policy()
            self._log_audit(
                "INFO",
                "Enforced audit retention policies",
                "system",
                event_type=EventType.SYSTEM_ERROR if AUDIT_ENHANCEMENT_AVAILABLE else None,
            )

    def get_audit_report(self, days: int = 30) -> Dict[str, Any]:
        """Generate comprehensive audit report"""
        report = {"period_days": days, "generated_at": datetime.now().isoformat()}

        if self.enhanced_audit:
            # Get rotation report from rotation manager
            if hasattr(self, "rotation_enforcer") and self.rotation_enforcer:
                # This would need integration with the rotation manager
                pass

            # Get security summary
            if self.security_monitor:
                report["security_summary"] = self.security_monitor.get_security_summary(
                    hours=days * 24
                )

            # Get rotation status
            if self.rotation_enforcer:
                report["rotation_status"] = self.rotation_enforcer.get_rotation_status()

        # Add basic statistics
        cutoff_date = datetime.now() - timedelta(days=days)
        access_count = 0

        for key_data in self.keys_data.values():
            if key_data.get("last_accessed"):
                last_accessed = datetime.fromisoformat(key_data["last_accessed"])
                if last_accessed > cutoff_date:
                    access_count += key_data.get("access_count", 0)

        report["statistics"] = {
            "total_accesses": access_count,
            "keys_rotated": len(
                [k for k, v in self.keys_data.items() if v.get("metadata", {}).get("rotated_from")]
            ),
            "keys_revoked": len(
                [k for k, v in self.keys_data.items() if not v.get("active", True)]
            ),
        }

        return report
