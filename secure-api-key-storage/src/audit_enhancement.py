"""
Enhanced Audit Logging System with Tamper-Proofing and Rotation Enforcement

This module provides:
- Cryptographically signed audit logs for tamper detection
- Configurable retention policies
- Automatic key rotation enforcement
- Security event monitoring and alerting
"""

import os
import json
import hashlib
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple, Any
from enum import Enum
from dataclasses import dataclass
from pathlib import Path
import sqlite3
from contextlib import contextmanager
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature
import threading
import queue
import logging
from prometheus_client import Counter


# Metrics for monitoring
audit_events_total = Counter(
    "audit_events_total", "Total number of audit events", ["event_type", "severity"]
)
audit_signatures_verified = Counter(
    "audit_signatures_verified", "Audit log signature verification attempts", ["result"]
)
rotation_enforcement_actions = Counter(
    "rotation_enforcement_actions", "Key rotation enforcement actions taken", ["action_type"]
)
security_alerts_total = Counter(
    "security_alerts_total", "Total security alerts generated", ["alert_type", "severity"]
)


class EventSeverity(Enum):
    """Severity levels for audit events"""

    DEBUG = "debug"
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


class EventType(Enum):
    """Types of audit events"""

    KEY_CREATED = "key_created"
    KEY_ACCESSED = "key_accessed"
    KEY_ROTATED = "key_rotated"
    KEY_REVOKED = "key_revoked"
    KEY_DELETED = "key_deleted"
    AUTH_SUCCESS = "auth_success"
    AUTH_FAILURE = "auth_failure"
    POLICY_VIOLATION = "policy_violation"
    TAMPERING_DETECTED = "tampering_detected"
    ROTATION_REQUIRED = "rotation_required"
    ROTATION_COMPLETED = "rotation_completed"
    SYSTEM_ERROR = "system_error"


@dataclass
class AuditEvent:
    """Represents a single audit event"""

    event_id: str
    timestamp: str
    event_type: EventType
    severity: EventSeverity
    user_id: str
    key_id: Optional[str]
    service: Optional[str]
    details: Dict[str, Any]
    ip_address: Optional[str]
    user_agent: Optional[str]
    signature: Optional[str] = None
    previous_hash: Optional[str] = None
    event_hash: Optional[str] = None


@dataclass
class RetentionPolicy:
    """Audit log retention policy"""

    default_retention_days: int = 365
    severity_retention: Dict[EventSeverity, int] = None
    event_type_retention: Dict[EventType, int] = None
    archive_after_days: int = 90
    compress_archives: bool = True

    def __post_init__(self):
        if self.severity_retention is None:
            self.severity_retention = {
                EventSeverity.DEBUG: 7,
                EventSeverity.INFO: 30,
                EventSeverity.WARNING: 90,
                EventSeverity.ERROR: 180,
                EventSeverity.CRITICAL: 730,  # 2 years
            }
        if self.event_type_retention is None:
            self.event_type_retention = {
                EventType.KEY_ROTATED: 730,
                EventType.AUTH_FAILURE: 180,
                EventType.POLICY_VIOLATION: 365,
                EventType.TAMPERING_DETECTED: 1825,  # 5 years
            }


@dataclass
class RotationPolicy:
    """Key rotation enforcement policy"""

    max_key_age_days: int = 90
    warning_before_days: int = 14
    enforce_rotation: bool = True
    auto_rotate: bool = False
    block_expired_keys: bool = True
    grace_period_days: int = 7
    exempt_services: List[str] = None

    def __post_init__(self):
        if self.exempt_services is None:
            self.exempt_services = []


class TamperProofAuditLogger:
    """Cryptographically signed audit logger with tamper detection"""

    def __init__(self, audit_dir: str, retention_policy: Optional[RetentionPolicy] = None):
        self.audit_dir = Path(audit_dir)
        self.audit_dir.mkdir(parents=True, exist_ok=True)

        self.retention_policy = retention_policy or RetentionPolicy()
        self.logger = self._setup_logging()

        # Initialize cryptographic keys
        self._init_crypto_keys()

        # Initialize database
        self.db_path = self.audit_dir / "audit.db"
        self._init_database()

        # Event queue for async processing
        self.event_queue = queue.Queue()
        self.processing_thread = threading.Thread(target=self._process_events, daemon=True)
        self.processing_thread.start()

        # Chain hash for tamper detection
        self.last_event_hash = self._get_last_event_hash()

    def _setup_logging(self) -> logging.Logger:
        """Setup logging configuration"""
        logger = logging.getLogger("TamperProofAudit")
        logger.setLevel(logging.INFO)

        # File handler
        log_file = self.audit_dir / "audit_system.log"
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(logging.INFO)

        # Formatter
        formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

        return logger

    def _init_crypto_keys(self):
        """Initialize or load cryptographic keys for signing"""
        key_file = self.audit_dir / ".audit_signing_key.pem"

        if key_file.exists():
            # Load existing key
            with open(key_file, "rb") as f:
                self.signing_key = serialization.load_pem_private_key(
                    f.read(), password=None, backend=default_backend()
                )
        else:
            # Generate new key pair
            self.signing_key = rsa.generate_private_key(
                public_exponent=65537, key_size=2048, backend=default_backend()
            )

            # Save private key
            pem = self.signing_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )

            with open(key_file, "wb") as f:
                f.write(pem)

            # Restrict permissions
            os.chmod(key_file, 0o600)

        # Get public key for verification
        self.public_key = self.signing_key.public_key()

        # Save public key separately
        pub_key_file = self.audit_dir / "audit_public_key.pem"
        pub_pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        with open(pub_key_file, "wb") as f:
            f.write(pub_pem)

    def _init_database(self):
        """Initialize audit database with tables"""
        with self._get_connection() as conn:
            # Main audit events table
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS audit_events (
                    event_id TEXT PRIMARY KEY,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    event_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    user_id TEXT NOT NULL,
                    key_id TEXT,
                    service TEXT,
                    details TEXT,
                    ip_address TEXT,
                    user_agent TEXT,
                    signature TEXT NOT NULL,
                    previous_hash TEXT,
                    event_hash TEXT NOT NULL,
                    archived BOOLEAN DEFAULT FALSE,
                    retention_date TIMESTAMP
                )
            """
            )

            # Indexes for performance
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_timestamp
                ON audit_events(timestamp)
            """
            )
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_event_type
                ON audit_events(event_type)
            """
            )
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_user_id
                ON audit_events(user_id)
            """
            )
            conn.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_key_id
                ON audit_events(key_id)
            """
            )

            # Tamper detection table
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS integrity_checks (
                    check_id INTEGER PRIMARY KEY AUTOINCREMENT,
                    check_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    events_checked INTEGER,
                    signatures_valid INTEGER,
                    chain_valid BOOLEAN,
                    issues_found TEXT,
                    check_signature TEXT
                )
            """
            )

            # Rotation enforcement table
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS rotation_enforcement (
                    key_id TEXT PRIMARY KEY,
                    service TEXT NOT NULL,
                    created_at TIMESTAMP,
                    last_rotated TIMESTAMP,
                    rotation_due TIMESTAMP,
                    warning_sent BOOLEAN DEFAULT FALSE,
                    rotation_enforced BOOLEAN DEFAULT FALSE,
                    blocked BOOLEAN DEFAULT FALSE
                )
            """
            )

    @contextmanager
    def _get_connection(self):
        """Get database connection"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    def _get_last_event_hash(self) -> Optional[str]:
        """Get the hash of the last event for chain integrity"""
        with self._get_connection() as conn:
            result = conn.execute(
                """
                SELECT event_hash FROM audit_events
                ORDER BY timestamp DESC LIMIT 1
            """
            ).fetchone()

            return result["event_hash"] if result else None

    def _calculate_event_hash(self, event: AuditEvent) -> str:
        """Calculate hash of event for chain integrity"""
        # Create deterministic string representation
        event_data = {
            "event_id": event.event_id,
            "timestamp": event.timestamp,
            "event_type": event.event_type.value,
            "severity": event.severity.value,
            "user_id": event.user_id,
            "key_id": event.key_id,
            "service": event.service,
            "details": json.dumps(event.details, sort_keys=True),
            "previous_hash": event.previous_hash,
        }

        event_string = json.dumps(event_data, sort_keys=True)
        return hashlib.sha256(event_string.encode()).hexdigest()

    def _sign_event(self, event: AuditEvent) -> str:
        """Create cryptographic signature for event"""
        # Create signing data
        sign_data = {
            "event_hash": event.event_hash,
            "timestamp": event.timestamp,
            "event_type": event.event_type.value,
        }

        message = json.dumps(sign_data, sort_keys=True).encode()

        # Sign with private key
        signature = self.signing_key.sign(
            message,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256(),
        )

        return signature.hex()

    def log_event(
        self,
        event_type: EventType,
        severity: EventSeverity,
        user_id: str,
        key_id: Optional[str] = None,
        service: Optional[str] = None,
        details: Optional[Dict] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
    ):
        """Log an audit event"""
        # Create event
        event = AuditEvent(
            event_id=f"{int(time.time() * 1000000)}_{os.urandom(4).hex()}",
            timestamp=datetime.utcnow().isoformat(),
            event_type=event_type,
            severity=severity,
            user_id=user_id,
            key_id=key_id,
            service=service,
            details=details or {},
            ip_address=ip_address,
            user_agent=user_agent,
            previous_hash=self.last_event_hash,
        )

        # Calculate hash
        event.event_hash = self._calculate_event_hash(event)

        # Sign event
        event.signature = self._sign_event(event)

        # Queue for processing
        self.event_queue.put(event)

        # Update metrics
        audit_events_total.labels(event_type=event_type.value, severity=severity.value).inc()

        # Update last hash
        self.last_event_hash = event.event_hash

        return event.event_id

    def _process_events(self):
        """Process events from queue"""
        while True:
            try:
                event = self.event_queue.get(timeout=1)
                self._store_event(event)

                # Check for security-critical events
                if event.severity in [EventSeverity.ERROR, EventSeverity.CRITICAL]:
                    self._trigger_alert(event)

                # Check rotation requirements
                if event.key_id and event.event_type == EventType.KEY_ACCESSED:
                    self._check_rotation_requirement(event.key_id, event.service)

            except queue.Empty:
                continue
            except Exception as e:
                self.logger.error(f"Error processing event: {e}")

    def _store_event(self, event: AuditEvent):
        """Store event in database"""
        # Calculate retention date based on policy
        retention_days = self.retention_policy.default_retention_days

        # Check severity-specific retention
        if event.severity in self.retention_policy.severity_retention:
            retention_days = max(
                retention_days, self.retention_policy.severity_retention[event.severity]
            )

        # Check event type-specific retention
        if event.event_type in self.retention_policy.event_type_retention:
            retention_days = max(
                retention_days, self.retention_policy.event_type_retention[event.event_type]
            )

        retention_date = datetime.utcnow() + timedelta(days=retention_days)

        with self._get_connection() as conn:
            conn.execute(
                """
                INSERT INTO audit_events
                (event_id, timestamp, event_type, severity, user_id, key_id,
                 service, details, ip_address, user_agent, signature,
                 previous_hash, event_hash, retention_date)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
                (
                    event.event_id,
                    event.timestamp,
                    event.event_type.value,
                    event.severity.value,
                    event.user_id,
                    event.key_id,
                    event.service,
                    json.dumps(event.details),
                    event.ip_address,
                    event.user_agent,
                    event.signature,
                    event.previous_hash,
                    event.event_hash,
                    retention_date,
                ),
            )

    def verify_integrity(
        self, start_date: Optional[datetime] = None, end_date: Optional[datetime] = None
    ) -> Tuple[bool, List[str]]:
        """Verify integrity of audit logs"""
        issues = []

        with self._get_connection() as conn:
            # Build query
            query = "SELECT * FROM audit_events"
            params = []

            if start_date or end_date:
                query += " WHERE"
                if start_date:
                    query += " timestamp >= ?"
                    params.append(start_date.isoformat())
                if start_date and end_date:
                    query += " AND"
                if end_date:
                    query += " timestamp <= ?"
                    params.append(end_date.isoformat())

            query += " ORDER BY timestamp ASC"

            rows = conn.execute(query, params).fetchall()

            previous_hash = None
            signatures_valid = 0
            events_checked = 0

            for row in rows:
                events_checked += 1

                # Reconstruct event
                event = AuditEvent(
                    event_id=row["event_id"],
                    timestamp=row["timestamp"],
                    event_type=EventType(row["event_type"]),
                    severity=EventSeverity(row["severity"]),
                    user_id=row["user_id"],
                    key_id=row["key_id"],
                    service=row["service"],
                    details=json.loads(row["details"]),
                    ip_address=row["ip_address"],
                    user_agent=row["user_agent"],
                    signature=row["signature"],
                    previous_hash=row["previous_hash"],
                    event_hash=row["event_hash"],
                )

                # Verify hash chain
                if previous_hash and event.previous_hash != previous_hash:
                    issues.append(f"Chain broken at event {event.event_id}")

                # Verify event hash
                calculated_hash = self._calculate_event_hash(event)
                if calculated_hash != event.event_hash:
                    issues.append(f"Hash mismatch for event {event.event_id}")

                # Verify signature
                try:
                    sign_data = {
                        "event_hash": event.event_hash,
                        "timestamp": event.timestamp,
                        "event_type": event.event_type.value,
                    }
                    message = json.dumps(sign_data, sort_keys=True).encode()

                    self.public_key.verify(
                        bytes.fromhex(event.signature),
                        message,
                        padding.PSS(
                            mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH
                        ),
                        hashes.SHA256(),
                    )
                    signatures_valid += 1
                except InvalidSignature:
                    issues.append(f"Invalid signature for event {event.event_id}")

                previous_hash = event.event_hash

            # Log integrity check
            check_valid = len(issues) == 0
            conn.execute(
                """
                INSERT INTO integrity_checks
                (events_checked, signatures_valid, chain_valid, issues_found)
                VALUES (?, ?, ?, ?)
            """,
                (
                    events_checked,
                    signatures_valid,
                    check_valid,
                    json.dumps(issues) if issues else None,
                ),
            )

            # Update metrics
            audit_signatures_verified.labels(result="success" if check_valid else "failure").inc()

            if not check_valid:
                # Log tampering detection
                self.log_event(
                    EventType.TAMPERING_DETECTED,
                    EventSeverity.CRITICAL,
                    "system",
                    details={
                        "issues_found": len(issues),
                        "events_checked": events_checked,
                        "first_issue": issues[0] if issues else None,
                    },
                )

        return check_valid, issues

    def _trigger_alert(self, event: AuditEvent):
        """Trigger security alert for critical events"""
        # Update metrics
        security_alerts_total.labels(
            alert_type=event.event_type.value, severity=event.severity.value
        ).inc()

        # Log alert
        self.logger.warning(f"Security alert: {event.event_type.value} - {event.details}")

        # Here you would integrate with your alerting system
        # (e.g., send to SIEM, email, Slack, PagerDuty, etc.)

    def enforce_retention_policy(self):
        """Enforce retention policy by archiving/deleting old events"""
        with self._get_connection() as conn:
            # Find events past retention
            expired_events = conn.execute(
                """
                SELECT event_id, event_type, severity, retention_date
                FROM audit_events
                WHERE retention_date < CURRENT_TIMESTAMP
                AND archived = FALSE
            """
            ).fetchall()

            if expired_events:
                # Archive events if configured
                if self.retention_policy.archive_after_days:
                    archive_date = datetime.utcnow() - timedelta(
                        days=self.retention_policy.archive_after_days
                    )

                    # Archive to file
                    archive_file = (
                        self.audit_dir / f"archive_{datetime.utcnow().strftime('%Y%m%d')}.json"
                    )
                    archived_events = []

                    for event in expired_events:
                        if datetime.fromisoformat(event["retention_date"]) > archive_date:
                            # Archive instead of delete
                            full_event = conn.execute(
                                "SELECT * FROM audit_events WHERE event_id = ?",
                                (event["event_id"],),
                            ).fetchone()

                            archived_events.append(dict(full_event))

                            # Mark as archived
                            conn.execute(
                                "UPDATE audit_events SET archived = TRUE WHERE event_id = ?",
                                (event["event_id"],),
                            )

                    if archived_events:
                        # Write archive
                        with open(archive_file, "w") as f:
                            json.dump(archived_events, f, indent=2)

                        if self.retention_policy.compress_archives:
                            import gzip

                            with open(archive_file, "rb") as f_in:
                                with gzip.open(f"{archive_file}.gz", "wb") as f_out:
                                    f_out.writelines(f_in)
                            os.remove(archive_file)

                # Delete expired and archived events
                conn.execute(
                    """
                    DELETE FROM audit_events
                    WHERE retention_date < CURRENT_TIMESTAMP
                    AND archived = TRUE
                """
                )

    def _check_rotation_requirement(self, key_id: str, service: Optional[str]):
        """Check if key rotation is required"""
        # This would integrate with the rotation policy enforcement
        pass


class RotationPolicyEnforcer:
    """Enforces key rotation policies with audit integration"""

    def __init__(
        self, audit_logger: TamperProofAuditLogger, rotation_policy: Optional[RotationPolicy] = None
    ):
        self.audit_logger = audit_logger
        self.rotation_policy = rotation_policy or RotationPolicy()
        self.logger = logging.getLogger("RotationEnforcer")

        # Start enforcement thread
        self.enforcement_thread = threading.Thread(target=self._enforcement_loop, daemon=True)
        self.enforcement_thread.start()

    def register_key(self, key_id: str, service: str, created_at: Optional[datetime] = None):
        """Register a key for rotation tracking"""
        created_at = created_at or datetime.utcnow()
        rotation_due = created_at + timedelta(days=self.rotation_policy.max_key_age_days)

        with self.audit_logger._get_connection() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO rotation_enforcement
                (key_id, service, created_at, rotation_due)
                VALUES (?, ?, ?, ?)
            """,
                (key_id, service, created_at, rotation_due),
            )

        # Log registration
        self.audit_logger.log_event(
            EventType.KEY_CREATED,
            EventSeverity.INFO,
            "system",
            key_id=key_id,
            service=service,
            details={
                "rotation_due": rotation_due.isoformat(),
                "max_age_days": self.rotation_policy.max_key_age_days,
            },
        )

    def update_rotation(self, key_id: str, rotated_at: Optional[datetime] = None):
        """Update rotation timestamp for a key"""
        rotated_at = rotated_at or datetime.utcnow()
        new_rotation_due = rotated_at + timedelta(days=self.rotation_policy.max_key_age_days)

        with self.audit_logger._get_connection() as conn:
            conn.execute(
                """
                UPDATE rotation_enforcement
                SET last_rotated = ?, rotation_due = ?,
                    warning_sent = FALSE, rotation_enforced = FALSE, blocked = FALSE
                WHERE key_id = ?
            """,
                (rotated_at, new_rotation_due, key_id),
            )

        # Update metrics
        rotation_enforcement_actions.labels(action_type="rotation_completed").inc()

    def check_key_validity(self, key_id: str) -> Tuple[bool, Optional[str]]:
        """Check if a key is valid according to rotation policy"""
        with self.audit_logger._get_connection() as conn:
            row = conn.execute(
                """
                SELECT * FROM rotation_enforcement
                WHERE key_id = ?
            """,
                (key_id,),
            ).fetchone()

            if not row:
                return True, None  # Unknown key, allow by default

            # Check if key is blocked
            if row["blocked"] and self.rotation_policy.block_expired_keys:
                return False, "Key is blocked due to rotation policy violation"

            # Check if key is expired
            rotation_due = datetime.fromisoformat(row["rotation_due"])
            now = datetime.utcnow()

            if now > rotation_due:
                # Check grace period
                grace_end = rotation_due + timedelta(days=self.rotation_policy.grace_period_days)

                if now > grace_end:
                    # Block the key if configured
                    if self.rotation_policy.block_expired_keys:
                        conn.execute(
                            "UPDATE rotation_enforcement SET blocked = TRUE WHERE key_id = ?",
                            (key_id,),
                        )

                        # Log blocking
                        self.audit_logger.log_event(
                            EventType.POLICY_VIOLATION,
                            EventSeverity.ERROR,
                            "system",
                            key_id=key_id,
                            details={
                                "reason": "key_expired",
                                "rotation_due": rotation_due.isoformat(),
                                "days_overdue": (now - rotation_due).days,
                            },
                        )

                        # Update metrics
                        rotation_enforcement_actions.labels(action_type="key_blocked").inc()

                        return False, f"Key expired {(now - rotation_due).days} days ago"
                    else:
                        # Just warn
                        return (
                            True,
                            f"Warning: Key should be rotated "
                            f"(expired {(now - rotation_due).days} days ago)",
                        )
                else:
                    # In grace period
                    return (
                        True,
                        f"Warning: Key in grace period (expires in {(grace_end - now).days} days)",
                    )

            # Check if warning needed
            warning_date = rotation_due - timedelta(days=self.rotation_policy.warning_before_days)

            if now > warning_date:
                days_until = (rotation_due - now).days
                return True, f"Info: Key rotation due in {days_until} days"

            return True, None

    def _enforcement_loop(self):
        """Background loop for policy enforcement"""
        while True:
            try:
                self._check_and_enforce_policies()
                time.sleep(3600)  # Check hourly
            except Exception as e:
                self.logger.error(f"Error in enforcement loop: {e}")

    def _check_and_enforce_policies(self):
        """Check and enforce rotation policies"""
        with self.audit_logger._get_connection() as conn:
            # Find keys needing attention
            now = datetime.utcnow()

            # Keys needing warning
            warning_date = now + timedelta(days=self.rotation_policy.warning_before_days)

            warning_keys = conn.execute(
                """
                SELECT * FROM rotation_enforcement
                WHERE rotation_due <= ?
                AND rotation_due > ?
                AND warning_sent = FALSE
                AND blocked = FALSE
            """,
                (warning_date.isoformat(), now.isoformat()),
            ).fetchall()

            for key in warning_keys:
                # Skip exempt services
                if key["service"] in self.rotation_policy.exempt_services:
                    continue

                # Send warning
                self.audit_logger.log_event(
                    EventType.ROTATION_REQUIRED,
                    EventSeverity.WARNING,
                    "system",
                    key_id=key["key_id"],
                    service=key["service"],
                    details={
                        "rotation_due": key["rotation_due"],
                        "days_until": (datetime.fromisoformat(key["rotation_due"]) - now).days,
                    },
                )

                # Mark warning sent
                conn.execute(
                    "UPDATE rotation_enforcement SET warning_sent = TRUE WHERE key_id = ?",
                    (key["key_id"],),
                )

                # Update metrics
                rotation_enforcement_actions.labels(action_type="warning_sent").inc()

            # Keys past due
            expired_keys = conn.execute(
                """
                SELECT * FROM rotation_enforcement
                WHERE rotation_due < ?
                AND blocked = FALSE
            """,
                (now.isoformat(),),
            ).fetchall()

            for key in expired_keys:
                # Skip exempt services
                if key["service"] in self.rotation_policy.exempt_services:
                    continue

                rotation_due = datetime.fromisoformat(key["rotation_due"])
                days_overdue = (now - rotation_due).days

                # Check if past grace period
                if days_overdue > self.rotation_policy.grace_period_days:
                    if self.rotation_policy.enforce_rotation:
                        # Block the key
                        conn.execute(
                            "UPDATE rotation_enforcement SET blocked = TRUE WHERE key_id = ?",
                            (key["key_id"],),
                        )

                        self.audit_logger.log_event(
                            EventType.POLICY_VIOLATION,
                            EventSeverity.ERROR,
                            "system",
                            key_id=key["key_id"],
                            service=key["service"],
                            details={
                                "action": "key_blocked",
                                "days_overdue": days_overdue,
                                "rotation_due": key["rotation_due"],
                            },
                        )

                        # Update metrics
                        rotation_enforcement_actions.labels(action_type="key_blocked").inc()

                    elif self.rotation_policy.auto_rotate:
                        # Trigger automatic rotation
                        self.audit_logger.log_event(
                            EventType.ROTATION_REQUIRED,
                            EventSeverity.ERROR,
                            "system",
                            key_id=key["key_id"],
                            service=key["service"],
                            details={
                                "action": "auto_rotation_triggered",
                                "days_overdue": days_overdue,
                            },
                        )

                        # Update metrics
                        rotation_enforcement_actions.labels(action_type="auto_rotation").inc()

                        # Mark for rotation
                        conn.execute(
                            "UPDATE rotation_enforcement SET rotation_enforced = TRUE "
                            "WHERE key_id = ?",
                            (key["key_id"],),
                        )

    def get_rotation_status(self) -> Dict[str, Any]:
        """Get current rotation enforcement status"""
        with self.audit_logger._get_connection() as conn:
            # Get statistics
            total_keys = conn.execute(
                "SELECT COUNT(*) as count FROM rotation_enforcement"
            ).fetchone()["count"]

            blocked_keys = conn.execute(
                "SELECT COUNT(*) as count FROM rotation_enforcement WHERE blocked = TRUE"
            ).fetchone()["count"]

            overdue_keys = conn.execute(
                "SELECT COUNT(*) as count FROM rotation_enforcement "
                "WHERE rotation_due < CURRENT_TIMESTAMP"
            ).fetchone()["count"]

            # Get details of problematic keys
            problem_keys = conn.execute(
                """
                SELECT key_id, service, rotation_due, blocked
                FROM rotation_enforcement
                WHERE rotation_due < CURRENT_TIMESTAMP OR blocked = TRUE
                ORDER BY rotation_due ASC
            """
            ).fetchall()

            return {
                "total_keys": total_keys,
                "blocked_keys": blocked_keys,
                "overdue_keys": overdue_keys,
                "problem_keys": [dict(k) for k in problem_keys],
                "policy": {
                    "max_age_days": self.rotation_policy.max_key_age_days,
                    "warning_days": self.rotation_policy.warning_before_days,
                    "grace_period_days": self.rotation_policy.grace_period_days,
                    "enforce_rotation": self.rotation_policy.enforce_rotation,
                    "auto_rotate": self.rotation_policy.auto_rotate,
                },
            }


class SecurityEventMonitor:
    """Monitor security events and generate alerts"""

    def __init__(self, audit_logger: TamperProofAuditLogger):
        self.audit_logger = audit_logger
        self.alert_thresholds = {
            EventType.AUTH_FAILURE: (5, timedelta(minutes=5)),  # 5 failures in 5 minutes
            EventType.POLICY_VIOLATION: (3, timedelta(hours=1)),  # 3 violations in 1 hour
            EventType.KEY_ACCESSED: (100, timedelta(minutes=1)),  # 100 accesses in 1 minute
        }

        # Track event occurrences
        self.event_tracker: Dict[str, List[datetime]] = {}

    def check_event(self, event_type: EventType, user_id: str, key_id: Optional[str] = None):
        """Check if event triggers security alert"""
        # Create tracking key
        track_key = f"{event_type.value}:{user_id}:{key_id or 'none'}"

        # Initialize tracker if needed
        if track_key not in self.event_tracker:
            self.event_tracker[track_key] = []

        # Add current event
        now = datetime.utcnow()
        self.event_tracker[track_key].append(now)

        # Check threshold
        if event_type in self.alert_thresholds:
            threshold_count, threshold_window = self.alert_thresholds[event_type]

            # Remove old events
            cutoff = now - threshold_window
            self.event_tracker[track_key] = [
                evt for evt in self.event_tracker[track_key] if evt > cutoff
            ]

            # Check if threshold exceeded
            if len(self.event_tracker[track_key]) >= threshold_count:
                # Generate alert
                self.audit_logger.log_event(
                    EventType.POLICY_VIOLATION,
                    EventSeverity.CRITICAL,
                    "system",
                    details={
                        "alert_type": "threshold_exceeded",
                        "event_type": event_type.value,
                        "user_id": user_id,
                        "key_id": key_id,
                        "count": len(self.event_tracker[track_key]),
                        "window": str(threshold_window),
                        "threshold": threshold_count,
                    },
                )

                # Clear tracker to avoid repeated alerts
                self.event_tracker[track_key] = []

                return True

        return False

    def get_security_summary(self, hours: int = 24) -> Dict[str, Any]:
        """Get security event summary"""
        cutoff = datetime.utcnow() - timedelta(hours=hours)

        with self.audit_logger._get_connection() as conn:
            # Get event counts by type
            event_counts = conn.execute(
                """
                SELECT event_type, severity, COUNT(*) as count
                FROM audit_events
                WHERE timestamp > ?
                GROUP BY event_type, severity
            """,
                (cutoff.isoformat(),),
            ).fetchall()

            # Get top users by activity
            top_users = conn.execute(
                """
                SELECT user_id, COUNT(*) as event_count
                FROM audit_events
                WHERE timestamp > ?
                GROUP BY user_id
                ORDER BY event_count DESC
                LIMIT 10
            """,
                (cutoff.isoformat(),),
            ).fetchall()

            # Get recent critical events
            critical_events = conn.execute(
                """
                SELECT event_id, timestamp, event_type, user_id, details
                FROM audit_events
                WHERE timestamp > ?
                AND severity IN ('error', 'critical')
                ORDER BY timestamp DESC
                LIMIT 20
            """,
                (cutoff.isoformat(),),
            ).fetchall()

            return {
                "period_hours": hours,
                "event_counts": [dict(e) for e in event_counts],
                "top_users": [dict(u) for u in top_users],
                "critical_events": [dict(e) for e in critical_events],
                "active_alerts": len(
                    [k for k, v in self.event_tracker.items() if v and v[-1] > cutoff]
                ),
            }


# Example usage and integration
if __name__ == "__main__":
    # Initialize components
    audit_logger = TamperProofAuditLogger(
        audit_dir="./audit",
        retention_policy=RetentionPolicy(default_retention_days=365, archive_after_days=90),
    )

    rotation_enforcer = RotationPolicyEnforcer(
        audit_logger=audit_logger,
        rotation_policy=RotationPolicy(
            max_key_age_days=90, warning_before_days=14, enforce_rotation=True
        ),
    )

    security_monitor = SecurityEventMonitor(audit_logger)

    # Example: Log a key access event
    audit_logger.log_event(
        EventType.KEY_ACCESSED,
        EventSeverity.INFO,
        user_id="user123",
        key_id="key_abc123",
        service="github",
        details={"purpose": "ci_deployment"},
        ip_address="192.168.1.100",
    )

    # Example: Verify audit log integrity
    is_valid, issues = audit_logger.verify_integrity()
    print(f"Audit log integrity: {'Valid' if is_valid else 'Compromised'}")

    # Example: Check rotation status
    rotation_status = rotation_enforcer.get_rotation_status()
    print(f"Rotation status: {rotation_status}")
