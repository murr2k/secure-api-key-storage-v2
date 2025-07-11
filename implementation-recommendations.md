# API Key Storage Implementation Recommendations

## 1. Technology Selection

### 1.1 Recommended Technology Stack

#### For Python Implementation
```python
# requirements.txt
cryptography>=41.0.0      # Modern cryptographic library
pynacl>=1.5.0            # Additional crypto primitives
sqlcipher3>=0.5.0        # Encrypted SQLite
keyring>=24.0.0          # OS keychain integration
pyotp>=2.9.0             # TOTP/HOTP for MFA
argon2-cffi>=23.0.0      # Alternative to PBKDF2
structlog>=23.0.0        # Structured logging
```

#### For Rust Implementation (Higher Security)
```toml
# Cargo.toml
[dependencies]
ring = "0.17"            # Cryptographic operations
sodiumoxide = "0.2"     # libsodium bindings
rusqlite = "0.30"       # SQLite with encryption
keyring = "2.0"         # OS keychain access
secrecy = "0.8"         # Secret management
zeroize = "1.7"         # Memory zeroing
```

### 1.2 Platform-Specific Recommendations

| Platform | Primary Storage | Backup Storage | Notes |
|----------|----------------|----------------|--------|
| Linux | libsecret/gnome-keyring | Encrypted file | Use XDG directories |
| macOS | Keychain Services | Encrypted file | Leverage Security.framework |
| Windows | Windows Credential Store | DPAPI encrypted | Use Win32 Crypto API |
| Server | Cloud KMS | HSM | No local storage |

## 2. Core Implementation

### 2.1 Secure Key Manager Class (Python)

```python
import os
import json
import base64
from typing import Optional, Dict, Any
from datetime import datetime, timedelta
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend
import structlog

logger = structlog.get_logger()

class SecureKeyManager:
    """Secure API key storage and management"""
    
    def __init__(self, storage_path: str = None):
        self.storage_path = storage_path or self._get_default_storage_path()
        self.iterations = 100_000
        self.salt_size = 32
        self.nonce_size = 12
        self.key_size = 32
        self._master_key: Optional[bytes] = None
        self._session_timeout = timedelta(minutes=15)
        self._last_activity = None
        
    def _get_default_storage_path(self) -> str:
        """Get platform-specific storage path"""
        if os.name == 'posix':
            # Linux/macOS
            config_home = os.environ.get('XDG_CONFIG_HOME', 
                                       os.path.expanduser('~/.config'))
            return os.path.join(config_home, 'secure-keys')
        else:
            # Windows
            app_data = os.environ.get('APPDATA')
            return os.path.join(app_data, 'SecureKeys')
    
    def derive_key(self, password: str, salt: bytes) -> bytes:
        """Derive encryption key from password using PBKDF2"""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=self.key_size,
            salt=salt,
            iterations=self.iterations,
            backend=default_backend()
        )
        return kdf.derive(password.encode())
    
    def encrypt_key(self, api_key: str, key_name: str) -> Dict[str, Any]:
        """Encrypt an API key with authenticated encryption"""
        if not self._master_key:
            raise ValueError("Not authenticated")
            
        # Generate random nonce
        nonce = os.urandom(self.nonce_size)
        
        # Create cipher
        cipher = AESGCM(self._master_key)
        
        # Additional authenticated data
        aad = json.dumps({
            "key_name": key_name,
            "timestamp": datetime.utcnow().isoformat(),
            "version": "1.0"
        }).encode()
        
        # Encrypt
        ciphertext = cipher.encrypt(nonce, api_key.encode(), aad)
        
        return {
            "ciphertext": base64.b64encode(ciphertext).decode(),
            "nonce": base64.b64encode(nonce).decode(),
            "aad": json.loads(aad.decode()),
            "algorithm": "AES-256-GCM"
        }
    
    def decrypt_key(self, encrypted_data: Dict[str, Any]) -> str:
        """Decrypt an API key"""
        if not self._master_key:
            raise ValueError("Not authenticated")
            
        # Check session timeout
        if self._last_activity and \
           datetime.utcnow() - self._last_activity > self._session_timeout:
            self._master_key = None
            raise ValueError("Session expired")
            
        # Decode components
        ciphertext = base64.b64decode(encrypted_data["ciphertext"])
        nonce = base64.b64decode(encrypted_data["nonce"])
        aad = json.dumps(encrypted_data["aad"]).encode()
        
        # Decrypt
        cipher = AESGCM(self._master_key)
        plaintext = cipher.decrypt(nonce, ciphertext, aad)
        
        # Update activity timestamp
        self._last_activity = datetime.utcnow()
        
        # Log access
        logger.info("key_accessed", 
                   key_name=encrypted_data["aad"]["key_name"],
                   timestamp=datetime.utcnow().isoformat())
        
        return plaintext.decode()
    
    def secure_delete(self, data: Any) -> None:
        """Securely overwrite sensitive data in memory"""
        if isinstance(data, str):
            data = data.encode()
        if isinstance(data, (bytes, bytearray)):
            for i in range(len(data)):
                data[i] = 0
```

### 2.2 Storage Backend Implementation

```python
import sqlite3
import json
from contextlib import contextmanager
from typing import Dict, List, Optional

class EncryptedStorage:
    """Encrypted storage backend using SQLCipher"""
    
    def __init__(self, db_path: str, password: str):
        self.db_path = db_path
        self.password = password
        self._init_db()
        
    def _init_db(self):
        """Initialize encrypted database"""
        with self._get_connection() as conn:
            # Enable SQLCipher encryption
            conn.execute(f"PRAGMA key = '{self.password}'")
            conn.execute("PRAGMA cipher_page_size = 4096")
            conn.execute("PRAGMA kdf_iter = 100000")
            
            # Create tables
            conn.execute("""
                CREATE TABLE IF NOT EXISTS api_keys (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL UNIQUE,
                    encrypted_data TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_accessed TIMESTAMP,
                    rotation_due TIMESTAMP,
                    metadata TEXT
                )
            """)
            
            conn.execute("""
                CREATE TABLE IF NOT EXISTS audit_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    event_type TEXT NOT NULL,
                    key_id TEXT,
                    user_id TEXT,
                    details TEXT,
                    FOREIGN KEY (key_id) REFERENCES api_keys(id)
                )
            """)
            
            conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_audit_timestamp 
                ON audit_log(timestamp)
            """)
            
    @contextmanager
    def _get_connection(self):
        """Get database connection with encryption"""
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
            
    def store_key(self, key_id: str, name: str, 
                  encrypted_data: Dict[str, Any],
                  metadata: Optional[Dict] = None) -> None:
        """Store encrypted API key"""
        with self._get_connection() as conn:
            conn.execute("""
                INSERT OR REPLACE INTO api_keys 
                (id, name, encrypted_data, metadata, rotation_due)
                VALUES (?, ?, ?, ?, datetime('now', '+90 days'))
            """, (
                key_id,
                name,
                json.dumps(encrypted_data),
                json.dumps(metadata or {})
            ))
            
            # Audit log
            self._log_event(conn, "key_stored", key_id)
            
    def get_key(self, name: str) -> Optional[Dict[str, Any]]:
        """Retrieve encrypted API key"""
        with self._get_connection() as conn:
            row = conn.execute("""
                SELECT id, encrypted_data, metadata 
                FROM api_keys 
                WHERE name = ?
            """, (name,)).fetchone()
            
            if row:
                # Update last accessed
                conn.execute("""
                    UPDATE api_keys 
                    SET last_accessed = CURRENT_TIMESTAMP 
                    WHERE name = ?
                """, (name,))
                
                # Audit log
                self._log_event(conn, "key_retrieved", row['id'])
                
                return {
                    "id": row['id'],
                    "encrypted_data": json.loads(row['encrypted_data']),
                    "metadata": json.loads(row['metadata'])
                }
            return None
            
    def _log_event(self, conn, event_type: str, key_id: str = None,
                   details: Dict = None) -> None:
        """Log audit event"""
        conn.execute("""
            INSERT INTO audit_log (event_type, key_id, details)
            VALUES (?, ?, ?)
        """, (
            event_type,
            key_id,
            json.dumps(details or {})
        ))
```

### 2.3 Cloud KMS Integration

```python
from abc import ABC, abstractmethod
from typing import Dict, Any
import boto3
from azure.keyvault.secrets import SecretClient
from azure.identity import DefaultAzureCredential
from google.cloud import kms

class CloudKMSProvider(ABC):
    """Abstract base class for cloud KMS providers"""
    
    @abstractmethod
    def encrypt(self, plaintext: bytes) -> bytes:
        pass
        
    @abstractmethod
    def decrypt(self, ciphertext: bytes) -> bytes:
        pass
        
    @abstractmethod
    def create_key(self, key_id: str) -> str:
        pass

class AWSKMSProvider(CloudKMSProvider):
    """AWS KMS implementation"""
    
    def __init__(self, key_id: str, region: str = 'us-east-1'):
        self.key_id = key_id
        self.client = boto3.client('kms', region_name=region)
        
    def encrypt(self, plaintext: bytes) -> bytes:
        response = self.client.encrypt(
            KeyId=self.key_id,
            Plaintext=plaintext,
            EncryptionContext={'purpose': 'api-key-storage'}
        )
        return response['CiphertextBlob']
        
    def decrypt(self, ciphertext: bytes) -> bytes:
        response = self.client.decrypt(
            CiphertextBlob=ciphertext,
            EncryptionContext={'purpose': 'api-key-storage'}
        )
        return response['Plaintext']
        
    def create_key(self, key_id: str) -> str:
        response = self.client.create_key(
            Description=f'API Key Storage - {key_id}',
            KeyUsage='ENCRYPT_DECRYPT',
            Origin='AWS_KMS'
        )
        return response['KeyMetadata']['KeyId']

class AzureKeyVaultProvider(CloudKMSProvider):
    """Azure Key Vault implementation"""
    
    def __init__(self, vault_url: str):
        self.vault_url = vault_url
        credential = DefaultAzureCredential()
        self.client = SecretClient(vault_url=vault_url, credential=credential)
        
    def encrypt(self, plaintext: bytes) -> bytes:
        # Azure Key Vault stores secrets, not direct encryption
        # Use client-side encryption with KEK from Key Vault
        pass
        
    def decrypt(self, ciphertext: bytes) -> bytes:
        pass
        
    def create_key(self, key_id: str) -> str:
        # Create a new secret in Key Vault
        secret = self.client.set_secret(key_id, "")
        return secret.name
```

## 3. Security Hardening

### 3.1 Memory Protection Implementation

```python
import ctypes
import sys
import gc
from typing import Any

class SecureString:
    """Secure string that zeros memory on deletion"""
    
    def __init__(self, value: str):
        self._value = value
        self._address = id(self._value)
        
    def __str__(self):
        return self._value
        
    def __del__(self):
        """Secure cleanup on deletion"""
        self.clear()
        
    def clear(self):
        """Overwrite string in memory"""
        if hasattr(self, '_value') and self._value:
            # Get the actual string object size
            size = sys.getsizeof(self._value)
            
            # Overwrite memory
            ctypes.memset(self._address, 0, size)
            
            # Force garbage collection
            self._value = None
            gc.collect()

class MemoryProtectedDict(dict):
    """Dictionary that securely clears values on deletion"""
    
    def __setitem__(self, key, value):
        if isinstance(value, str):
            value = SecureString(value)
        super().__setitem__(key, value)
        
    def __delitem__(self, key):
        if key in self:
            value = self[key]
            if isinstance(value, SecureString):
                value.clear()
        super().__delitem__(key)
        
    def clear(self):
        """Securely clear all values"""
        for key in list(self.keys()):
            del self[key]
        super().clear()
```

### 3.2 Anti-Debugging Protection

```python
import os
import platform
import psutil
import signal

class AntiDebugger:
    """Basic anti-debugging protections"""
    
    @staticmethod
    def check_debugger():
        """Check for common debuggers"""
        # Check for debugger on Linux
        if platform.system() == 'Linux':
            try:
                with open('/proc/self/status', 'r') as f:
                    for line in f:
                        if line.startswith('TracerPid:'):
                            tracer_pid = int(line.split()[1])
                            if tracer_pid != 0:
                                return True
            except:
                pass
                
        # Check for common debugger processes
        debuggers = ['gdb', 'lldb', 'x64dbg', 'ollydbg', 'ida', 'radare2']
        for proc in psutil.process_iter(['name']):
            if proc.info['name'].lower() in debuggers:
                return True
                
        # Check for debug environment variables
        debug_vars = ['PYTHONBREAKPOINT', '_PYTHON_DEBUGGER']
        for var in debug_vars:
            if os.environ.get(var):
                return True
                
        return False
        
    @staticmethod
    def protect():
        """Enable anti-debugging protections"""
        if AntiDebugger.check_debugger():
            # Clear sensitive data and exit
            os._exit(1)
            
        # Disable SIGINT in production
        if os.environ.get('PRODUCTION'):
            signal.signal(signal.SIGINT, signal.SIG_IGN)
```

### 3.3 Rate Limiting and Throttling

```python
import time
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Dict, Tuple

class RateLimiter:
    """Rate limiting for key access"""
    
    def __init__(self, max_requests: int = 10, 
                 window_seconds: int = 60):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.requests: Dict[str, List[float]] = defaultdict(list)
        
    def check_rate_limit(self, user_id: str) -> Tuple[bool, int]:
        """Check if user is within rate limit"""
        now = time.time()
        window_start = now - self.window_seconds
        
        # Clean old requests
        self.requests[user_id] = [
            req_time for req_time in self.requests[user_id]
            if req_time > window_start
        ]
        
        # Check limit
        if len(self.requests[user_id]) >= self.max_requests:
            # Calculate time until next available request
            oldest_request = min(self.requests[user_id])
            wait_time = int(oldest_request + self.window_seconds - now)
            return False, wait_time
            
        # Add current request
        self.requests[user_id].append(now)
        return True, 0
```

## 4. CLI Implementation

```python
#!/usr/bin/env python3
import click
import getpass
import sys
from typing import Optional

@click.group()
@click.pass_context
def cli(ctx):
    """Secure API Key Manager CLI"""
    ctx.ensure_object(dict)
    ctx.obj['manager'] = SecureKeyManager()

@cli.command()
@click.option('--name', prompt='Key name', help='Name for the API key')
@click.option('--value', help='API key value (will prompt if not provided)')
@click.pass_context
def add(ctx, name: str, value: Optional[str]):
    """Add a new API key"""
    manager = ctx.obj['manager']
    
    # Get master password
    password = getpass.getpass('Master password: ')
    
    try:
        manager.authenticate(password)
        
        # Get API key value if not provided
        if not value:
            value = getpass.getpass('API key value: ')
            
        # Store the key
        manager.store_key(name, value)
        click.echo(f"API key '{name}' stored successfully")
        
    except Exception as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)
    finally:
        # Clear sensitive data
        if 'value' in locals():
            value = None
        password = None

@cli.command()
@click.option('--name', prompt='Key name', help='Name of the API key')
@click.option('--show', is_flag=True, help='Display the key value')
@click.pass_context
def get(ctx, name: str, show: bool):
    """Retrieve an API key"""
    manager = ctx.obj['manager']
    
    # Get master password
    password = getpass.getpass('Master password: ')
    
    try:
        manager.authenticate(password)
        
        # Retrieve the key
        api_key = manager.get_key(name)
        
        if show:
            click.echo(f"API Key: {api_key}")
        else:
            # Copy to clipboard instead of displaying
            import pyperclip
            pyperclip.copy(api_key)
            click.echo("API key copied to clipboard")
            
    except Exception as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)
    finally:
        password = None

if __name__ == '__main__':
    cli()
```

## 5. Testing Recommendations

### 5.1 Security Test Suite

```python
import pytest
import tempfile
import os
from unittest.mock import patch, MagicMock

class TestSecureKeyManager:
    """Security-focused test suite"""
    
    @pytest.fixture
    def temp_storage(self):
        """Create temporary storage directory"""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield tmpdir
            
    def test_encryption_decryption(self, temp_storage):
        """Test that encryption/decryption works correctly"""
        manager = SecureKeyManager(temp_storage)
        password = "test_password"
        api_key = "sk-1234567890abcdef"
        
        # Derive key
        salt = os.urandom(32)
        master_key = manager.derive_key(password, salt)
        manager._master_key = master_key
        
        # Encrypt
        encrypted = manager.encrypt_key(api_key, "test_key")
        
        # Decrypt
        decrypted = manager.decrypt_key(encrypted)
        
        assert decrypted == api_key
        assert encrypted['ciphertext'] != api_key
        
    def test_wrong_password_fails(self, temp_storage):
        """Test that wrong password cannot decrypt"""
        manager = SecureKeyManager(temp_storage)
        
        # Encrypt with one password
        salt = os.urandom(32)
        key1 = manager.derive_key("password1", salt)
        manager._master_key = key1
        encrypted = manager.encrypt_key("secret", "test")
        
        # Try to decrypt with different password
        key2 = manager.derive_key("password2", salt)
        manager._master_key = key2
        
        with pytest.raises(Exception):
            manager.decrypt_key(encrypted)
            
    def test_memory_protection(self):
        """Test secure memory cleanup"""
        secret = SecureString("sensitive_data")
        secret_str = str(secret)
        
        # Get memory address
        addr = id(secret_str)
        
        # Clear the secret
        secret.clear()
        
        # Memory should be zeroed
        # Note: This is hard to test reliably across platforms
        
    def test_rate_limiting(self):
        """Test rate limiting protection"""
        limiter = RateLimiter(max_requests=3, window_seconds=60)
        
        # First 3 requests should succeed
        for i in range(3):
            allowed, wait = limiter.check_rate_limit("user1")
            assert allowed
            
        # 4th request should be blocked
        allowed, wait = limiter.check_rate_limit("user1")
        assert not allowed
        assert wait > 0
        
    @patch('psutil.process_iter')
    def test_anti_debugging(self, mock_process_iter):
        """Test anti-debugging checks"""
        # Mock debugger process
        mock_proc = MagicMock()
        mock_proc.info = {'name': 'gdb'}
        mock_process_iter.return_value = [mock_proc]
        
        # Should detect debugger
        assert AntiDebugger.check_debugger() == True
```

### 5.2 Integration Testing

```python
def test_full_integration():
    """Test complete key storage workflow"""
    with tempfile.TemporaryDirectory() as tmpdir:
        # Initialize manager
        manager = SecureKeyManager(tmpdir)
        storage = EncryptedStorage(
            os.path.join(tmpdir, "keys.db"),
            "storage_password"
        )
        
        # Authenticate
        password = "master_password"
        salt = os.urandom(32)
        manager._master_key = manager.derive_key(password, salt)
        
        # Store multiple keys
        test_keys = {
            "github_token": "ghp_1234567890",
            "claude_api": "sk-ant-1234567890",
            "aws_secret": "aws_secret_key_123"
        }
        
        for name, value in test_keys.items():
            encrypted = manager.encrypt_key(value, name)
            storage.store_key(
                key_id=f"key_{name}",
                name=name,
                encrypted_data=encrypted
            )
            
        # Retrieve and verify
        for name, expected_value in test_keys.items():
            stored = storage.get_key(name)
            decrypted = manager.decrypt_key(stored['encrypted_data'])
            assert decrypted == expected_value
```

## 6. Deployment Recommendations

### 6.1 Docker Deployment

```dockerfile
# Dockerfile for secure key manager
FROM python:3.11-slim

# Security: Run as non-root user
RUN useradd -m -s /bin/bash keymanager

# Install dependencies
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY --chown=keymanager:keymanager . .

# Security hardening
RUN chmod 700 /app
RUN chmod 600 /app/config/*

# Switch to non-root user
USER keymanager

# Use secrets for sensitive data
RUN --mount=type=secret,id=master_key \
    export MASTER_KEY=$(cat /run/secrets/master_key)

ENTRYPOINT ["python", "-m", "secure_keys"]
```

### 6.2 Kubernetes Deployment

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: secure-key-manager
spec:
  replicas: 3
  selector:
    matchLabels:
      app: secure-key-manager
  template:
    metadata:
      labels:
        app: secure-key-manager
    spec:
      serviceAccountName: key-manager
      securityContext:
        runAsNonRoot: true
        runAsUser: 1000
        fsGroup: 1000
      containers:
      - name: key-manager
        image: secure-key-manager:latest
        securityContext:
          allowPrivilegeEscalation: false
          readOnlyRootFilesystem: true
          capabilities:
            drop:
            - ALL
        env:
        - name: KMS_ENDPOINT
          valueFrom:
            secretKeyRef:
              name: kms-config
              key: endpoint
        volumeMounts:
        - name: tmp
          mountPath: /tmp
        - name: cache
          mountPath: /app/cache
        resources:
          limits:
            memory: "256Mi"
            cpu: "500m"
          requests:
            memory: "128Mi"
            cpu: "250m"
      volumes:
      - name: tmp
        emptyDir: {}
      - name: cache
        emptyDir: {}
```

## 7. Monitoring and Alerting

### 7.1 Metrics to Monitor

```python
from prometheus_client import Counter, Histogram, Gauge

# Define metrics
key_access_total = Counter('key_access_total', 
                          'Total number of key access attempts',
                          ['key_name', 'result'])
key_access_duration = Histogram('key_access_duration_seconds',
                               'Key access duration')
active_sessions = Gauge('active_sessions_total',
                       'Number of active sessions')
failed_auth_attempts = Counter('failed_auth_attempts_total',
                              'Failed authentication attempts')

# Usage in code
@key_access_duration.time()
def get_api_key(name: str):
    try:
        # ... key retrieval logic ...
        key_access_total.labels(key_name=name, result='success').inc()
        return key
    except Exception as e:
        key_access_total.labels(key_name=name, result='failure').inc()
        raise
```

### 7.2 Alert Rules

```yaml
# Prometheus alert rules
groups:
- name: key_manager_alerts
  rules:
  - alert: HighFailureRate
    expr: rate(key_access_total{result="failure"}[5m]) > 0.1
    for: 5m
    labels:
      severity: warning
    annotations:
      summary: High key access failure rate
      
  - alert: SuspiciousActivity
    expr: rate(failed_auth_attempts_total[5m]) > 10
    for: 1m
    labels:
      severity: critical
    annotations:
      summary: Multiple failed authentication attempts
      
  - alert: KeyRotationDue
    expr: days_until_rotation < 7
    for: 1h
    labels:
      severity: warning
    annotations:
      summary: API key rotation due soon
```

## 8. Disaster Recovery

### 8.1 Backup Strategy

```python
class BackupManager:
    """Secure backup management"""
    
    def create_backup(self, storage: EncryptedStorage, 
                     backup_password: str) -> bytes:
        """Create encrypted backup"""
        # Export all keys
        all_keys = storage.export_all()
        
        # Create backup encryption key
        backup_salt = os.urandom(32)
        backup_key = self.derive_key(backup_password, backup_salt)
        
        # Encrypt backup
        cipher = AESGCM(backup_key)
        nonce = os.urandom(12)
        
        backup_data = {
            "version": "1.0",
            "created_at": datetime.utcnow().isoformat(),
            "keys": all_keys
        }
        
        ciphertext = cipher.encrypt(
            nonce,
            json.dumps(backup_data).encode(),
            None
        )
        
        return backup_salt + nonce + ciphertext
        
    def restore_backup(self, backup_data: bytes, 
                      backup_password: str) -> Dict:
        """Restore from encrypted backup"""
        # Extract components
        backup_salt = backup_data[:32]
        nonce = backup_data[32:44]
        ciphertext = backup_data[44:]
        
        # Derive backup key
        backup_key = self.derive_key(backup_password, backup_salt)
        
        # Decrypt
        cipher = AESGCM(backup_key)
        plaintext = cipher.decrypt(nonce, ciphertext, None)
        
        return json.loads(plaintext.decode())
```

## 9. Best Practices Summary

1. **Always use authenticated encryption** (AES-GCM or ChaCha20-Poly1305)
2. **Implement proper key derivation** with sufficient iterations
3. **Never store keys in plaintext**, even temporarily
4. **Use platform-specific secure storage** when available
5. **Implement comprehensive audit logging**
6. **Regular key rotation** (90 days maximum)
7. **Memory protection** for sensitive data
8. **Rate limiting** to prevent brute force
9. **Secure backup and recovery** procedures
10. **Regular security audits** and penetration testing