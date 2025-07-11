# Secure API Key Storage Architecture

## 1. Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                    Application Layer                         │
├─────────────────────────────────────────────────────────────┤
│                    Key Manager API                           │
│  ┌─────────────┐  ┌──────────────┐  ┌──────────────────┐  │
│  │   Auth &    │  │    Access    │  │     Audit        │  │
│  │   Authz     │  │   Control    │  │    Logging       │  │
│  └─────────────┘  └──────────────┘  └──────────────────┘  │
├─────────────────────────────────────────────────────────────┤
│                 Encryption Service Layer                     │
│  ┌─────────────┐  ┌──────────────┐  ┌──────────────────┐  │
│  │  Key Deriv. │  │   AES-256    │  │     HMAC         │  │
│  │   (PBKDF2)  │  │     GCM      │  │   SHA-256        │  │
│  └─────────────┘  └──────────────┘  └──────────────────┘  │
├─────────────────────────────────────────────────────────────┤
│                    Storage Layer                             │
│  ┌─────────────┐  ┌──────────────┐  ┌──────────────────┐  │
│  │   Local     │  │    Cloud     │  │      HSM         │  │
│  │  Encrypted  │  │   Key Vault  │  │   (Optional)     │  │
│  └─────────────┘  └──────────────┘  └──────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

## 2. Encryption Strategy

### 2.1 Multi-Layer Encryption Architecture

```
Master Password (User Input)
        │
        ▼
┌─────────────────┐
│    PBKDF2       │ ← Salt (Random 32 bytes)
│ 100k iterations │
└────────┬────────┘
         │
         ▼
Master Encryption Key (MEK)
         │
         ├──────────────┬──────────────┐
         ▼              ▼              ▼
    Key Encryption  Data Encryption  HMAC Key
      Key (KEK)      Key (DEK)     (Integrity)
         │              │              │
         ▼              ▼              ▼
    Encrypted      Encrypted API    MAC for
    DEK Storage       Keys         Integrity
```

### 2.2 Encryption Implementation

```python
# Pseudocode for encryption flow

class SecureKeyStorage:
    def __init__(self):
        self.algorithm = AES-256-GCM
        self.kdf = PBKDF2-HMAC-SHA256
        self.iterations = 100000
        self.salt_size = 32
        self.iv_size = 16
        self.tag_size = 16
        
    def derive_master_key(self, password, salt):
        return PBKDF2(
            password=password,
            salt=salt,
            iterations=self.iterations,
            key_length=32,
            hash_function=SHA256
        )
    
    def encrypt_api_key(self, api_key, master_key):
        iv = generate_random_bytes(self.iv_size)
        cipher = AES_GCM(master_key, iv)
        
        # Additional authenticated data
        aad = {
            "version": "1.0",
            "timestamp": current_timestamp(),
            "key_id": generate_key_id()
        }
        
        ciphertext, tag = cipher.encrypt_and_authenticate(
            plaintext=api_key,
            associated_data=json.dumps(aad)
        )
        
        return {
            "ciphertext": base64_encode(ciphertext),
            "iv": base64_encode(iv),
            "tag": base64_encode(tag),
            "aad": aad
        }
```

## 3. Key Derivation Function (KDF) Design

### 3.1 PBKDF2 Configuration
- **Algorithm**: PBKDF2-HMAC-SHA256
- **Iterations**: Minimum 100,000 (adjustable based on hardware)
- **Salt**: 32 bytes from cryptographically secure random source
- **Output**: 256-bit master encryption key

### 3.2 Key Hierarchy
```
Master Password
     │
     ├─→ Authentication Key (for user verification)
     ├─→ Encryption Key (for API key encryption)
     └─→ Integrity Key (for HMAC verification)
```

## 4. Access Control Mechanisms

### 4.1 Authentication Flow
```
┌─────────┐     ┌──────────┐     ┌─────────────┐     ┌──────────┐
│  User   │────▶│  Auth    │────▶│   MFA       │────▶│  Token   │
│         │     │  Service │     │  Provider   │     │  Service │
└─────────┘     └──────────┘     └─────────────┘     └──────────┘
                                                            │
                                                            ▼
                                                      Access Token
                                                      (JWT, 15 min)
```

### 4.2 Role-Based Access Control (RBAC)
```yaml
roles:
  admin:
    permissions:
      - create_key
      - read_key
      - update_key
      - delete_key
      - manage_users
      - view_audit_logs
      
  developer:
    permissions:
      - read_key
      - update_own_keys
      - view_own_audit_logs
      
  ci_service:
    permissions:
      - read_key
      - limited_time_access
```

## 5. Secure Storage Locations

### 5.1 Storage Options Comparison

| Storage Type | Security Level | Performance | Cost | Use Case |
|--------------|---------------|-------------|------|----------|
| Local File   | Medium        | High        | Low  | Development |
| OS Keychain  | High          | High        | Low  | Desktop Apps |
| Cloud KMS    | Very High     | Medium      | Med  | Production |
| HSM          | Highest       | Low         | High | Critical Keys |

### 5.2 Storage Implementation

#### Local Encrypted Storage
```
~/.config/secure-keys/
├── config.json          # Non-sensitive configuration
├── keys.db             # SQLite with encrypted blobs
├── keys.db.lock        # Lock file for concurrent access
└── audit.log           # Encrypted audit log
```

#### Cloud Key Management Service (KMS)
```
AWS KMS / Azure Key Vault / Google Cloud KMS
├── Customer Master Key (CMK)
├── Data Encryption Keys (DEK)
└── API Key Ciphertext
```

## 6. Implementation Architecture

### 6.1 Component Diagram
```
┌──────────────────┐     ┌──────────────────┐
│   CLI Interface  │     │   API Interface  │
└────────┬─────────┘     └────────┬─────────┘
         │                        │
         └────────────┬───────────┘
                      │
              ┌───────▼──────────┐
              │   Core Library   │
              │  ┌────────────┐  │
              │  │ Key Manager │  │
              │  └────────────┘  │
              │  ┌────────────┐  │
              │  │  Crypto     │  │
              │  └────────────┘  │
              │  ┌────────────┐  │
              │  │  Storage    │  │
              │  └────────────┘  │
              └──────────────────┘
```

### 6.2 Data Flow for Key Retrieval
```
1. User Authentication
   └─→ Verify credentials
   └─→ Check MFA if enabled
   └─→ Generate session token

2. Key Request
   └─→ Validate permissions
   └─→ Check rate limits
   └─→ Log access attempt

3. Key Decryption
   └─→ Retrieve encrypted key
   └─→ Derive decryption key
   └─→ Decrypt and verify integrity

4. Key Delivery
   └─→ Secure transmission (TLS)
   └─→ Memory protection
   └─→ Auto-cleanup after use
```

## 7. Security Best Practices

### 7.1 Memory Protection
```python
# Use secure memory allocation
import ctypes
import sys

def secure_zero_memory(data):
    """Securely overwrite memory containing sensitive data"""
    if isinstance(data, str):
        data = data.encode()
    
    # Get memory address and size
    address = id(data)
    size = sys.getsizeof(data)
    
    # Overwrite with random data
    ctypes.memset(address, 0, size)
```

### 7.2 Key Rotation Strategy
```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│  Current    │────▶│   Pending   │────▶│   Active    │
│   (v1.0)    │     │   (v2.0)    │     │   (v2.0)    │
└─────────────┘     └─────────────┘     └─────────────┘
                           │
                           ▼
                    ┌─────────────┐
                    │  Archived   │
                    │   (v1.0)    │
                    └─────────────┘
```

### 7.3 Audit Log Format
```json
{
  "timestamp": "2025-01-11T10:30:45Z",
  "event_type": "key_access",
  "user_id": "user123",
  "key_id": "github_api_key_001",
  "action": "read",
  "result": "success",
  "ip_address": "192.168.1.100",
  "user_agent": "SecureKeysCLI/1.0",
  "session_id": "sess_abc123",
  "additional_context": {
    "mfa_used": true,
    "access_duration_ms": 45
  }
}
```

## 8. Recommended Technology Stack

### 8.1 Core Libraries
- **Cryptography**: `cryptography` (Python) / `ring` (Rust)
- **Key Derivation**: Native PBKDF2 implementations
- **Storage**: SQLCipher for encrypted SQLite
- **Cloud Integration**: AWS SDK, Azure SDK, or Google Cloud SDK

### 8.2 Security Libraries
- **MFA**: `pyotp` for TOTP/HOTP
- **Audit**: Structured logging with `structlog`
- **Memory Protection**: `SecureString` implementations

## 9. Integration Patterns

### 9.1 Application Integration
```python
from secure_keys import KeyManager

# Initialize with master password
km = KeyManager()
km.authenticate(password="master_password", mfa_token="123456")

# Retrieve API key
api_key = km.get_key("github_api_key")

# Use in application
github_client = GithubClient(api_key=api_key)

# Key is automatically cleared from memory after use
```

### 9.2 CI/CD Integration
```yaml
# GitHub Actions Example
- name: Setup Secure Keys
  uses: secure-keys/action@v1
  with:
    vault-url: ${{ secrets.VAULT_URL }}
    role-id: ${{ secrets.ROLE_ID }}
    
- name: Use API Key
  run: |
    API_KEY=$(secure-keys get github_api_key)
    # Use the key
    unset API_KEY  # Clear from environment
```