# API Key Storage System - QA Security Audit

A secure API key storage system with comprehensive security testing and audit capabilities.

## Overview

This system provides encrypted storage for API keys with:
- Strong encryption (Fernet/AES-128-CBC)
- Password-based key derivation (PBKDF2)
- Comprehensive audit logging
- Key rotation and revocation
- Multi-user support
- Performance optimization

## Security Features

- **Encryption at Rest**: All API keys encrypted using Fernet
- **Secure Key Derivation**: PBKDF2 with 100,000 iterations
- **Access Control**: User-based access with audit trails
- **Key Rotation**: Automated rotation with old key revocation
- **Audit Logging**: Complete activity tracking
- **File Security**: Restrictive permissions (0600)

## Installation

```bash
# Clone or navigate to the project directory
cd swarm-auto-centralized-1752251187404/qa-auditor

# Install dependencies
pip install -r requirements.txt
```

## Usage

### Interactive CLI Mode

```bash
python src/user_interface.py
```

This launches an interactive menu for:
- Adding new API keys
- Retrieving keys
- Listing all keys
- Rotating keys
- Revoking keys
- Checking expiring keys
- Exporting audit logs

### Command Line Mode

```bash
# Add a new key
python src/user_interface.py add github --user developer1

# Retrieve a key
python src/user_interface.py get <key_id> --user developer1

# List all keys
python src/user_interface.py list --user admin

# Rotate a key
python src/user_interface.py rotate <key_id> --user admin

# Revoke a key
python src/user_interface.py revoke <key_id> --user admin

# Check expiring keys
python src/user_interface.py check-expiry --days 90

# Export audit log
python src/user_interface.py audit --output audit.log
```

### Programmatic Usage

```python
from src.api_key_storage import APIKeyStorage

# Initialize storage with password
storage = APIKeyStorage(storage_path="./keys", master_password="secure_password")

# Add a key
key_id = storage.add_api_key(
    service="github",
    api_key="ghp_1234567890",
    user="developer1",
    metadata={"environment": "production"}
)

# Retrieve a key
api_key = storage.get_api_key(key_id, "developer1")

# List keys
keys = storage.list_keys("admin")

# Rotate a key
storage.rotate_key(key_id, "new_api_key", "admin")

# Revoke a key
storage.revoke_key(key_id, "admin")
```

## Running Tests

### Run All Tests
```bash
python run_tests.py
```

### Run Specific Test Suites
```bash
# Security tests only
python -m unittest tests.test_security

# Integration tests only
python -m unittest tests.test_integration

# Performance tests only
python -m unittest tests.test_performance
```

## Project Structure

```
qa-auditor/
├── src/
│   ├── api_key_storage.py    # Core storage implementation
│   └── user_interface.py      # CLI and UI components
├── tests/
│   ├── test_security.py       # Security test suite
│   ├── test_integration.py    # Integration test suite
│   └── test_performance.py    # Performance test suite
├── reports/
│   ├── security_audit_report.md  # Security audit findings
│   ├── test_report.md           # Test execution report
│   └── test_results.json        # Test results data
├── run_tests.py              # Test runner script
├── requirements.txt          # Python dependencies
└── README.md                # This file
```

## Security Considerations

1. **Master Password**: Use a strong password (min 12 characters)
2. **File Permissions**: Ensure proper permissions on key storage directory
3. **Regular Rotation**: Rotate keys every 90 days
4. **Audit Logs**: Review audit logs regularly
5. **Backups**: Implement secure backup procedures

## Performance Benchmarks

- **Add Key**: ~5ms average
- **Get Key**: ~2ms average
- **List Keys**: ~8ms for 1000 keys
- **Concurrent Operations**: 100+ ops/second
- **Memory Usage**: ~5KB per key

## Security Audit Results

Overall Security Rating: **8.5/10** (STRONG)

Key findings:
- ✅ Strong encryption implementation
- ✅ Comprehensive audit logging
- ✅ Thread-safe operations
- ✅ Injection attack resistance
- ⚠️ Minor timing attack vulnerability
- ⚠️ Memory security improvements needed

See `reports/security_audit_report.md` for full details.

## Contributing

When contributing:
1. Run all tests before submitting
2. Maintain test coverage above 90%
3. Follow security best practices
4. Update documentation

## License

This system was created as part of a security audit demonstration.