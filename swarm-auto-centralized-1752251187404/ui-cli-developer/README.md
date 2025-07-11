# Secure Key Manager - UI/CLI Developer Implementation

A comprehensive command-line interface for secure API key management with military-grade encryption, key rotation, backup/restore functionality, and extensive integration capabilities.

## Features

### Core Functionality
- 🔐 **AES-256 Encryption**: All keys encrypted using PBKDF2-derived keys
- 🔑 **Master Password Protection**: Single password to access all keys
- 📋 **Service Organization**: Group keys by service (GitHub, AWS, etc.)
- 🔄 **Key Rotation**: Manual and automated key rotation support
- 💾 **Backup & Restore**: Full backup/restore with versioning
- 🔍 **Search**: Find keys across all services
- 📊 **Audit & Stats**: Security compliance and usage statistics

### Advanced Features
- 🖥️ **Interactive Mode**: Full-featured REPL with auto-completion
- 🐍 **Python Library**: Programmatic access for automation
- 🔗 **Integration Examples**: Ready-to-use integrations for popular services
- 🚀 **CI/CD Support**: GitHub Actions, GitLab CI, Docker, Kubernetes
- 📦 **Bulk Operations**: Import/export, batch add/remove
- 🎯 **Temporary Keys**: Context manager for ephemeral keys

## Quick Start

### Installation

1. **Run the setup script:**
```bash
chmod +x setup.sh
./setup.sh
```

2. **Initialize with the wizard:**
```bash
./key-manager wizard
```

### Basic Usage

```bash
# Add a key
./key-manager add github personal

# Get a key (copies to clipboard)
./key-manager get github personal

# List all services
./key-manager list

# Rotate a key
./key-manager rotate github personal

# Create backup
./key-manager backup --name daily
```

### Interactive Mode

Start the advanced interactive interface:
```bash
./key-manager-advanced.py
# or
python key-manager-advanced.py interactive
```

## File Structure

```
ui-cli-developer/
├── key-manager-cli.py          # Main CLI application
├── key-manager-advanced.py     # Advanced CLI with interactive mode
├── key_manager_lib.py          # Python library for programmatic access
├── setup.sh                    # Installation script
├── user-documentation.md       # Comprehensive user guide
├── examples/
│   ├── example-usage.sh        # Usage examples
│   └── integration-examples.py # Integration code samples
└── tests/
    └── test_key_manager.py     # Test suite and demo
```

## Python Library Usage

```python
from key_manager_lib import KeyManager

# Initialize
km = KeyManager(master_password="your_password")

# Add a key
km.add_key("github", "token", "ghp_abc123")

# Get a key
token = km.get_key("github", "token")

# Bulk operations
keys = [
    {"service": "aws", "key_name": "access", "value": "AKIA..."},
    {"service": "aws", "key_name": "secret", "value": "secret..."}
]
km.bulk_add(keys)

# Export to environment
km.export_env({
    "GITHUB_TOKEN": ("github", "token"),
    "AWS_ACCESS_KEY": ("aws", "access")
})
```

## Integration Examples

### GitHub Actions
```yaml
- name: Setup Keys
  run: |
    export GITHUB_TOKEN=$(./key-manager get github ci-cd --show)
    export AWS_ACCESS_KEY=$(./key-manager get aws access --show)
```

### Docker
```python
# See examples/integration-examples.py
docker_integration_example()  # Generates docker-compose.yml with secrets
```

### Kubernetes
```bash
# Generate Kubernetes secrets
python examples/integration-examples.py
# Creates k8s-secrets.yaml and k8s-deployment.yaml
```

## Security Features

- **Encryption**: AES-256 (Fernet) with PBKDF2 key derivation
- **Salt**: Random 16-byte salt per installation
- **Iterations**: 100,000 PBKDF2 iterations
- **Storage**: Encrypted file at `~/.secure-keys/keys.enc`
- **Memory**: Keys never stored in plain text
- **Input**: Secure password input, clipboard integration

## Advanced Usage

### Interactive Mode Features
- Auto-completion for commands and services
- Command history
- Tree view of all keys
- Statistics and audit reports
- Real-time monitoring
- Batch import/export

### Programmatic Access
- Full Python API
- Context managers for temporary keys
- Async support (planned)
- Event hooks (planned)

### Testing
```bash
# Run test suite
python tests/test_key_manager.py

# Run feature demo
python tests/test_key_manager.py demo
```

## Best Practices

1. **Password Security**
   - Use a strong master password (12+ characters)
   - Don't reuse passwords
   - Change periodically

2. **Key Organization**
   - Use descriptive service names
   - Add metadata for context
   - Group by environment (prod/dev)

3. **Backup Strategy**
   - Regular automated backups
   - Store backups securely
   - Test restore process

4. **Key Rotation**
   - Rotate production keys quarterly
   - Use different keys per environment
   - Document rotation procedures

## Troubleshooting

### Common Issues

1. **"Key manager not initialized"**
   - Run: `./key-manager setup`

2. **"Invalid master password"**
   - Check caps lock
   - Passwords are case-sensitive

3. **Import Errors**
   - Run: `pip install -r requirements.txt`

4. **Permission Denied**
   - Run: `chmod +x key-manager-cli.py`

## Architecture

### Components
1. **CLI Layer**: Click-based command interface
2. **Encryption Layer**: Cryptography library with Fernet
3. **Storage Layer**: JSON-based encrypted storage
4. **Library Layer**: Python API for programmatic access
5. **Integration Layer**: Examples and templates

### Data Flow
```
User Input → CLI → Library → Encryption → Storage
                ↓
            Validation
                ↓
            Response
```

## Future Enhancements

- [ ] Cloud sync support
- [ ] Team sharing capabilities
- [ ] Hardware token support
- [ ] API server mode
- [ ] Mobile app companion
- [ ] Audit logging
- [ ] Key expiration tracking
- [ ] Multi-factor authentication

## Contributing

This implementation follows secure coding practices:
- Input validation
- Error handling
- Secure defaults
- Comprehensive testing
- Clear documentation

## License

This implementation is part of the swarm-auto-centralized project.

---

For detailed usage instructions, see `user-documentation.md`
For integration examples, see `examples/`
For API documentation, see docstrings in `key_manager_lib.py`