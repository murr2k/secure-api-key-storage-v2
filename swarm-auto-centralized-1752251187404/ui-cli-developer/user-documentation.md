# Secure Key Manager - User Documentation

## Table of Contents
1. [Overview](#overview)
2. [Installation](#installation)
3. [Quick Start](#quick-start)
4. [Commands Reference](#commands-reference)
5. [Security Features](#security-features)
6. [Best Practices](#best-practices)
7. [Troubleshooting](#troubleshooting)

## Overview

The Secure Key Manager is a command-line tool for managing API keys and sensitive credentials with military-grade encryption. It provides:

- 🔐 AES-256 encryption for all stored keys
- 🔑 Master password protection
- 🔄 Key rotation capabilities
- 💾 Backup and restore functionality
- 📋 Service organization
- 🛡️ Secure input methods

## Installation

### Requirements
- Python 3.7 or higher
- pip (Python package manager)

### Quick Install

1. Clone or download the repository
2. Run the setup script:
```bash
chmod +x setup.sh
./setup.sh
```

### Manual Installation

1. Create a virtual environment:
```bash
python3 -m venv venv
source venv/bin/activate
```

2. Install dependencies:
```bash
pip install click rich cryptography pyperclip
```

3. Make the CLI executable:
```bash
chmod +x key-manager-cli.py
```

## Quick Start

### First Time Setup

Run the interactive wizard:
```bash
./key-manager wizard
```

Or manually initialize:
```bash
./key-manager setup
```

### Adding Your First Key

```bash
./key-manager add github personal
# You'll be prompted for the API key value
```

### Retrieving a Key

```bash
# Copy to clipboard (requires pyperclip)
./key-manager get github personal

# Show the key value
./key-manager get github personal --show
```

## Commands Reference

### `setup`
Initialize the key manager with a master password.
```bash
./key-manager setup
```

### `wizard`
Interactive setup wizard for new users.
```bash
./key-manager wizard
```

### `add`
Add a new API key.
```bash
# Interactive (prompts for key value)
./key-manager add <service> <key_name>

# With key value
./key-manager add <service> <key_name> --key-value "your-api-key"

# With metadata
./key-manager add <service> <key_name> --metadata '{"environment": "production"}'
```

### `remove`
Remove an API key.
```bash
./key-manager remove <service> <key_name>
```

### `update`
Update an existing key (use `rotate` for key rotation).
```bash
./key-manager rotate <service> <key_name> --new-value "new-key-value"
```

### `rotate`
Rotate an API key with optional new value.
```bash
# Generate new random key
./key-manager rotate <service> <key_name>

# Specify new value
./key-manager rotate <service> <key_name> --new-value "new-key-value"
```

### `list`
List all services and keys.
```bash
# List all services
./key-manager list

# Filter by service
./key-manager list --service github
```

### `get`
Retrieve a specific API key.
```bash
# Copy to clipboard
./key-manager get <service> <key_name>

# Display key value
./key-manager get <service> <key_name> --show
```

### `backup`
Create a backup of all keys.
```bash
# Auto-named backup
./key-manager backup

# Named backup
./key-manager backup --name "pre-update"
```

### `restore`
Restore keys from a backup.
```bash
# List available backups
./key-manager restore list

# Restore specific backup
./key-manager restore <backup_name>
```

## Security Features

### Encryption
- **Algorithm**: AES-256 (Fernet)
- **Key Derivation**: PBKDF2 with SHA256
- **Iterations**: 100,000
- **Salt**: Randomly generated 16-byte salt

### Master Password
- Minimum 8 characters required
- Used to derive encryption key
- Never stored on disk
- Required for every operation

### Secure Storage
- Keys stored in `~/.secure-keys/keys.enc`
- Configuration in `~/.secure-keys/config.json`
- Backups in `~/.secure-keys/backups/`

### Input Protection
- Password input is hidden
- Option to input keys interactively
- Clipboard integration for secure copying

## Best Practices

### Password Management
1. Use a strong master password (12+ characters)
2. Don't reuse passwords from other services
3. Consider using a password manager for the master password
4. Change master password periodically

### Key Organization
1. Use descriptive service names (e.g., `github`, `aws-prod`)
2. Use meaningful key names (e.g., `personal`, `ci-cd`, `deployment`)
3. Add metadata for additional context

### Backup Strategy
1. Create regular backups before major changes
2. Store backups in a secure location
3. Test restore process periodically
4. Keep multiple backup versions

### Security Tips
1. Never share your master password
2. Don't store keys in plain text files
3. Rotate keys regularly
4. Remove unused keys
5. Use different keys for different environments

## Example Workflows

### Managing GitHub Keys
```bash
# Add personal access token
./key-manager add github personal

# Add CI/CD token
./key-manager add github ci-cd --metadata '{"scope": "repo,workflow"}'

# List GitHub keys
./key-manager list --service github

# Rotate CI/CD token
./key-manager rotate github ci-cd
```

### Managing AWS Credentials
```bash
# Add production credentials
./key-manager add aws-prod access-key
./key-manager add aws-prod secret-key

# Add development credentials
./key-manager add aws-dev access-key
./key-manager add aws-dev secret-key

# Backup before rotation
./key-manager backup --name "pre-aws-rotation"

# Rotate all AWS keys
./key-manager rotate aws-prod access-key
./key-manager rotate aws-prod secret-key
```

### Disaster Recovery
```bash
# Regular backup
./key-manager backup --name "weekly-$(date +%Y%m%d)"

# In case of issues
./key-manager restore list
./key-manager restore weekly-20240112
```

## Troubleshooting

### "Key manager not initialized"
Run `./key-manager setup` to initialize with a master password.

### "Invalid master password"
Ensure you're entering the correct master password. Passwords are case-sensitive.

### "Key not found"
Check the service and key name spelling. Use `./key-manager list` to see available keys.

### Forgotten Master Password
Unfortunately, if you forget your master password, the keys cannot be recovered. This is by design for security. Always keep backups in a secure location.

### Permission Errors
Ensure the config directory has proper permissions:
```bash
chmod 700 ~/.secure-keys
chmod 600 ~/.secure-keys/*
```

## Advanced Usage

### Environment Variables
Export keys to environment variables:
```bash
export GITHUB_TOKEN=$(./key-manager get github personal --show)
```

### Script Integration
Use in scripts with non-interactive mode:
```python
import subprocess
import json

# Get key value
result = subprocess.run(
    ['./key-manager', 'get', 'github', 'personal', '--show'],
    capture_output=True,
    text=True,
    input='your-master-password\n'
)
api_key = result.stdout.strip()
```

### Automation
Create aliases for common operations:
```bash
# Add to ~/.bashrc or ~/.zshrc
alias km='./key-manager'
alias km-github='./key-manager get github personal'
alias km-backup='./key-manager backup --name "auto-$(date +%Y%m%d-%H%M%S)"'
```

## Support

For issues, feature requests, or questions:
1. Check this documentation
2. Review the `--help` output for each command
3. Check the error messages for guidance
4. Create an issue in the project repository