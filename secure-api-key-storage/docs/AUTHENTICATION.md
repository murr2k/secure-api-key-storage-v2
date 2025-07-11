# Authentication System Documentation

## Overview

The Secure API Key Storage system now includes a comprehensive authentication layer that provides:

- **User Management**: Create and manage user accounts with secure password storage
- **Two-Factor Authentication (2FA)**: TOTP-based 2FA with backup codes
- **Certificate-Based Authentication**: Support for X.509 client certificates
- **Session Management**: Secure session handling with JWT tokens
- **Audit Logging**: Comprehensive authentication audit trail
- **Integration**: Seamless integration with both CLI and Dashboard components

## Architecture

### Components

1. **AuthenticationManager** (`src/auth_manager.py`)
   - Core authentication logic
   - User database management
   - Password hashing (Argon2/BCrypt)
   - 2FA/TOTP implementation
   - Certificate validation
   - Session and JWT management

2. **AuthIntegration** (`src/auth_integration.py`)
   - CLI authentication commands
   - Dashboard API endpoints
   - Session persistence
   - Authentication decorators

3. **Enhanced Backend** (`dashboard/backend/auth.py`)
   - FastAPI integration
   - OAuth2 password bearer flow
   - JWT token validation
   - Role-based access control

## Setup Instructions

### 1. Install Dependencies

```bash
pip install -r requirements.txt
```

Key dependencies:
- `passlib[argon2]`: Secure password hashing
- `pyotp`: TOTP/2FA implementation
- `qrcode[pil]`: QR code generation
- `python-jose[cryptography]`: JWT handling

### 2. Initialize Authentication

Run the setup script:

```bash
python setup_auth.py
```

This will:
- Create an admin user account
- Set up 2FA (optional)
- Generate necessary configuration

### 3. Environment Variables

Add to your `.env` file:

```env
# Master password for key encryption
API_KEY_MASTER=your_secure_master_password

# JWT secret key (generate with: python -c "import secrets; print(secrets.token_hex(32))")
JWT_SECRET_KEY=your_jwt_secret_key_here
```

## CLI Usage

### Authentication Commands

#### Login
```bash
# Password authentication
secure-keys auth login

# With username
secure-keys auth login -u username

# Certificate authentication
secure-keys auth login --certificate
```

#### Register New User
```bash
secure-keys auth register
```

#### Logout
```bash
secure-keys auth logout
```

#### Two-Factor Authentication Setup
```bash
secure-keys auth setup-2fa
```

#### Certificate Setup
```bash
secure-keys auth setup-certificate
```

#### Change Password
```bash
secure-keys auth change-password
```

### Protected Commands

Key management commands now require authentication:

```bash
# Must be logged in to use these commands
secure-keys add service keyname
secure-keys remove service keyname
secure-keys rotate service keyname
```

## Dashboard API Endpoints

### Authentication Endpoints

#### Login
```http
POST /api/auth/login
Content-Type: application/x-www-form-urlencoded

username=admin&password=your_password
```

Response:
```json
{
  "access_token": "eyJ...",
  "refresh_token": "eyJ...",
  "token_type": "bearer",
  "require_2fa": false
}
```

#### 2FA Verification
```http
POST /api/auth/verify-2fa
Authorization: Bearer <access_token>
Content-Type: application/json

{
  "totp_code": "123456"
}
```

#### Register User
```http
POST /api/auth/register
Content-Type: application/json

{
  "username": "newuser",
  "password": "SecurePassword123!",
  "email": "user@example.com",
  "enable_2fa": true
}
```

#### Setup 2FA
```http
POST /api/auth/setup-2fa
Authorization: Bearer <access_token>
```

Response:
```json
{
  "qr_code": "base64_encoded_qr_image",
  "backup_codes": ["code1", "code2", ...]
}
```

#### Certificate Login
```http
POST /api/auth/login-certificate
Content-Type: application/json

{
  "certificate_pem": "-----BEGIN CERTIFICATE-----\n..."
}
```

#### Audit Logs
```http
GET /api/auth/audit-logs?limit=100
Authorization: Bearer <access_token>
```

## Security Features

### Password Security
- Minimum 12 characters required
- Hashed using Argon2id (memory-hard, resistant to GPU attacks)
- Automatic rehashing if needed

### Account Protection
- Account lockout after 5 failed login attempts (30 minutes)
- Failed login attempt tracking
- IP address logging for audit trail

### Two-Factor Authentication
- TOTP (Time-based One-Time Password) implementation
- Compatible with Google Authenticator, Authy, etc.
- 10 backup codes for account recovery
- 30-second time window with 1 period tolerance

### Certificate Authentication
- X.509 client certificate support
- Certificate validation and expiry checking
- SHA-256 fingerprint verification
- Secure certificate storage

### Session Management
- JWT tokens with short expiration (15 minutes access, 7 days refresh)
- Secure session storage (file permissions 0600)
- Session invalidation on password change
- Automatic cleanup of expired sessions

## Database Schema

### Users Table
```sql
CREATE TABLE users (
    id INTEGER PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    email TEXT UNIQUE,
    is_active BOOLEAN DEFAULT 1,
    is_admin BOOLEAN DEFAULT 0,
    created_at TIMESTAMP,
    updated_at TIMESTAMP,
    last_login TIMESTAMP,
    failed_attempts INTEGER DEFAULT 0,
    locked_until TIMESTAMP,
    require_2fa BOOLEAN DEFAULT 0,
    totp_secret TEXT,
    backup_codes TEXT,
    certificate_subject TEXT,
    certificate_fingerprint TEXT
);
```

### Sessions Table
```sql
CREATE TABLE sessions (
    id INTEGER PRIMARY KEY,
    user_id INTEGER NOT NULL,
    session_token TEXT UNIQUE NOT NULL,
    ip_address TEXT,
    user_agent TEXT,
    created_at TIMESTAMP,
    expires_at TIMESTAMP NOT NULL,
    is_active BOOLEAN DEFAULT 1,
    FOREIGN KEY (user_id) REFERENCES users (id)
);
```

### Audit Log Table
```sql
CREATE TABLE auth_audit_log (
    id INTEGER PRIMARY KEY,
    user_id INTEGER,
    action TEXT NOT NULL,
    ip_address TEXT,
    user_agent TEXT,
    success BOOLEAN,
    details TEXT,
    timestamp TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users (id)
);
```

## Integration Examples

### CLI Integration

```python
from auth_integration import auth_integration

# Require authentication for a command
@auth_integration.require_auth()
def protected_command(ctx):
    # User is authenticated
    session = ctx.obj['session']
    print(f"Hello {session['username']}")

# Require admin privileges
@auth_integration.require_auth(require_admin=True)
def admin_command(ctx):
    # Only admins can run this
    pass
```

### Dashboard Integration

```python
from fastapi import Depends
from auth import get_current_user, User

@app.get("/api/protected")
async def protected_route(current_user: User = Depends(get_current_user)):
    return {"message": f"Hello {current_user.username}"}
```

## Testing

Run the test suite:

```bash
python test_auth_integration.py
```

This tests:
- User creation and authentication
- 2FA setup and verification
- Session management
- Security features (lockout, password complexity)
- CLI integration
- Audit logging

## Troubleshooting

### Common Issues

1. **"Authentication module not available"**
   - Ensure all dependencies are installed
   - Check Python path includes the src directory

2. **"Session expired"**
   - Login again with `secure-keys auth login`
   - Check system time is synchronized

3. **"Account locked"**
   - Wait 30 minutes or contact admin
   - Check audit logs for failed attempts

4. **2FA Issues**
   - Ensure device time is synchronized
   - Use backup codes if TOTP fails
   - Regenerate 2FA if needed

### Debug Mode

Enable debug logging:
```python
import logging
logging.basicConfig(level=logging.DEBUG)
```

## Best Practices

1. **Password Policy**
   - Enforce minimum 12 characters
   - Encourage passphrases
   - Regular password rotation

2. **2FA Adoption**
   - Enable 2FA for all admin accounts
   - Provide user training
   - Keep backup codes secure

3. **Certificate Management**
   - Use proper certificate authority
   - Monitor certificate expiration
   - Implement certificate revocation

4. **Audit Review**
   - Regularly review audit logs
   - Monitor for suspicious activity
   - Set up alerts for critical events

## Future Enhancements

Potential improvements:
- FIDO2/WebAuthn support
- OAuth2/SAML integration
- Risk-based authentication
- Passwordless authentication
- Multi-device session management