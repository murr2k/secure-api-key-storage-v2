# Role-Based Access Control (RBAC) Guide

## Overview

The Secure API Key Storage system now includes a comprehensive Role-Based Access Control (RBAC) system that provides:

- **User authentication and authorization**
- **Three predefined roles**: Admin, User, and Viewer
- **Granular permissions** for key operations
- **Per-key access policies** for fine-grained control
- **Comprehensive audit logging** of all access attempts

## User Roles

### Admin Role
- **Full system access** including all key operations
- Can create, update, and delete users
- Can view all keys in the system
- Can grant/revoke access to any key
- Can view system-wide audit logs
- Can perform system maintenance tasks

### User Role  
- Can create new API keys
- Full control over their own keys (read, update, delete, rotate)
- Can share keys with other users by granting specific permissions
- Can view audit logs for their own actions
- Cannot access keys owned by others unless explicitly granted permission

### Viewer Role
- **Read-only access** to assigned keys
- Cannot create new keys
- Cannot modify or delete existing keys
- Can only view keys they've been granted access to
- Can view limited audit logs

## Permissions

The system uses granular permissions for fine-grained access control:

### Key Permissions
- `key:create` - Create new API keys
- `key:read` - Read/view API key values
- `key:update` - Update key metadata or values
- `key:delete` - Delete/revoke API keys
- `key:rotate` - Rotate API key values
- `key:list` - List available keys
- `key:export` - Export key data

### User Management Permissions
- `user:create` - Create new users
- `user:read` - View user information
- `user:update` - Update user details
- `user:delete` - Delete users
- `user:list` - List all users

### Audit Permissions
- `audit:read` - View audit logs
- `audit:export` - Export audit logs

### System Permissions
- `system:config` - Modify system configuration
- `system:backup` - Perform system backups

## Per-Key Access Policies

Beyond role-based permissions, the system supports per-key access policies:

```python
# Grant specific permissions to a user for a key
secure_storage.grant_key_access(
    key_id="key_abc123",
    granting_user_id=1,  # Admin or key owner
    target_user_id=5,    # User receiving access
    permissions=[Permission.KEY_READ, Permission.KEY_ROTATE],
    expires_at=datetime(2024, 12, 31)  # Optional expiration
)
```

## Authentication & Authorization Flow

1. **User Login**
   - User provides username and password
   - System validates credentials against RBAC database
   - JWT tokens are issued (access + refresh tokens)

2. **Request Authorization**
   - Each API request includes JWT token
   - System validates token and extracts user identity
   - Permission checks are performed based on:
     - User's role permissions
     - Specific key access policies
     - Request context (IP, time, etc.)

3. **Audit Logging**
   - All access attempts are logged
   - Includes success/failure status
   - Tracks user, action, resource, and context

## API Integration

### Creating a User
```python
POST /api/rbac/users
{
    "username": "john_doe",
    "password": "secure_password",
    "role": "user",
    "email": "john@example.com"
}
```

### Granting Key Access
```python
POST /api/rbac/keys/{key_id}/grant-access
{
    "user_id": 5,
    "permissions": ["key:read", "key:rotate"],
    "expires_at": "2024-12-31T23:59:59"
}
```

### Checking Permissions
```python
# In code
if rbac_manager.check_permission(user_id, Permission.KEY_READ, key_id):
    # Allow access
    key_value = secure_storage.get_api_key_with_rbac(key_id, user_id)
```

## Migration from Non-RBAC System

Use the migration script to upgrade existing storage:

```bash
python migrate_to_rbac.py \
    --source ./keys \
    --destination ./keys_rbac \
    --admin-password "new_admin_password"
```

The migration script will:
1. Copy all existing keys to the new RBAC-enabled storage
2. Create user accounts for all key owners
3. Set up appropriate permissions
4. Generate a migration report

## Security Best Practices

1. **Change Default Passwords**
   - The system creates a default admin account
   - Change the password immediately after setup
   - Migrated users get username as password - must be changed

2. **Principle of Least Privilege**
   - Assign users the minimum role needed
   - Use per-key policies for temporary access
   - Set expiration dates on granted permissions

3. **Regular Audits**
   - Review audit logs regularly
   - Check for failed access attempts
   - Monitor permission grants and changes

4. **Secure Configuration**
   - Use strong JWT secret keys
   - Enable HTTPS in production
   - Configure appropriate CORS origins
   - Set reasonable token expiration times

## Database Schema

The RBAC system uses SQLite with the following main tables:

- **users**: User accounts and authentication
- **key_policies**: Per-key access policies
- **access_tokens**: Active session tokens
- **rbac_audit_log**: Comprehensive audit trail

## Troubleshooting

### Common Issues

1. **"Access denied" errors**
   - Check user's role and permissions
   - Verify key-specific access policies
   - Review audit logs for details

2. **Migration failures**
   - Ensure source directory exists
   - Check file permissions
   - Review migration report for specific errors

3. **Authentication problems**
   - Verify JWT secret key is set
   - Check token expiration
   - Ensure CORS is properly configured

### Debug Endpoints

- `GET /api/rbac/users/me` - View current user info
- `GET /api/rbac/permissions` - List all permissions
- `GET /api/rbac/roles` - List all roles
- `GET /api/rbac/audit` - View audit logs

## Environment Variables

Configure the system using these environment variables:

```bash
# Storage paths
STORAGE_PATH=/path/to/keys
RBAC_DB_PATH=/path/to/rbac.db

# Security
JWT_SECRET_KEY=your-secret-key
API_KEY_MASTER=master-password
DEFAULT_ADMIN_PASSWORD=admin-password

# API Configuration  
CORS_ORIGINS=http://localhost:3000,https://app.example.com
```

## Future Enhancements

The RBAC system is designed to be extensible:

- **Custom Roles**: Define organization-specific roles
- **Attribute-Based Access Control (ABAC)**: Add context-aware policies
- **OAuth/SAML Integration**: Connect to existing identity providers
- **Multi-Factor Authentication**: Add additional security layers
- **Dynamic Permissions**: Time-based or condition-based access