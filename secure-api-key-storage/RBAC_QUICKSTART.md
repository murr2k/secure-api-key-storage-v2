# RBAC Quick Start Guide

## 🚀 Getting Started with RBAC

### 1. Migration (for existing systems)

If you have an existing secure storage setup, migrate to RBAC:

```bash
# Install dependencies
pip install -r requirements.txt

# Run migration
python src/migrate_to_rbac.py \
    --source ./keys \
    --destination ./keys_rbac \
    --admin-password "your_secure_admin_password"
```

### 2. New Installation

For new installations, the RBAC system initializes automatically:

```python
from secure_storage_rbac import SecureKeyStorageRBAC

# Initialize with RBAC
storage = SecureKeyStorageRBAC(
    storage_path="./secure_keys",
    master_password="your_master_password"
)
```

Default admin credentials:
- Username: `admin`
- Password: `admin123` (CHANGE THIS IMMEDIATELY!)

### 3. Update Dashboard Backend

Replace the existing backend with the RBAC-enabled version:

```bash
cd dashboard/backend

# Use the RBAC-enabled main file
cp main_rbac.py main.py

# Or run directly
python main_rbac.py
```

### 4. Environment Variables

Set these environment variables:

```bash
export STORAGE_PATH="./keys_rbac"
export JWT_SECRET_KEY="your-secret-jwt-key-change-this"
export DEFAULT_ADMIN_PASSWORD="secure_admin_password"
export CORS_ORIGINS="http://localhost:3000"
```

### 5. Test the System

Run the test suite to verify everything works:

```bash
python tests/test_rbac.py
```

## 📝 Common Operations

### Create a New User

```bash
curl -X POST http://localhost:8000/api/rbac/users \
  -H "Authorization: Bearer YOUR_ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "username": "developer",
    "password": "secure_password",
    "role": "user",
    "email": "dev@company.com"
  }'
```

### Grant Key Access

```bash
curl -X POST http://localhost:8000/api/rbac/keys/KEY_ID/grant-access \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "user_id": 2,
    "permissions": ["key:read", "key:rotate"],
    "expires_at": "2024-12-31T23:59:59"
  }'
```

### Login

```bash
curl -X POST http://localhost:8000/api/auth/login \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "username=admin&password=your_password"
```

## 🔑 Key Concepts

1. **Roles**: Admin, User, Viewer
2. **Permissions**: Granular access control (key:read, key:update, etc.)
3. **Per-Key Policies**: Share specific keys with specific permissions
4. **Audit Trail**: Every access attempt is logged

## 🛡️ Security Checklist

- [ ] Changed default admin password
- [ ] Set strong JWT secret key
- [ ] Configured HTTPS for production
- [ ] Reviewed user roles and permissions
- [ ] Set up regular audit log reviews
- [ ] Implemented key rotation policies

## 📚 Next Steps

1. Read the full [RBAC Guide](docs/RBAC_GUIDE.md)
2. Review the [example code](examples/rbac_example.py)
3. Set up user accounts for your team
4. Configure key sharing policies
5. Implement automated key rotation

## 🆘 Troubleshooting

If you encounter issues:

1. Check the audit logs: `GET /api/rbac/audit`
2. Verify user permissions: `GET /api/rbac/users/me`
3. Review available permissions: `GET /api/rbac/permissions`
4. Check system health: `GET /api/health`

For more help, see the [RBAC Guide](docs/RBAC_GUIDE.md) troubleshooting section.