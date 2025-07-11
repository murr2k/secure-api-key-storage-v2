"""
RBAC Integration for Dashboard Backend
Provides FastAPI dependencies and utilities for RBAC enforcement
"""

import os
import sys
from typing import Optional, Dict, List
from datetime import datetime, timedelta
from pathlib import Path

from fastapi import Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from pydantic import BaseModel

# Add parent directory to path
sys.path.append(str(Path(__file__).parent.parent.parent / "src"))

from rbac_models import RBACManager, Role, Permission, ROLE_PERMISSIONS
from secure_storage_rbac import SecureKeyStorageRBAC


# JWT Configuration
SECRET_KEY = os.environ.get("JWT_SECRET_KEY", "your-secret-key-change-this-in-production")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 15

# OAuth2 scheme
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="api/auth/login")

# Global RBAC manager instance
rbac_manager = RBACManager(os.path.join(os.environ.get("STORAGE_PATH", "./keys"), "rbac.db"))

# Global secure storage with RBAC
secure_storage = SecureKeyStorageRBAC(
    storage_path=os.environ.get("STORAGE_PATH", "./keys"),
    master_password=os.environ.get("API_KEY_MASTER"),
    rbac_db_path=os.path.join(os.environ.get("STORAGE_PATH", "./keys"), "rbac.db")
)


# Pydantic models for RBAC
class UserCreate(BaseModel):
    username: str
    password: str
    role: str  # admin, user, viewer
    email: Optional[str] = None
    metadata: Optional[Dict] = None


class UserUpdate(BaseModel):
    role: Optional[str] = None
    email: Optional[str] = None
    is_active: Optional[bool] = None


class UserResponse(BaseModel):
    id: int
    username: str
    role: str
    email: Optional[str]
    created_at: datetime
    last_login: Optional[datetime]
    is_active: bool


class PermissionGrant(BaseModel):
    user_id: int
    permissions: List[str]
    expires_at: Optional[datetime] = None


class CurrentUser(BaseModel):
    id: int
    username: str
    role: Role
    permissions: List[str]


# JWT helper functions
def create_access_token(user_id: int, username: str, role: str) -> str:
    """Create JWT access token with user information"""
    to_encode = {
        "sub": str(user_id),
        "username": username,
        "role": role,
        "exp": datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES),
        "type": "access"
    }
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def decode_token(token: str) -> Dict:
    """Decode and validate JWT token"""
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        if payload.get("type") != "access":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token type"
            )
        return payload
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials"
        )


# FastAPI dependencies
async def get_current_user(token: str = Depends(oauth2_scheme)) -> CurrentUser:
    """Get current authenticated user from JWT token"""
    payload = decode_token(token)
    
    user_id = int(payload.get("sub"))
    username = payload.get("username")
    role_str = payload.get("role")
    
    if not all([user_id, username, role_str]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token payload"
        )
    
    try:
        role = Role(role_str)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid user role"
        )
    
    # Get user's permissions
    permissions = [p.value for p in ROLE_PERMISSIONS.get(role, set())]
    
    return CurrentUser(
        id=user_id,
        username=username,
        role=role,
        permissions=permissions
    )


def require_permission(permission: Permission):
    """Dependency to require specific permission"""
    async def permission_checker(current_user: CurrentUser = Depends(get_current_user)):
        if not rbac_manager.check_permission(current_user.id, permission):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Insufficient permissions. Required: {permission.value}"
            )
        return current_user
    return permission_checker


def require_role(role: Role):
    """Dependency to require specific role or higher"""
    async def role_checker(current_user: CurrentUser = Depends(get_current_user)):
        # Define role hierarchy
        role_hierarchy = {
            Role.VIEWER: 0,
            Role.USER: 1,
            Role.ADMIN: 2
        }
        
        user_level = role_hierarchy.get(current_user.role, -1)
        required_level = role_hierarchy.get(role, 999)
        
        if user_level < required_level:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Insufficient role. Required: {role.value}"
            )
        return current_user
    return role_checker


async def get_current_user_with_key_access(
    key_id: str,
    permission: Permission,
    current_user: CurrentUser = Depends(get_current_user)
) -> CurrentUser:
    """Verify user has specific permission for a key"""
    if not rbac_manager.check_permission(current_user.id, permission, key_id):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Access denied for key {key_id}"
        )
    return current_user


# Utility functions
def get_client_ip(request: Request) -> str:
    """Extract client IP from request"""
    # Check for X-Forwarded-For header (proxy/load balancer)
    forwarded_for = request.headers.get("X-Forwarded-For")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()
    
    # Check for X-Real-IP header
    real_ip = request.headers.get("X-Real-IP")
    if real_ip:
        return real_ip
    
    # Fall back to direct client connection
    return request.client.host if request.client else "unknown"


def log_rbac_action(
    user: CurrentUser,
    action: str,
    resource_type: str,
    resource_id: Optional[str] = None,
    success: bool = True,
    request: Optional[Request] = None,
    details: Optional[Dict] = None
):
    """Log RBAC action with context"""
    ip_address = get_client_ip(request) if request else None
    
    rbac_manager._log_audit(
        user_id=user.id,
        username=user.username,
        action=action,
        resource_type=resource_type,
        resource_id=resource_id,
        permission_used=None,
        success=success,
        ip_address=ip_address,
        details=details
    )


# Export dependencies and utilities
__all__ = [
    'rbac_manager',
    'secure_storage',
    'get_current_user',
    'require_permission',
    'require_role',
    'get_current_user_with_key_access',
    'create_access_token',
    'log_rbac_action',
    'UserCreate',
    'UserUpdate',
    'UserResponse',
    'PermissionGrant',
    'CurrentUser',
    'Role',
    'Permission'
]