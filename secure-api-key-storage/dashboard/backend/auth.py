"""
Authentication and authorization module
"""

from datetime import datetime, timedelta
from typing import Optional, Dict, Any
import os
import sys
from pathlib import Path

from fastapi import Depends, HTTPException, status, Request
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel

# Add parent directory to path to import auth modules
sys.path.append(str(Path(__file__).parent.parent.parent / "src"))

try:
    from auth_integration import auth_integration
    ENHANCED_AUTH_AVAILABLE = True
except ImportError:
    ENHANCED_AUTH_AVAILABLE = False
    auth_integration = None

# Configuration
SECRET_KEY = os.environ.get("JWT_SECRET_KEY", "your-secret-key-change-this-in-production")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 15
REFRESH_TOKEN_EXPIRE_DAYS = 7

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# OAuth2 scheme
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="api/auth/login")

class Token(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    require_2fa: bool = False

class TokenData(BaseModel):
    username: Optional[str] = None
    role: Optional[str] = None
    token_type: Optional[str] = None
    user_id: Optional[int] = None

class User(BaseModel):
    username: str
    role: str = "admin"
    is_active: bool = True
    user_id: Optional[int] = None

class LoginRequest(BaseModel):
    username: str
    password: str
    totp_code: Optional[str] = None

class RegisterRequest(BaseModel):
    username: str
    password: str
    email: Optional[str] = None
    enable_2fa: bool = True

class Setup2FAResponse(BaseModel):
    qr_code: str
    backup_codes: list[str]

class CertificateLoginRequest(BaseModel):
    certificate_pem: str

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a password against its hash"""
    if ENHANCED_AUTH_AVAILABLE:
        # Use enhanced auth manager's password context
        return auth_integration.auth_manager.pwd_context.verify(plain_password, hashed_password)
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password: str) -> str:
    """Hash a password"""
    if ENHANCED_AUTH_AVAILABLE:
        # Use enhanced auth manager's password context
        return auth_integration.auth_manager.pwd_context.hash(password)
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    """Create a JWT access token"""
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire, "type": "access"})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def create_refresh_token(data: dict):
    """Create a JWT refresh token"""
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    to_encode.update({"exp": expire, "type": "refresh"})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def decode_token(token: str) -> TokenData:
    """Decode and validate a JWT token"""
    if ENHANCED_AUTH_AVAILABLE:
        # Use enhanced auth manager's JWT validation
        token_data = auth_integration.auth_manager.validate_jwt_token(token)
        if token_data:
            return TokenData(
                username=token_data.get("username"),
                role="admin" if token_data.get("is_admin") else "user",
                token_type="access",
                user_id=token_data.get("user_id")
            )
        raise ValueError("Invalid token")
    else:
        # Fallback to original implementation
        try:
            payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
            username: str = payload.get("sub")
            role: str = payload.get("role", "user")
            token_type: str = payload.get("type")
            if username is None:
                raise ValueError("Invalid token")
            return TokenData(username=username, role=role, token_type=token_type)
        except JWTError:
            raise ValueError("Could not validate token")

async def get_current_user(token: str = Depends(oauth2_scheme), request: Request = None) -> User:
    """Get the current authenticated user"""
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    
    if ENHANCED_AUTH_AVAILABLE:
        # Use enhanced authentication
        user_data = auth_integration.auth_manager.validate_jwt_token(token)
        if not user_data:
            raise credentials_exception
        
        return User(
            username=user_data["username"],
            role="admin" if user_data.get("is_admin") else "user",
            is_active=True,
            user_id=user_data.get("user_id")
        )
    else:
        # Fallback to original implementation
        try:
            token_data = decode_token(token)
            if token_data.token_type != "access":
                raise credentials_exception
        except ValueError:
            raise credentials_exception
        
        # For now, we only have one admin user
        # In production, you'd fetch from a database
        if token_data.username == "admin":
            return User(username=token_data.username, role=token_data.role)
        else:
            raise credentials_exception

async def get_current_active_user(current_user: User = Depends(get_current_user)) -> User:
    """Ensure the current user is active"""
    if not current_user.is_active:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user

def require_role(required_role: str):
    """Dependency to require a specific role"""
    async def role_checker(current_user: User = Depends(get_current_active_user)):
        if current_user.role != required_role and current_user.role != "admin":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient permissions"
            )
        return current_user
    return role_checker

# Role-based dependencies
require_admin = require_role("admin")
require_user = require_role("user")

# Enhanced authentication endpoints (if available)
if ENHANCED_AUTH_AVAILABLE:
    # Get enhanced auth routes
    enhanced_routes = auth_integration.create_dashboard_auth_routes(sys.modules[__name__])
    
    # Export enhanced functions
    enhanced_login = enhanced_routes["login"]
    verify_2fa = enhanced_routes["verify_2fa"]
    register_user = enhanced_routes["register"]
    setup_2fa = enhanced_routes["setup_2fa"]
    setup_certificate = enhanced_routes["setup_certificate"]
    get_auth_audit_logs = enhanced_routes["get_audit_logs"]