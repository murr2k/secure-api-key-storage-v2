"""
Secure API Key Storage Dashboard - Backend API
"""

import os
import sys
from datetime import datetime, timedelta
from typing import List, Optional, Dict, Any
from pathlib import Path

from fastapi import FastAPI, Depends, HTTPException, status, WebSocket, WebSocketDisconnect, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from jose import JWTError, jwt
from passlib.context import CryptContext
from dotenv import load_dotenv
import uvicorn

# Load environment variables from .env file
load_dotenv()

# Add parent directory to path to import secure_storage module
sys.path.append(str(Path(__file__).parent.parent.parent))

# Import middleware
try:
    from middleware import (
        SecurityHeadersMiddleware,
        RateLimitMiddleware,
        RequestLoggingMiddleware,
        CSRFMiddleware
    )
    MIDDLEWARE_AVAILABLE = True
except ImportError:
    try:
        from dashboard.backend.middleware import (
            SecurityHeadersMiddleware,
            RateLimitMiddleware,
            RequestLoggingMiddleware,
            CSRFMiddleware
        )
        MIDDLEWARE_AVAILABLE = True
    except ImportError:
        print("Warning: Middleware not available, using default middleware")
        MIDDLEWARE_AVAILABLE = False
        
        # Create dummy middleware classes
        class SecurityHeadersMiddleware:
            def __init__(self, app):
                self.app = app
        class RateLimitMiddleware:
            def __init__(self, app, calls=100, period=60):
                self.app = app
        class RequestLoggingMiddleware:
            def __init__(self, app):
                self.app = app
        class CSRFMiddleware:
            def __init__(self, app):
                self.app = app

try:
    from src.secure_storage_rbac import SecureKeyStorageRBAC as SecureKeyStorage
    from src.config_manager import ConfigurationManager as ConfigManager
    from src.key_rotation import KeyRotationManager
    STORAGE_AVAILABLE = True
except ImportError as e:
    print(f"Warning: Could not import secure storage modules: {e}")
    print("Running in demo mode without actual key storage")
    STORAGE_AVAILABLE = False
    # Create dummy classes for demo mode
    class SecureKeyStorage:
        def list_keys(self):
            return []
        def store_key(self, *args, **kwargs):
            pass
        def get_key(self, *args, **kwargs):
            return "demo-key"
        def delete_key(self, *args, **kwargs):
            pass
        def update_key(self, *args, **kwargs):
            pass
    
    class ConfigManager:
        def __init__(self, storage):
            pass
    
    class KeyRotationManager:
        def __init__(self, storage):
            pass
        def rotate_key(self, *args, **kwargs):
            return "new-demo-key"

# Configuration
SECRET_KEY = os.environ.get("JWT_SECRET_KEY", "your-secret-key-change-this-in-production")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 15
REFRESH_TOKEN_EXPIRE_DAYS = 7

# FastAPI app
app = FastAPI(
    title="Secure API Key Storage Dashboard",
    description="Web API for managing encrypted API keys",
    version="1.0.0"
)

# Add middleware
if MIDDLEWARE_AVAILABLE:
    app.add_middleware(SecurityHeadersMiddleware)
    app.add_middleware(RateLimitMiddleware, calls=100, period=60)
    app.add_middleware(RequestLoggingMiddleware)
    app.add_middleware(CSRFMiddleware)
else:
    print("Running without custom middleware")

# CORS configuration
cors_origins = os.environ.get("CORS_ORIGINS", "http://localhost:3000").split(",")
app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Security
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="api/auth/login")

# Storage instances
storage = SecureKeyStorage()
config_manager = ConfigManager("./api_config")  # Provide config path
rotation_manager = KeyRotationManager(config_manager)

# WebSocket connections for real-time updates
active_connections: List[WebSocket] = []

# Pydantic models
class Token(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"

class TokenData(BaseModel):
    username: Optional[str] = None

class User(BaseModel):
    username: str
    role: str = "admin"  # For now, single admin user

class LoginRequest(BaseModel):
    master_password: str

class KeyCreate(BaseModel):
    name: str
    value: str
    service: Optional[str] = None
    description: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None

class KeyUpdate(BaseModel):
    value: Optional[str] = None
    service: Optional[str] = None
    description: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None

class KeyResponse(BaseModel):
    id: str
    name: str
    service: Optional[str]
    description: Optional[str]
    created_at: datetime
    updated_at: datetime
    last_accessed: Optional[datetime]
    rotation_due: Optional[datetime]

class AuditLogEntry(BaseModel):
    id: str
    timestamp: datetime
    action: str
    key_name: Optional[str]
    user: str
    ip_address: Optional[str]
    details: Dict[str, Any]

class AnalyticsOverview(BaseModel):
    total_keys: int
    total_services: int
    keys_accessed_today: int
    keys_rotated_this_month: int
    upcoming_rotations: int
    recent_activity: List[AuditLogEntry]

# Helper functions
def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire, "type": "access"})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def create_refresh_token(data: dict):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
    to_encode.update({"exp": expire, "type": "refresh"})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_user(token: str = Depends(oauth2_scheme)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        token_type: str = payload.get("type")
        if username is None or token_type != "access":
            raise credentials_exception
        token_data = TokenData(username=username)
    except JWTError:
        raise credentials_exception
    return User(username=token_data.username)

def verify_master_password(password: str) -> bool:
    """Verify the master password matches the environment variable"""
    master_password = os.environ.get("MASTER_PASSWORD")
    if not master_password:
        # Fallback to API_KEY_MASTER for backwards compatibility
        master_password = os.environ.get("API_KEY_MASTER")
    if not master_password:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Master password not configured"
        )
    return password == master_password

async def broadcast_audit_log(entry: AuditLogEntry):
    """Broadcast audit log entry to all connected WebSocket clients"""
    for connection in active_connections:
        try:
            await connection.send_json(entry.dict())
        except:
            # Remove dead connections
            active_connections.remove(connection)

# Import enhanced auth if available
try:
    from auth import (
        ENHANCED_AUTH_AVAILABLE, enhanced_login, verify_2fa, 
        register_user, setup_2fa, setup_certificate, get_auth_audit_logs,
        LoginRequest, RegisterRequest, Setup2FAResponse, CertificateLoginRequest
    )
except ImportError:
    ENHANCED_AUTH_AVAILABLE = False

# Authentication endpoints
@app.post("/api/auth/login", response_model=Token)
async def login(form_data: OAuth2PasswordRequestForm = Depends(), request: Request = None):
    """Login endpoint with optional 2FA support."""
    if ENHANCED_AUTH_AVAILABLE:
        return await enhanced_login(form_data, request)
    
    # Original implementation as fallback
    # Debug logging
    print(f"Login attempt - Username: {form_data.username}")
    master_pass = os.environ.get('MASTER_PASSWORD', os.environ.get('API_KEY_MASTER', 'NOT SET'))
    print(f"Master password from env: {master_pass[:3] if master_pass != 'NOT SET' else 'NOT SET'}...")
    
    if not verify_master_password(form_data.password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect master password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Create tokens
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": "admin"}, expires_delta=access_token_expires
    )
    refresh_token = create_refresh_token(data={"sub": "admin"})
    
    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer"
    }

# Enhanced authentication endpoints (if available)
if ENHANCED_AUTH_AVAILABLE:
    @app.post("/api/auth/verify-2fa")
    async def verify_2fa_endpoint(totp_code: str, current_user: User = Depends(get_current_user)):
        """Verify 2FA code and get new tokens."""
        return await verify_2fa(totp_code, current_user)
    
    @app.post("/api/auth/register")
    async def register_endpoint(request: RegisterRequest):
        """Register a new user account."""
        return await register_user(request)
    
    @app.post("/api/auth/setup-2fa", response_model=Setup2FAResponse)
    async def setup_2fa_endpoint(current_user: User = Depends(get_current_user)):
        """Set up 2FA for the current user."""
        return await setup_2fa(current_user)
    
    @app.post("/api/auth/setup-certificate")
    async def setup_certificate_endpoint(
        certificate_pem: str,
        current_user: User = Depends(get_current_user)
    ):
        """Set up certificate authentication."""
        from auth import CertificateSetupRequest
        request = CertificateSetupRequest(certificate_pem=certificate_pem)
        return await setup_certificate(request, current_user)
    
    @app.post("/api/auth/login-certificate")
    async def login_certificate_endpoint(request: CertificateLoginRequest):
        """Login using client certificate."""
        try:
            from auth_integration import auth_integration
            auth_result = auth_integration.auth_manager.authenticate_certificate(
                request.certificate_pem
            )
            session = auth_integration.auth_manager.create_session(auth_result['user_id'])
            return {
                "access_token": session['access_token'],
                "refresh_token": session['refresh_token'],
                "token_type": "bearer"
            }
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=str(e)
            )
    
    @app.get("/api/auth/audit-logs")
    async def get_auth_audit_logs_endpoint(
        limit: int = 100,
        current_user: User = Depends(get_current_user)
    ):
        """Get authentication audit logs."""
        return await get_auth_audit_logs(limit, current_user)

class RefreshTokenRequest(BaseModel):
    refresh_token: str

@app.post("/api/auth/refresh", response_model=Token)
async def refresh_token(request: RefreshTokenRequest):
    try:
        payload = jwt.decode(request.refresh_token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        token_type: str = payload.get("type")
        if username is None or token_type != "refresh":
            raise HTTPException(status_code=401, detail="Invalid refresh token")
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid refresh token")
    
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": username}, expires_delta=access_token_expires
    )
    new_refresh_token = create_refresh_token(data={"sub": username})
    
    return {
        "access_token": access_token,
        "refresh_token": new_refresh_token,
        "token_type": "bearer"
    }

@app.post("/api/auth/logout")
async def logout(current_user: User = Depends(get_current_user)):
    # In a production app, you would invalidate the token here
    return {"message": "Successfully logged out"}

@app.get("/api/auth/session")
async def get_session(current_user: User = Depends(get_current_user)):
    return {"username": current_user.username, "role": current_user.role}

# Key management endpoints
@app.get("/api/keys", response_model=List[KeyResponse])
async def list_keys(
    service: Optional[str] = None,
    search: Optional[str] = None,
    current_user: User = Depends(get_current_user)
):
    """List all keys with optional filtering"""
    keys = storage.list_keys()
    
    # Filter by service if provided
    if service:
        keys = [k for k in keys if k.get("service") == service]
    
    # Search in key names and descriptions
    if search:
        search_lower = search.lower()
        keys = [
            k for k in keys 
            if search_lower in k.get("name", "").lower() or 
               search_lower in (k.get("description") or "").lower()
        ]
    
    # Convert to response format
    response_keys = []
    for key in keys:
        response_keys.append(KeyResponse(
            id=key.get("id", key.get("name", "")),  # Use id if available, fallback to name
            name=key.get("name", ""),
            service=key.get("service"),
            description=key.get("description"),
            created_at=key.get("created_at", datetime.utcnow()),
            updated_at=key.get("updated_at", datetime.utcnow()),
            last_accessed=key.get("last_accessed"),
            rotation_due=key.get("rotation_due")
        ))
    
    return response_keys

@app.post("/api/keys", response_model=KeyResponse)
async def create_key(
    key_data: KeyCreate,
    current_user: User = Depends(get_current_user)
):
    """Create a new API key"""
    try:
        # Store the key (returns key_id)
        key_id = storage.store_key(
            key_data.name,
            key_data.value,
            service=key_data.service,
            metadata={
                "description": key_data.description,
                "created_by": current_user.username,
                "created_at": datetime.utcnow().isoformat(),
                **(key_data.metadata or {})
            }
        )
        
        # Broadcast audit log
        audit_entry = AuditLogEntry(
            id=f"audit_{datetime.utcnow().timestamp()}",
            timestamp=datetime.utcnow(),
            action="key_created",
            key_name=key_data.name,
            user=current_user.username,
            ip_address=None,  # Would get from request in production
            details={"service": key_data.service}
        )
        await broadcast_audit_log(audit_entry)
        
        return KeyResponse(
            id=key_id,  # Use the returned key_id
            name=key_data.name,
            service=key_data.service,
            description=key_data.description,
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow(),
            last_accessed=None,
            rotation_due=None
        )
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.get("/api/keys/{key_id}")
async def get_key(
    key_id: str,
    current_user: User = Depends(get_current_user)
):
    """Get key metadata (not the actual key value)"""
    keys = storage.list_keys()
    key_data = next((k for k in keys if k.get("id") == key_id), None)
    
    if not key_data:
        raise HTTPException(status_code=404, detail="Key not found")
    
    return KeyResponse(
        id=key_data["name"],
        name=key_data["name"],
        service=key_data.get("service"),
        description=key_data.get("metadata", {}).get("description"),
        created_at=key_data.get("created_at", datetime.utcnow()),
        updated_at=key_data.get("updated_at", datetime.utcnow()),
        last_accessed=key_data.get("last_accessed"),
        rotation_due=key_data.get("rotation_due")
    )

@app.put("/api/keys/{key_id}")
async def update_key(
    key_id: str,
    key_update: KeyUpdate,
    current_user: User = Depends(get_current_user)
):
    """Update an existing key"""
    try:
        if key_update.value:
            # Update the key value
            storage.update_key(key_id, key_update.value)
        
        # Update metadata
        # Note: This would need to be implemented in the storage backend
        
        # Broadcast audit log
        audit_entry = AuditLogEntry(
            id=f"audit_{datetime.utcnow().timestamp()}",
            timestamp=datetime.utcnow(),
            action="key_updated",
            key_name=key_id,
            user=current_user.username,
            ip_address=None,
            details={"fields_updated": list(key_update.dict(exclude_unset=True).keys())}
        )
        await broadcast_audit_log(audit_entry)
        
        return {"message": "Key updated successfully"}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.delete("/api/keys/{key_id}")
async def delete_key(
    key_id: str,
    current_user: User = Depends(get_current_user)
):
    """Delete a key"""
    try:
        storage.delete_key(key_id)
        
        # Broadcast audit log
        audit_entry = AuditLogEntry(
            id=f"audit_{datetime.utcnow().timestamp()}",
            timestamp=datetime.utcnow(),
            action="key_deleted",
            key_name=key_id,
            user=current_user.username,
            ip_address=None,
            details={}
        )
        await broadcast_audit_log(audit_entry)
        
        return {"message": "Key deleted successfully"}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.post("/api/keys/{key_id}/rotate")
async def rotate_key(
    key_id: str,
    current_user: User = Depends(get_current_user)
):
    """Rotate a key"""
    try:
        new_key = storage.rotate_key(key_id)
        
        # Broadcast audit log
        audit_entry = AuditLogEntry(
            id=f"audit_{datetime.utcnow().timestamp()}",
            timestamp=datetime.utcnow(),
            action="key_rotated",
            key_name=key_id,
            user=current_user.username,
            ip_address=None,
            details={"success": True}
        )
        await broadcast_audit_log(audit_entry)
        
        return {"message": "Key rotated successfully", "new_key_preview": new_key[:8] + "..."}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

@app.post("/api/keys/{key_id}/copy")
async def copy_key(
    key_id: str,
    current_user: User = Depends(get_current_user)
):
    """Get the actual key value for copying to clipboard"""
    try:
        key_value = storage.get_key(key_id)
        
        # Broadcast audit log
        audit_entry = AuditLogEntry(
            id=f"audit_{datetime.utcnow().timestamp()}",
            timestamp=datetime.utcnow(),
            action="key_accessed",
            key_name=key_id,
            user=current_user.username,
            ip_address=None,
            details={"purpose": "copy_to_clipboard"}
        )
        await broadcast_audit_log(audit_entry)
        
        return {"key": key_value}
    except Exception as e:
        raise HTTPException(status_code=404, detail="Key not found")

# Audit log endpoints
@app.get("/api/audit", response_model=List[AuditLogEntry])
async def get_audit_logs(
    skip: int = 0,
    limit: int = 100,
    action: Optional[str] = None,
    key_name: Optional[str] = None,
    current_user: User = Depends(get_current_user)
):
    """Get audit logs with pagination and filtering"""
    # In a real implementation, this would query from a database
    # For now, returning mock data
    logs = []
    for i in range(5):
        logs.append(AuditLogEntry(
            id=f"audit_{i}",
            timestamp=datetime.utcnow() - timedelta(hours=i),
            action="key_accessed",
            key_name=f"test_key_{i}",
            user="admin",
            ip_address="127.0.0.1",
            details={"source": "dashboard"}
        ))
    
    return logs[skip:skip + limit]

@app.websocket("/api/audit/stream")
async def audit_stream(websocket: WebSocket):
    """WebSocket endpoint for real-time audit log streaming"""
    await websocket.accept()
    active_connections.append(websocket)
    try:
        while True:
            # Keep connection alive
            await websocket.receive_text()
    except WebSocketDisconnect:
        active_connections.remove(websocket)

# Analytics endpoints
@app.get("/api/analytics/overview", response_model=AnalyticsOverview)
async def get_analytics_overview(current_user: User = Depends(get_current_user)):
    """Get dashboard overview statistics"""
    keys = storage.list_keys()
    services = set(k.get("service", "unknown") for k in keys)
    
    # Mock data for demonstration
    recent_logs = []
    for i in range(5):
        recent_logs.append(AuditLogEntry(
            id=f"audit_{i}",
            timestamp=datetime.utcnow() - timedelta(hours=i),
            action="key_accessed",
            key_name=f"test_key_{i}",
            user="admin",
            ip_address="127.0.0.1",
            details={"source": "dashboard"}
        ))
    
    return AnalyticsOverview(
        total_keys=len(keys),
        total_services=len(services),
        keys_accessed_today=3,  # Mock data
        keys_rotated_this_month=2,  # Mock data
        upcoming_rotations=1,  # Mock data
        recent_activity=recent_logs
    )

# Health check
@app.get("/api/health")
async def health_check():
    return {
        "status": "healthy", 
        "timestamp": datetime.utcnow(),
        "master_password_set": bool(os.environ.get("API_KEY_MASTER")),
        "jwt_secret_set": bool(os.environ.get("JWT_SECRET_KEY")),
        "storage_available": STORAGE_AVAILABLE
    }

# Debug endpoint (remove in production)
@app.post("/api/debug/test-login")
async def debug_test_login(password: str = "test"):
    """Debug endpoint to test login without OAuth2 form"""
    master_password = os.environ.get("MASTER_PASSWORD", os.environ.get("API_KEY_MASTER"))
    return {
        "master_password_set": bool(master_password),
        "password_matches": password == master_password if master_password else False,
        "password_length": len(password),
        "master_length": len(master_password) if master_password else 0
    }

# Startup event
@app.on_event("startup")
async def startup_event():
    print("=" * 50)
    print("Secure API Key Storage Dashboard - Backend")
    print("=" * 50)
    print(f"Master password configured: {bool(os.environ.get('MASTER_PASSWORD', os.environ.get('API_KEY_MASTER')))}")
    print(f"JWT secret configured: {bool(os.environ.get('JWT_SECRET_KEY'))}")
    print(f"CORS origins: {os.environ.get('CORS_ORIGINS', 'http://localhost:3000')}")
    print(f"Enhanced authentication: {ENHANCED_AUTH_AVAILABLE}")
    if ENHANCED_AUTH_AVAILABLE:
        print("Features: User management, 2FA (TOTP), Certificate auth, Audit logging")
    print("=" * 50)

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)