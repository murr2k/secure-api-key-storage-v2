"""
Enhanced Secure API Key Storage Dashboard with RBAC
Backend API with integrated Role-Based Access Control
"""

import os
import sys
from datetime import datetime, timedelta
from typing import List, Optional, Dict, Any
from pathlib import Path

from fastapi import FastAPI, Depends, HTTPException, status, WebSocket, WebSocketDisconnect, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordRequestForm
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from jose import JWTError, jwt
from passlib.context import CryptContext
from dotenv import load_dotenv
import uvicorn

# Load environment variables
load_dotenv()

# Add parent directory to path
sys.path.append(str(Path(__file__).parent.parent.parent / "src"))

# Import middleware
from middleware import (
    SecurityHeadersMiddleware,
    RateLimitMiddleware,
    RequestLoggingMiddleware,
    CSRFMiddleware
)

# Import RBAC components
from rbac_integration import (
    rbac_manager, secure_storage, get_current_user, require_permission,
    create_access_token, log_rbac_action, CurrentUser, Role, Permission
)
from rbac_endpoints import router as rbac_router

# FastAPI app
app = FastAPI(
    title="Secure API Key Storage Dashboard with RBAC",
    description="Web API for managing encrypted API keys with Role-Based Access Control",
    version="2.0.0"
)

# Add middleware
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(RateLimitMiddleware, calls=100, period=60)
app.add_middleware(RequestLoggingMiddleware)
app.add_middleware(CSRFMiddleware)

# CORS configuration
cors_origins = os.environ.get("CORS_ORIGINS", "http://localhost:3000").split(",")
app.add_middleware(
    CORSMiddleware,
    allow_origins=cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include RBAC router
app.include_router(rbac_router)

# WebSocket connections for real-time updates
active_connections: List[WebSocket] = []

# Pydantic models
class Token(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"

class KeyCreate(BaseModel):
    name: str
    value: str
    service: Optional[str] = None
    description: Optional[str] = None
    metadata: Optional[Dict[str, Any]] = None
    shared_with: Optional[List[Dict[str, Any]]] = None  # [{"user_id": 1, "permissions": ["key:read"]}]

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
    owner: str
    shared_with_count: int = 0
    user_can_update: bool = False
    user_can_delete: bool = False
    user_can_rotate: bool = False

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
    my_keys: int
    shared_keys: int
    total_services: int
    keys_accessed_today: int
    keys_rotated_this_month: int
    upcoming_rotations: int
    recent_activity: List[AuditLogEntry]

# Helper functions
def create_refresh_token(user_id: int, username: str, role: str) -> str:
    """Create JWT refresh token"""
    to_encode = {
        "sub": str(user_id),
        "username": username,
        "role": role,
        "exp": datetime.utcnow() + timedelta(days=7),
        "type": "refresh"
    }
    return jwt.encode(to_encode, os.environ.get("JWT_SECRET_KEY"), algorithm="HS256")

async def broadcast_audit_log(entry: AuditLogEntry):
    """Broadcast audit log entry to all connected WebSocket clients"""
    for connection in active_connections:
        try:
            await connection.send_json(entry.dict())
        except:
            active_connections.remove(connection)

# Authentication endpoints
@app.post("/api/auth/login", response_model=Token)
async def login(form_data: OAuth2PasswordRequestForm = Depends(), request: Request = None):
    """Authenticate user with username and password"""
    # Authenticate user through RBAC
    auth_result = rbac_manager.authenticate_user(form_data.username, form_data.password)
    
    if not auth_result:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    user_id, role = auth_result
    
    # Create tokens
    access_token = create_access_token(user_id, form_data.username, role.value)
    refresh_token = create_refresh_token(user_id, form_data.username, role.value)
    
    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "bearer"
    }

@app.post("/api/auth/refresh", response_model=Token)
async def refresh_token(refresh_token: str):
    """Refresh access token using refresh token"""
    try:
        payload = jwt.decode(
            refresh_token, 
            os.environ.get("JWT_SECRET_KEY"), 
            algorithms=["HS256"]
        )
        
        user_id = int(payload.get("sub"))
        username = payload.get("username")
        role = payload.get("role")
        token_type = payload.get("type")
        
        if not all([user_id, username, role]) or token_type != "refresh":
            raise HTTPException(status_code=401, detail="Invalid refresh token")
            
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid refresh token")
    
    # Create new tokens
    access_token = create_access_token(user_id, username, role)
    new_refresh_token = create_refresh_token(user_id, username, role)
    
    return {
        "access_token": access_token,
        "refresh_token": new_refresh_token,
        "token_type": "bearer"
    }

@app.post("/api/auth/logout")
async def logout(current_user: CurrentUser = Depends(get_current_user)):
    """Logout current user"""
    # In a production app, you would invalidate the token here
    return {"message": "Successfully logged out"}

@app.get("/api/auth/session")
async def get_session(current_user: CurrentUser = Depends(get_current_user)):
    """Get current user session information"""
    return {
        "id": current_user.id,
        "username": current_user.username,
        "role": current_user.role.value,
        "permissions": current_user.permissions
    }

# Key management endpoints with RBAC
@app.get("/api/keys", response_model=List[KeyResponse])
async def list_keys(
    service: Optional[str] = None,
    search: Optional[str] = None,
    include_shared: bool = True,
    current_user: CurrentUser = Depends(get_current_user)
):
    """List all keys accessible to the current user"""
    try:
        # Get keys through RBAC-enabled storage
        keys = secure_storage.list_keys_with_rbac(
            user_id=current_user.id,
            include_inactive=False
        )
        
        # Filter by service if provided
        if service:
            keys = [k for k in keys if k.get("service") == service]
        
        # Search in key names and descriptions
        if search:
            search_lower = search.lower()
            keys = [
                k for k in keys 
                if search_lower in k.get("key_id", "").lower() or 
                   search_lower in k.get("service", "").lower() or
                   search_lower in str(k.get("metadata", {}).get("description", "")).lower()
            ]
        
        # Convert to response format with RBAC info
        response_keys = []
        for key in keys:
            # Check user permissions for this key
            can_update = rbac_manager.check_permission(
                current_user.id, Permission.KEY_UPDATE, key["key_id"]
            )
            can_delete = rbac_manager.check_permission(
                current_user.id, Permission.KEY_DELETE, key["key_id"]
            )
            can_rotate = rbac_manager.check_permission(
                current_user.id, Permission.KEY_ROTATE, key["key_id"]
            )
            
            # Get share count
            try:
                access_list = secure_storage.get_key_access_list(
                    key["key_id"], current_user.id
                )
                shared_count = len(access_list) - 1  # Exclude owner
            except:
                shared_count = 0
            
            response_keys.append(KeyResponse(
                id=key["key_id"],
                name=key["service"],
                service=key.get("service"),
                description=key.get("metadata", {}).get("description"),
                created_at=datetime.fromisoformat(key["created_at"]),
                updated_at=datetime.fromisoformat(key.get("updated_at", key["created_at"])),
                last_accessed=datetime.fromisoformat(key["last_accessed"]) if key.get("last_accessed") else None,
                rotation_due=None,  # Can be calculated based on policy
                owner=key["user"],
                shared_with_count=shared_count,
                user_can_update=can_update,
                user_can_delete=can_delete,
                user_can_rotate=can_rotate
            ))
        
        return response_keys
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )

@app.post("/api/keys", response_model=KeyResponse)
async def create_key(
    key_data: KeyCreate,
    request: Request,
    current_user: CurrentUser = Depends(require_permission(Permission.KEY_CREATE))
):
    """Create a new API key"""
    try:
        # Parse shared_with data
        shared_with = []
        if key_data.shared_with:
            for share in key_data.shared_with:
                user_id = share.get("user_id")
                perms = share.get("permissions", [])
                
                # Convert permission strings to Permission enums
                permissions = []
                for perm_str in perms:
                    try:
                        permissions.append(Permission(perm_str))
                    except ValueError:
                        raise HTTPException(
                            status_code=status.HTTP_400_BAD_REQUEST,
                            detail=f"Invalid permission: {perm_str}"
                        )
                
                shared_with.append((user_id, permissions))
        
        # Create key with RBAC
        key_id = secure_storage.add_api_key_with_rbac(
            service=key_data.name,
            api_key=key_data.value,
            user_id=current_user.id,
            metadata={
                "description": key_data.description,
                "service": key_data.service,
                **(key_data.metadata or {})
            },
            shared_with=shared_with
        )
        
        # Log action
        log_rbac_action(
            current_user, "key_created", "key", key_id,
            success=True, request=request,
            details={"service": key_data.service}
        )
        
        # Broadcast audit log
        audit_entry = AuditLogEntry(
            id=f"audit_{datetime.utcnow().timestamp()}",
            timestamp=datetime.utcnow(),
            action="key_created",
            key_name=key_data.name,
            user=current_user.username,
            ip_address=request.client.host if request.client else None,
            details={"service": key_data.service}
        )
        await broadcast_audit_log(audit_entry)
        
        return KeyResponse(
            id=key_id,
            name=key_data.name,
            service=key_data.service,
            description=key_data.description,
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow(),
            last_accessed=None,
            rotation_due=None,
            owner=current_user.username,
            shared_with_count=len(shared_with),
            user_can_update=True,
            user_can_delete=True,
            user_can_rotate=True
        )
        
    except Exception as e:
        log_rbac_action(
            current_user, "key_create_failed", "key", None,
            success=False, request=request,
            details={"error": str(e)}
        )
        raise HTTPException(status_code=400, detail=str(e))

@app.get("/api/keys/{key_id}")
async def get_key(
    key_id: str,
    current_user: CurrentUser = Depends(get_current_user)
):
    """Get key metadata (not the actual key value)"""
    # Check read permission
    if not rbac_manager.check_permission(current_user.id, Permission.KEY_READ, key_id):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied for this key"
        )
    
    keys = secure_storage.list_keys_with_rbac(current_user.id)
    key_data = next((k for k in keys if k["key_id"] == key_id), None)
    
    if not key_data:
        raise HTTPException(status_code=404, detail="Key not found")
    
    # Get permissions and share info
    can_update = rbac_manager.check_permission(current_user.id, Permission.KEY_UPDATE, key_id)
    can_delete = rbac_manager.check_permission(current_user.id, Permission.KEY_DELETE, key_id)
    can_rotate = rbac_manager.check_permission(current_user.id, Permission.KEY_ROTATE, key_id)
    
    try:
        access_list = secure_storage.get_key_access_list(key_id, current_user.id)
        shared_count = len(access_list) - 1
    except:
        shared_count = 0
    
    return KeyResponse(
        id=key_data["key_id"],
        name=key_data["service"],
        service=key_data.get("service"),
        description=key_data.get("metadata", {}).get("description"),
        created_at=datetime.fromisoformat(key_data["created_at"]),
        updated_at=datetime.fromisoformat(key_data.get("updated_at", key_data["created_at"])),
        last_accessed=datetime.fromisoformat(key_data["last_accessed"]) if key_data.get("last_accessed") else None,
        rotation_due=None,
        owner=key_data["user"],
        shared_with_count=shared_count,
        user_can_update=can_update,
        user_can_delete=can_delete,
        user_can_rotate=can_rotate
    )

@app.put("/api/keys/{key_id}")
async def update_key(
    key_id: str,
    key_update: KeyUpdate,
    request: Request,
    current_user: CurrentUser = Depends(get_current_user)
):
    """Update an existing key"""
    # Check update permission
    if not rbac_manager.check_permission(current_user.id, Permission.KEY_UPDATE, key_id):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied: cannot update this key"
        )
    
    try:
        if key_update.value:
            # Update the key value
            secure_storage.update_api_key_with_rbac(
                key_id, key_update.value, current_user.id
            )
        
        # Update metadata (would need to be implemented in storage)
        # For now, log the attempt
        
        # Log action
        log_rbac_action(
            current_user, "key_updated", "key", key_id,
            success=True, request=request,
            details={"fields_updated": list(key_update.dict(exclude_unset=True).keys())}
        )
        
        # Broadcast audit log
        audit_entry = AuditLogEntry(
            id=f"audit_{datetime.utcnow().timestamp()}",
            timestamp=datetime.utcnow(),
            action="key_updated",
            key_name=key_id,
            user=current_user.username,
            ip_address=request.client.host if request.client else None,
            details={"fields_updated": list(key_update.dict(exclude_unset=True).keys())}
        )
        await broadcast_audit_log(audit_entry)
        
        return {"message": "Key updated successfully"}
        
    except Exception as e:
        log_rbac_action(
            current_user, "key_update_failed", "key", key_id,
            success=False, request=request,
            details={"error": str(e)}
        )
        raise HTTPException(status_code=400, detail=str(e))

@app.delete("/api/keys/{key_id}")
async def delete_key(
    key_id: str,
    request: Request,
    current_user: CurrentUser = Depends(get_current_user)
):
    """Delete a key"""
    # Check delete permission
    if not rbac_manager.check_permission(current_user.id, Permission.KEY_DELETE, key_id):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied: cannot delete this key"
        )
    
    try:
        secure_storage.revoke_key_with_rbac(key_id, current_user.id)
        
        # Log action
        log_rbac_action(
            current_user, "key_deleted", "key", key_id,
            success=True, request=request
        )
        
        # Broadcast audit log
        audit_entry = AuditLogEntry(
            id=f"audit_{datetime.utcnow().timestamp()}",
            timestamp=datetime.utcnow(),
            action="key_deleted",
            key_name=key_id,
            user=current_user.username,
            ip_address=request.client.host if request.client else None,
            details={}
        )
        await broadcast_audit_log(audit_entry)
        
        return {"message": "Key deleted successfully"}
        
    except Exception as e:
        log_rbac_action(
            current_user, "key_delete_failed", "key", key_id,
            success=False, request=request,
            details={"error": str(e)}
        )
        raise HTTPException(status_code=400, detail=str(e))

@app.post("/api/keys/{key_id}/rotate")
async def rotate_key(
    key_id: str,
    new_key: Dict[str, str],
    request: Request,
    current_user: CurrentUser = Depends(get_current_user)
):
    """Rotate a key"""
    # Check rotate permission
    if not rbac_manager.check_permission(current_user.id, Permission.KEY_ROTATE, key_id):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied: cannot rotate this key"
        )
    
    try:
        new_api_key = new_key.get("new_key")
        if not new_api_key:
            raise ValueError("New key value is required")
        
        secure_storage.rotate_key_with_rbac(key_id, new_api_key, current_user.id)
        
        # Log action
        log_rbac_action(
            current_user, "key_rotated", "key", key_id,
            success=True, request=request
        )
        
        # Broadcast audit log
        audit_entry = AuditLogEntry(
            id=f"audit_{datetime.utcnow().timestamp()}",
            timestamp=datetime.utcnow(),
            action="key_rotated",
            key_name=key_id,
            user=current_user.username,
            ip_address=request.client.host if request.client else None,
            details={"success": True}
        )
        await broadcast_audit_log(audit_entry)
        
        return {"message": "Key rotated successfully", "new_key_preview": new_api_key[:8] + "..."}
        
    except Exception as e:
        log_rbac_action(
            current_user, "key_rotate_failed", "key", key_id,
            success=False, request=request,
            details={"error": str(e)}
        )
        raise HTTPException(status_code=400, detail=str(e))

@app.post("/api/keys/{key_id}/copy")
async def copy_key(
    key_id: str,
    request: Request,
    current_user: CurrentUser = Depends(get_current_user)
):
    """Get the actual key value for copying to clipboard"""
    # Check read permission
    if not rbac_manager.check_permission(current_user.id, Permission.KEY_READ, key_id):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied: cannot read this key"
        )
    
    try:
        key_value = secure_storage.get_api_key_with_rbac(key_id, current_user.id)
        
        # Log action
        log_rbac_action(
            current_user, "key_accessed", "key", key_id,
            success=True, request=request,
            details={"purpose": "copy_to_clipboard"}
        )
        
        # Broadcast audit log
        audit_entry = AuditLogEntry(
            id=f"audit_{datetime.utcnow().timestamp()}",
            timestamp=datetime.utcnow(),
            action="key_accessed",
            key_name=key_id,
            user=current_user.username,
            ip_address=request.client.host if request.client else None,
            details={"purpose": "copy_to_clipboard"}
        )
        await broadcast_audit_log(audit_entry)
        
        return {"key": key_value}
        
    except Exception as e:
        log_rbac_action(
            current_user, "key_access_failed", "key", key_id,
            success=False, request=request,
            details={"error": str(e)}
        )
        raise HTTPException(status_code=404, detail="Key not found or access denied")

# Audit log endpoints
@app.get("/api/audit", response_model=List[AuditLogEntry])
async def get_audit_logs(
    skip: int = 0,
    limit: int = 100,
    action: Optional[str] = None,
    key_name: Optional[str] = None,
    current_user: CurrentUser = Depends(require_permission(Permission.AUDIT_READ))
):
    """Get combined audit logs from storage and RBAC systems"""
    # Get RBAC audit logs
    rbac_logs = rbac_manager.get_audit_logs(limit=limit)
    
    # Convert to response format
    logs = []
    for log in rbac_logs[skip:]:
        logs.append(AuditLogEntry(
            id=str(log["id"]),
            timestamp=datetime.fromisoformat(log["timestamp"]),
            action=log["action"],
            key_name=log.get("resource_id") if log.get("resource_type") == "key" else None,
            user=log["username"] or f"user_{log['user_id']}",
            ip_address=log["ip_address"],
            details=log.get("details", {})
        ))
    
    # Filter if needed
    if action:
        logs = [l for l in logs if l.action == action]
    if key_name:
        logs = [l for l in logs if l.key_name == key_name]
    
    return logs

@app.websocket("/api/audit/stream")
async def audit_stream(websocket: WebSocket):
    """WebSocket endpoint for real-time audit log streaming"""
    await websocket.accept()
    active_connections.append(websocket)
    try:
        while True:
            await websocket.receive_text()
    except WebSocketDisconnect:
        active_connections.remove(websocket)

# Analytics endpoints
@app.get("/api/analytics/overview", response_model=AnalyticsOverview)
async def get_analytics_overview(current_user: CurrentUser = Depends(get_current_user)):
    """Get dashboard overview statistics"""
    try:
        # Get all keys accessible to user
        all_keys = secure_storage.list_keys_with_rbac(current_user.id)
        
        # Count keys by ownership
        my_keys = [k for k in all_keys if k["user"] == current_user.username]
        shared_keys = [k for k in all_keys if k["user"] != current_user.username]
        
        # Get unique services
        services = set(k.get("service", "unknown") for k in all_keys)
        
        # Get recent activity
        recent_logs = rbac_manager.get_audit_logs(user_id=current_user.id, limit=10)
        recent_activity = []
        
        for log in recent_logs:
            recent_activity.append(AuditLogEntry(
                id=str(log["id"]),
                timestamp=datetime.fromisoformat(log["timestamp"]),
                action=log["action"],
                key_name=log.get("resource_id") if log.get("resource_type") == "key" else None,
                user=log["username"] or f"user_{log['user_id']}",
                ip_address=log["ip_address"],
                details=log.get("details", {})
            ))
        
        # Calculate access stats (mock data for now)
        keys_accessed_today = 0
        keys_rotated_this_month = 0
        upcoming_rotations = 0
        
        # Count today's accesses
        today = datetime.utcnow().date()
        for key in all_keys:
            if key.get("last_accessed"):
                last_access = datetime.fromisoformat(key["last_accessed"]).date()
                if last_access == today:
                    keys_accessed_today += 1
        
        return AnalyticsOverview(
            total_keys=len(all_keys),
            my_keys=len(my_keys),
            shared_keys=len(shared_keys),
            total_services=len(services),
            keys_accessed_today=keys_accessed_today,
            keys_rotated_this_month=keys_rotated_this_month,
            upcoming_rotations=upcoming_rotations,
            recent_activity=recent_activity
        )
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )

# Health check
@app.get("/api/health")
async def health_check():
    """System health check"""
    return {
        "status": "healthy",
        "timestamp": datetime.utcnow(),
        "rbac_enabled": True,
        "storage_available": True,
        "version": "2.0.0"
    }

# Startup event
@app.on_event("startup")
async def startup_event():
    """Initialize system on startup"""
    print("=" * 60)
    print("Secure API Key Storage Dashboard with RBAC")
    print("=" * 60)
    print(f"RBAC System: Enabled")
    print(f"Default Admin: Created (check logs for credentials)")
    print(f"Storage Path: {os.environ.get('STORAGE_PATH', './keys')}")
    print(f"CORS Origins: {os.environ.get('CORS_ORIGINS', 'http://localhost:3000')}")
    print("=" * 60)
    print("Security Features:")
    print("- Role-Based Access Control (Admin, User, Viewer)")
    print("- Granular key permissions")
    print("- Per-key access policies")
    print("- Comprehensive audit logging")
    print("=" * 60)

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)