"""
RBAC-specific API endpoints for user and permission management
"""

from typing import List, Optional
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, status, Request
from pydantic import BaseModel

from rbac_integration import (
    rbac_manager, secure_storage, get_current_user, require_permission,
    require_role, log_rbac_action, UserCreate, UserUpdate, UserResponse,
    PermissionGrant, CurrentUser, Role, Permission
)


# Create router for RBAC endpoints
router = APIRouter(prefix="/api/rbac", tags=["rbac"])


# Additional Pydantic models
class KeyAccessResponse(BaseModel):
    user_id: int
    username: str
    role: str
    permissions: List[str]
    granted_at: datetime
    expires_at: Optional[datetime]


class AuditLogResponse(BaseModel):
    id: int
    timestamp: datetime
    user_id: Optional[int]
    username: Optional[str]
    action: str
    resource_type: Optional[str]
    resource_id: Optional[str]
    permission_used: Optional[str]
    success: bool
    ip_address: Optional[str]
    details: Optional[dict]


# User management endpoints
@router.post("/users", response_model=UserResponse)
async def create_user(
    user_data: UserCreate,
    request: Request,
    current_user: CurrentUser = Depends(require_permission(Permission.USER_CREATE))
):
    """Create a new user (admin only)"""
    try:
        # Validate role
        try:
            role = Role(user_data.role)
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid role: {user_data.role}"
            )
        
        # Create user
        user_id = rbac_manager.create_user(
            username=user_data.username,
            password=user_data.password,
            role=role,
            email=user_data.email,
            metadata=user_data.metadata
        )
        
        # Log action
        log_rbac_action(
            current_user, "user_created", "user", str(user_id),
            success=True, request=request,
            details={"new_user": user_data.username, "role": role.value}
        )
        
        # Get user details
        import sqlite3
        conn = sqlite3.connect(rbac_manager.db_path)
        cursor = conn.cursor()
        cursor.execute("""
            SELECT id, username, role, email, created_at, last_login, is_active
            FROM users WHERE id = ?
        """, (user_id,))
        user = cursor.fetchone()
        conn.close()
        
        return UserResponse(
            id=user[0],
            username=user[1],
            role=user[2],
            email=user[3],
            created_at=datetime.fromisoformat(user[4]),
            last_login=datetime.fromisoformat(user[5]) if user[5] else None,
            is_active=bool(user[6])
        )
        
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(e)
        )
    except Exception as e:
        log_rbac_action(
            current_user, "user_create_failed", "user", None,
            success=False, request=request,
            details={"error": str(e)}
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to create user: {str(e)}"
        )


@router.get("/users", response_model=List[UserResponse])
async def list_users(
    skip: int = 0,
    limit: int = 100,
    current_user: CurrentUser = Depends(require_permission(Permission.USER_LIST))
):
    """List all users (admin only)"""
    import sqlite3
    conn = sqlite3.connect(rbac_manager.db_path)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    cursor.execute("""
        SELECT id, username, role, email, created_at, last_login, is_active
        FROM users
        ORDER BY created_at DESC
        LIMIT ? OFFSET ?
    """, (limit, skip))
    
    users = []
    for row in cursor.fetchall():
        users.append(UserResponse(
            id=row["id"],
            username=row["username"],
            role=row["role"],
            email=row["email"],
            created_at=datetime.fromisoformat(row["created_at"]),
            last_login=datetime.fromisoformat(row["last_login"]) if row["last_login"] else None,
            is_active=bool(row["is_active"])
        ))
    
    conn.close()
    return users


@router.get("/users/me", response_model=UserResponse)
async def get_current_user_info(
    current_user: CurrentUser = Depends(get_current_user)
):
    """Get current user information"""
    import sqlite3
    conn = sqlite3.connect(rbac_manager.db_path)
    cursor = conn.cursor()
    
    cursor.execute("""
        SELECT id, username, role, email, created_at, last_login, is_active
        FROM users WHERE id = ?
    """, (current_user.id,))
    
    user = cursor.fetchone()
    conn.close()
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    return UserResponse(
        id=user[0],
        username=user[1],
        role=user[2],
        email=user[3],
        created_at=datetime.fromisoformat(user[4]),
        last_login=datetime.fromisoformat(user[5]) if user[5] else None,
        is_active=bool(user[6])
    )


@router.get("/users/{user_id}", response_model=UserResponse)
async def get_user(
    user_id: int,
    current_user: CurrentUser = Depends(require_permission(Permission.USER_READ))
):
    """Get user by ID"""
    import sqlite3
    conn = sqlite3.connect(rbac_manager.db_path)
    cursor = conn.cursor()
    
    cursor.execute("""
        SELECT id, username, role, email, created_at, last_login, is_active
        FROM users WHERE id = ?
    """, (user_id,))
    
    user = cursor.fetchone()
    conn.close()
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    return UserResponse(
        id=user[0],
        username=user[1],
        role=user[2],
        email=user[3],
        created_at=datetime.fromisoformat(user[4]),
        last_login=datetime.fromisoformat(user[5]) if user[5] else None,
        is_active=bool(user[6])
    )


@router.patch("/users/{user_id}")
async def update_user(
    user_id: int,
    user_update: UserUpdate,
    request: Request,
    current_user: CurrentUser = Depends(require_permission(Permission.USER_UPDATE))
):
    """Update user information (admin only)"""
    import sqlite3
    conn = sqlite3.connect(rbac_manager.db_path)
    cursor = conn.cursor()
    
    # Build update query
    updates = []
    params = []
    
    if user_update.role is not None:
        try:
            Role(user_update.role)  # Validate role
            updates.append("role = ?")
            params.append(user_update.role)
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid role: {user_update.role}"
            )
    
    if user_update.email is not None:
        updates.append("email = ?")
        params.append(user_update.email)
    
    if user_update.is_active is not None:
        updates.append("is_active = ?")
        params.append(int(user_update.is_active))
    
    if not updates:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="No fields to update"
        )
    
    # Add updated_at
    updates.append("updated_at = CURRENT_TIMESTAMP")
    params.append(user_id)
    
    # Execute update
    query = f"UPDATE users SET {', '.join(updates)} WHERE id = ?"
    cursor.execute(query, params)
    
    if cursor.rowcount == 0:
        conn.close()
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    conn.commit()
    conn.close()
    
    # Log action
    log_rbac_action(
        current_user, "user_updated", "user", str(user_id),
        success=True, request=request,
        details={"updates": user_update.dict(exclude_unset=True)}
    )
    
    return {"message": "User updated successfully"}


@router.delete("/users/{user_id}")
async def delete_user(
    user_id: int,
    request: Request,
    current_user: CurrentUser = Depends(require_permission(Permission.USER_DELETE))
):
    """Delete user (admin only)"""
    if user_id == current_user.id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot delete your own account"
        )
    
    import sqlite3
    conn = sqlite3.connect(rbac_manager.db_path)
    cursor = conn.cursor()
    
    # Check if user exists
    cursor.execute("SELECT username FROM users WHERE id = ?", (user_id,))
    user = cursor.fetchone()
    
    if not user:
        conn.close()
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    username = user[0]
    
    # Delete user (cascades to related tables)
    cursor.execute("DELETE FROM users WHERE id = ?", (user_id,))
    conn.commit()
    conn.close()
    
    # Log action
    log_rbac_action(
        current_user, "user_deleted", "user", str(user_id),
        success=True, request=request,
        details={"deleted_user": username}
    )
    
    return {"message": "User deleted successfully"}


# Key access management endpoints
@router.post("/keys/{key_id}/grant-access")
async def grant_key_access(
    key_id: str,
    grant_data: PermissionGrant,
    request: Request,
    current_user: CurrentUser = Depends(get_current_user)
):
    """Grant access to a key for another user"""
    try:
        # Convert permission strings to Permission enums
        permissions = []
        for perm_str in grant_data.permissions:
            try:
                permissions.append(Permission(perm_str))
            except ValueError:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Invalid permission: {perm_str}"
                )
        
        # Grant access through secure storage
        secure_storage.grant_key_access(
            key_id=key_id,
            granting_user_id=current_user.id,
            target_user_id=grant_data.user_id,
            permissions=permissions,
            expires_at=grant_data.expires_at
        )
        
        # Log action
        log_rbac_action(
            current_user, "key_access_granted", "key", key_id,
            success=True, request=request,
            details={
                "target_user_id": grant_data.user_id,
                "permissions": grant_data.permissions
            }
        )
        
        return {"message": "Access granted successfully"}
        
    except Exception as e:
        log_rbac_action(
            current_user, "key_access_grant_failed", "key", key_id,
            success=False, request=request,
            details={"error": str(e)}
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )


@router.delete("/keys/{key_id}/revoke-access/{user_id}")
async def revoke_key_access(
    key_id: str,
    user_id: int,
    request: Request,
    current_user: CurrentUser = Depends(get_current_user)
):
    """Revoke access to a key from a user"""
    try:
        # Revoke access through secure storage
        secure_storage.revoke_key_access(
            key_id=key_id,
            revoking_user_id=current_user.id,
            target_user_id=user_id
        )
        
        # Log action
        log_rbac_action(
            current_user, "key_access_revoked", "key", key_id,
            success=True, request=request,
            details={"target_user_id": user_id}
        )
        
        return {"message": "Access revoked successfully"}
        
    except Exception as e:
        log_rbac_action(
            current_user, "key_access_revoke_failed", "key", key_id,
            success=False, request=request,
            details={"error": str(e)}
        )
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )


@router.get("/keys/{key_id}/access", response_model=List[KeyAccessResponse])
async def get_key_access_list(
    key_id: str,
    current_user: CurrentUser = Depends(get_current_user)
):
    """Get list of users with access to a key"""
    try:
        access_list = secure_storage.get_key_access_list(key_id, current_user.id)
        
        response_list = []
        for access in access_list:
            response_list.append(KeyAccessResponse(
                user_id=access["user_id"],
                username=access["username"],
                role=access["role"],
                permissions=access["permissions"],
                granted_at=datetime.fromisoformat(access["granted_at"]),
                expires_at=datetime.fromisoformat(access["expires_at"]) if access["expires_at"] else None
            ))
        
        return response_list
        
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=str(e)
        )


# Audit log endpoints
@router.get("/audit", response_model=List[AuditLogResponse])
async def get_rbac_audit_logs(
    skip: int = 0,
    limit: int = 100,
    user_id: Optional[int] = None,
    current_user: CurrentUser = Depends(require_permission(Permission.AUDIT_READ))
):
    """Get RBAC audit logs"""
    logs = rbac_manager.get_audit_logs(user_id=user_id, limit=limit)
    
    # Skip to the requested offset
    logs = logs[skip:]
    
    response_logs = []
    for log in logs:
        response_logs.append(AuditLogResponse(
            id=log["id"],
            timestamp=datetime.fromisoformat(log["timestamp"]),
            user_id=log["user_id"],
            username=log["username"],
            action=log["action"],
            resource_type=log["resource_type"],
            resource_id=log["resource_id"],
            permission_used=log["permission_used"],
            success=bool(log["success"]),
            ip_address=log["ip_address"],
            details=log.get("details", {})
        ))
    
    return response_logs


@router.get("/permissions")
async def get_available_permissions(
    current_user: CurrentUser = Depends(get_current_user)
):
    """Get list of all available permissions"""
    permissions = {}
    
    # Group permissions by category
    for perm in Permission:
        category, action = perm.value.split(":", 1)
        if category not in permissions:
            permissions[category] = []
        permissions[category].append({
            "value": perm.value,
            "action": action,
            "description": f"Permission to {action} {category}"
        })
    
    return permissions


@router.get("/roles")
async def get_available_roles(
    current_user: CurrentUser = Depends(get_current_user)
):
    """Get list of all available roles with their permissions"""
    from rbac_models import ROLE_PERMISSIONS
    
    roles = []
    for role in Role:
        role_perms = ROLE_PERMISSIONS.get(role, set())
        roles.append({
            "value": role.value,
            "name": role.name,
            "permissions": [p.value for p in role_perms],
            "description": f"{role.name} role with {len(role_perms)} permissions"
        })
    
    return roles


# Export router
__all__ = ['router']