"""
Role-Based Access Control (RBAC) Module (Lab 7 - Task 1.d)

Implements comprehensive RBAC with:
- Role definitions and permissions
- Permission verification decorators
- Access control for administrative functions
- User capability checking
"""

from functools import wraps
from typing import Callable, List, Optional
from fastapi import HTTPException, Request, Depends
from sqlalchemy.orm import Session
import logging

logger = logging.getLogger('security.rbac')


class Role:
    """Define user roles"""
    GUEST = 0  # Not logged in
    USER = 1  # Regular authenticated user
    MODERATOR = 2  # Moderator with additional privileges
    ADMIN = 3  # Full administrative access

    @staticmethod
    def get_role_name(role_id: int) -> str:
        """Get human-readable role name"""
        role_names = {
            Role.GUEST: "Guest",
            Role.USER: "User",
            Role.MODERATOR: "Moderator",
            Role.ADMIN: "Administrator"
        }
        return role_names.get(role_id, "Unknown")


class Permission:
    """Define granular permissions"""

    # Content permissions
    CREATE_POST = "create_post"
    EDIT_OWN_POST = "edit_own_post"
    DELETE_OWN_POST = "delete_own_post"
    DELETE_ANY_POST = "delete_any_post"

    CREATE_COMMENT = "create_comment"
    EDIT_OWN_COMMENT = "edit_own_comment"
    DELETE_OWN_COMMENT = "delete_own_comment"
    DELETE_ANY_COMMENT = "delete_any_comment"

    CREATE_THREAD = "create_thread"
    DELETE_OWN_THREAD = "delete_own_thread"
    DELETE_ANY_THREAD = "delete_any_thread"

    # User permissions
    VIEW_USER_LIST = "view_user_list"
    EDIT_ANY_USER = "edit_any_user"
    BAN_USER = "ban_user"

    # Administrative permissions
    ACCESS_ADMIN_PANEL = "access_admin_panel"
    VIEW_LOGS = "view_logs"
    MANAGE_ROLES = "manage_roles"

    # Rate limit exemptions
    BYPASS_RATE_LIMIT = "bypass_rate_limit"


# Role -> Permissions mapping
ROLE_PERMISSIONS = {
    Role.GUEST: [],

    Role.USER: [
        Permission.CREATE_POST,
        Permission.EDIT_OWN_POST,
        Permission.DELETE_OWN_POST,
        Permission.CREATE_COMMENT,
        Permission.EDIT_OWN_COMMENT,
        Permission.DELETE_OWN_COMMENT,
        Permission.CREATE_THREAD,
        Permission.DELETE_OWN_THREAD,
    ],

    Role.MODERATOR: [
        # All user permissions
        Permission.CREATE_POST,
        Permission.EDIT_OWN_POST,
        Permission.DELETE_OWN_POST,
        Permission.CREATE_COMMENT,
        Permission.EDIT_OWN_COMMENT,
        Permission.DELETE_OWN_COMMENT,
        Permission.CREATE_THREAD,
        Permission.DELETE_OWN_THREAD,
        # Additional moderator permissions
        Permission.DELETE_ANY_POST,
        Permission.DELETE_ANY_COMMENT,
        Permission.DELETE_ANY_THREAD,
    ],

    Role.ADMIN: [
        # All permissions
        Permission.CREATE_POST,
        Permission.EDIT_OWN_POST,
        Permission.DELETE_OWN_POST,
        Permission.DELETE_ANY_POST,
        Permission.CREATE_COMMENT,
        Permission.EDIT_OWN_COMMENT,
        Permission.DELETE_OWN_COMMENT,
        Permission.DELETE_ANY_COMMENT,
        Permission.CREATE_THREAD,
        Permission.DELETE_OWN_THREAD,
        Permission.DELETE_ANY_THREAD,
        Permission.VIEW_USER_LIST,
        Permission.EDIT_ANY_USER,
        Permission.BAN_USER,
        Permission.ACCESS_ADMIN_PANEL,
        Permission.VIEW_LOGS,
        Permission.MANAGE_ROLES,
        Permission.BYPASS_RATE_LIMIT,
    ]
}


class RBACManager:
    """Manages role-based access control"""

    @staticmethod
    def get_user_role(user) -> int:
        """
        Get user's role from user object

        Args:
            user: User object with is_admin attribute

        Returns:
            Role ID (from Role class)
        """
        if not user:
            return Role.GUEST

        # Map is_admin to role (backward compatibility)
        # is_admin = 1 means ADMIN
        # is_admin = 0 means USER
        if hasattr(user, 'role'):
            return user.role
        elif hasattr(user, 'is_admin'):
            return Role.ADMIN if user.is_admin == 1 else Role.USER
        else:
            return Role.USER

    @staticmethod
    def has_permission(user, permission: str) -> bool:
        """
        Check if user has specific permission

        Args:
            user: User object
            permission: Permission string from Permission class

        Returns:
            True if user has permission, False otherwise
        """
        if not user:
            return False

        role = RBACManager.get_user_role(user)
        permissions = ROLE_PERMISSIONS.get(role, [])

        has_perm = permission in permissions

        if not has_perm:
            logger.warning(
                f"Permission denied: user_id={user.id}, "
                f"username={user.username}, "
                f"role={Role.get_role_name(role)}, "
                f"permission={permission}"
            )

        return has_perm

    @staticmethod
    def has_any_permission(user, permissions: List[str]) -> bool:
        """
        Check if user has any of the specified permissions

        Args:
            user: User object
            permissions: List of permission strings

        Returns:
            True if user has at least one permission
        """
        return any(RBACManager.has_permission(user, perm) for perm in permissions)

    @staticmethod
    def has_all_permissions(user, permissions: List[str]) -> bool:
        """
        Check if user has all specified permissions

        Args:
            user: User object
            permissions: List of permission strings

        Returns:
            True if user has all permissions
        """
        return all(RBACManager.has_permission(user, perm) for perm in permissions)

    @staticmethod
    def is_owner_or_admin(user, resource_user_id: int) -> bool:
        """
        Check if user is the owner of a resource or an admin

        Args:
            user: User object
            resource_user_id: ID of the user who owns the resource

        Returns:
            True if user is owner or admin
        """
        if not user:
            return False

        # User is owner
        if user.id == resource_user_id:
            return True

        # User is admin
        return RBACManager.has_permission(user, Permission.DELETE_ANY_POST)

    @staticmethod
    def require_admin(user) -> None:
        """
        Raise exception if user is not admin

        Args:
            user: User object

        Raises:
            HTTPException: If user is not admin
        """
        if not user:
            raise HTTPException(status_code=401, detail="Authentication required")

        if not RBACManager.has_permission(user, Permission.ACCESS_ADMIN_PANEL):
            logger.warning(
                f"Unauthorized admin access attempt: user_id={user.id}, "
                f"username={user.username}"
            )
            raise HTTPException(
                status_code=403,
                detail="Administrative privileges required"
            )

    @staticmethod
    def require_permission(user, permission: str, resource_user_id: Optional[int] = None) -> None:
        """
        Raise exception if user doesn't have permission

        Args:
            user: User object
            permission: Required permission
            resource_user_id: Optional - if provided, also allows resource owner

        Raises:
            HTTPException: If user lacks permission
        """
        if not user:
            raise HTTPException(status_code=401, detail="Authentication required")

        # Check if user is resource owner (if resource_user_id provided)
        if resource_user_id and user.id == resource_user_id:
            return

        # Check permission
        if not RBACManager.has_permission(user, permission):
            raise HTTPException(
                status_code=403,
                detail=f"You don't have permission to perform this action"
            )


# Decorator functions for route protection

def require_auth(func: Callable) -> Callable:
    """
    Decorator to require authentication for a route

    Usage:
        @app.get("/protected")
        @require_auth
        async def protected_route(current_user = Depends(get_current_user)):
            return {"message": "You are authenticated"}
    """
    @wraps(func)
    async def wrapper(*args, **kwargs):
        # Check if current_user is in kwargs
        current_user = kwargs.get('current_user')
        if not current_user:
            raise HTTPException(status_code=401, detail="Authentication required")
        return await func(*args, **kwargs)
    return wrapper


def require_admin(func: Callable) -> Callable:
    """
    Decorator to require admin privileges for a route

    Usage:
        @app.delete("/admin/delete-post/{post_id}")
        @require_admin
        async def delete_post(post_id: int, current_user = Depends(get_current_user)):
            # Only admins can access this
            pass
    """
    @wraps(func)
    async def wrapper(*args, **kwargs):
        current_user = kwargs.get('current_user')
        if not current_user:
            raise HTTPException(status_code=401, detail="Authentication required")

        RBACManager.require_admin(current_user)
        return await func(*args, **kwargs)
    return wrapper


def require_permission(permission: str):
    """
    Decorator to require specific permission for a route

    Usage:
        @app.delete("/post/{post_id}")
        @require_permission(Permission.DELETE_ANY_POST)
        async def delete_post(post_id: int, current_user = Depends(get_current_user)):
            pass
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def wrapper(*args, **kwargs):
            current_user = kwargs.get('current_user')
            if not current_user:
                raise HTTPException(status_code=401, detail="Authentication required")

            RBACManager.require_permission(current_user, permission)
            return await func(*args, **kwargs)
        return wrapper
    return decorator


def require_owner_or_admin(resource_id_param: str = "post_id", user_id_field: str = "user_id"):
    """
    Decorator to require resource ownership or admin privileges

    Args:
        resource_id_param: Name of the parameter containing resource ID
        user_id_field: Field name in resource that contains owner user_id

    Usage:
        @app.delete("/post/{post_id}")
        @require_owner_or_admin(resource_id_param="post_id")
        async def delete_post(
            post_id: int,
            current_user = Depends(get_current_user),
            db: Session = Depends(get_db)
        ):
            pass
    """
    def decorator(func: Callable) -> Callable:
        @wraps(func)
        async def wrapper(*args, **kwargs):
            current_user = kwargs.get('current_user')
            if not current_user:
                raise HTTPException(status_code=401, detail="Authentication required")

            # Get resource ID from kwargs
            resource_id = kwargs.get(resource_id_param)
            if not resource_id:
                raise HTTPException(status_code=400, detail="Resource ID not provided")

            # Get database session
            db = kwargs.get('db')
            if not db:
                raise HTTPException(status_code=500, detail="Database session not available")

            # This would need to be customized per resource type
            # For now, just check if user is admin
            if not RBACManager.is_owner_or_admin(current_user, None):
                RBACManager.require_admin(current_user)

            return await func(*args, **kwargs)
        return wrapper
    return decorator


# Access control audit logging

class AccessControlAuditor:
    """Audit access control decisions"""

    @staticmethod
    def log_access_granted(user, resource_type: str, resource_id: int, action: str):
        """Log successful access"""
        logger.info(
            f"ACCESS GRANTED: user_id={user.id}, username={user.username}, "
            f"resource={resource_type}:{resource_id}, action={action}"
        )

    @staticmethod
    def log_access_denied(user, resource_type: str, resource_id: int, action: str, reason: str):
        """Log denied access"""
        logger.warning(
            f"ACCESS DENIED: user_id={user.id if user else 'anonymous'}, "
            f"username={user.username if user else 'anonymous'}, "
            f"resource={resource_type}:{resource_id}, action={action}, reason={reason}"
        )

    @staticmethod
    def log_privilege_escalation_attempt(user, attempted_action: str):
        """Log potential privilege escalation attempt"""
        logger.critical(
            f"PRIVILEGE ESCALATION ATTEMPT: user_id={user.id}, "
            f"username={user.username}, attempted_action={attempted_action}"
        )


__all__ = [
    'Role',
    'Permission',
    'RBACManager',
    'require_auth',
    'require_admin',
    'require_permission',
    'require_owner_or_admin',
    'AccessControlAuditor'
]
