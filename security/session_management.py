"""
Session Management Module

Provides session timeout and expiration checking middleware.
Implements secure session management with automatic session expiration.
"""

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import RedirectResponse
from datetime import datetime, timedelta


class SessionTimeoutMiddleware(BaseHTTPMiddleware):
    """
    Session Timeout Middleware

    Checks if a session has expired based on the last activity time.
    Sessions expire after a configurable period of inactivity.
    """

    def __init__(self, app, timeout_minutes: int = 30):
        """
        Initialize session timeout middleware.

        Args:
            app: The ASGI application
            timeout_minutes: Session timeout in minutes (default: 30)
        """
        super().__init__(app)
        self.timeout_seconds = timeout_minutes * 60

    async def dispatch(self, request: Request, call_next):
        # Skip session check for public endpoints
        public_paths = ['/login', '/register', '/health', '/static', '/uploads']
        if any(request.url.path.startswith(path) for path in public_paths):
            return await call_next(request)

        # Check if user is logged in
        user_id = request.session.get('user_id')
        if user_id:
            # Check last activity time
            last_activity = request.session.get('last_activity')

            if last_activity:
                try:
                    last_activity_time = datetime.fromisoformat(last_activity)
                    current_time = datetime.utcnow()

                    # Check if session has expired
                    if (current_time - last_activity_time).total_seconds() > self.timeout_seconds:
                        # Session expired, clear and redirect to login
                        request.session.clear()
                        return RedirectResponse(url='/login?error=Session expired. Please log in again.', status_code=303)
                except (ValueError, TypeError):
                    # Invalid datetime format, clear session
                    request.session.clear()
                    return RedirectResponse(url='/login', status_code=303)

            # Update last activity time
            request.session['last_activity'] = datetime.utcnow().isoformat()

        response = await call_next(request)
        return response


def init_session(request: Request, user_id: int, username: str):
    """
    Initialize a new user session with security metadata.

    Args:
        request: The current request object
        user_id: The user's database ID
        username: The user's username
    """
    request.session['user_id'] = user_id
    request.session['username'] = username
    request.session['created_at'] = datetime.utcnow().isoformat()
    request.session['last_activity'] = datetime.utcnow().isoformat()


def get_session_info(request: Request) -> dict:
    """
    Get information about the current session.

    Args:
        request: The current request object

    Returns:
        Dictionary with session information
    """
    return {
        'user_id': request.session.get('user_id'),
        'username': request.session.get('username'),
        'created_at': request.session.get('created_at'),
        'last_activity': request.session.get('last_activity')
    }
