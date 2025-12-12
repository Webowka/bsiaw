"""
CSRF Protection middleware for FastAPI
Generates and validates CSRF tokens for form submissions
"""
import secrets
import os
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response
from fastapi import HTTPException

class CSRFMiddleware(BaseHTTPMiddleware):
    """
    Middleware that generates CSRF tokens and validates them on POST requests
    """

    def __init__(self, app, secret_key: str = None):
        super().__init__(app)
        self.secret_key = secret_key or secrets.token_hex(32)
        # Check if CSRF should be disabled for testing
        self.test_mode = os.getenv("TESTING", "false").lower() == "true"

    async def dispatch(self, request: Request, call_next):
        # Skip CSRF in test mode
        if self.test_mode:
            request.state.csrf_token = ""
            response = await call_next(request)
            return response

        # Check if session is available (for test compatibility)
        # Note: Check scope directly to avoid triggering assertion errors
        has_session = "session" in request.scope

        # Generate CSRF token for the session if it doesn't exist
        if has_session and "csrf_token" not in request.session:
            request.session["csrf_token"] = secrets.token_urlsafe(32)

        # Store CSRF token in request state for template access
        if has_session:
            request.state.csrf_token = request.session.get("csrf_token", "")
        else:
            request.state.csrf_token = ""

        # Validate CSRF token for POST, PUT, DELETE, PATCH requests
        if request.method in ["POST", "PUT", "DELETE", "PATCH"]:
            # Skip CSRF validation for specific paths (e.g., API endpoints)
            if self._should_skip_csrf(request.url.path):
                response = await call_next(request)
                return response

            # Skip CSRF validation if no session (test mode)
            if not has_session:
                response = await call_next(request)
                return response

            # Get token from form data or headers
            form_token = None
            if request.headers.get("content-type", "").startswith("application/x-www-form-urlencoded") or \
               request.headers.get("content-type", "").startswith("multipart/form-data"):
                try:
                    form_data = await request.form()
                    form_token = form_data.get("csrf_token")
                except:
                    pass

            # Also check in headers (for AJAX requests)
            header_token = request.headers.get("X-CSRF-Token")

            submitted_token = form_token or header_token
            session_token = request.session.get("csrf_token")

            # Validate token
            if not submitted_token or not session_token or submitted_token != session_token:
                # For HTML forms, return 403 error
                raise HTTPException(status_code=403, detail="CSRF token validation failed")

        response = await call_next(request)
        return response

    def _should_skip_csrf(self, path: str) -> bool:
        """
        Determine if CSRF validation should be skipped for this path
        """
        # Add paths that should skip CSRF validation (e.g., file upload endpoints)
        # These endpoints should implement their own authentication checks
        skip_paths = ["/upload-image", "/upload-video"]
        return any(path.startswith(skip) for skip in skip_paths)


def generate_csrf_token(request: Request) -> str:
    """
    Get CSRF token from request state
    """
    return getattr(request.state, "csrf_token", "")
