from starlette.middleware.base import BaseHTTPMiddleware
from starlette.types import ASGIApp
from starlette.requests import Request

class AddSecurityHeadersMiddleware(BaseHTTPMiddleware):
    """
    Comprehensive security headers middleware for FastAPI/Starlette.

    Adds multiple security headers to protect against:
    - Clickjacking (X-Frame-Options, CSP frame-ancestors)
    - XSS attacks (Content-Security-Policy)
    - MIME sniffing (X-Content-Type-Options)
    - Spectre vulnerabilities (CORS headers)
    - Unauthorized feature access (Permissions-Policy)
    - Cache attacks (Cache-Control for sensitive pages)
    """
    def __init__(self, app: ASGIApp):
        super().__init__(app)

    async def dispatch(self, request: Request, call_next):
        response = await call_next(request)

        # X-Frame-Options - Prevent clickjacking
        if "X-Frame-Options" not in response.headers:
            response.headers["X-Frame-Options"] = "DENY"

        # Referrer-Policy - control Referer header leakage
        if "Referrer-Policy" not in response.headers:
            response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"

        # Content Security Policy - Comprehensive protection against XSS and injection attacks
        if "Content-Security-Policy" not in response.headers:
            # Define a strict CSP without unsafe-inline
            csp_directives = [
                "default-src 'self'",
                "script-src 'self'",
                "style-src 'self'",
                "img-src 'self' data:",
                "font-src 'self'",
                "connect-src 'self'",
                "frame-ancestors 'none'",
                "form-action 'self'",
                "base-uri 'self'",
                "object-src 'none'",
                "frame-src 'none'",
                "media-src 'self'",
                "manifest-src 'self'",
                "worker-src 'self'"
            ]
            response.headers["Content-Security-Policy"] = "; ".join(csp_directives)

        # X-Content-Type-Options - Prevent MIME sniffing
        if "X-Content-Type-Options" not in response.headers:
            response.headers["X-Content-Type-Options"] = "nosniff"

        # Cross-Origin-Resource-Policy - Protect against Spectre attacks
        if "Cross-Origin-Resource-Policy" not in response.headers:
            response.headers["Cross-Origin-Resource-Policy"] = "same-origin"

        # Cross-Origin-Embedder-Policy - Additional Spectre protection
        if "Cross-Origin-Embedder-Policy" not in response.headers:
            response.headers["Cross-Origin-Embedder-Policy"] = "require-corp"

        # Cross-Origin-Opener-Policy - Isolate browsing context
        if "Cross-Origin-Opener-Policy" not in response.headers:
            response.headers["Cross-Origin-Opener-Policy"] = "same-origin"

        # Permissions-Policy - Restrict browser features
        if "Permissions-Policy" not in response.headers:
            permissions = [
                "camera=()",
                "microphone=()",
                "geolocation=()",
                "payment=()",
                "usb=()",
                "magnetometer=()",
                "accelerometer=()",
                "gyroscope=()"
            ]
            response.headers["Permissions-Policy"] = ", ".join(permissions)

        # Cache-Control for sensitive pages (login, register, user-specific pages)
        sensitive_paths = ["/login", "/register", "/threads", "/create", "/edit"]
        if any(request.url.path.startswith(path) for path in sensitive_paths):
            if "Cache-Control" not in response.headers:
                response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate, private"
                response.headers["Pragma"] = "no-cache"
                response.headers["Expires"] = "0"

        # Strict-Transport-Security - Force HTTPS (only in production)
        # Commented out for local development
        # if "Strict-Transport-Security" not in response.headers:
        #     response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"

        return response
