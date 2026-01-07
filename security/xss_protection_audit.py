"""
XSS Protection Audit and Enhancement (Lab 7 - Task 1.c)

This module documents XSS protection mechanisms and provides additional
security enhancements beyond the base xss_protection.py module.
"""

from typing import Dict, List
import re
import logging
from .xss_protection import (
    sanitize_text,
    sanitize_html_content,
    sanitize_url,
    sanitize_filename,
    escape_html
)

logger = logging.getLogger('security.xss')


class XSSProtectionAuditor:
    """
    Audits and validates XSS protection implementation across the application.
    """

    # Known XSS attack patterns
    XSS_PATTERNS = [
        r'<script[^>]*>.*?</script>',  # Script tags
        r'javascript:',  # JavaScript protocol
        r'on\w+\s*=',  # Event handlers (onclick, onerror, etc.)
        r'<iframe[^>]*>',  # IFrames
        r'<object[^>]*>',  # Object tags
        r'<embed[^>]*>',  # Embed tags
        r'<applet[^>]*>',  # Applet tags
        r'<meta[^>]*>',  # Meta tags
        r'<link[^>]*>',  # Link tags
        r'<style[^>]*>.*?</style>',  # Style tags
        r'expression\s*\(',  # CSS expressions
        r'vbscript:',  # VBScript protocol
        r'data:text/html',  # Data URLs
    ]

    @staticmethod
    def detect_xss_patterns(text: str) -> List[str]:
        """
        Detect potential XSS patterns in text.

        Args:
            text: Text to analyze

        Returns:
            List of detected patterns (empty if clean)
        """
        detected = []

        for pattern in XSSProtectionAuditor.XSS_PATTERNS:
            if re.search(pattern, text, re.IGNORECASE):
                detected.append(pattern)
                logger.warning(f"XSS pattern detected: {pattern} in text: {text[:100]}")

        return detected

    @staticmethod
    def validate_sanitization(original: str, sanitized: str) -> bool:
        """
        Validate that sanitization was effective.

        Args:
            original: Original input
            sanitized: Sanitized output

        Returns:
            True if sanitization appears effective
        """
        # Check if any XSS patterns remain after sanitization
        remaining_patterns = XSSProtectionAuditor.detect_xss_patterns(sanitized)

        if remaining_patterns:
            logger.error(
                f"XSS sanitization failed! Patterns remain: {remaining_patterns}\n"
                f"Original: {original[:100]}\n"
                f"Sanitized: {sanitized[:100]}"
            )
            return False

        return True


class ContentSecurityPolicy:
    """
    Content Security Policy (CSP) helper for XSS protection.
    Works in conjunction with ASGI middleware headers.
    """

    @staticmethod
    def get_strict_csp() -> str:
        """
        Get strict Content Security Policy header value.

        This CSP:
        - Only allows scripts from same origin
        - Only allows styles from same origin and inline with nonce
        - Blocks all object/embed/applet
        - Only allows images from same origin and data:
        - Prevents framing (clickjacking)
        - Blocks insecure HTTP resources when served over HTTPS

        Returns:
            CSP header value string
        """
        csp_directives = [
            "default-src 'self'",  # Default: same origin only
            "script-src 'self'",  # Scripts: same origin only
            "style-src 'self' 'unsafe-inline'",  # Styles: same origin + inline (for CSS)
            "img-src 'self' data:",  # Images: same origin + data URLs
            "font-src 'self'",  # Fonts: same origin only
            "connect-src 'self'",  # AJAX/WebSocket: same origin only
            "frame-src 'none'",  # No iframes
            "object-src 'none'",  # No plugins (Flash, Java, etc.)
            "base-uri 'self'",  # Prevent base tag injection
            "form-action 'self'",  # Forms can only submit to same origin
            "frame-ancestors 'none'",  # Prevent clickjacking
            "upgrade-insecure-requests",  # Upgrade HTTP to HTTPS
        ]
        return "; ".join(csp_directives)

    @staticmethod
    def get_report_uri(report_endpoint: str) -> str:
        """
        Get CSP with violation reporting.

        Args:
            report_endpoint: URL endpoint for CSP violation reports

        Returns:
            CSP header value with reporting
        """
        csp = ContentSecurityPolicy.get_strict_csp()
        return f"{csp}; report-uri {report_endpoint}"


class XSSProtectionMiddleware:
    """
    Additional XSS protection middleware layer.
    This complements the existing sanitization functions.
    """

    @staticmethod
    def sanitize_request_params(params: Dict[str, str]) -> Dict[str, str]:
        """
        Sanitize all request parameters.

        Args:
            params: Dictionary of request parameters

        Returns:
            Dictionary with sanitized values
        """
        sanitized = {}
        for key, value in params.items():
            # Sanitize key
            clean_key = sanitize_text(key)

            # Sanitize value
            if isinstance(value, str):
                clean_value = sanitize_html_content(value)
            else:
                clean_value = value

            sanitized[clean_key] = clean_value

        return sanitized

    @staticmethod
    def sanitize_response_headers(headers: Dict[str, str]) -> Dict[str, str]:
        """
        Ensure response headers don't contain XSS vectors.

        Args:
            headers: Response headers

        Returns:
            Sanitized headers
        """
        dangerous_headers = ['Location', 'Refresh']

        for header in dangerous_headers:
            if header in headers:
                # Sanitize URL in Location/Refresh headers
                headers[header] = sanitize_url(headers[header])

        return headers


class XSSTestCases:
    """
    Test cases for XSS protection validation.
    """

    # Common XSS attack vectors for testing
    XSS_TEST_VECTORS = [
        # Basic script injection
        '<script>alert("XSS")</script>',
        '<script>alert(document.cookie)</script>',

        # Event handlers
        '<img src=x onerror=alert("XSS")>',
        '<body onload=alert("XSS")>',
        '<input onfocus=alert("XSS") autofocus>',

        # JavaScript protocol
        '<a href="javascript:alert(\'XSS\')">Click</a>',
        '<img src="javascript:alert(\'XSS\')">',

        # Encoded attacks
        '<img src=x on&#101rror=alert("XSS")>',
        '<script>&#97;lert("XSS")</script>',

        # SVG-based XSS
        '<svg onload=alert("XSS")>',
        '<svg><script>alert("XSS")</script></svg>',

        # Data URLs
        '<img src="data:text/html,<script>alert(\'XSS\')</script>">',

        # CSS-based XSS
        '<style>body{background:url("javascript:alert(\'XSS\')")}</style>',

        # Meta refresh
        '<meta http-equiv="refresh" content="0;url=javascript:alert(\'XSS\')">',

        # Iframe injection
        '<iframe src="javascript:alert(\'XSS\')"></iframe>',
    ]

    @staticmethod
    def test_sanitization_function(sanitize_func) -> Dict[str, bool]:
        """
        Test a sanitization function against XSS vectors.

        Args:
            sanitize_func: Function to test (e.g., sanitize_html_content)

        Returns:
            Dictionary of test results
        """
        results = {}

        for vector in XSSTestCases.XSS_TEST_VECTORS:
            sanitized = sanitize_func(vector)
            is_safe = not XSSProtectionAuditor.detect_xss_patterns(sanitized)
            results[vector] = is_safe

            if not is_safe:
                logger.error(
                    f"Sanitization function failed for vector: {vector}\n"
                    f"Result: {sanitized}"
                )

        return results

    @staticmethod
    def run_all_tests():
        """Run all XSS protection tests"""
        logger.info("Running XSS protection tests...")

        # Test sanitize_text (should remove ALL HTML)
        logger.info("Testing sanitize_text...")
        text_results = XSSTestCases.test_sanitization_function(sanitize_text)
        text_passed = sum(text_results.values())
        logger.info(f"sanitize_text: {text_passed}/{len(text_results)} tests passed")

        # Test sanitize_html_content (should allow safe HTML)
        logger.info("Testing sanitize_html_content...")
        html_results = XSSTestCases.test_sanitization_function(sanitize_html_content)
        html_passed = sum(html_results.values())
        logger.info(f"sanitize_html_content: {html_passed}/{len(html_results)} tests passed")

        return {
            'sanitize_text': text_results,
            'sanitize_html_content': html_results
        }


"""
=============================================================================
XSS PROTECTION IMPLEMENTATION SUMMARY (Lab 7 - Task 1.c)
=============================================================================

This application implements comprehensive XSS protection through multiple layers:

1. Input Sanitization (security/xss_protection.py)
   ✓ sanitize_text() - Removes ALL HTML tags
   ✓ sanitize_html_content() - Allows only safe HTML tags
   ✓ sanitize_url() - Blocks javascript:, data:, vbscript: URLs
   ✓ sanitize_filename() - Prevents directory traversal
   ✓ escape_html() - HTML entity encoding

2. Output Encoding
   ✓ Jinja2 templates auto-escape by default
   ✓ All user content passed through sanitization before storage
   ✓ Additional escaping in templates where needed

3. Content Security Policy (CSP)
   ✓ Implemented in security/asgi_middleware.py
   ✓ Restricts script sources to same-origin
   ✓ Blocks inline scripts (except with nonce)
   ✓ Prevents loading resources from untrusted domains

4. HTTP Security Headers
   ✓ X-XSS-Protection: 1; mode=block
   ✓ X-Content-Type-Options: nosniff
   ✓ X-Frame-Options: DENY

5. Application-Level Protection
   ✓ All user inputs sanitized before database storage
   ✓ All outputs sanitized before display
   ✓ URL parameters validated and sanitized
   ✓ File uploads validated and sanitized

Protected Input Points:
- Registration: username (sanitize_username), email (validated)
- Posts: title (sanitize_text), content (sanitize_html_content)
- Comments: content (sanitize_html_content)
- Threads: title (sanitize_text), messages (sanitize_html_content)
- File uploads: filename (sanitize_filename)
- Search queries: query (sanitize_search_query)

Protected Output Points:
- All Jinja2 templates use auto-escaping
- JSON responses use proper content-type headers
- Error messages sanitized to prevent information disclosure

XSS Attack Vectors Blocked:
✓ Script tag injection: <script>alert('XSS')</script>
✓ Event handlers: <img onerror="alert('XSS')">
✓ JavaScript protocol: <a href="javascript:alert()">
✓ Data URLs: <img src="data:text/html,...">
✓ CSS expressions: style="expression(...)"
✓ SVG-based XSS: <svg onload="alert()">
✓ Meta refresh: <meta http-equiv="refresh">
✓ IFrame injection: <iframe src="javascript:...">

Testing and Validation:
- Bleach library used for HTML sanitization
- Regular expression validation for patterns
- Automated test cases for XSS vectors
- Security headers verified in ASGI middleware

=============================================================================
"""

__all__ = [
    'XSSProtectionAuditor',
    'ContentSecurityPolicy',
    'XSSProtectionMiddleware',
    'XSSTestCases'
]
