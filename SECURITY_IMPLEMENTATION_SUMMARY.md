# Lab 7 - Security Implementation Summary

This document summarizes the security features implemented for tasks 1.e - 1.h from Lab 7: BSIAW.

## Implemented Security Features

### 1.e - Secure Session Management (Bezpieczne zarządzanie sesją)

**Implementation Details:**
- Created `security/session_management.py` module with `SessionTimeoutMiddleware`
- Session timeout: 30 minutes (configurable via `SESSION_TIMEOUT_MINUTES` environment variable)
- Automatic session expiration based on inactivity
- Session metadata tracking:
  - `created_at`: Session creation timestamp
  - `last_activity`: Last activity timestamp
  - Automatic update on each request

**Files Modified:**
- `main.py:14` - Added import for session management module
- `main.py:423-424` - Added session timeout configuration
- `main.py:436` - Added `SessionTimeoutMiddleware` to middleware stack
- `main.py:768` - Updated login to use `init_session()` function

**Security Benefits:**
- Prevents session hijacking by limiting session lifetime
- Automatic logout after period of inactivity
- Reduces risk of unauthorized access from unattended sessions

---

### 1.f - Cookie Security (Bezpieczeństwo ciasteczek)

**Implementation Details:**
- Configured `SessionMiddleware` with secure cookie parameters:
  - `https_only=True` (in production) - Secure flag, cookies only sent over HTTPS
  - `same_site="strict"` - Prevents CSRF attacks by restricting cross-site cookie sending
  - `max_age` - Cookie lifetime matches session timeout
  - HttpOnly is enabled by default in SessionMiddleware (JavaScript cannot access cookies)

**Files Modified:**
- `main.py:425-435` - Configured SessionMiddleware with secure parameters

**Security Benefits:**
- **Secure flag**: Prevents cookie transmission over unencrypted HTTP
- **HttpOnly**: Prevents XSS attacks from stealing session cookies via JavaScript
- **SameSite=strict**: Strong CSRF protection by preventing cross-site request forgery

---

### 1.g - Activity Monitoring (Monitorowanie aktywności)

**Implementation Details:**
- Created `LoginAttempt` database model to track all login attempts
- Implemented comprehensive logging using Python's `logging` module
- Logs written to `security.log` file and console
- Tracked information:
  - Username (sanitized, max 50 chars)
  - Success/failure status
  - IP address
  - User agent
  - Timestamp
  - Failure reason (invalid_format, invalid_username, invalid_password)

**Files Modified:**
- `main.py:20-32` - Added logging configuration with `security_logger`
- `main.py:108-117` - Created `LoginAttempt` model
- `main.py:648-774` - Updated login endpoint with comprehensive logging

**Logged Events:**
- Failed login attempts (with reason)
- Successful login attempts
- User registration
- Password changes
- User logout
- Password expiration notices

**Security Benefits:**
- Security incident detection and forensics
- Brute force attack detection capability
- Audit trail for compliance
- User behavior analysis

---

### 1.h - Secure Password Storage (Bezpieczne przechowywanie haseł)

**Implementation Details:**

#### Password Policy (Already Implemented - Enhanced)
Strong password requirements enforced via `RegisterRequest` validation:
- Minimum 8 characters
- At least one uppercase letter
- At least one lowercase letter
- At least one digit
- At least one special character

#### Password Hashing (Already Implemented - Bcrypt)
- Using `bcrypt` algorithm via `passlib`
- Automatic salt generation
- Configurable work factor for future-proofing

#### Password Rotation (NEW)
- Automatic password expiration after 90 days
- `password_changed_at` field tracks password age
- `force_password_change` flag for mandatory password updates
- Automatic check on login with redirect to password change page

#### Password History (NEW)
- Prevents reuse of last 5 passwords
- `password_history` field stores JSON array of previous hashes
- Password comparison using bcrypt verification
- Enforced during password change

**Files Modified:**
- `main.py:104-106` - Added password rotation fields to User model
- `main.py:633-635` - Initialize password fields on registration
- `main.py:746-753` - Password expiration check on login
- `main.py:790-918` - Complete password change implementation with history checking

**New Endpoints:**
- `GET /change-password` - Password change form
- `POST /change-password` - Password change handler with validation

**Security Benefits:**
- **Strong passwords**: Reduces brute force attack success
- **Bcrypt hashing**: Industry-standard, slow hashing prevents rainbow table attacks
- **Password rotation**: Limits exposure window if password is compromised
- **Password history**: Prevents password cycling and reuse of compromised passwords

---

## Additional Security Modules Created

### 1. `security/csrf.py`
- CSRF token generation and validation
- Session-based token storage
- Cryptographically secure token generation using `secrets.token_urlsafe()`

### 2. `security/session_management.py`
- Session timeout middleware
- Session initialization helper functions
- Session info retrieval utilities

### 3. `templates/change_password.html`
- User-friendly password change interface
- Password requirements display
- Error handling and validation feedback

**Important Note:** Middleware are added in reverse execution order. SessionMiddleware must be added LAST so it executes FIRST and makes the session available to other middleware.

---

## Database Schema Changes

### New Columns in `users` Table:
- `password_changed_at` (DateTime) - Tracks when password was last changed
- `password_history` (Text) - JSON array of previous password hashes
- `force_password_change` (Integer) - Flag to force password change on next login

### New Table: `login_attempts`
- `id` (Integer, Primary Key)
- `username` (String, Indexed)
- `success` (Integer) - 1 for success, 0 for failure
- `ip_address` (String)
- `user_agent` (String)
- `timestamp` (DateTime, Indexed)
- `failure_reason` (String)

---

## Configuration Options

### Environment Variables:
- `SECRET_KEY` - Session encryption key (default: auto-generated, should be set in production)
- `SESSION_TIMEOUT_MINUTES` - Session timeout duration (default: 30 minutes)
- `ENVIRONMENT` - Set to "production" to enable HTTPS-only cookies (default: "development")

### Hardcoded Constants (can be moved to environment):
- `PASSWORD_MAX_AGE_DAYS` - Password expiration period (default: 90 days)
- `PASSWORD_HISTORY_COUNT` - Number of previous passwords to check (default: 5)

---

## Security Best Practices Implemented

1. **Defense in Depth**: Multiple layers of security (session, cookies, logging, passwords)
2. **Least Privilege**: Sessions expire automatically
3. **Fail Securely**: Failed login attempts are logged but don't reveal which part failed
4. **Complete Mediation**: Every login attempt is checked and logged
5. **Audit Trail**: Comprehensive logging for security events
6. **Password Complexity**: Strong password policy enforced
7. **Secure Defaults**: HttpOnly and SameSite cookies enabled by default

---

## Testing Recommendations

1. **Session Timeout Testing**:
   - Verify session expires after 30 minutes of inactivity
   - Test that session is refreshed on activity

2. **Cookie Security Testing**:
   - Verify cookies have Secure flag in production
   - Confirm HttpOnly flag is set
   - Test SameSite=strict behavior

3. **Login Monitoring Testing**:
   - Check `security.log` for login attempts
   - Verify database `login_attempts` table is populated
   - Test with both successful and failed logins

4. **Password Rotation Testing**:
   - Create user and manually set `password_changed_at` to 91 days ago
   - Verify forced password change on login
   - Test password change flow

5. **Password History Testing**:
   - Change password multiple times
   - Attempt to reuse old password
   - Verify prevention of reuse

---

## Files Created/Modified Summary

### Created Files:
- `security/csrf.py` - CSRF protection module
- `security/session_management.py` - Session timeout and management
- `templates/change_password.html` - Password change UI
- `SECURITY_IMPLEMENTATION_SUMMARY.md` - This documentation

### Modified Files:
- `main.py` - Major updates for all security features
  - Added logging configuration
  - Added User model fields for password rotation
  - Created LoginAttempt model
  - Updated SessionMiddleware configuration
  - Enhanced login endpoint with logging
  - Added password change endpoints
  - Updated registration to initialize password fields

---

## Compliance Mapping

These implementations address the following requirements from Lab 7:

| Requirement | Status | Implementation |
|-------------|--------|----------------|
| 1.e - Session token expiration | ✅ Complete | SessionTimeoutMiddleware, max_age config |
| 1.f - Secure cookies (Secure, HttpOnly, SameSite) | ✅ Complete | SessionMiddleware configuration |
| 1.g - Login attempt monitoring | ✅ Complete | LoginAttempt model, security logging |
| 1.h - Password policy | ✅ Complete | Strong validation rules (already existed) |
| 1.h - Password hashing | ✅ Complete | Bcrypt via passlib (already existed) |
| 1.h - Password rotation | ✅ Complete | 90-day expiration, forced change |
| 1.h - Password history | ✅ Complete | Last 5 passwords stored and checked |

---

## Next Steps for Production

1. Set `ENVIRONMENT=production` environment variable
2. Generate and set a strong `SECRET_KEY` (32+ random characters)
3. Configure log rotation for `security.log`
4. Set up monitoring/alerting on failed login attempts
5. Consider implementing account lockout after N failed attempts
6. Add admin dashboard for viewing login attempts
7. Implement password complexity meter on frontend
8. Consider adding 2FA (Two-Factor Authentication)

---

*Generated: 2025-12-19*
*Lab: BSIAW - Lab 7 Tasks 1.e-1.h*
