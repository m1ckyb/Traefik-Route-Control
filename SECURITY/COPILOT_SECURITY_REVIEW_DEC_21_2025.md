# Security Review Report - December 2024

**Date:** 2024-12-20  
**Reviewer:** GitHub Copilot Security Review  
**Scope:** Comprehensive code review for security vulnerabilities

## Executive Summary

A comprehensive security review was conducted on the RouteGhost application. The application demonstrates good security practices in several areas, but **8 security vulnerabilities** were identified that require attention. These range from high-severity input validation issues to medium-severity information disclosure concerns.

**Overall Security Rating:** 🟡 **MODERATE** (6.5/10)

---

## Critical & High Severity Findings

### 🔴 HIGH: Insufficient Input Validation for Subdomain Prefix

**Location:** `main.py:2464`, `main.py:2504`  
**Risk:** Subdomain injection / DNS manipulation

**Description:**  
The `subdomain_prefix` field is directly accepted from user input without validation. A malicious user could potentially inject special characters that could:
- Break DNS records
- Create unexpected subdomains
- Cause issues with Cloudflare API calls

**Current Code:**
```python
db.add_service(
    subdomain_prefix=request.form['subdomain_prefix'],  # No validation!
    ...
)
```

**Vulnerable Input Examples:**
- `../../../etc` (path traversal attempt)
- `test..test` (double dots)
- `test@malicious` (special chars)
- `-test` (leading hyphen - invalid DNS)
- `test-` (trailing hyphen - invalid DNS)

**Recommendation:**
```python
def validate_subdomain_prefix(prefix):
    """Validate subdomain prefix for DNS safety."""
    if not prefix:
        raise ValueError("Subdomain prefix is required")
    
    # DNS label rules: alphanumeric and hyphens only, no leading/trailing hyphens
    # Max 63 characters per label
    if not re.match(r'^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$', prefix, re.IGNORECASE):
        raise ValueError("Subdomain prefix must contain only letters, numbers, and hyphens (not at start/end)")
    
    if len(prefix) > 63:
        raise ValueError("Subdomain prefix too long (max 63 characters)")
    
    return prefix.lower()

# In new_service() and edit_service():
subdomain_prefix = validate_subdomain_prefix(request.form['subdomain_prefix'])
```

---

### 🔴 HIGH: Insufficient Validation for Service Names and Router Names

**Location:** `main.py:2460-2462`, `main.py:2500-2502`  
**Risk:** Traefik configuration injection / Redis key manipulation

**Description:**  
The `name`, `router_name`, and `service_name` fields are stored directly in Redis keys without validation. Malicious input could:
- Break Traefik routing configuration
- Create collisions or overwrite other service configs
- Inject special characters that break Redis commands

**Current Code:**
```python
db.add_service(
    name=request.form['name'],  # Used in display
    router_name=request.form['router_name'],  # Used in Redis key!
    service_name=request.form['service_name'],  # Used in Redis key!
    ...
)
```

**Vulnerable Input Examples:**
- Router name: `traefik/http/routers/admin` (could overwrite system routes)
- Service name: `../../sensitive-service` (path traversal in key name)
- Name with special chars: `My Service'; DROP TABLE--`

**Recommendation:**
```python
def validate_router_name(name):
    """Validate router name for Traefik/Redis safety."""
    if not name:
        raise ValueError("Router name is required")
    
    # Alphanumeric, hyphens, underscores only
    if not re.match(r'^[a-zA-Z0-9_-]+$', name):
        raise ValueError("Router name must contain only letters, numbers, hyphens, and underscores")
    
    if len(name) > 64:
        raise ValueError("Router name too long (max 64 characters)")
    
    return name

def validate_service_name(name):
    """Validate service name for Traefik/Redis safety."""
    # Same rules as router name
    return validate_router_name(name)

def validate_display_name(name):
    """Validate display name."""
    if not name:
        raise ValueError("Service name is required")
    
    if len(name) > 128:
        raise ValueError("Service name too long (max 128 characters)")
    
    # Allow more characters for display, but strip dangerous ones
    return name.strip()
```

---

### 🟠 MEDIUM-HIGH: Flash Message XSS Vulnerability

**Location:** `templates/base.html:92`, `templates/login.html:32`  
**Risk:** Cross-Site Scripting (XSS)

**Description:**  
Flask's `flash()` messages are rendered directly into JavaScript without proper escaping. While the `showToast` function uses `textContent` (safe), the message is first embedded in a JavaScript string literal without escaping.

**Current Code:**
```html
<script>
    document.addEventListener('DOMContentLoaded', function() {
        {% for category, message in messages %}
            showToast("{{ message }}", "{{ category }}");  <!-- Potential XSS -->
        {% endfor %}
    });
</script>
```

**Vulnerable Scenario:**
If an exception contains user-controlled data that gets passed to `flash()`:
```python
flash(f'Error: {str(e)}', 'error')  # If e contains user input
```

An attacker could craft input that breaks out of the string:
```
Input: test"); alert('XSS');//
Output: showToast("test"); alert('XSS');//", "error");
```

**Recommendation:**
Use Jinja's `tojson` filter to safely encode the message:
```html
<script>
    document.addEventListener('DOMContentLoaded', function() {
        {% for category, message in messages %}
            showToast({{ message|tojson }}, {{ category|tojson }});
        {% endfor %}
    });
</script>
```

---

### 🟠 MEDIUM: Missing CSRF Protection on Settings and Onboarding Forms

**Location:** `main.py:2430`, `main.py:2528`  
**Risk:** Cross-Site Request Forgery (CSRF)

**Description:**  
The `/onboarding/complete` and `/settings` routes accept POST requests with form data but rely only on `@login_required`. While CSRF protection is enabled globally via `CSRFProtect`, these routes process form data in a way that could be vulnerable if CSRF tokens aren't properly validated.

**Current Code:**
```python
@app.route('/onboarding/complete', methods=['POST'])
@login_required
def onboarding_complete():
    for key in request.form:  # Processes ALL form keys!
        db.set_setting(key, request.form[key])
```

**Risk:**  
1. The code iterates over ALL form keys and saves them directly to settings
2. An attacker could craft a malicious form that includes dangerous settings
3. No validation of which settings are allowed to be changed

**Recommendation:**
```python
# Define allowed settings that can be changed via these forms
ALLOWED_ONBOARDING_SETTINGS = {
    'CF_API_TOKEN', 'CF_ZONE_ID', 'DOMAIN_ROOT', 'ORIGIN_RULE_NAME',
    'REDIS_HOST', 'REDIS_PORT', 'REDIS_PASS',
    'HASS_URL', 'HASS_TOKEN', 'HASS_ENABLED',
    'UNIFI_HOST', 'UNIFI_USER', 'UNIFI_PASS', 'FIREWALL_TYPE',
    # ... add other safe settings
}

@app.route('/onboarding/complete', methods=['POST'])
@login_required
def onboarding_complete():
    try:
        # Only save whitelisted settings
        for key in request.form:
            if key in ALLOWED_ONBOARDING_SETTINGS:
                db.set_setting(key, request.form[key])
            else:
                print(f"⚠️ Attempted to set disallowed setting: {key}")
        
        db.update_user_onboarding_status(current_user.id, True)
        flash('Setup completed successfully!', 'success')
        return redirect(url_for('index'))
    except Exception as e:
        flash(f'Error: {str(e)}', 'error')
        return redirect(url_for('onboarding'))
```

---

## Medium Severity Findings

### 🟠 MEDIUM: Information Disclosure in Error Messages

**Location:** Multiple locations (`main.py:2472`, `main.py:2518`, etc.)  
**Risk:** Information leakage

**Description:**  
Error messages from exceptions are directly displayed to users via `flash()`, which can expose:
- Internal file paths
- Database schema information
- Configuration details
- Stack traces (in development mode)

**Current Code:**
```python
except Exception as e:
    flash(f'Error: {str(e)}', 'error')
```

**Example Leak:**
```
Error: constraint failed: UNIQUE constraint failed: services.router_name
```
This reveals database schema details.

**Recommendation:**
```python
import logging

logger = logging.getLogger(__name__)

# In routes:
except ValueError as e:
    # Expected user errors - safe to show
    flash(f'Error: {str(e)}', 'error')
except Exception as e:
    # Unexpected errors - log but don't expose details
    logger.error(f"Unexpected error in {request.path}: {str(e)}", exc_info=True)
    flash('An unexpected error occurred. Please try again or contact support.', 'error')
```

---

### 🟠 MEDIUM: Insufficient URL Validation

**Location:** `main.py:2447-2449`, `main.py:2486-2488`  
**Risk:** Server-Side Request Forgery (SSRF)

**Description:**  
The `target_url` validation only checks if it starts with `http://` or `https://`, but doesn't validate:
- The hostname/IP address
- URL structure
- Potential redirects
- Protocol restrictions

**Current Code:**
```python
target_url = request.form['target_url']
if not target_url.startswith(('http://', 'https://')):
    raise ValueError("Target URL must start with http:// or https://")
```

**Vulnerable Scenarios:**
1. User enters: `http://169.254.169.254/latest/meta-data/` (AWS metadata)
2. User enters: `http://localhost:6379/` (Redis port)
3. User enters: `http://[::1]:5000/` (IPv6 localhost)
4. User enters: `http://admin:password@internal-server/`

**Recommendation:**
```python
def validate_target_url(url):
    """Validate target URL for security."""
    if not url.startswith(('http://', 'https://')):
        raise ValueError("Target URL must start with http:// or https://")
    
    try:
        parsed = urlparse(url)
        
        if not parsed.netloc:
            raise ValueError("Invalid URL format")
        
        # Check for credentials in URL (security risk)
        if '@' in parsed.netloc:
            raise ValueError("URLs with credentials are not allowed")
        
        # Extract hostname (handles IPv6)
        hostname = parsed.hostname
        if not hostname:
            raise ValueError("Invalid hostname")
        
        # Resolve hostname to IP
        try:
            ip = socket.gethostbyname(hostname)
            ip_obj = ipaddress.ip_address(ip)
            
            # Allow private IPs (this is the use case), but block special ranges
            # Block link-local (169.254.0.0/16, fe80::/10)
            if ip_obj.is_link_local:
                raise ValueError("Link-local addresses are not allowed")
            
            # Block loopback (127.0.0.0/8, ::1)
            if ip_obj.is_loopback:
                raise ValueError("Loopback addresses are not allowed")
            
            # Block multicast
            if ip_obj.is_multicast:
                raise ValueError("Multicast addresses are not allowed")
                
        except socket.gaierror:
            raise ValueError("Cannot resolve hostname")
        
        return url
        
    except ValueError:
        raise
    except Exception as e:
        raise ValueError(f"Invalid URL: {str(e)}")
```

**Note:** Since this application is designed to proxy to internal services, blocking private IPs would break the core functionality. The validation above allows private IPs but blocks special/dangerous ranges.

---

### 🟠 MEDIUM: Rate Limiting Implementation Issues

**Location:** `main.py:220-237`  
**Risk:** Brute force attacks, DoS

**Description:**  
The rate limiting implementation has several issues:
1. Uses in-memory dictionary (lost on restart)
2. No cleanup of old entries (memory leak)
3. Only applied to password login, not WebAuthn
4. No rate limiting on other sensitive endpoints

**Current Code:**
```python
LOGIN_ATTEMPTS = {}  # Global in-memory dict

def check_rate_limit(ip_address, limit=5, window=60):
    current_time = time.time()
    if ip_address not in LOGIN_ATTEMPTS:
        LOGIN_ATTEMPTS[ip_address] = []
    
    LOGIN_ATTEMPTS[ip_address] = [t for t in LOGIN_ATTEMPTS[ip_address] if current_time - t < window]
    
    if len(LOGIN_ATTEMPTS[ip_address]) >= limit:
        return False
    
    LOGIN_ATTEMPTS[ip_address].append(current_time)
    return True
```

**Issues:**
1. No cleanup task (entries grow indefinitely)
2. Rate limit can be bypassed by restarting the app
3. No distributed rate limiting (won't work with multiple instances)

**Recommendation:**
1. Store rate limits in Redis for persistence and distribution
2. Add periodic cleanup
3. Apply rate limiting to more endpoints:
   - WebAuthn registration/authentication
   - API key creation
   - Service enable/disable
   - Settings updates

```python
def check_rate_limit(identifier, limit=5, window=60, category='login'):
    """Check rate limit using Redis for persistence."""
    r = get_redis()
    if not r:
        # Fallback to in-memory if Redis unavailable
        return check_rate_limit_memory(identifier, limit, window)
    
    key = f"rate_limit:{category}:{identifier}"
    pipe = r.pipeline()
    
    current_time = int(time.time())
    window_start = current_time - window
    
    # Remove old entries
    pipe.zremrangebyscore(key, 0, window_start)
    # Add current attempt
    pipe.zadd(key, {str(current_time): current_time})
    # Count attempts in window
    pipe.zcard(key)
    # Set expiration
    pipe.expire(key, window * 2)
    
    results = pipe.execute()
    attempt_count = results[2]
    
    return attempt_count <= limit
```

---

### 🟠 MEDIUM: Insecure Logging of Sensitive Data

**Location:** Multiple locations in `main.py`  
**Risk:** Sensitive data exposure in logs

**Description:**  
The application logs sensitive information that could be exposed if logs are compromised:

**Examples:**
```python
# main.py:896
print(f"🔹 Connecting to UniFi Controller ({unifi_host})...")

# main.py:1490
print(f"   IP:      {public_ip}")
```

While not directly logging credentials, the logs contain:
- IP addresses
- Hostnames
- Service names
- Configuration details

**Recommendation:**
1. Review all logging statements
2. Redact sensitive information
3. Use proper log levels (DEBUG, INFO, WARNING, ERROR)
4. Consider log rotation and retention policies

```python
# Example improvements:
logger.info("Connecting to UniFi Controller")  # Don't log host
logger.debug(f"Generated hostname: {full_hostname[:8]}...")  # Truncate
```

---

## Low Severity Findings

### 🟡 LOW: Missing Input Length Limits

**Location:** Multiple form inputs  
**Risk:** DoS, database bloat

**Description:**  
Many form inputs don't have maximum length validation, allowing users to submit very long strings that could:
- Consume excessive database space
- Slow down queries
- Cause display issues

**Recommendation:**
Add length validation to all text inputs:
```python
def validate_length(value, field_name, max_length):
    if len(value) > max_length:
        raise ValueError(f"{field_name} must be {max_length} characters or less")
    return value
```

---

### 🟡 LOW: Hardcoded Security Parameters

**Location:** `main.py:1716`, `main.py:2118`  
**Risk:** Inflexible security configuration

**Description:**  
Security parameters are hardcoded:
- Setup window: 300 seconds
- Rate limit: 5 attempts per 60 seconds
- Session timeout: Not explicitly configured

**Recommendation:**
Make these configurable via environment variables with secure defaults:
```python
SETUP_WINDOW_SECONDS = int(os.getenv('SETUP_WINDOW_SECONDS', '300'))
RATE_LIMIT_ATTEMPTS = int(os.getenv('RATE_LIMIT_ATTEMPTS', '5'))
RATE_LIMIT_WINDOW = int(os.getenv('RATE_LIMIT_WINDOW', '60'))
```

---

## Positive Security Practices Observed

✅ **Excellent:**
1. Uses parameterized SQL queries throughout (no SQL injection)
2. CSRF protection enabled globally
3. Password hashing with werkzeug
4. WebAuthn/Passkey support
5. 2FA with TOTP
6. API key authentication with hashing
7. No use of dangerous functions (eval, exec, shell=True)
8. Runs as non-root user in container
9. Session secrets persisted securely

✅ **Good:**
1. HTTPS enforcement via Cloudflare
2. Rate limiting on password login
3. Input validation for URLs (basic)
4. Error handling in place
5. Separation of concerns (database, main logic)

---

## Recommendations Priority

### Immediate (Fix within 1 week):
1. ✅ Add subdomain prefix validation
2. ✅ Add router/service name validation  
3. ✅ Fix flash message XSS vulnerability
4. ✅ Add settings whitelist for onboarding/settings routes

### Short-term (Fix within 1 month):
5. ✅ Improve URL validation with SSRF protection
6. ✅ Enhance rate limiting (use Redis, apply to more endpoints)
7. ✅ Improve error message handling (avoid information disclosure)

### Medium-term (Fix within 3 months):
8. ✅ Review and sanitize all logging
9. ✅ Add input length limits
10. ✅ Make security parameters configurable

---

## Testing Recommendations

1. **Penetration Testing:** Conduct professional penetration testing
2. **Dependency Scanning:** Use `safety` or Dependabot for dependency vulnerabilities
3. **SAST:** Integrate static analysis tools (Bandit for Python)
4. **Dynamic Testing:** Use OWASP ZAP or Burp Suite for dynamic testing

---

## Conclusion

The RouteGhost application has a solid security foundation with good authentication practices and protection against common vulnerabilities like SQL injection. However, the identified issues, particularly around input validation and XSS vulnerabilities, should be addressed promptly to improve the overall security posture.

**Key Takeaway:** Focus on input validation and sanitization as the primary area for improvement. Implementing the recommended validation functions will significantly reduce the attack surface.
