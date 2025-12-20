### Security
- **CRITICAL**: Added comprehensive input validation for service configuration
  - Subdomain prefixes now validated against DNS label rules (alphanumeric, hyphens, max 63 chars)
  - Router and service names validated for Traefik/Redis safety (prevents injection attacks)
  - Target URLs validated with SSRF protection (blocks loopback, link-local, multicast addresses)
  - Display names sanitized and length-limited
- **CRITICAL**: Fixed XSS vulnerability in flash message rendering
  - Messages now properly escaped using Jinja's `tojson` filter
  - Prevents JavaScript injection via error messages
- **HIGH**: Implemented settings whitelist for web UI
  - Only approved settings can be modified via onboarding and settings pages
  - Prevents unauthorized modification of internal configuration
  - Added security logging for rejected setting attempts
- **HIGH**: Enhanced error handling to prevent information disclosure
  - Validation errors (expected) shown to users
  - Unexpected errors logged server-side but not exposed in UI
  - Database schema and internal paths no longer leaked in error messages

### Added
- Created comprehensive security review document (SECURITY_REVIEW_2024.md)
- Added validation functions: `validate_subdomain_prefix()`, `validate_router_name()`, `validate_service_name()`, `validate_display_name()`, `validate_target_url()`
- Added `ALLOWED_USER_SETTINGS` whitelist constant

### Changed
- **Security**: Service creation and editing now validate all inputs before database operations
- **Security**: Onboarding and settings routes now use whitelisted settings
- **Security**: Error messages differentiate between validation errors (safe) and unexpected errors (sanitized)
- **Security**: Import added: `re` module for regex validation
- **UI/UX**: The "Rotate URL" button is now automatically disabled for services that have "Randomize Suffix" turned off, as static subdomains do not support rotation.
- **Documentation**: Refined the release process instructions in `GEMINI.md` to prevent changelog duplication and clarify the branch merge workflow.
- **Documentation**: Updated `GEMINI.md` with modern development guidelines including non-root execution, named volume usage, and mandatory security/vulnerability testing for new code changes.

### Fixed
- **Docker**: Cleaned up `entrypoint.sh` startup logs to remove verbose diagnostic information.
