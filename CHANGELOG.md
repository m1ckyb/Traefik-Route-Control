# Changelog

All notable changes to this project will be documented in this file.

## [0.0.23] - 2025-12-22

### Fixed
- Debounced `turn_off_service` to ignore redundant shutdown requests if the service is already offline.

## [0.0.22] - 2025-12-22

### Changed
- Refactored `main.py` to remove legacy CLI code and `argparse` dependency.
- Hardened `static/js/main.js` against XSS by sanitizing inputs in `showDiagnosticsModal`.
- Home Assistant config modal now uses a clearer placeholder for API keys and prevents password manager interference.

### Fixed
- Reverted API Key selection flow in HASS modal to simplify the user experience (removed misleading "Authorize" flow).

### Removed
- Removed legacy `cmd_on` and `cmd_off` functions from `main.py`.

## [0.0.21] - 2025-12-22

### Added
- Option to delete WebAuthn passkeys from the Settings page.
- API Key selection dropdown in Home Assistant settings modal with re-authorization flow.

## [0.0.20] - 2025-12-21

### Added
- **Docker**: Configurable timezone support in the Docker container via `TZ` environment variable.
- **Logging**: Application logs now include local timestamps with timezone offset for better readability.

## [0.0.19] - 2025-12-21

### Added
- **UI/UX**: Added a "Clear Traefik Routes from Redis" button in the Redis settings to allow manual cleanup of orphan Traefik entries.
- **API**: Added `/api/test/redis/clear` endpoint to facilitate manual Redis cleanup.
- **Logging**: Added "Actor" identification to service startup and shutdown logs. Logs now explicitly show whether an action was triggered via the WebUI (with username), an API Key (with key name), or a background task.

### Changed
- **UI/UX**: The "Rotate URL" button is now automatically disabled for services that have "Randomize Suffix" turned off, as static subdomains do not support rotation.
- **Documentation**: Refined the release process instructions in `GEMINI.md` to prevent changelog duplication and clarify the branch merge workflow.
- **Documentation**: Updated `GEMINI.md` with modern development guidelines including non-root execution, named volume usage, and mandatory security/vulnerability testing for new code changes.

### Fixed
- **Core**: Fixed a `SyntaxError` in `main.py` caused by an unmatched closing brace in the `turn_on_service` function.
- **Core**: Restored the `/api/test/redis/clear` endpoint which was accidentally corrupted in a previous edit, fixing the "Error: JSON.parse" issue when clearing Redis routes.
- **Docker**: Cleaned up `entrypoint.sh` startup logs to remove verbose diagnostic information.

## [0.0.18] - 2025-12-21

### Added
- **Documentation**: Created comprehensive security review document (`SECURITY/COPILOT_SECURITY_REVIEW_DEC_21_2025.md`) and executive summary.
- **API**: Added robust validation functions for subdomains, router names, service names, and target URLs.
- **API**: Implemented `ALLOWED_USER_SETTINGS` whitelist to prevent unauthorized configuration changes.

### Changed
- **Security**: Implemented strict SSRF protection in URL validation, blocking loopback and link-local addresses.
- **Security**: Hardened flash message rendering against XSS using Jinja's `tojson` filter.
- **Security**: Improved error handling to prevent sensitive information disclosure in user-facing messages.

## [0.0.17] - 2025-12-20

### Changed
- **Security**: Updated Docker image to run as a non-root user (`appuser`) with configurable UID/GID (`PUID`/`PGID`), improving container security and host file system compatibility.
- **Infrastructure**: Switched from host-mounted directories to **Named Docker Volumes** (`routeghost_data`) for the `/app/data` directory. This resolves SQLite "readonly database" errors and permission issues specifically encountered when running via WSL2 on Windows host mounts.

### Fixed
- **Docker**: Fixed `sqlite3.OperationalError: attempt to write a readonly database` by enhancing the entrypoint script with recursive ownership/permission enforcement and adding startup diagnostic logging.
- **Docker**: Fixed permission issues with log files and persistent storage by adding an `entrypoint.sh` script that uses `su-exec` to correct file ownership at runtime.
- **Home Assistant Integration**: Fixed a bug where "None" would be rendered and saved in the Home Assistant Entity ID field when left empty.

## [0.0.16] - 2025-12-20

### Changed
- **Branding**: Renamed the project from "Traefik Route Control" to **RouteGhost** 👻 and updated all UI elements, documentation, and Docker configuration.

## [0.0.15] - 2025-12-20

### Fixed
- **UI**: Fixed a bug where the Regex Pattern was still visible on the dashboard even when "Show Regex Pattern" was disabled for the service.

## [0.0.14] - 2025-12-20

### Added
- **Service Configuration**: Added "Show Regex Pattern" toggle to service edit page, allowing users to control whether the regex pattern is displayed on the dashboard for that service.

## [0.0.13] - 2025-12-20

### Changed
- Streamlined `README.md` for better readability and conciseness.
- Updated `GEMINI.md` Release Process section to include dev release workflow and expanded release steps (PR, GitHub Release, Pre-release).

## [0.0.12] - 2025-12-19

### Added
- **UI/UX**: Added a "Rotate Port" button to the main dashboard to manually trigger an immediate firewall port rotation.

### Changed
- **UI/UX**: Added a "Save" button to the Base URL field in the Home Assistant Settings modal.
- **UI/UX**: Added an editable "Base URL" field to the Home Assistant Settings modal.
- **UI/UX**: Replaced the numeric input for "Port Rotation Interval" with a dropdown menu featuring 30-minute increments up to 8 hours for better usability.
- **UI/UX**: "Check Health" and "Rotate Port" buttons on the dashboard are now automatically disabled when the firewall is closed.
- **UI/UX**: Enhanced disabled button styling with reduced opacity and saturation.
- **UI/UX**: Dynamic status updates: Toggling services now updates the firewall status and buttons without a page refresh.
- **UI/UX**: Dynamic health updates: Clicking "Check Health" updates service cards without a page refresh.
- **UI/UX**: Background status polling: The dashboard now polls the server status every 30 seconds.
- **License**: Switched project license to **GNU Affero General Public License v3.0 (AGPLv3)**.

### Fixed
- **Core**: Editing an active service now automatically synchronizes configuration with external APIs.

## [0.0.11] - 2025-12-19

### Added
- **API**: Added `/api/settings` endpoint for saving individual configuration settings via AJAX.

## [0.0.10] - 2025-12-19

### Added
- **Authentication**: Added support for traditional password-based login alongside Passkeys.
- **Security**: Implemented TOTP-based 2FA with QR code setup and recovery codes.
- **Security**: Added Global 2FA enforcement and rate limiting on login attempts.
- **Monitoring**: Added background health checks and Discord webhook notifications.
- **UI/UX**: Reorganized Settings page into a tabbed interface.
- **UI/UX**: Added Dark Mode toggle and Backup/Restore functionality.

## [0.0.1] - Initial Release
- Basic Traefik route rotation.
- Cloudflare DNS and Origin Rule integration.
- UniFi Firewall integration.