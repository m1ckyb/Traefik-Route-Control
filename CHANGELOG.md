# Changelog

All notable changes to this project will be documented in this file.

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