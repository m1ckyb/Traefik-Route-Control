# Changelog

All notable changes to this project will be documented in this file.

## [0.0.12] - 2025-12-19

### Added
- **API**: Added `/api/settings` endpoint for saving individual configuration settings via AJAX.
- **UI/UX**: Added a "Rotate Port" button to the main dashboard to manually trigger an immediate firewall port rotation.

### Changed
- **UI/UX**: Added a "Save" button to the Base URL field in the Home Assistant Settings modal, allowing users to persist their preferred application address for Home Assistant configuration.
- **UI/UX**: Added an editable "Base URL" field to the Home Assistant Settings modal, allowing users to easily customize the API address (e.g., using an IP address instead of a domain) in the generated YAML configuration.
- **UI/UX**: Replaced the numeric input for "Port Rotation Interval" with a dropdown menu featuring 30-minute increments up to 8 hours for better usability.
- **UI/UX**: "Check Health" and "Rotate Port" buttons on the dashboard are now automatically disabled when the firewall is closed, with a tooltip explaining the reason.
- **UI/UX**: Enhanced disabled button styling with reduced opacity and saturation to provide better visual feedback when actions are unavailable.
- **UI/UX**: Dynamic status updates: Toggling services now automatically updates the firewall status badge and enables/disables dashboard buttons without a page refresh.
- **UI/UX**: Dynamic health updates: Clicking "Check Health" now updates service badges and slider colors immediately without a page refresh.
- **UI/UX**: Background status polling: The dashboard now polls the server status every 30 seconds to automatically update firewall and health status indicators.
- **License**: Switched project license from MIT to GNU Affero General Public License v3.0 (AGPLv3) to ensure continued open-source availability of modifications.

### Fixed
- **Core**: Editing an active service now automatically synchronizes the new configuration with Redis and external APIs (DNS, Cloudflare) without requiring a toggle.
- **Home Assistant Integration**: Fixed a bug where "None" would be rendered and saved in the Home Assistant Entity ID field when left empty.
- **Authentication**: Fixed a bug where login and registration would fail due to missing CSRF tokens in AJAX requests.
- **CSRF Protection**: Fixed "Request failed" errors on Dashboard (Check Health, Toggle All), Settings, and Onboarding pages by ensuring all AJAX requests include the required CSRF token.
- **Home Assistant Integration**: Removed misleading "global setting" references and updated service-specific Entity ID helper text. Home Assistant updates are now strictly per-service.
- **Background Tasks**: Fixed an issue where Health Check and Port Rotation threads were not starting when running the application with Gunicorn (Docker default).
- **UI Layout**: Fixed column spanning issues in the Settings form.
- **Validation**: Improved validation logic for Home Assistant entity IDs.
- **UI/UX**: Fixed toast notifications disappearing too quickly by removing page reload on service toggle.

## [0.0.11] - 2025-12-19

### Added
- **API**: Added `/api/settings` endpoint for saving individual configuration settings via AJAX.
- **UI/UX**: Added a "Rotate Port" button to the main dashboard to manually trigger an immediate firewall port rotation.

### Changed
- **UI/UX**: Added a "Save" button to the Base URL field in the Home Assistant Settings modal, allowing users to persist their preferred application address for Home Assistant configuration.
- **UI/UX**: Added an editable "Base URL" field to the Home Assistant Settings modal, allowing users to easily customize the API address (e.g., using an IP address instead of a domain) in the generated YAML configuration.
- **UI/UX**: Replaced the numeric input for "Port Rotation Interval" with a dropdown menu featuring 30-minute increments up to 8 hours for better usability.
- **UI/UX**: "Check Health" and "Rotate Port" buttons on the dashboard are now automatically disabled when the firewall is closed, with a tooltip explaining the reason.
- **UI/UX**: Enhanced disabled button styling with reduced opacity and saturation to provide better visual feedback when actions are unavailable.
- **UI/UX**: Dynamic status updates: Toggling services now automatically updates the firewall status badge and enables/disables dashboard buttons without a page refresh.
- **License**: Switched project license from MIT to GNU Affero General Public License v3.0 (AGPLv3) to ensure continued open-source availability of modifications.

## [0.0.10] - 2025-12-19

### Added

#### Documentation
- **Workflow Guidelines**: Updated `GEMINI.md` with explicit instructions for maintaining the changelog and workflow procedures.

#### Authentication & Security
- **Username/Password Login**: Added support for traditional password-based login alongside Passkeys.
- **Two-Factor Authentication (2FA)**: Implemented TOTP-based 2FA with QR code setup.
- **Recovery Codes**: Added generation and usage of recovery codes for 2FA lockout scenarios.
- **Global 2FA Enforcement**: Added a setting to force all users to set up 2FA.
- **Rate Limiting**: Added protection against brute-force attacks on login and password reset endpoints (5 attempts per minute).
- **Password Management**: Added "Change Password" functionality in settings and an API endpoint for admin password resets.
- **Passkey Management**: Added UI to list and register new Passkeys for logged-in users.

#### Monitoring & Notifications
- **Health Checks**: Added a background thread to periodically check service connectivity.
- **Discord Notifications**: Added webhooks for service health events (Healthy/Unhealthy) and system events.
- **Notification Settings**: Added granular controls to enable/disable specific notification types (Health vs. System).
- **Visual Indicators**: Updated Dashboard to show "UNHEALTHY" badges and red status switches when services fail checks.
- **Manual Checks**: Added a "Check Health Now" button to the dashboard for immediate status updates.

#### Settings & UI
- **Tabbed Interface**: Reorganized the Settings page into logical tabs (General, Security, Monitoring, Infrastructure, Integrations).
- **Dark Mode**: Added a persistent Dark Mode toggle.
- **Backup & Restore**: Added functionality to export settings to JSON and restore them from a file.
- **Connection Testing**: Added "Test Connection" buttons for Redis, Home Assistant, Cloudflare, and Discord Webhooks.
- **Tooltips**: Added informational tooltips to settings fields for better UX.
- **Input Validation**: Added HTML5 validation for URLs, IP addresses, and Domain names.
- **Service Management**: Added "Randomize Suffix" toggle to service configuration, allowing for static subdomains.
- **Port Rotation**: Added automated firewall port rotation (changing the external port periodically) without restarting services.

#### Core Logic
- **Service State Management**: Updated `turn_on_service` to ignore requests if the service is already online (preventing unnecessary rotation).
- **Force Flag**: Added a `force` parameter to the API to bypass state checks when needed.

### Changed
- **UI/UX**: Unified notification system to use toast messages for all server feedback, removing redundant/static alert banners from the dashboard and login pages.
- **UI/UX**: "Subdomain Prefix" label now dynamically changes to "Subdomain Hostname" in the service form and dashboard when Randomize Suffix is disabled, to better reflect the behavior.
- **UI/UX**: Reduced button height/padding on the main dashboard for a more compact look.
- **UI/UX**: Eliminated page refresh when toggling or rotating services; UI now updates dynamically.
- **UI/UX**: Standardized button sizes across the application for a more consistent interface.
- **UI/UX**: Unified service control notifications to use the same toast style as the settings page.
- **UI/UX**: Changed Home Assistant Settings icon to `🏠` and configured it to only appear when an Entity ID is set for the service.
- **API**: Updated `turn_on_service` response to include the generated regex pattern.
- **Database**: Added migrations for `password_hash`, `totp_secret`, and `recovery_codes` columns/tables.
- **Database**: Added migration for `random_suffix` column in services table.
- **Dependencies**: Added `pyotp` and `qrcode[pil]` to `requirements.txt`.
- **Logging**: Password reset operations now log the temporary password to the container logs for security.
- **UI/UX**: Improved layout of Settings page and standardized styling for inputs and notifications.

### Fixed
- **Authentication**: Fixed a bug where login and registration would fail due to missing CSRF tokens in AJAX requests.
- **CSRF Protection**: Fixed "Request failed" errors on Dashboard (Check Health, Toggle All), Settings, and Onboarding pages by ensuring all AJAX requests include the required CSRF token.
- **Home Assistant Integration**: Removed misleading "global setting" references and updated service-specific Entity ID helper text. Home Assistant updates are now strictly per-service.
- **Background Tasks**: Fixed an issue where Health Check and Port Rotation threads were not starting when running the application with Gunicorn (Docker default).
- **UI Layout**: Fixed column spanning issues in the Settings form.
- **Validation**: Improved validation logic for Home Assistant entity IDs.
- **UI/UX**: Fixed toast notifications disappearing too quickly by removing page reload on service toggle.

## [0.1.0] - Initial Release
