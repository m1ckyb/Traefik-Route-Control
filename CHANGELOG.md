# Changelog

All notable changes to this project will be documented in this file.

## [Unreleased]

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
- **UI/UX**: Standardized button sizes across the application for a more consistent interface.
- **UI/UX**: Unified service control notifications to use the same toast style as the settings page.
- **Database**: Added migrations for `password_hash`, `totp_secret`, and `recovery_codes` columns/tables.
- **Database**: Added migration for `random_suffix` column in services table.
- **Dependencies**: Added `pyotp` and `qrcode[pil]` to `requirements.txt`.
- **Logging**: Password reset operations now log the temporary password to the container logs for security.
- **UI/UX**: Improved layout of Settings page and standardized styling for inputs and notifications.

### Fixed
- **UI Layout**: Fixed column spanning issues in the Settings form.
- **Validation**: Improved validation logic for Home Assistant entity IDs.

## [0.1.0] - Initial Release
- Basic Traefik route rotation.
- Cloudflare DNS and Origin Rule integration.
- UniFi Firewall integration.