### Added
- **API**: Added `/api/settings` endpoint for saving individual configuration settings via AJAX.
- **UI/UX**: Added a "Rotate Port" button to the main dashboard to manually trigger an immediate firewall port rotation.

### Changed
- **Branding**: Renamed the project from "Traefik Route Control" to **RouteGhost** 👻 and updated all UI elements, documentation, and Docker configuration.
- **Security**: Updated Docker image to run as a non-root user (`appuser`) with configurable UID/GID (`PUID`/`PGID`), improving container security and host file system compatibility.
- **Infrastructure**: Switched from host-mounted directories to **Named Docker Volumes** (`routeghost_data`) for the `/app/data` directory. This resolves SQLite "readonly database" errors and permission issues specifically encountered when running via WSL2 on Windows host mounts.
- **UI/UX**: Added a "Save" button to the Base URL field in the Home Assistant Settings modal, allowing users to persist their preferred application address for Home Assistant configuration.
- **UI/UX**: Added an editable "Base URL" field to the Home Assistant Settings modal, allowing users to easily customize the API address (e.g., using an IP address instead of a domain) in the generated YAML configuration.
- **UI/UX**: Replaced the numeric input for "Port Rotation Interval" with a dropdown menu featuring 30-minute increments up to 8 hours for better usability.
- **UI/UX**: "Check Health" and "Rotate Port" buttons on the dashboard are now automatically disabled when the firewall is closed, with a tooltip explaining the reason.
- **UI/UX**: Enhanced disabled button styling with reduced opacity and saturation to provide better visual feedback when actions are unavailable.
- **UI/UX**: Dynamic status updates: Toggling services now automatically updates the firewall status badge and enables/disables dashboard buttons without a page refresh.
- **UI/UX**: Dynamic health updates: Clicking "Check Health" now updates service badges and slider colors immediately without a page refresh.
- **UI/UX**: Background status polling: The dashboard now polls the server status every 30 seconds to automatically update firewall and health status indicators.
- **UI/UX**: The "Rotate URL" button is now automatically disabled for services that have "Randomize Suffix" turned off, as static subdomains do not support rotation.
- **CI/CD**: Updated Docker Image CI workflow to stop creating tags based on branch names (e.g., removing the `main` tag), sticking to `latest` and semantic version tags.
- **License**: Switched project license from MIT to GNU Affero General Public License v3.0 (AGPLv3) to ensure continued open-source availability of modifications.

### Fixed
- **Docker**: Implemented aggressive permission enforcement (`chmod 777`) in the entrypoint script to resolve `sqlite3.OperationalError: attempt to write a readonly database` issues, particularly on restrictive host filesystem mounts like WSL2.
- **Docker**: Fixed permission issues with log files and persistent storage by adding an `entrypoint.sh` script that uses `su-exec` to correct file ownership at runtime.
- **Core**: Editing an active service now automatically synchronizes the new configuration with Redis and external APIs (DNS, Cloudflare) without requiring a toggle.
- **Home Assistant Integration**: Fixed a bug where "None" would be rendered and saved in the Home Assistant Entity ID field when left empty.
- **Authentication**: Fixed a bug where login and registration would fail due to missing CSRF tokens in AJAX requests.
- **CSRF Protection**: Fixed "Request failed" errors on Dashboard (Check Health, Toggle All), Settings, and Onboarding pages by ensuring all AJAX requests include the required CSRF token.
- **Home Assistant Integration**: Removed misleading "global setting" references and updated service-specific Entity ID helper text. Home Assistant updates are now strictly per-service.
- **Background Tasks**: Fixed an issue where Health Check and Port Rotation threads were not starting when running the application with Gunicorn (Docker default).
- **UI Layout**: Fixed column spanning issues in the Settings form.
- **Validation**: Improved validation logic for Home Assistant entity IDs.
- **UI/UX**: Fixed toast notifications disappearing too quickly by removing page reload on service toggle.
