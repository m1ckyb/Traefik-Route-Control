# Gemini Onboarding - Traefik Route Control

## Project Overview
**Traefik Route Control** is a Python/Flask application designed to securely expose local services (like Jellyfin, Sonarr, Radarr) to the internet temporarily. It uses a combination of:
- **Traefik** (via Redis provider) for dynamic routing.
- **Cloudflare** for DNS records and Origin Rules (port rewrites).
- **UniFi UDM Pro** for firewall control (opening/closing ports).
- **Home Assistant** for state updates.

## Architecture
- **Backend**: Flask (`main.py`) handles the web UI and API.
- **Database**: SQLite (`database.py`) stores configuration, users, services, and auth credentials.
- **Frontend**: HTML/CSS/JS (`templates/`, `static/`).
- **Background Tasks**: Threading in `main.py` handles health checks.
- **External Integrations**:
    - **Redis**: Stores Traefik routing configuration.
    - **Cloudflare API**: Manages DNS A records and Origin Rules.
    - **UniFi Controller API**: Toggles port forwarding rules.
    - **Home Assistant API**: Updates entity states.

## Key Files
- `main.py`: Core application logic, API endpoints, background threads, and external API interactions.
- `database.py`: Database schema, migrations, and CRUD operations.
- `templates/`: Jinja2 HTML templates.
    - `base.html`: Layout and common JS/CSS.
    - `index.html`: Main dashboard.
    - `settings.html`: Configuration page (tabbed).
    - `login.html`: Authentication page.
- `requirements.txt`: Python dependencies.

## Development Guidelines

### Database Migrations
- The database schema is versioned in `database.py` inside `init_db()`.
- When adding columns or tables, increment the schema version and add a migration block checking `current_version`.

### Authentication
- Supports **Passkeys** (WebAuthn) and **Password** login.
- **2FA (TOTP)** is supported and can be enforced globally.
- **API Keys** allow programmatic access (`X-API-Key` header).
- Use `@login_required` for UI routes and `@api_key_or_login_required` for API endpoints.

### Configuration
- Settings are stored in the `settings` table in SQLite.
- Accessed via `db.get_setting(key)`.
- Configured via the Web UI (`/settings`).

### Logging
- Logs are written to `app.log` in the `DATA_DIR`.
- `sys.stdout` and `sys.stderr` are redirected to this log file using the `Tee` class in `main.py`.

### Error Handling
- API endpoints should return JSON with `error` keys on failure.
- UI routes should use `flash()` messages.

## Common Tasks

### Adding a New Setting
1. Add the input field in `templates/settings.html`.
2. The `settings` route in `main.py` automatically saves all form data to the DB, so no backend change is usually needed for simple string settings unless validation logic is required.
3. Use `db.get_setting('KEY')` in `main.py` to use the value.

### Adding a New Feature
1. If it requires DB changes, update `database.py`.
2. Add backend logic/routes in `main.py`.
3. Update templates if UI is needed.

### Security
- Always check permissions.
- Validate inputs (especially URLs and IP addresses).
- Ensure sensitive data (passwords, tokens) is handled securely.

## Context for Gemini
When working on this project, assume the user wants robust, production-ready code. Pay attention to:
- **Error handling**: External APIs (Cloudflare, UniFi) can fail.
- **User Experience**: The UI should be responsive and provide feedback (toasts/alerts).
- **Security**: This app controls firewall rules, so security is paramount.