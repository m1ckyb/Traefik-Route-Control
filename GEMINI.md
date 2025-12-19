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



## Workflow & Changelog

**CRITICAL**: Every time you make a change to the codebase that affects functionality, user experience, or configuration (features, bug fixes, refactoring, style updates), you **MUST** follow these steps:

1.  **Update `unreleased.md`**: 
    - **Format**: Follow the [Keep a Changelog](https://keepachangelog.com/en/1.0.0/) convention.
    - **Categories**: Use sub-headers like `### Added`, `### Changed`, `### Fixed`, `### Removed`.
    - **Content**: Be concise but descriptive. Explain *what* changed and *why*.
    - **Process**: Perform the `unreleased.md` update in the same turn as the code changes.

2.  **Rebuild Local Container**:
    - After making changes, always rebuild and restart the local development container to verify the fix/feature.
    - Command: `docker-compose -f docker-compose-dev.yml up -d --build`

3.  **Git Push Restriction**:
    - **NEVER** push code to GitHub (e.g., `git push`) unless the user explicitly instructs you to do so.
    - Only commit changes locally unless told otherwise.

## Release Process

When requested to "Make a release", where `<type>` is Patch, Minor, or Major, the following steps must be performed based on Semantic Versioning:

1.  **Determine New Version**: Read the current version from `VERSION.txt` (e.g., X.Y.Z).
    - For a Patch release, the new version will be X.Y.(Z+1).
    - For a Minor release, the new version will be X.(Y+1).0.
    - For a Major release, the new version will be (X+1).0.0.

2.  **Update `CHANGELOG.md`**:
    - Create a new version heading with the new version number and current date (e.g., `## [1.0.0] - YYYY-MM-DD`).
    - Move all content from `unreleased.md` into this new section.
    - Ensure the formatting is correct and consistent with previous entries.
    - Do not add an `[Unreleased]` section back to the top of `CHANGELOG.md`. This file should only contain released versions.

3.  **Clear `unreleased.md`**: After moving the content, reset `unreleased.md` to its default empty state, ready for the next development cycle.

4.  **Update `VERSION.txt`**: Change the content of `VERSION.txt` to the new version number.

5.  **Update `docker-compose.yml`**: Update the image tags for the dashboard and worker services to the new version number.

6.  **Update `README.md` and `summary.md`**: Review both files to see if any of the new features or significant changes from the changelog need to be reflected in the project overview or feature list. Update them as necessary.
