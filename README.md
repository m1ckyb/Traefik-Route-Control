# Traefik Route Control

A security-focused Python automation tool that temporarily exposes multiple local services to the internet using rotating subdomains, dynamic Traefik routing, and automated firewall control.

It integrates directly with Cloudflare, UniFi UDM Pro, Traefik (Redis), and Home Assistant.

## ✨ Features

- **Multi-Service Management**: Control multiple services (Jellyfin, Sonarr, Radarr, etc.) from a single web interface
- **Passkey Authentication**: Secure login with WebAuthn passkey support (biometric or PIN-based authentication)
- **Two-Factor Authentication**: Optional TOTP-based 2FA with recovery codes for added security
- **API Key Support**: Generate API keys for programmatic access via curl, scripts, or automation tools
- **Service Diagnostics & Repair**: Comprehensive diagnostic tools to identify and fix configuration issues (DNS, Traefik, Cloudflare, firewall)
- **Per-Service Home Assistant Integration**: Each service can have its own Home Assistant entity ID for granular control, with a customizable API URL
- **Web UI Configuration**: Configure all settings and services through an intuitive web interface - no .env files needed
- **Rotating Subdomains**: Generates a random URL (e.g., https://jf-k92m1x0p.domain.com) every time you enable a service
- **Random Port Generation**: Automatically generates a unique random port (1024-65535) for each service activation, avoiding known assigned ports for enhanced security
- **Cloudflare Integration**: Automatically creates DNS records and updates Origin Rules (Port Rewrites)
- **Traefik Dynamic Routing**: Uses Redis to inject routing rules into Traefik without restarting containers
- **UniFi Firewall Control**: Automatically opens the specific Port Forwarding rule on your UDM Pro with dynamic port assignment
- **Manual Port Rotation**: Instantly rotate the firewall port for all services with a single button click
- **Multi-Service Safety**: Checks if other services are using the port before closing the firewall
- **Backup & Restore**: Easily export and import your configuration settings
- **Persistent Storage**: All configuration stored in SQLite database with Docker volume support

## 🚀 Quick Start

### Docker Compose (Recommended)

1. Clone the repository:
```bash
git clone https://github.com/m1ckyb/Jellyfin_Traefik_Control.git
cd Jellyfin_Traefik_Control
```

2. Create data directory for persistent storage:
```bash
mkdir -p data
```

3. Start the container:
```bash
docker-compose up -d
```

4. Access the Web UI:
```
http://localhost:5000
```

5. **First-Time Setup**:
   - On first access, you'll be redirected to the login page to create an admin account
   - You have 5 minutes from application startup to complete this setup
   - Enter a username and click "Create Account with Passkey"
   - Follow your browser's prompts to register a passkey (fingerprint, face ID, or device PIN)
   - Once registered, you'll be logged in automatically
   - If the 5-minute window expires, restart the application to create the admin account

6. Configure settings:
   - Navigate to http://localhost:5000/settings
   - Enter your Cloudflare, Redis, UniFi, and Home Assistant credentials
   - Save settings

7. Add services:
   - Click "Add Service" on the home page
   - Configure each service with:
     - Service Name (e.g., "Jellyfin")
     - Router Name (e.g., "jellyfin-secure")
     - Service Name (Traefik) (e.g., "jellyfin-service")
     - Target URL (e.g., "http://192.168.1.10:8096")
     - Subdomain Prefix (e.g., "jf")

### Docker Run

```bash
docker run -d \
  -p 5000:5000 \
  -v $(pwd)/data:/app/data \
  --name traefik-control \
  ghcr.io/m1ckyb/jellyfin_traefik_control:main
```

### Manual Installation

```bash
# Install dependencies
pip install -r requirements.txt

# Run the web server
python3 main.py serve
```

## 📖 Usage

### Web Interface

The primary way to use this application is through the web interface at http://localhost:5000.

**Main Dashboard**: View all configured services and their status. Control services with turn on/off and rotate buttons.

**Settings Page**: Configure global settings for Cloudflare, Redis, UniFi, and Home Assistant integrations.

**Add/Edit Service**: Configure individual services with their specific routing and target information.

### API Endpoints

The application provides a REST API for programmatic control.

#### Authentication

API endpoints support two authentication methods:

1. **Session-based authentication** (for web UI): Use your browser session after logging in with passkeys
2. **API Key authentication** (for programmatic access): Include an `X-API-Key` header in your requests

To create an API key:
1. Log in to the web UI
2. Navigate to "API Keys" in the top menu
3. Create a new API key with a descriptive name
4. Copy the generated key (it will only be shown once)

Example usage:
```bash
# Using curl with API key
curl -X GET http://localhost:5000/api/status \
  -H "X-API-Key: your-api-key-here"

# Turn on a service
curl -X POST http://localhost:5000/api/services/1/on \
  -H "X-API-Key: your-api-key-here"

# Get service status
curl -X GET http://localhost:5000/api/services/1/status \
  -H "X-API-Key: your-api-key-here"
```

#### Available Endpoints

- `GET /api/status` - Get overall system status
- `GET /api/firewall-status` - Get firewall status
- `GET /api/services/{id}/status` - Get status of a specific service
- `GET /api/services/{id}/diagnose` - Run comprehensive diagnostics on a service
- `POST /api/services/{id}/on` - Turn on a specific service
- `POST /api/services/{id}/off` - Turn off a specific service
- `POST /api/services/{id}/rotate` - Rotate URL for a service
- `POST /api/services/{id}/repair` - Repair service configuration mismatches
- `DELETE /api/services/{id}` - Delete a service

Legacy endpoints (control first service):
- `POST /api/turn_on` - Turn on first service
- `POST /api/turn_off` - Turn off first service

### Service Diagnostics

The application includes comprehensive diagnostic tools to help troubleshoot service issues:

**Web UI**: Click the "🔍 Diagnose" button on any enabled service to run a full diagnostic check. The diagnostics modal will show:
- ✅ **Redis Connection**: Verifies connectivity to Redis/Traefik
- ✅ **Traefik Router**: Checks if the router is configured correctly
- ✅ **Traefik Service**: Validates backend URL configuration
- ✅ **DNS Record**: Confirms DNS record exists in Cloudflare
- ✅ **Origin Rule**: Checks Cloudflare Origin Rule configuration
- ✅ **Firewall**: Verifies firewall rule status and port

Each check will show:
- ✅ Green checkmark for passing checks
- ⚠️ Yellow warning for potential issues
- ❌ Red X for failures
- ℹ️ Blue info for informational messages

If configuration mismatches are detected, you can click the "🔧 Repair Configuration" button to automatically fix them.

**API**: Use `GET /api/services/{id}/diagnose` to get detailed diagnostic information in JSON format:

```bash
curl -X GET http://localhost:5000/api/services/1/diagnose \
  -H "X-API-Key: your-api-key-here"
```

Example response:
```json
{
  "service": {...},
  "checks": {
    "redis": {"status": "ok", "message": "Redis connection successful"},
    "traefik_router": {"status": "ok", "hostname": "jf-abc123.example.com"},
    "traefik_service": {
      "status": "warning",
      "message": "Service backend URL mismatch",
      "expected": "http://192.168.10.125:8096",
      "actual": "http://192.168.10.125:80"
    },
    "dns": {"status": "ok", "message": "DNS record exists"},
    "firewall": {"status": "ok", "port": 54231}
  }
}
```

To repair configuration issues:
```bash
curl -X POST http://localhost:5000/api/services/1/repair \
  -H "X-API-Key: your-api-key-here"
```

### Command Line Interface

```bash
# Start the web server (default)
python3 main.py serve

# Check status
python3 main.py status

# Turn on first service
python3 main.py on

# Turn off all services
python3 main.py off

# Rotate first service URL
python3 main.py rotate
```

## 🔧 Configuration

### Required Settings

Configure these via the Web UI at `/settings`:

**Cloudflare**:
- API Token (with DNS and Zone edit permissions)
- Zone ID
- Domain Root (e.g., example.com)
- Origin Rule Name

**Traefik/Redis**:
- Redis Host
- Redis Port
- Redis Password (optional)

**UniFi Controller**:
- Host address
- Username
- Password
- Port Forward Rule Name

**Home Assistant** (optional):
- URL
- Entity ID (Global Fallback) - Used if a service doesn't specify its own entity ID
- Long-lived Access Token

### Service Configuration

Each service requires:
- **Name**: Friendly identifier (e.g., "Jellyfin")
- **Router Name**: Unique Traefik router name (e.g., "jellyfin-secure")
- **Service Name**: Traefik service name (e.g., "jellyfin-service")
- **Target URL**: Internal URL of the service (e.g., "http://192.168.1.10:8096")
- **Subdomain Prefix**: Short prefix for rotating URLs (e.g., "jf")
- **Home Assistant Entity ID** (optional): Specific entity ID for this service. If left empty, the global entity ID will be used.

## 🔐 Authentication & Security

### Passkey Authentication

The application uses **WebAuthn** (passkeys) for secure, passwordless authentication:

- **No passwords to remember or store**: Uses your device's built-in biometric authentication (fingerprint, face recognition) or PIN
- **Phishing-resistant**: Passkeys are cryptographically bound to your domain
- **Hardware-backed security**: Private keys never leave your device
- **Easy setup**: Just enter a username and follow your browser's prompts

**Supported authentication methods:**
- Fingerprint readers
- Face recognition (Face ID, Windows Hello)
- Device PIN or pattern
- Security keys (YubiKey, etc.)

**Browser requirements:**
- Chrome/Edge 67+
- Firefox 60+
- Safari 13+
- Opera 54+

**First-time setup:**
1. Navigate to the web UI (e.g., http://localhost:5000)
2. Enter a username for your admin account
3. Click "Create Account with Passkey"
4. Follow your browser's prompts to register your biometric/PIN

**Subsequent logins:**
1. Enter your username
2. Click "Sign In with Passkey"
3. Authenticate with your biometric/PIN

### Environment Variables for WebAuthn

**For development (localhost):**
- No configuration needed! The application automatically detects the origin (localhost, 127.0.0.1, etc.) from your browser request
- Supports `http://localhost:5000`, `http://127.0.0.1:5000`, and any other localhost-like addresses
- Works out of the box for local testing

**For production (custom domain/reverse proxy):**
When deploying behind a reverse proxy or with a custom domain, set these environment variables:

- `RP_ID`: Your domain (e.g., `example.com`)
- `ORIGIN`: Full URL of your application (e.g., `https://example.com`)
- `SETUP_WINDOW_SECONDS`: Time window in seconds for initial admin account creation (default: 300 = 5 minutes)

Example Docker Compose:
```yaml
environment:
  - RP_ID=traefik.example.com
  - ORIGIN=https://traefik.example.com
  - SETUP_WINDOW_SECONDS=300
```

## 🔄 Migrating from Single Service

If you were using the previous version with a .env file:

1. The application will automatically detect and migrate your .env settings on first run
2. Your single service configuration will be imported as "Jellyfin"
3. You can then add more services via the web UI
4. The .env file is no longer needed and can be removed

## 📁 Data Persistence

All configuration is stored in an SQLite database at `/app/data/config.db` inside the container. Make sure to mount a volume to `/app/data` to persist your configuration across container restarts:

```yaml
volumes:
  - ./data:/app/data
```

## 🔒 Security Notes

- **Passkey authentication required**: All routes are protected with WebAuthn passkey authentication
- **Localhost development**: Automatically works with localhost, 127.0.0.1, and other local addresses - no configuration needed
- Store sensitive credentials securely - they are saved in the SQLite database
- Consider using Docker secrets or environment variables for production deployments
- Rotating URLs provide security through obscurity - they are temporary by design
- **Random port assignment**: Each service activation generates a unique random port (1024-65535), avoiding 1100+ known assigned ports from the IANA registry
- Passkeys are hardware-backed and phishing-resistant
- For production use behind HTTPS, set `RP_ID` and `ORIGIN` environment variables correctly

## 🎲 Random Port Feature

When you enable a service, the application automatically:

1. **Generates a random port** between 1024 and 65535
2. **Avoids known assigned ports** including:
   - System ports (1-1023)
   - Common service ports (HTTP, HTTPS, SSH, MySQL, Redis, etc.)
   - Ports already in use by other active services
3. **Updates UniFi** port forwarding rule with the new port
4. **Updates Cloudflare** Origin Rules to route traffic to the new port
5. **Displays the port** in the service status on the web UI

This provides an additional layer of security by making it harder to predict which port your service is using at any given time. The port changes each time you enable a service (or rotate its URL).

**Example**: When you enable Jellyfin, it might use port 54231 the first time, then port 12847 when you rotate it, and so on.

## 🏗️ Architecture

```
┌─────────────┐
│   Web UI    │ ← Users interact here
└──────┬──────┘
       │
┌──────▼──────┐
│  Flask App  │ ← Main application
└──────┬──────┘
       │
┌──────▼──────┐
│  SQLite DB  │ ← Configuration storage
└──────┬──────┘
       │
    ┌──▼───────────────────────────┐
    │                              │
┌───▼────┐  ┌──────┐  ┌──────┐  ┌─▼───┐
│ Redis  │  │ CF   │  │ UniFi│  │ HA  │
│Traefik │  │ API  │  │ UDM  │  │ API │
└────────┘  └──────┘  └──────┘  └─────┘
```

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## 📄 License

This project is open source and available under the GNU Affero General Public License v3.0 (AGPLv3).
