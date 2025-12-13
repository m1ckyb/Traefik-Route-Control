# Traefik Route Control

A security-focused Python automation tool that temporarily exposes multiple local services to the internet using rotating subdomains, dynamic Traefik routing, and automated firewall control.

It integrates directly with Cloudflare, UniFi UDM Pro, Traefik (Redis), and Home Assistant.

## ✨ Features

- **Multi-Service Management**: Control multiple services (Jellyfin, Sonarr, Radarr, etc.) from a single web interface
- **Passkey Authentication**: Secure login with WebAuthn passkey support (biometric or PIN-based authentication)
- **Per-Service Home Assistant Integration**: Each service can have its own Home Assistant entity ID for granular control
- **Web UI Configuration**: Configure all settings and services through an intuitive web interface - no .env files needed
- **Rotating Subdomains**: Generates a random URL (e.g., https://jf-k92m1x0p.domain.com) every time you enable a service
- **Cloudflare Integration**: Automatically creates DNS records and updates Origin Rules (Port Rewrites)
- **Traefik Dynamic Routing**: Uses Redis to inject routing rules into Traefik without restarting containers
- **UniFi Firewall Control**: Automatically opens the specific Port Forwarding rule on your UDM Pro only when services are active
- **Multi-Service Safety**: Checks if other services are using the port before closing the firewall
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
   - On first access, you'll be prompted to create an admin account
   - Enter a username and click "Create Account with Passkey"
   - Follow your browser's prompts to register a passkey (fingerprint, face ID, or device PIN)
   - Once registered, you'll be logged in automatically

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

The application provides a REST API for programmatic control:

- `GET /api/status` - Get overall system status
- `GET /api/firewall-status` - Get firewall status
- `POST /api/services/{id}/on` - Turn on a specific service
- `POST /api/services/{id}/off` - Turn off a specific service
- `POST /api/services/{id}/rotate` - Rotate URL for a service
- `DELETE /api/services/{id}` - Delete a service

Legacy endpoints (control first service):
- `POST /api/turn_on` - Turn on first service
- `POST /api/turn_off` - Turn off first service

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

When deploying behind a reverse proxy or with a custom domain, set these environment variables:

- `RP_ID`: Your domain (e.g., `example.com` or `localhost` for local testing)
- `ORIGIN`: Full URL of your application (e.g., `https://example.com` or `http://localhost:5000`)

Example Docker Compose:
```yaml
environment:
  - RP_ID=traefik.example.com
  - ORIGIN=https://traefik.example.com
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
- Store sensitive credentials securely - they are saved in the SQLite database
- Consider using Docker secrets or environment variables for production deployments
- Rotating URLs provide security through obscurity - they are temporary by design
- Passkeys are hardware-backed and phishing-resistant
- For production use behind HTTPS, set `RP_ID` and `ORIGIN` environment variables correctly

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

This project is open source and available under the MIT License.
