# RouteGhost 👻

A security-focused Python application to temporarily expose local services (Jellyfin, Sonarr, etc.) to the internet using rotating subdomains, dynamic Traefik routing, and automated firewall control. Integrates with **Cloudflare**, **UniFi UDM Pro**, **Traefik (Redis)**, and **Home Assistant**.

## ✨ Features

*   **Dynamic Access**: Rotating subdomains and random port generation (1024-65535) for every session.
*   **Security First**: Passkey (WebAuthn) authentication, 2FA (TOTP), and automated firewall toggling.
*   **Centralized Control**: Manage multiple services from a single dashboard.
*   **Integrations**:
    *   **Cloudflare**: Automated DNS and Origin Rules.
    *   **Traefik**: Dynamic routing via Redis.
    *   **UniFi**: Automatic Port Forwarding management.
    *   **Home Assistant**: Entity state updates.
*   **Diagnostics**: Built-in tools to verify DNS, Traefik, and Firewall status.

## 🚀 Quick Start

### Docker Compose

1. Clone the repository:
```bash
git clone https://github.com/m1ckyb/RouteGhost.git
cd RouteGhost
```

2.  **Run**:
    ```bash
    docker-compose up -d
    ```

3.  **Initial Setup (5-minute window)**:
    *   Access `http://localhost:5000`.
    *   Register the admin account using a **Passkey** (FaceID, TouchID, YubiKey, or PIN).
    *   Navigate to **Settings** to configure your API keys and integrations.

### Manual Run
```bash
pip install -r requirements.txt
python3 main.py serve
```

## 🔧 Configuration

Configure these in the Web UI (`/settings`):

| Category | Requirements |
|----------|--------------|
| **Cloudflare** | API Token (DNS/Zone edit), Zone ID, Domain Root, Origin Rule Name |
| **Traefik/Redis** | Host, Port, Password |
| **UniFi** | Host, Credentials, Port Forward Rule Name |
| **Home Assistant** | URL, Access Token, Entity ID (Optional) |

## 📖 Usage

### Web Interface
*   **Dashboard**: Toggle services on/off, rotate URLs, and view status.
*   **Services**: Configure internal URLs, Traefik router names, and subdomain prefixes.
*   **Diagnostics**: Run health checks on any service to verify connectivity.

### API
Authenticate via browser session or `X-API-Key` header.

*   `GET /api/status`: System status.
*   `POST /api/services/{id}/on`: Enable service.
*   `POST /api/services/{id}/off`: Disable service.
*   `POST /api/services/{id}/rotate`: Rotate subdomain/port.
*   `GET /api/services/{id}/diagnose`: Run deep health checks.

## 🔐 Security & Auth

*   **Passkeys**: Uses WebAuthn for passwordless, phishing-resistant login.
*   **Network**: Randomizes ports to evade scanners. Firewall rules are only active when services are enabled.
*   **Production**: If running behind a reverse proxy, set `RP_ID` (e.g., `example.com`) and `ORIGIN` (e.g., `https://example.com`) environment variables.

## 🏗️ Architecture

```
[Web UI] -> [Flask App] -> [SQLite]
               |
               +-> [Redis/Traefik]
               +-> [Cloudflare API]
               +-> [UniFi API]
               +-> [Home Assistant]
```

## 📁 Data Persistence

All configuration is stored in an SQLite database at `/app/data/config.db` inside the container. RouteGhost uses **Named Docker Volumes** (`routeghost_data`) by default to ensure reliability and performance, especially when running on Windows via WSL2.

```yaml
volumes:
  routeghost_data:
```

## 📄 License

This project is open source and available under the **GNU Affero General Public License v3.0 (AGPLv3)**.