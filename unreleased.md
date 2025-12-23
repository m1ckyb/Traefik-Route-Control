### Added
- **Infrastructure**: Added support for "VPS Gateway + WireGuard" routing mode, allowing RouteGhost to bypass Cloudflare Proxy and UniFi ingress entirely by tunneling traffic through a remote VPS.
- **UI**: Added "VPS / WireGuard" settings tab to configure SSH credentials and WireGuard peers.
- **Backend**: Implemented `routing.py` module for managing WireGuard interfaces and remote VPS `iptables` rules via SSH.
- **Dependencies**: Added `wireguard-tools`, `openresolv`, `iproute2`, `openssh-client`, and `paramiko` to the Docker image.

### Security
- **Hardening**: Implemented strict input sanitization (`shlex.quote`) and validation for all VPS/WireGuard settings to prevent command injection and configuration tampering.
- **Whitelist**: Expanded `ALLOWED_USER_SETTINGS` to include new VPS configuration keys.

### Changed
- Refactored Settings UI:
    - Moved Traefik and Redis settings to the "Integrations" tab.
    - Consolidated "VPS / WireGuard" tab into "Infrastructure" tab.
    - Added "Routing Mode" dropdown to "Infrastructure" tab to toggle between "Cloudflare + UniFi" and "VPS + WireGuard" settings.
    - Moved UniFi firewall settings to "Infrastructure" tab under "Cloudflare + UniFi" mode.

### Fixed

### Removed