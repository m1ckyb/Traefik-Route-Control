### Added
- **Infrastructure**: Added support for "VPS Gateway + WireGuard" routing mode, allowing RouteGhost to bypass Cloudflare Proxy and UniFi ingress entirely by tunneling traffic through a remote VPS.
- **UI**: Added "VPS / WireGuard" settings tab to configure SSH credentials and WireGuard peers.
- **Backend**: Implemented `routing.py` module for managing WireGuard interfaces and remote VPS `iptables` rules via SSH.
- **Dependencies**: Added `wireguard-tools`, `openresolv`, `iproute2`, `openssh-client`, and `paramiko` to the Docker image.

### Changed

### Fixed

### Removed