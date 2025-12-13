Jellyfin Traefik Control
A security-focused Python automation tool that temporarily exposes a local service (like Jellyfin) to the internet using rotating subdomains, dynamic Traefik routing, and automated firewall control.

It integrates directly with Cloudflare, UniFi UDM Pro, Traefik (Redis), and Home Assistant.

✨ Features
Rotating Subdomains: Generates a random URL (e.g., https://jf-k92m1x0p.domain.com) every time you turn it on.

Cloudflare Integration: Automatically creates DNS records and updates Origin Rules (Port Rewrites).

Traefik Dynamic Routing: Uses Redis to inject routing rules into Traefik without restarting containers.

UniFi Firewall Control: Automatically opens the specific Port Forwarding rule on your UDM Pro only when the service is active.

Multi-Service Safety: Checks if other services are using the port before closing the firewall.

Home Assistant Integration: Updates a dashboard entity with the live URL and provides a toggle switch.
