# TrakBridge

A web application for bridging tracking devices and services to TAK (Team Awareness Kit) servers. Provides real-time data streaming from various GPS sources to TAK servers for situational awareness.

**🌐 [trakbridge.io](https://trakbridge.io)** — documentation, downloads, and support

## Features

- **Multi-Source Integration**: Bring GPS trackers (Garmin InReach, SPOT, Traccar), OSINT platforms (Deepstate, LiveUAMap), and emergency management feeds onto your TAK map
- **Multiple TAK Servers**: Distribute streams to any number of TAK servers with full certificate (P12/TLS) support
- **Self-Healing Connections**: TAK server or feed outages recover automatically — streams back off, keep watch, and resume on their own with the degraded state visible in the UI
- **Inbound Streams**: Receive CoT into TrakBridge via HTTP push (JSON/XML) or active-connect transports (MQTT, WebSocket, UDP multicast) — including bridging LAN Mesh SA multicast to TAK servers across VPN/WAN
- **CoT Forwarding & Notifications**: Forward CoT from connected TAK servers to external systems (HTTP, MQTT, WebSocket, UDP multicast) or post alerts to Discord, Slack, and IRC
- **Scoped API Keys**: Personal access tokens for scripts and integrations, with per-key permissions and a fully documented REST API (OpenAPI 3.1 + Swagger UI)
- **Plugin SDK & Manager**: `pip install trakbridge-plugin-sdk` to build custom plugins in ~30-40 lines; install and manage packaged plugins from the admin UI with signature verification and code safety scanning
- **Team Member CoT & Callsign Mapping**: Display trackers as ATAK team members with roles and colours; per-tracker callsigns and CoT type overrides
- **Multi-Provider Authentication**: Local, LDAP/Active Directory, and OIDC/SSO with role-based access control
- **Security-Hardened by Default**: CSRF protection, strict session cookies, authenticated telemetry endpoints, signed premium plugins, field-level encryption
- **Monitoring Built In**: Real-time dashboard with queue metrics, stream health, connection state, and performance graphs
- **Enterprise Ready**: PostgreSQL/MySQL/SQLite, audit logging, offline licence tiers, multi-arch containers (amd64/arm64)

<img width="1900" height="690" alt="image" src="https://github.com/user-attachments/assets/d09d3e17-de62-4524-a0d6-d1990c827ac7" />


## Quick Start

### Docker (Recommended)

```bash
# Download setup files
wget https://raw.githubusercontent.com/trakbridge/trakbridge/main/docker-compose.yml
wget https://raw.githubusercontent.com/trakbridge/trakbridge/refs/heads/main/scripts/setup.sh

# Setup and run
chmod +x setup.sh
./setup.sh --enable-nginx --nginx-ssl yourdomain.com
docker-compose --profile postgres --profile nginx up -d
```

Access the web interface at `https://yourdomain.com`

**First-time login**:
- Username: `admin`
- Password: `TrakBridge-Setup-2025!`
- You'll be forced to change the password on first logins

#### Docker networking note for the UDP Multicast CoT Bridge

The **UDP Multicast CoT Bridge** inbound plugin joins a multicast group on the LAN. By default a container's only NIC is the Docker bridge (typically `172.x.x.x`), and the IGMP join lands there rather than on the host's physical LAN NIC — so no ATAK traffic arrives. Two ways to fix it depending on your setup:

**Option A — `macvlan` network (recommended when behind a reverse proxy like Traefik).** Add a second network on the host's LAN NIC; the container keeps its existing bridge IP for HTTP and gets a real LAN IP for multicast.

```yaml
networks:
  lan_multicast:
    driver: macvlan
    driver_opts:
      parent: eth0           # host's LAN NIC
    ipam:
      config:
        - subnet: 192.168.1.0/24
          gateway: 192.168.1.1
          ip_range: 192.168.1.240/29

services:
  trakbridge:
    networks:
      web: {}                # existing reverse-proxy network
      lan_multicast:
        ipv4_address: 192.168.1.242
```

Then set `bind_interface = 192.168.1.242` in the multicast stream config. Caveat: on Linux the Docker *host* cannot reach the macvlan IP directly on the same NIC — other devices on the LAN can. Not an issue when traffic flows through the reverse proxy on the bridge network.

**Option B — `network_mode: host` (simplest when there's no reverse proxy in front of TrakBridge).**

```yaml
services:
  trakbridge:
    network_mode: host
    # delete `ports:` and `networks:` — host mode bypasses them
```

The container shares the host's network namespace and joins multicast on the host NICs directly. Don't use this if Traefik / nginx is fronting TrakBridge on a Docker network — host mode will bypass it. Also not available on Docker Desktop for Mac/Windows (host networking is not supported there).

In both cases, set `bind_interface` to the explicit LAN IP rather than `0.0.0.0` so the IGMP join is deterministic on multi-homed hosts. See [Inbound Streams Guide](docs/INBOUND_STREAMS_GUIDE.md#built-in-plugin-udp-multicast-cot-bridge) for full troubleshooting.

### Environment Configuration
All configuration is managed directly in the docker-compose.yml file. Edit the `x-environment` section to customise your deployment:

```yaml
# Edit these values in docker-compose.yml
x-environment: &common-environment
  # Application Settings
  FLASK_ENV: "production"
  USER_ID: "1000"  # Change if needed for filesystem permissions
  GROUP_ID: "1000"  # Change if needed for filesystem permissions

  # Database Configuration (choose one)
  DB_TYPE: "postgresql"  # postgresql, mysql, or sqlite
  DB_HOST: "postgres"
  DB_NAME: "trakbridge"
  DB_USER: "trakbridge"

  # Security Configuration (NEW in v1.2.0)
  PROXY_TRUSTED: "false"  # Set to "true" if behind reverse proxy (nginx, load balancer)
  TRUSTED_PROXY_COUNT: "0"  # Number of proxies in chain (e.g., "1" for nginx)
  FORCE_HTTPS: "true"  # Force HTTPS redirect (disable with "false" for internal deployments only)

  # LDAP Authentication (set LDAP_ENABLED to "true" to enable)
  LDAP_ENABLED: "false"
  LDAP_SERVER: "ldap://your-ad-server.company.com"  # Update for your LDAP server
  LDAP_BIND_DN: "CN=trakbridge,OU=Service Accounts,DC=company,DC=com"  # Update for your domain

  # OIDC/SSO Authentication (set OIDC_ENABLED to "true" to enable)
  OIDC_ENABLED: "false"
  OIDC_ISSUER: "https://your-identity-provider.com"  # Update for your OIDC provider
  OIDC_CLIENT_ID: "trakbridge-client"  # Update with your client ID
  OIDC_REDIRECT_URI: "https://trakbridge.company.com/auth/oidc/callback"  # Update for your domain
```

#### Docker Secrets Setup
Sensitive credentials are managed through Docker secrets. These are created by the setup.sh script.
If LDAP or OIDC authentication backends are being used the password / OIDC client secret must be inserted into their respective secret file.

```bash
# LDAP password (if using LDAP authentication)
echo "your-ldap-bind-password" > secrets/ldap_bind_password

# OIDC client secret (if using OIDC authentication)
echo "your-oidc-client-secret" > secrets/oidc_client_secret
```

### Python Development

```bash
git clone <repository-url>
cd trakbridge
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install .
hypercorn app.py  # Single worker deployment for optimal performance
```

## Basic Usage

1. **Login**: Use default admin credentials (change password on first login)
2. **Create Users**: Set up user accounts with appropriate roles (Admin → User Management)
3. **Configure TAK Server**: Add your TAK server details and certificates
4. **Create Stream**: Select from categorised data sources (OSINT, Tracker, EMS) and configure credentials
5. **Start Streaming**: Monitor real-time data flow to your TAK server

## Documentation

Full documentation lives at **[trakbridge.io](https://trakbridge.io)**. In-repo references:

- [Documentation Hub](docs/index.md) - Complete documentation index
- [Installation Guide](docs/INSTALLATION.md) - First-time setup and deployment
- [User Guide](docs/USER_GUIDE.md) - End-user procedures and workflows
- [Administrator Guide](docs/ADMINISTRATOR_GUIDE.md) - System administration
- [Authentication Guide](docs/AUTHENTICATION.md) - Multi-provider authentication setup
- [Security Documentation](docs/SECURITY.md) - Comprehensive security guide
- [Plugin Development](docs/PLUGIN_DEVELOPMENT.md) - Creating custom plugins
- [Inbound Streams Guide](docs/INBOUND_STREAMS_GUIDE.md) - Push-based and active-connect inbound plugins, UDP multicast bridge
- [Output Plugins Guide](docs/OUTPUT_PLUGINS_GUIDE.md) - CoT forwarding and notification plugins, custom plugin development
- [API Reference](docs/API_REFERENCE.md) - Complete API documentation
- [Upgrade Guide](docs/UPGRADE_GUIDE.md) - Version upgrade procedures
- [Performance Guide](docs/PERFORMANCE_CONFIGURATION.md) - Performance Tuning Guide
- [Monitoring Guide](docs/MONITORING.md) - Real-time monitoring and dashboards

## Supported Providers and Plugins

### OSINT Platforms
- **Deepstate** - OSINT platform for battlefield intelligence and situational awareness
- **LiveMapUA** - OSINT platform for independent global news and information

### GPS Trackers
- **Garmin InReach** - Satellite communicators and GPS tracking devices
- **SPOT Tracker** - GPS tracking devices and emergency communicators
- **Traccar** - Open-source GPS tracking platform and server

### Inbound Plugins (receive data into TrakBridge)

- **JSON Receiver** - HTTP push with configurable dot-notation field mapping
- **XML Receiver** - HTTP push with XPath-based field extraction
- **HTTP Location Endpoint** - Lightweight HTTP push for ad-hoc devices
- **MQTT / WebSocket Client** - Active-connect MQTT broker or WebSocket source
- **UDP Multicast CoT Bridge** - Joins a multicast group and forwards CoT XML or TAK Protocol v1 (Mesh SA protobuf) to TAK servers; bridges LAN multicast over VPN/WAN

### CoT Forwarding Plugins (forward CoT from TAK to external systems)

- **OutboundHTTP** - POST/PUT JSON, XML, or template payloads to an endpoint
- **OutboundMQTT** - Publish CoT to an MQTT broker topic with TLS support
- **OutboundWebSocket** - Push CoT to a WebSocket server with automatic reconnect
- **UDP Multicast Publisher** - Publish CoT to a UDP multicast group on the LAN

### Notification Plugins (post CoT alerts to messaging platforms)

- **Discord** - Rich embeds or plain text via incoming webhook
- **Slack** - Block Kit formatted messages via incoming webhook
- **IRC** - Plain text or templated messages to an IRC channel

### External Plugin Support
- Docker volume mount support for custom plugins
- Plugin categorisation system for organised management
- API endpoints for category-based plugin discovery

## Health Check & Monitoring

```bash
# Basic health check
curl -f https://yourdomain.com/api/health

# Real-time monitoring dashboard
curl https://yourdomain.com/api/monitoring/dashboard
```

## License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.

## Support

- [Website & Documentation](https://trakbridge.io)
- [Report Issues](../../issues)
- [Discussions](../../discussions)
- [Wiki](../../wiki)
- [Troubleshooting Guide](../../wiki/Troubleshooting)

---

**TrakBridge v2.2.1** - Production-ready GPS tracking data bridge for TAK servers with scoped API keys, a documented REST API, self-healing connections, a public plugin SDK, inbound streams, CoT forwarding, notifications, and enterprise security, monitoring, and reliability features. Learn more at [trakbridge.io](https://trakbridge.io).
