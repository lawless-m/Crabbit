# Crabbit Configuration

Crabbit uses TOML configuration. All settings in one file.

## Example Configuration

```toml
# Crabbit configuration

[listen]
# Where to listen for 9P connections
address = "0.0.0.0:564"
# Or Unix socket: address = "/tmp/crabbit.sock"

[wireguard]
# Your private key (base64, from wg genkey)
private_key = "PRIVATE_KEY_HERE"

# Port to listen for WireGuard traffic
listen_port = 51820

# Your address on the WireGuard network
address = "10.0.0.5/24"

[[wireguard.peers]]
name = "homeserver"
public_key = "PEER_PUBLIC_KEY_HERE"
endpoint = "home.example.com:51820"
allowed_ips = ["10.0.0.1/32"]
persistent_keepalive = 25

[[wireguard.peers]]
name = "vps"
public_key = "ANOTHER_PUBLIC_KEY"
endpoint = "vps.example.com:51820"
allowed_ips = ["10.0.0.2/32"]
persistent_keepalive = 25

[[wireguard.peers]]
name = "laptop"
public_key = "LAPTOP_PUBLIC_KEY"
# No endpoint - this peer connects to us
allowed_ips = ["10.0.0.3/32"]

[dns]
# Upstream DNS servers (reached via WireGuard tunnel)
servers = ["1.1.1.1", "8.8.8.8"]

# Optional: cache TTL in seconds (default 300)
cache_ttl = 300

# Optional: hosts table for mesh peer names
[dns.hosts]
homeserver = "10.0.0.1"
vps = "10.0.0.2"
laptop = "10.0.0.3"

[auth]
# Mode: "standalone" or "authserver"
mode = "standalone"

# Auth identity and domain
authid = "crabbit"
authdom = "crabbit"

# For authserver mode only:
# server = "10.0.0.1!567"

# Users (standalone mode only)
[[auth.users]]
name = "glenda"
key = "0123456789abcdef"  # 7 bytes as hex

[[auth.users]]
name = "alice" 
key = "fedcba9876543210"

[logging]
# Level: error, warn, info, debug, trace
level = "info"

# Optional: log to file instead of stderr
# file = "/var/log/crabbit.log"
```

## Section Reference

### [listen]

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `address` | string | yes | 9P listen address. TCP (`host:port`) or Unix socket (path) |

### [wireguard]

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `private_key` | string | yes | WireGuard private key (base64) |
| `listen_port` | integer | yes | UDP port for WireGuard |
| `address` | string | yes | Your IP on the WireGuard network (CIDR) |

### [[wireguard.peers]]

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | yes | Friendly name for this peer |
| `public_key` | string | yes | Peer's public key (base64) |
| `endpoint` | string | no | Peer's external address (`host:port`) |
| `allowed_ips` | array | yes | IPs this peer can send from (CIDR) |
| `persistent_keepalive` | integer | no | Keepalive interval in seconds |

**Notes:**
- `endpoint` is optional for peers that connect to you
- `allowed_ips` controls routing — packets for these IPs go to this peer
- `persistent_keepalive` useful for NAT traversal

### [dns]

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `servers` | array | yes | Upstream DNS server IPs |
| `cache_ttl` | integer | no | Cache lifetime in seconds (default 300) |

### [dns.hosts]

Optional static hostname mappings. Checked before upstream DNS.

```toml
[dns.hosts]
mybox = "10.0.0.1"
otherbox = "10.0.0.2"
```

### [auth]

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `mode` | string | yes | `standalone` or `authserver` |
| `authid` | string | yes | Server's auth identity |
| `authdom` | string | yes | Auth domain |
| `server` | string | no | Auth server address (authserver mode) |

### [[auth.users]]

For standalone mode. Each entry:

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | yes | Username |
| `key` | string | yes | DES key as hex (14 characters = 7 bytes) |

### [logging]

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `level` | string | no | Log level (default `info`) |
| `file` | string | no | Log to file instead of stderr |

## Generating Keys

### WireGuard keys

```bash
# Generate private key
wg genkey > private.key

# Derive public key
wg pubkey < private.key > public.key
```

### Auth keys

Use Plan 9 `auth/wrkey` or your C# tool to convert password to key:

```
password → passtokey() → 7-byte key → hex string
```

## Command Line

```
crabbit [OPTIONS]

OPTIONS:
    -c, --config <FILE>    Config file path (default: /etc/crabbit.toml)
    -v, --verbose          Increase log level
    -q, --quiet            Decrease log level
    --check                Validate config and exit
    -h, --help             Show help
```

## Environment Variables

| Variable | Description |
|----------|-------------|
| `CRABBIT_CONFIG` | Config file path (overridden by -c) |
| `CRABBIT_LOG` | Log level (overridden by config/flags) |
| `CRABBIT_PRIVATE_KEY` | WireGuard private key (avoids putting in file) |

## File Permissions

Config file should be readable only by Crabbit's user:

```bash
chmod 600 /etc/crabbit.toml
chown crabbit:crabbit /etc/crabbit.toml
```

The private key and auth keys are sensitive. Consider:

- Running Crabbit as dedicated user
- Using environment variable for private key
- Encrypted filesystem for config storage
