# Crabbit /net Protocol

This document describes the Plan 9 `/net` filesystem semantics that Crabbit implements.

## File Tree Structure

```
/net/
├── tcp/
│   ├── clone
│   ├── stats
│   ├── 0/
│   │   ├── ctl
│   │   ├── data
│   │   ├── listen
│   │   ├── local
│   │   ├── remote
│   │   └── status
│   ├── 1/
│   │   └── ...
│   └── ...
├── udp/
│   ├── clone
│   ├── stats
│   └── <n>/
│       ├── ctl
│       ├── data
│       ├── local
│       ├── remote
│       └── status
├── dns
├── cs
└── wg/
    ├── peers
    ├── status
    └── <peer>/
        ├── status
        └── config
```

## TCP

### /net/tcp/clone

Opening this file allocates a new conversation directory and returns its number.

**Read:** Returns the conversation number as ASCII (e.g., "0", "1", "42").

### /net/tcp/n/ctl

Control file for conversation n. Write commands to establish connections.

**Commands:**

| Command | Description |
|---------|-------------|
| `connect <addr>!<port>` | Connect to remote address |
| `announce <port>` | Listen on port (local only) |
| `hangup` | Close connection |
| `keepalive` | Enable TCP keepalive |
| `keepalive <n>` | Set keepalive interval (seconds) |

**Read:** Returns connection state information.

### /net/tcp/n/data

Bidirectional data stream.

**Read:** Returns received data. Blocks if no data available. Returns EOF on connection close.

**Write:** Sends data. Returns error if connection not established.

### /net/tcp/n/listen

For announced connections only. Opening blocks until a connection arrives, then returns new conversation number for the accepted connection.

### /net/tcp/n/local

**Read:** Returns local address as `<addr>!<port>` (e.g., "10.0.0.5!12345").

### /net/tcp/n/remote

**Read:** Returns remote address as `<addr>!<port>` (e.g., "10.0.0.1!22").

### /net/tcp/n/status

**Read:** Returns connection status string.

| Status | Meaning |
|--------|---------|
| `Closed` | Not connected |
| `Announcing` | Listening for connections |
| `Connecting` | Connection in progress |
| `Established` | Connected |
| `Closing` | Shutdown in progress |

### /net/tcp/stats

**Read:** Returns global TCP statistics (optional, can return empty).

## UDP

### /net/udp/clone

As per TCP — allocates conversation directory, returns number.

### /net/udp/n/ctl

**Commands:**

| Command | Description |
|---------|-------------|
| `connect <addr>!<port>` | Set default remote (optional) |
| `announce <port>` | Bind to local port |
| `headers` | Include address headers in data |

### /net/udp/n/data

**Without headers mode:**

- Write: Sends to connected address
- Read: Returns datagram payload only

**With headers mode:**

- Write format: `<remote>!<port> <data>`
- Read format: `<remote>!<port> <data>`

### /net/udp/n/local, remote, status

As per TCP, where applicable.

## DNS

### /net/dns

Simple DNS resolution interface.

**Write:** Query in form `<name> <type>` (e.g., "example.com ip", "example.com ipv6", "10.0.0.1 ptr").

**Read:** Returns result lines, one per record.

**Supported query types:**

| Type | Description |
|------|-------------|
| `ip` | A record (IPv4) |
| `ipv6` | AAAA record (IPv6) |
| `ptr` | Reverse lookup |
| `mx` | Mail exchange |
| `txt` | Text record |
| `cname` | Canonical name |

**Resolution order:**

1. Check hosts table (from config)
2. Forward to configured DNS servers via WireGuard tunnel

## CS (Connection Server)

### /net/cs

Translates symbolic names to dial strings.

**Write:** Query like `tcp!example.com!http`

**Read:** Returns resolved dial string like `tcp!93.184.216.34!80`

This is a convenience — clients can also use /net/dns directly.

## WireGuard Status (Crabbit Extension)

These files are Crabbit-specific, not standard Plan 9 `/net`.

### /net/wg/peers

**Read:** Returns list of configured peer names, one per line.

### /net/wg/status

**Read:** Returns overall WireGuard status:

```
interface: crabbit
public_key: <base64>
listen_port: 51820
peers: 3
```

### /net/wg/<peer>/status

**Read:** Returns peer status:

```
name: homeserver
public_key: <base64>
endpoint: 192.168.1.100:51820
allowed_ips: 10.0.0.1/32
last_handshake: 2025-01-15T14:32:00Z
transfer_rx: 1234567
transfer_tx: 7654321
```

### /net/wg/<peer>/config

**Read:** Returns peer configuration (no secrets):

```
public_key: <base64>
allowed_ips: 10.0.0.1/32
endpoint: 192.168.1.100:51820
persistent_keepalive: 25
```

## Error Handling

Errors are returned via 9P Rerror messages with descriptive strings:

| Error | Meaning |
|-------|---------|
| `connection refused` | Remote rejected connection |
| `network unreachable` | No route to host |
| `host not found` | DNS resolution failed |
| `permission denied` | Operation not allowed |
| `address in use` | Port already bound |
| `not connected` | Data operation on unconnected socket |

## Notes

- All addresses are in Plan 9 format: `<addr>!<port>` not `<addr>:<port>`
- IPv6 addresses are written directly (no brackets needed in Plan 9)
- Port can be numeric or symbolic (if cs resolves it)
- Conversation directories are reused after close
