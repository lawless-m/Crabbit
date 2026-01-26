# Crabbit

A grumpy wee guardian that bridges WireGuard and Plan 9.

## What It Is

Crabbit is a self-contained userspace WireGuard peer that exposes a Plan 9 `/net` filesystem over 9P. It lets any Plan 9 system (9front, plan9port, drawterm, etc.) use a WireGuard VPN by simply importing `/net` from Crabbit.

Plan 9 doesn't know or care that it's WireGuard underneath — it just sees a normal network interface to import.

## Why It Exists

Plan 9's networking model is elegant: import `/net` from somewhere, use it. VPNs in Plan 9 traditionally work by importing a remote `/net` into `/net.alt`. But WireGuard doesn't speak 9P, and Plan 9 doesn't speak WireGuard.

Crabbit bridges that gap. It:

- Handles WireGuard protocol entirely in userspace
- Joins an existing WireGuard mesh as a peer
- Presents the tunnel as a Plan 9 `/net` filesystem
- Authenticates connections using native Plan 9 authentication

The host system doesn't participate — no kernel WireGuard, no `wg0` interface, no shared network stack. Crabbit is the peer.

## Design Philosophy

**Self-contained**: Single binary, no runtime dependencies on the host beyond basic networking.

**Minimal**: TCP, UDP, DNS. No exotic protocols. Does one thing well.

**Plan 9 native**: Proper `/net` semantics, proper 9P, proper Plan 9 authentication. Not a bodge.

**Antithetical implementation**: Written in Rust with maximum ceremony to serve Plan 9's maximum simplicity. There's joy in that contradiction.

## Use Cases

- Plan 9 VM needs to reach your home network while you're away
- 9front box joining a WireGuard mesh without native WireGuard support
- Drawterm on a restricted network tunnelling through WireGuard
- Any Plan 9 system that wants VPN access without modification

## Status

**In Development** - Basic project structure is complete. Core functionality is being implemented.

### Current Progress

- ✅ Project structure with Cargo.toml and dependencies
- ✅ Configuration loading (TOML)
- ✅ Basic 9P server skeleton (protocol parsing, version negotiation)
- ✅ Stub modules for all major components
- 🚧 9P server implementation (walk, open, read, write)
- 🚧 WireGuard integration (boringtun)
- 🚧 /net engine (TCP/UDP operations)
- 🚧 Plan 9 authentication (p9sk1)
- 🚧 DNS resolution

## Building

```bash
cargo build --release
```

The binary will be in `target/release/crabbit`.

## Configuration

See `crabbit.example.toml` for a complete configuration example.

Basic structure:

```toml
[listen]
address = "0.0.0.0:564"

[wireguard]
private_key = "YOUR_PRIVATE_KEY"
listen_port = 51820
address = "10.0.0.5/24"

[[wireguard.peers]]
name = "homeserver"
public_key = "PEER_PUBLIC_KEY"
endpoint = "home.example.com:51820"
allowed_ips = ["10.0.0.1/32"]

[dns]
servers = ["1.1.1.1", "8.8.8.8"]

[auth]
mode = "standalone"
authid = "crabbit"
authdom = "crabbit"

[[auth.users]]
name = "glenda"
key = "0123456789abcdef"
```

## Usage

```bash
# Run with default config location
crabbit

# Specify config file
crabbit -c /path/to/config.toml

# Check config validity
crabbit --check -c config.toml

# Increase verbosity
crabbit -v

# See all options
crabbit --help
```

From Plan 9:

```rc
# Import /net from Crabbit
import -a tcp!crabbit-host!564 /net /net.alt

# Or with authentication
import -a -C tcp!crabbit-host!564 /net /net.alt

# Use it
dial tcp!example.com!80 </net.alt/tcp/clone
```

## Documentation

The `crabbit/` directory contains detailed design documents:

- **README.md** - What Crabbit is and why it exists
- **ARCHITECTURE.md** - System architecture and components
- **PROTOCOL.md** - The `/net` filesystem semantics
- **AUTH.md** - Plan 9 authentication (p9sk1) details
- **CONFIG.md** - Configuration file reference

## Name

Scottish for bad-tempered. Plus the Rust crab. A crabbit wee thing that reluctantly lets Plan 9 through the tunnel.

## License

MIT

## Contributing

This project is in early development. The core architecture is being implemented according to the design documents in `crabbit/`.
