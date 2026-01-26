# Crabbit Design Documents

## Contents

| File | Description |
|------|-------------|
| **README.md** | Start here. What Crabbit is, why it exists, design philosophy |
| **ARCHITECTURE.md** | System architecture, components, data flow, threading model |
| **PROTOCOL.md** | The `/net` filesystem semantics — file tree, operations, errors |
| **AUTH.md** | Plan 9 authentication integration — p9sk1 protocol, modes, keys |
| **CONFIG.md** | Configuration file format, all options, examples |

## Reading Order

1. **README.md** — Understand what we're building
2. **ARCHITECTURE.md** — How the pieces fit together
3. **PROTOCOL.md** — The Plan 9 interface contract
4. **AUTH.md** — Authentication details
5. **CONFIG.md** — Reference when implementing

## Quick Summary

Crabbit is a Rust program that:

- Joins a WireGuard mesh as a userspace peer
- Exposes that tunnel as a Plan 9 `/net` filesystem over 9P
- Authenticates Plan 9 clients using native p9sk1

Plan 9 imports `/net` from Crabbit, uses it like any network. WireGuard handles encryption. Crabbit bridges the gap.

## Implementation Notes

**Rust crates to consider:**

- WireGuard: `boringtun` or `wireguard-rs`
- 9P: `jj-9p`, `nine`, or roll your own (protocol is simple)
- Async: `tokio`
- Config: `toml` + `serde`
- Crypto (for auth): `des` crate

**Start with:**

1. 9P server skeleton — can connect, walk basic tree
2. WireGuard handshake — can join mesh
3. Wire them together — TCP through tunnel
4. Add auth
5. Add DNS
6. Add peer status

## Open Questions

- Should `/net/wg/` be optional (hidden unless you walk to it)?
- Rate limiting on auth failures?
- Hot reload of config?
- Metrics endpoint?

These can wait for v1.1.
