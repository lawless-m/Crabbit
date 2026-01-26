# Crabbit Authentication

Crabbit implements Plan 9 authentication (p9sk1) to verify clients before granting access to the `/net` filesystem.

## Overview

Plan 9 authentication is challenge-response based, using shared secrets and a ticket system. Crabbit can operate in two modes:

1. **Standalone**: Crabbit holds the keys and validates directly
2. **Auth server**: Crabbit delegates to an external auth server (like your C# implementation)

## Protocol Summary

The p9sk1 protocol works as follows:

```
Client                         Crabbit
   │                              │
   │──── Tauth(afid, uname) ─────►│
   │◄─── Rauth(aqid) ─────────────│
   │                              │
   │──── read(afid) ─────────────►│  
   │◄─── AuthChall ───────────────│  (challenge from server)
   │                              │
   │──── write(afid, ticket) ────►│  (client's ticket + authenticator)
   │◄─── AuthOK / error ──────────│
   │                              │
   │──── Tattach(afid, ...) ─────►│  (afid proves auth completed)
   │◄─── Rattach ─────────────────│
```

## Standalone Mode

In standalone mode, Crabbit holds user keys directly in its configuration.

### Key Storage

Keys are derived from passwords using Plan 9's standard key derivation (passtokey).

Configuration:

```toml
[auth]
mode = "standalone"
authid = "crabbit"
authdom = "crabbit"

[[auth.users]]
name = "alice"
# Key as hex (output of passtokey or your C# tool)
key = "0123456789abcdef0123456789abcdef"

[[auth.users]]
name = "bob"
key = "fedcba9876543210fedcba9876543210"
```

### Challenge-Response

1. Client connects, sends Tauth with username
2. Crabbit generates random challenge, sends as AuthChall
3. Client constructs ticket request, gets ticket from auth server (or local)
4. Client sends ticket + authenticator to Crabbit
5. Crabbit decrypts ticket with its key, verifies authenticator
6. If valid, auth succeeds; client can now Tattach

## Auth Server Mode

In auth server mode, Crabbit delegates authentication to an external Plan 9 auth server.

Configuration:

```toml
[auth]
mode = "authserver"
authid = "crabbit"
authdom = "yourdomain"
server = "10.0.0.1!567"  # Auth server address
```

Crabbit acts as a relay:

1. Client sends Tauth
2. Crabbit connects to auth server
3. Challenge-response flows through Crabbit
4. Auth server validates, Crabbit learns result
5. Auth succeeds or fails accordingly

This mode is useful if you have an existing Plan 9 auth infrastructure or want centralised user management.

## Key Derivation

Plan 9 keys are 56-bit DES keys derived from passwords:

```
passtokey(password) → 7-byte key
```

The algorithm:

1. Pad or truncate password to 28 bytes
2. Fold with XOR into 7 bytes
3. Set parity bits for DES

Crabbit accepts keys in hex format (14 hex chars = 7 bytes). Use your C# tool or Plan 9's `auth/wrkey` to generate.

## Ticket Structure

A Plan 9 ticket contains:

| Field | Size | Description |
|-------|------|-------------|
| num | 1 | Ticket type (AuthTs = 64) |
| chal | 8 | Challenge from server |
| cuid | 28 | Client user ID |
| suid | 28 | Server user ID |
| key | 7 | Session key |

Total: 72 bytes, encrypted with server's key.

## Authenticator Structure

| Field | Size | Description |
|-------|------|-------------|
| num | 1 | Auth type (AuthAc = 65) |
| chal | 8 | Challenge from server |
| rand | 4 | Random nonce |

Total: 13 bytes, encrypted with session key from ticket.

## Security Considerations

**Key storage**: In standalone mode, keys are in the config file. Protect it accordingly (600 permissions, encrypted filesystem, etc.).

**Replay protection**: Challenges are random and single-use. Tickets are bound to specific challenges.

**No password transmission**: Passwords never cross the wire — only encrypted tickets.

**DES weakness**: Yes, DES is ancient. This is Plan 9 compatibility, not modern security. The WireGuard layer provides actual transport security.

## Implementation Notes

For Rust implementation:

- Use `des` crate for DES operations
- Random challenge generation via `rand` or `getrandom`
- Ticket parsing is straightforward struct unpacking
- The C# auth server you built can serve as reference for the protocol details

## Debugging

Crabbit will log auth failures with reasons:

- `unknown user`: Username not in config (standalone mode)
- `bad ticket`: Decryption failed or wrong format  
- `bad authenticator`: Authenticator doesn't match challenge
- `auth server unreachable`: Can't connect to auth server (server mode)

Enable debug logging to see the full auth exchange.
