# Crabbit Architecture

## Overview

Crabbit consists of four main components that work together:

```
┌─────────────────────────────────────────────────────────────┐
│                         Crabbit                             │
│                                                             │
│  ┌──────────┐   ┌──────────┐   ┌──────────┐   ┌──────────┐ │
│  │   9P     │   │   Auth   │   │   /net   │   │   Wire   │ │
│  │  Server  │◄─►│  Module  │   │  Engine  │◄─►│  Guard   │ │
│  └────┬─────┘   └──────────┘   └────┬─────┘   └────┬─────┘ │
│       │                             │               │       │
│       └─────────────────────────────┘               │       │
│                     │                               │       │
└─────────────────────┼───────────────────────────────┼───────┘
                      │                               │
              Plan 9 Client                    WireGuard Mesh
```

## Components

### 9P Server

Listens for 9P connections from Plan 9 clients. Handles:

- Connection establishment
- Authentication handoff to Auth Module
- File tree operations (walk, open, read, write, clunk)
- Session management

The 9P server presents a virtual filesystem. All file operations are translated into actions on the /net Engine.

**Key decisions:**

- 9P2000 protocol (not 9P2000.L or 9P2000.u)
- Single listen address, multiple concurrent sessions
- Per-session fid tracking

### Auth Module

Implements Plan 9 authentication protocol (p9sk1). Validates clients before granting access to the `/net` filesystem.

**Integration:**

- Called by 9P Server during Tauth/Rauth exchange
- Uses configured authid and authdom
- Can optionally connect to external auth server, or handle locally

**Key decisions:**

- Authentication is mandatory, not optional
- Keys stored in configuration file
- Supports the same auth protocol as your existing C# auth server

### /net Engine

The core logic. Maintains the virtual `/net` filesystem and translates file operations into network operations.

**Responsibilities:**

- Maintains open connections (TCP sessions, UDP bindings)
- Routes read/write on data files to appropriate sockets
- Handles clone/ctl/data/status file semantics
- DNS resolution via configured upstream servers
- Hosts file lookup for mesh peer names

**State:**

- Connection table: maps fids to network connections
- Clone counter: assigns conversation directories
- DNS cache: short-lived cache for resolved names

### WireGuard Module

Userspace WireGuard implementation. Handles:

- Key management (private key, peer public keys)
- Handshake protocol
- Packet encryption/decryption
- Peer endpoint management
- Keepalive

**Key decisions:**

- Userspace only — no kernel WireGuard, no TUN/TAP
- Uses existing Rust WireGuard implementations (boringtun or similar)
- All network I/O bound to the WireGuard UDP socket
- The /net Engine's sockets route through this module

## Data Flow

### Outbound (Plan 9 → WireGuard mesh)

1. Plan 9 writes to `/net/tcp/0/data`
2. 9P Server receives Twrite, routes to /net Engine
3. /net Engine looks up connection, writes to internal socket
4. WireGuard Module encrypts, sends to peer endpoint

### Inbound (WireGuard mesh → Plan 9)

1. WireGuard Module receives encrypted packet from peer
2. Decrypts, delivers to internal socket
3. /net Engine buffers data for the connection
4. Plan 9 reads from `/net/tcp/0/data`
5. 9P Server responds with Rread

### DNS Resolution

1. Plan 9 writes query to `/net/dns`
2. /net Engine checks hosts table first
3. If not found, forwards to configured DNS servers via WireGuard tunnel
4. Response written back to client

## Threading Model

Rust async throughout (tokio):

- One task for 9P listener
- One task per 9P session
- One task for WireGuard packet handling
- Internal channels connect components

No shared mutable state between components — message passing only.

## Error Handling

- Network errors: reported via 9P Rerror
- Auth failures: connection closed after Rerror
- WireGuard failures: connections marked down, reads/writes fail
- Configuration errors: fail at startup with clear message

## Security Boundaries

- Plan 9 clients must authenticate before any /net access
- WireGuard provides encryption for all mesh traffic  
- Host system has no access to tunnel traffic
- Keys never leave memory (no temp files)

## Build Artefact

Single static binary. No runtime dependencies except libc. Configuration via file or command line.
