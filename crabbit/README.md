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

Design phase. See the other documents in this repository for architecture, protocol details, and configuration.

## Name

Scottish for bad-tempered. Plus the Rust crab. A crabbit wee thing that reluctantly lets Plan 9 through the tunnel.
