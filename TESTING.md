# Testing Crabbit WireGuard Party

This guide shows how to test Crabbit's WireGuard implementation by connecting to an existing WireGuard peer.

## Prerequisites

- A WireGuard peer to connect to (see setup instructions below)
- Rust and Cargo installed
- WireGuard tools (`wg`, `wg-quick`) installed on the test peer

## Quick Test with Existing WireGuard Peer

### 1. Generate Your Keys

```bash
# Generate your private key
wg genkey > crabbit.key

# Show the private key (you'll put this in test-config.toml)
cat crabbit.key

# Generate your public key (share this with the peer)
wg pubkey < crabbit.key
```

### 2. Configure test-config.toml

Edit `test-config.toml` and fill in:

```toml
[wireguard]
private_key = "YOUR_PRIVATE_KEY_FROM_STEP_1"
listen_port = 51821
address = "10.0.0.2"  # Your IP in the WireGuard network

[[wireguard.peers]]
name = "test-peer"
public_key = "PEER_PUBLIC_KEY"
endpoint = "PEER_IP:51820"
allowed_ips = ["10.0.0.1/32"]  # The peer's WireGuard IP
persistent_keepalive = 25
```

### 3. Configure the Peer

On the peer machine, add Crabbit to the WireGuard config:

```bash
# Add Crabbit as a peer
sudo wg set wg0 peer YOUR_CRABBIT_PUBLIC_KEY \
  allowed-ips 10.0.0.2/32 \
  endpoint YOUR_CRABBIT_IP:51821
```

Or edit `/etc/wireguard/wg0.conf`:

```ini
[Peer]
PublicKey = YOUR_CRABBIT_PUBLIC_KEY
AllowedIPs = 10.0.0.2/32
Endpoint = YOUR_CRABBIT_IP:51821
```

Then reload: `sudo wg-quick down wg0 && sudo wg-quick up wg0`

### 4. Run the Test

```bash
# Build and run the test
cargo run --example test-wg-connection test-config.toml

# Or with debug logging
RUST_LOG=debug cargo run --example test-wg-connection test-config.toml
```

### 5. Verify Connection

You should see output like:

```
INFO Initializing WireGuard party...
INFO WireGuard listening on 0.0.0.0:51821
INFO Added peer 'test-peer' to the party (endpoint: Some(1.2.3.4:51820))
INFO WireGuard party initialized successfully!
INFO Connected peers in the party:
INFO   - test-peer
INFO Running for 30 seconds to allow WireGuard handshakes...
INFO   ✓ Peer 'test-peer' has completed handshake!
INFO ✓ Successfully encapsulated and sent test packet to 'test-peer'
```

On the peer, check the handshake:

```bash
sudo wg show wg0
```

You should see:
```
peer: YOUR_CRABBIT_PUBLIC_KEY
  endpoint: YOUR_CRABBIT_IP:51821
  allowed ips: 10.0.0.2/32
  latest handshake: X seconds ago
  transfer: Y B received, Z B sent
```

## Setting Up a Test WireGuard Peer (if you don't have one)

### Using a Linux VPS or VM

1. **Install WireGuard:**

```bash
sudo apt update
sudo apt install wireguard
```

2. **Generate keys:**

```bash
cd /etc/wireguard
umask 077
wg genkey | tee server.key | wg pubkey > server.pub
```

3. **Create config:**

```bash
sudo nano /etc/wireguard/wg0.conf
```

```ini
[Interface]
Address = 10.0.0.1/24
ListenPort = 51820
PrivateKey = CONTENTS_OF_server.key

# Crabbit will be added as a peer
```

4. **Start WireGuard:**

```bash
sudo wg-quick up wg0
sudo systemctl enable wg-quick@wg0
```

5. **Allow UDP through firewall:**

```bash
sudo ufw allow 51820/udp
```

6. **Get your public IP:**

```bash
curl ifconfig.me
```

Use this IP in Crabbit's `endpoint` config.

### Using Docker (for local testing)

```bash
# Run a WireGuard peer in Docker
docker run -d \
  --name=wireguard \
  --cap-add=NET_ADMIN \
  --cap-add=SYS_MODULE \
  -e PUID=1000 \
  -e PGID=1000 \
  -e TZ=UTC \
  -p 51820:51820/udp \
  -v /path/to/config:/config \
  --sysctl="net.ipv4.conf.all.src_valid_mark=1" \
  linuxserver/wireguard
```

## Troubleshooting

### No handshake happening

1. **Check firewall:** Make sure UDP port 51821 is open on Crabbit's host
2. **Check peer firewall:** Make sure UDP port 51820 is open on the peer
3. **Verify keys:** Double-check public keys match between configs
4. **Check endpoint:** Make sure the peer's endpoint IP:port is reachable
5. **Try pinging:** From the peer, try: `ping 10.0.0.2` (may not work yet without routing)

### Connection refused

- Check that Crabbit is actually listening: `ss -ulnp | grep 51821`
- Verify the port in `test-config.toml` matches what you're connecting to

### Handshake fails

- Check that private/public keys are correct
- Verify the allowed_ips include each other's WireGuard IPs
- Check system time on both machines (large time differences can cause issues)

## Testing Different Scenarios

### Multiple Peers

Add more `[[wireguard.peers]]` sections to test the "party" with multiple peers:

```toml
[[wireguard.peers]]
name = "peer1"
public_key = "..."
endpoint = "..."
allowed_ips = ["10.0.0.1/32"]

[[wireguard.peers]]
name = "peer2"
public_key = "..."
endpoint = "..."
allowed_ips = ["10.0.0.3/32"]
```

### Roaming Peer (no endpoint)

To test a peer that connects to you (road warrior):

```toml
[[wireguard.peers]]
name = "laptop"
public_key = "LAPTOP_PUBLIC_KEY"
# No endpoint - waits for the peer to initiate
allowed_ips = ["10.0.0.10/32"]
```

## Next Steps

Once the WireGuard party is working:

1. Integrate with NetEngine to forward decrypted packets
2. Connect the 9P filesystem layer
3. Test actual network operations through the tunnel
