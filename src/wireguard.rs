// WireGuard userspace implementation - The Party Manager

use anyhow::{Context, Result};
use boringtun::noise::{Tunn, TunnResult};
use boringtun::x25519::{PublicKey, StaticSecret};
use crate::config::{PeerConfig, WireGuardConfig};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::{Mutex, RwLock};
use tokio::time;
use tracing::{debug, error, info, warn};

const MAX_PACKET_SIZE: usize = 65536;
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(180);
const KEEPALIVE_TIMEOUT: Duration = Duration::from_secs(10);
const REKEY_TIMEOUT: Duration = Duration::from_secs(120);

/// A grumpy WireGuard peer in the party
struct Peer {
    name: String,
    public_key: PublicKey,
    tunn: Arc<Mutex<Box<Tunn>>>,
    endpoint: Option<SocketAddr>,
    allowed_ips: Vec<ipnet::IpNet>,
    persistent_keepalive: Option<u16>,
    last_handshake: Option<Instant>,
    last_rx: Option<Instant>,
}

/// The WireGuard Party - manages multiple grumpy peers
pub struct WireGuard {
    socket: Arc<UdpSocket>,
    peers: Arc<RwLock<HashMap<String, Peer>>>,
    peer_by_pubkey: Arc<RwLock<HashMap<[u8; 32], String>>>,
    interface_addr: IpAddr,
}

impl WireGuard {
    pub async fn new(config: &WireGuardConfig) -> Result<Self> {
        info!("Initializing WireGuard party");

        // Parse private key
        let private_key = decode_key(&config.private_key)
            .context("Failed to decode WireGuard private key")?;
        let static_secret = StaticSecret::from(private_key);

        // Parse interface address
        let interface_addr: IpAddr = config
            .address
            .parse()
            .context("Failed to parse WireGuard interface address")?;

        // Bind UDP socket
        let bind_addr = format!("0.0.0.0:{}", config.listen_port);
        let socket = UdpSocket::bind(&bind_addr)
            .await
            .context("Failed to bind WireGuard UDP socket")?;
        info!("WireGuard listening on {}", bind_addr);

        let socket = Arc::new(socket);
        let mut peers = HashMap::new();
        let mut peer_by_pubkey = HashMap::new();

        // Initialize peers (the party members)
        for peer_config in &config.peers {
            let peer = Self::create_peer(&static_secret, peer_config)?;
            info!(
                "Added peer '{}' to the party (endpoint: {:?})",
                peer.name, peer.endpoint
            );

            let pubkey_bytes = peer.public_key.as_bytes();
            peer_by_pubkey.insert(*pubkey_bytes, peer.name.clone());
            peers.insert(peer.name.clone(), peer);
        }

        let wg = WireGuard {
            socket: socket.clone(),
            peers: Arc::new(RwLock::new(peers)),
            peer_by_pubkey: Arc::new(RwLock::new(peer_by_pubkey)),
            interface_addr,
        };

        // Start background tasks
        let wg_clone = wg.clone();
        tokio::spawn(async move {
            wg_clone.run_receive_loop().await;
        });

        let wg_clone = wg.clone();
        tokio::spawn(async move {
            wg_clone.run_timer_loop().await;
        });

        Ok(wg)
    }

    fn create_peer(static_secret: &StaticSecret, config: &PeerConfig) -> Result<Peer> {
        let public_key_bytes = decode_key(&config.public_key)
            .context("Failed to decode peer public key")?;
        let public_key = PublicKey::from(public_key_bytes);

        let endpoint = if let Some(ref ep) = config.endpoint {
            Some(
                ep.parse()
                    .context("Failed to parse peer endpoint address")?,
            )
        } else {
            None
        };

        let allowed_ips: Result<Vec<ipnet::IpNet>> = config
            .allowed_ips
            .iter()
            .map(|ip| {
                ip.parse()
                    .context(format!("Failed to parse allowed IP: {}", ip))
            })
            .collect();
        let allowed_ips = allowed_ips?;

        // Create boringtun tunnel for this peer
        let tunn = Tunn::new(
            static_secret.clone(),
            public_key,
            None,
            config.persistent_keepalive,
            0, // index
            None,
        )
        .map_err(|e| anyhow::anyhow!("Failed to create boringtun tunnel: {}", e))?;

        Ok(Peer {
            name: config.name.clone(),
            public_key,
            tunn: Arc::new(Mutex::new(Box::new(tunn))),
            endpoint,
            allowed_ips,
            persistent_keepalive: config.persistent_keepalive,
            last_handshake: None,
            last_rx: None,
        })
    }

    /// Clone for spawning background tasks
    fn clone(&self) -> Self {
        WireGuard {
            socket: self.socket.clone(),
            peers: self.peers.clone(),
            peer_by_pubkey: self.peer_by_pubkey.clone(),
            interface_addr: self.interface_addr,
        }
    }

    /// Main receive loop - processes incoming WireGuard packets
    async fn run_receive_loop(&self) {
        let mut buf = vec![0u8; MAX_PACKET_SIZE];
        info!("WireGuard receive loop started");

        loop {
            match self.socket.recv_from(&mut buf).await {
                Ok((len, src)) => {
                    if let Err(e) = self.handle_incoming_packet(&buf[..len], src).await {
                        debug!("Error handling packet from {}: {}", src, e);
                    }
                }
                Err(e) => {
                    error!("Error receiving UDP packet: {}", e);
                    time::sleep(Duration::from_millis(100)).await;
                }
            }
        }
    }

    async fn handle_incoming_packet(&self, packet: &[u8], src: SocketAddr) -> Result<()> {
        // Find which peer this packet is from by trying each peer
        // In a real implementation, we'd parse the packet header to identify the peer
        let peers = self.peers.read().await;

        for peer in peers.values() {
            // Update endpoint if this is from a known peer
            if let Some(endpoint) = peer.endpoint {
                if endpoint == src {
                    let mut tunn = peer.tunn.lock().await;
                    let mut dst_buf = vec![0u8; MAX_PACKET_SIZE];

                    match tunn.decapsulate(Some(src.ip()), packet, &mut dst_buf) {
                        TunnResult::Done => {
                            debug!("Handshake packet processed from {}", peer.name);
                        }
                        TunnResult::Err(e) => {
                            warn!("Error decapsulating packet from {}: {:?}", peer.name, e);
                        }
                        TunnResult::WriteToNetwork(packet) => {
                            // Response needed (e.g., handshake response)
                            if let Err(e) = self.socket.send_to(packet, src).await {
                                error!("Failed to send response to {}: {}", peer.name, e);
                            }
                        }
                        TunnResult::WriteToTunnelV4(packet, _) | TunnResult::WriteToTunnelV6(packet, _) => {
                            debug!("Received {} bytes from peer {}", packet.len(), peer.name);
                            // TODO: Forward decrypted packet to network stack
                            // This will be integrated with NetEngine later
                        }
                    }
                    return Ok(());
                }
            }
        }

        debug!("Received packet from unknown source: {}", src);
        Ok(())
    }

    /// Timer loop - handles keepalives, rekeys, and handshake timeouts
    async fn run_timer_loop(&self) {
        info!("WireGuard timer loop started");
        let mut interval = time::interval(Duration::from_secs(1));

        loop {
            interval.tick().await;

            let peers = self.peers.read().await;
            for peer in peers.values() {
                let mut tunn = peer.tunn.lock().await;
                let mut dst_buf = vec![0u8; MAX_PACKET_SIZE];

                match tunn.update_timers(&mut dst_buf) {
                    TunnResult::Done => {}
                    TunnResult::Err(e) => {
                        warn!("Timer error for peer {}: {:?}", peer.name, e);
                    }
                    TunnResult::WriteToNetwork(packet) => {
                        if let Some(endpoint) = peer.endpoint {
                            if let Err(e) = self.socket.send_to(packet, endpoint).await {
                                error!("Failed to send timer packet to {}: {}", peer.name, e);
                            }
                        }
                    }
                    TunnResult::WriteToTunnelV4(_, _) | TunnResult::WriteToTunnelV6(_, _) => {
                        // Shouldn't happen from update_timers
                    }
                }
            }
        }
    }

    /// Send encrypted packet through WireGuard tunnel to a specific peer
    pub async fn send_to_peer(&self, peer_name: &str, data: &[u8]) -> Result<()> {
        let peers = self.peers.read().await;
        let peer = peers
            .get(peer_name)
            .context(format!("Peer '{}' not found in party", peer_name))?;

        let endpoint = peer
            .endpoint
            .context(format!("Peer '{}' has no endpoint configured", peer_name))?;

        let mut tunn = peer.tunn.lock().await;
        let mut dst_buf = vec![0u8; MAX_PACKET_SIZE];

        match tunn.encapsulate(data, &mut dst_buf) {
            TunnResult::Done => {
                anyhow::bail!("Encapsulation returned Done - tunnel not ready?");
            }
            TunnResult::Err(e) => {
                anyhow::bail!("Failed to encapsulate packet: {:?}", e);
            }
            TunnResult::WriteToNetwork(packet) => {
                self.socket
                    .send_to(packet, endpoint)
                    .await
                    .context("Failed to send encrypted packet")?;
                debug!("Sent {} encrypted bytes to peer {}", packet.len(), peer_name);
                Ok(())
            }
            TunnResult::WriteToTunnelV4(_, _) | TunnResult::WriteToTunnelV6(_, _) => {
                anyhow::bail!("Unexpected WriteToTunnel from encapsulate");
            }
        }
    }

    /// Send packet to appropriate peer based on destination IP
    pub async fn send_packet(&self, data: &[u8], dest_ip: IpAddr) -> Result<()> {
        let peer_name = {
            let peers = self.peers.read().await;

            // Find peer that allows this destination IP
            let mut found_peer = None;
            for peer in peers.values() {
                for allowed in &peer.allowed_ips {
                    if allowed.contains(&dest_ip) {
                        found_peer = Some(peer.name.clone());
                        break;
                    }
                }
                if found_peer.is_some() {
                    break;
                }
            }
            found_peer
        };

        if let Some(name) = peer_name {
            self.send_to_peer(&name, data).await
        } else {
            anyhow::bail!("No peer found with route to {}", dest_ip);
        }
    }

    pub fn get_peer_endpoint(&self, _peer_name: &str) -> Option<SocketAddr> {
        // This would need to be async in real usage, but keeping the signature for compatibility
        None // Placeholder - would need to change API to be async
    }

    /// Get list of all peers in the party
    pub async fn list_peers(&self) -> Vec<String> {
        let peers = self.peers.read().await;
        peers.keys().cloned().collect()
    }

    /// Get peer status information
    pub async fn get_peer_info(&self, peer_name: &str) -> Option<PeerInfo> {
        let peers = self.peers.read().await;
        peers.get(peer_name).map(|peer| PeerInfo {
            name: peer.name.clone(),
            endpoint: peer.endpoint,
            last_handshake: peer.last_handshake,
            last_rx: peer.last_rx,
        })
    }
}

#[derive(Debug, Clone)]
pub struct PeerInfo {
    pub name: String,
    pub endpoint: Option<SocketAddr>,
    pub last_handshake: Option<Instant>,
    pub last_rx: Option<Instant>,
}

/// Decode base64-encoded WireGuard key
fn decode_key(key_str: &str) -> Result<[u8; 32]> {
    use base64::Engine;
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(key_str.trim())
        .context("Failed to decode base64 key")?;

    if decoded.len() != 32 {
        anyhow::bail!("WireGuard key must be 32 bytes, got {}", decoded.len());
    }

    let mut key = [0u8; 32];
    key.copy_from_slice(&decoded);
    Ok(key)
}
