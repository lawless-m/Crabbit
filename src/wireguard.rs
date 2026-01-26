// WireGuard userspace implementation

use anyhow::Result;
use crate::config::WireGuardConfig;
use std::net::SocketAddr;

pub struct WireGuard {
    config: WireGuardConfig,
}

impl WireGuard {
    pub async fn new(config: &WireGuardConfig) -> Result<Self> {
        // TODO: Initialize WireGuard
        // - Parse private key
        // - Set up UDP socket
        // - Configure peers
        // - Start handshake process

        Ok(WireGuard {
            config: config.clone(),
        })
    }

    pub async fn send_packet(&self, _data: &[u8], _dest: SocketAddr) -> Result<()> {
        // TODO: Encrypt and send packet
        anyhow::bail!("Send packet not yet implemented");
    }

    pub async fn recv_packet(&self, _buf: &mut [u8]) -> Result<usize> {
        // TODO: Receive and decrypt packet
        anyhow::bail!("Recv packet not yet implemented");
    }

    pub fn get_peer_endpoint(&self, _peer_name: &str) -> Option<SocketAddr> {
        // TODO: Look up peer endpoint
        None
    }
}
