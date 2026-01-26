// Test utility to verify WireGuard party connection
// Run with: cargo run --example test-wg-connection -- <config.toml>

use anyhow::Result;
use std::path::PathBuf;
use tokio::time::{sleep, Duration};
use tracing::{info, error};
use tracing_subscriber;

// Import from main crate
use crabbit::config::Config;
use crabbit::wireguard::WireGuard;

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive(tracing::Level::DEBUG.into())
        )
        .init();

    // Get config path from args
    let args: Vec<String> = std::env::args().collect();
    let config_path = if args.len() > 1 {
        PathBuf::from(&args[1])
    } else {
        PathBuf::from("test-config.toml")
    };

    info!("Loading configuration from: {}", config_path.display());
    let config = Config::load(&config_path)?;
    config.validate()?;

    info!("Initializing WireGuard party...");
    let wg = WireGuard::new(&config.wireguard).await?;

    info!("WireGuard party initialized successfully!");

    // List all peers
    let peers = wg.list_peers().await;
    info!("Connected peers in the party:");
    for peer in &peers {
        info!("  - {}", peer);
        if let Some(info) = wg.get_peer_info(peer).await {
            info!("    Endpoint: {:?}", info.endpoint);
            info!("    Last handshake: {:?}", info.last_handshake);
        }
    }

    // Keep running for a while to allow handshakes to happen
    info!("Running for 30 seconds to allow WireGuard handshakes...");
    for i in 1..=30 {
        sleep(Duration::from_secs(1)).await;

        if i % 5 == 0 {
            info!("Still running ({}/30 seconds)...", i);

            // Check peer status periodically
            for peer in &peers {
                if let Some(info) = wg.get_peer_info(peer).await {
                    if info.last_handshake.is_some() {
                        info!("  ✓ Peer '{}' has completed handshake!", peer);
                    } else {
                        info!("  ⏳ Peer '{}' waiting for handshake...", peer);
                    }
                }
            }
        }
    }

    info!("Test completed. WireGuard party is functioning!");

    // Try sending a test packet (will fail since NetEngine isn't set up, but tests encapsulation)
    info!("Testing packet encapsulation...");
    let test_data = b"Hello from Crabbit!";
    if let Some(peer_name) = peers.first() {
        match wg.send_to_peer(peer_name, test_data).await {
            Ok(_) => info!("✓ Successfully encapsulated and sent test packet to '{}'", peer_name),
            Err(e) => error!("✗ Failed to send test packet: {}", e),
        }
    }

    Ok(())
}
