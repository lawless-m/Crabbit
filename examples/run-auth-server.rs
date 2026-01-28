// Standalone p9sk1 auth server for testing with 9front
//
// Usage: cargo run --example run-auth-server -- [--port PORT] [--authdom DOMAIN]
//
// Default: listens on 0.0.0.0:567 with authdom "crabbit"

use anyhow::Result;
use std::sync::Arc;
use crabbit::auth::AuthModule;
use crabbit::auth_server::AuthServer;
use crabbit::config::{AuthConfig, AuthMode, UserConfig};

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("crabbit=debug".parse().unwrap()),
        )
        .init();

    // Parse args
    let args: Vec<String> = std::env::args().collect();
    let mut port = 567u16;
    let mut authdom = "crabbit".to_string();

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--port" | "-p" => {
                i += 1;
                port = args.get(i).map(|s| s.parse().unwrap_or(567)).unwrap_or(567);
            }
            "--authdom" | "-d" => {
                i += 1;
                authdom = args.get(i).cloned().unwrap_or_else(|| "crabbit".to_string());
            }
            "--help" | "-h" => {
                println!("Usage: {} [--port PORT] [--authdom DOMAIN]", args[0]);
                println!();
                println!("Options:");
                println!("  --port, -p     Port to listen on (default: 567)");
                println!("  --authdom, -d  Auth domain (default: crabbit)");
                println!();
                println!("Built-in users:");
                println!("  glenda:test1234");
                println!("  bootes:bootes");
                return Ok(());
            }
            _ => {}
        }
        i += 1;
    }

    // Create auth config with test users
    let config = AuthConfig {
        mode: AuthMode::Standalone,
        authid: "authserver".to_string(),
        authdom: authdom.clone(),
        server: None,
        users: vec![
            UserConfig {
                name: "glenda".to_string(),
                key: String::new(),
                password: Some("test1234".to_string()),
            },
            UserConfig {
                name: "bootes".to_string(),
                key: String::new(),
                password: Some("bootes".to_string()),
            },
        ],
    };

    let auth = Arc::new(AuthModule::new(&config)?);

    // Print key info for debugging
    if let Some(glenda) = auth.get_user("glenda") {
        println!("glenda key: {:02x?}", glenda.des_key);
    }
    if let Some(bootes) = auth.get_user("bootes") {
        println!("bootes key: {:02x?}", bootes.des_key);
    }

    let addr = format!("0.0.0.0:{}", port);
    println!();
    println!("=== Crabbit p9sk1 Auth Server ===");
    println!("Listening on: {}", addr);
    println!("Auth domain:  {}", authdom);
    println!();
    println!("Users: glenda, bootes");
    println!();
    println!("To configure 9front, add to /lib/ndb/local:");
    println!("  authdom={}  auth=<your-host-ip>", authdom);
    println!();

    let server = AuthServer::bind(&addr, auth).await?;
    server.run().await
}
