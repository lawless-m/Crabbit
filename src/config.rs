use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::Path;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Config {
    pub listen: ListenConfig,
    pub wireguard: WireGuardConfig,
    pub dns: DnsConfig,
    pub auth: AuthConfig,
    #[serde(default)]
    pub logging: LoggingConfig,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ListenConfig {
    pub address: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct WireGuardConfig {
    pub private_key: String,
    pub listen_port: u16,
    pub address: String,
    pub peers: Vec<PeerConfig>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PeerConfig {
    pub name: String,
    pub public_key: String,
    #[serde(default)]
    pub endpoint: Option<String>,
    pub allowed_ips: Vec<String>,
    #[serde(default)]
    pub persistent_keepalive: Option<u16>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DnsConfig {
    pub servers: Vec<String>,
    #[serde(default = "default_cache_ttl")]
    pub cache_ttl: u64,
    #[serde(default)]
    pub hosts: HashMap<String, String>,
}

fn default_cache_ttl() -> u64 {
    300
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct AuthConfig {
    pub mode: AuthMode,
    pub authid: String,
    pub authdom: String,
    #[serde(default)]
    pub server: Option<String>,
    #[serde(default)]
    pub users: Vec<UserConfig>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum AuthMode {
    Standalone,
    AuthServer,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct UserConfig {
    pub name: String,
    #[serde(default)]
    pub key: String, // 7-byte DES key as hex (14 hex chars), optional if password provided
    #[serde(default)]
    pub password: Option<String>, // Password to derive key from (preferred)
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
pub struct LoggingConfig {
    #[serde(default = "default_log_level")]
    pub level: String,
    #[serde(default)]
    pub file: Option<String>,
}

fn default_log_level() -> String {
    "info".to_string()
}

impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        let contents = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read config file: {}", path.display()))?;

        let mut config: Config = toml::from_str(&contents)
            .with_context(|| format!("Failed to parse config file: {}", path.display()))?;

        // Check for private key in environment
        if let Ok(env_key) = std::env::var("CRABBIT_PRIVATE_KEY") {
            config.wireguard.private_key = env_key;
        }

        Ok(config)
    }

    pub fn validate(&self) -> Result<()> {
        // Validate listen address
        if self.listen.address.is_empty() {
            anyhow::bail!("Listen address cannot be empty");
        }

        // Validate WireGuard config
        if self.wireguard.private_key.is_empty() {
            anyhow::bail!("WireGuard private key cannot be empty");
        }

        if self.wireguard.peers.is_empty() {
            anyhow::bail!("At least one WireGuard peer must be configured");
        }

        // Validate peers
        for peer in &self.wireguard.peers {
            if peer.name.is_empty() {
                anyhow::bail!("Peer name cannot be empty");
            }
            if peer.public_key.is_empty() {
                anyhow::bail!("Peer {} public key cannot be empty", peer.name);
            }
            if peer.allowed_ips.is_empty() {
                anyhow::bail!("Peer {} must have at least one allowed IP", peer.name);
            }
        }

        // Validate DNS config
        if self.dns.servers.is_empty() {
            anyhow::bail!("At least one DNS server must be configured");
        }

        // Validate auth config
        match self.auth.mode {
            AuthMode::Standalone => {
                if self.auth.users.is_empty() {
                    anyhow::bail!("Standalone auth mode requires at least one user");
                }
                // Validate user credentials - must have either password or key
                for user in &self.auth.users {
                    if user.password.is_none() && user.key.is_empty() {
                        anyhow::bail!(
                            "User {} must have either password or key",
                            user.name
                        );
                    }
                    // If key is provided, validate it
                    if !user.key.is_empty() {
                        if user.key.len() != 14 {
                            anyhow::bail!(
                                "User {} key must be 14 hex characters (7 bytes)",
                                user.name
                            );
                        }
                        // Verify it's valid hex
                        hex::decode(&user.key).with_context(|| {
                            format!("User {} key is not valid hex", user.name)
                        })?;
                    }
                }
            }
            AuthMode::AuthServer => {
                if self.auth.server.is_none() {
                    anyhow::bail!("AuthServer mode requires server address");
                }
            }
        }

        Ok(())
    }
}

// Simple hex decoding for key validation
mod hex {
    use anyhow::{Context, Result};

    pub fn decode(s: &str) -> Result<Vec<u8>> {
        if s.len() % 2 != 0 {
            anyhow::bail!("Hex string must have even length");
        }

        (0..s.len())
            .step_by(2)
            .map(|i| {
                u8::from_str_radix(&s[i..i + 2], 16)
                    .with_context(|| format!("Invalid hex at position {}", i))
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hex_decode() {
        assert!(hex::decode("0123456789abcdef").is_ok());
        assert!(hex::decode("invalid").is_err());
        assert!(hex::decode("0").is_err()); // Odd length
    }
}
