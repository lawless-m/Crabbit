// Plan 9 Authentication (p9sk1) Implementation

use anyhow::Result;
use crate::config::{AuthConfig, AuthMode};
use std::collections::HashMap;

pub struct AuthModule {
    config: AuthConfig,
    users: HashMap<String, Vec<u8>>, // username -> DES key
}

impl AuthModule {
    pub fn new(config: &AuthConfig) -> Result<Self> {
        let mut users = HashMap::new();

        if config.mode == AuthMode::Standalone {
            for user in &config.users {
                // Decode hex key
                let key = hex_decode(&user.key)?;
                users.insert(user.name.clone(), key);
            }
        }

        Ok(AuthModule {
            config: config.clone(),
            users,
        })
    }

    pub fn authenticate(&self, username: &str, _challenge: &[u8], _response: &[u8]) -> Result<bool> {
        match self.config.mode {
            AuthMode::Standalone => {
                if !self.users.contains_key(username) {
                    anyhow::bail!("Unknown user: {}", username);
                }
                // TODO: Implement actual p9sk1 authentication
                Ok(true)
            }
            AuthMode::AuthServer => {
                // TODO: Implement auth server delegation
                anyhow::bail!("AuthServer mode not yet implemented");
            }
        }
    }
}

fn hex_decode(s: &str) -> Result<Vec<u8>> {
    if s.len() % 2 != 0 {
        anyhow::bail!("Hex string must have even length");
    }

    (0..s.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&s[i..i + 2], 16)
                .map_err(|e| anyhow::anyhow!("Invalid hex at position {}: {}", i, e))
        })
        .collect()
}
