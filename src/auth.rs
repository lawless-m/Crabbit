// Plan 9 Authentication (p9sk1) Implementation
//
// This module implements the p9sk1 authentication protocol from Plan 9.
// Reference: Nawin.Auth (C#) and 9front's authsrv(6)

use anyhow::{bail, Result};
use rand::RngCore;
use std::collections::HashMap;

use crate::config::{AuthConfig, AuthMode};
use crate::des9::{plan9_encrypt, plan9_decrypt};
use crate::authpak::{authpak_hash, PAKHASHLEN};
#[cfg(test)]
use crate::des9::des56to64;

// Protocol constants from Plan 9's authsrv.h
pub const ANAMELEN: usize = 28;    // User/host name field size
pub const DOMLEN: usize = 48;      // Auth domain size
pub const CHALLEN: usize = 8;      // Challenge size
pub const DESSION: usize = 7;      // DES session key size (7 bytes)
pub const TICKETLEN: usize = 72;   // type[1] + chal[8] + cuid[28] + suid[28] + key[7]

// Auth message types
pub const AUTH_TREQ: u8 = 1;   // Ticket request
pub const AUTH_OK: u8 = 4;     // Success
pub const AUTH_ERR: u8 = 5;    // Error
pub const AUTH_TS: u8 = 64;    // Server ticket
pub const AUTH_TC: u8 = 65;    // Client ticket
pub const AUTH_AS: u8 = 66;    // Server authenticator
pub const AUTH_AC: u8 = 67;    // Client authenticator

/// User credentials for p9sk1 and dp9ik authentication
#[derive(Clone)]
pub struct UserCredentials {
    pub username: String,
    pub des_key: [u8; DESSION],      // 7-byte DES key for p9sk1
    pub pak_hash: [u8; PAKHASHLEN],  // 448-byte PAK hash for dp9ik
}

/// The authentication module handles p9sk1 auth
pub struct AuthModule {
    config: AuthConfig,
    users: HashMap<String, UserCredentials>,
}

impl AuthModule {
    pub fn new(config: &AuthConfig) -> Result<Self> {
        let mut users = HashMap::new();

        if config.mode == AuthMode::Standalone {
            for user in &config.users {
                let des_key = if let Some(ref password) = user.password {
                    // Derive key from password
                    pass_to_key(password)
                } else {
                    // Use pre-computed hex key
                    let key_bytes = hex_decode(&user.key)?;
                    if key_bytes.len() != DESSION {
                        bail!("User {} key must be {} bytes", user.name, DESSION);
                    }
                    let mut key = [0u8; DESSION];
                    key.copy_from_slice(&key_bytes);
                    key
                };

                // Compute PAK hash for dp9ik
                let pak_hash = if let Some(ref password) = user.password {
                    authpak_hash(password, &user.name)
                } else {
                    // No password, can't compute pakhash - use zeros (dp9ik won't work)
                    [0u8; PAKHASHLEN]
                };

                users.insert(
                    user.name.clone(),
                    UserCredentials {
                        username: user.name.clone(),
                        des_key,
                        pak_hash,
                    },
                );
            }
        }

        Ok(AuthModule {
            config: config.clone(),
            users,
        })
    }

    /// Get the auth domain
    pub fn authdom(&self) -> &str {
        &self.config.authdom
    }

    /// Get the auth ID (server identity)
    pub fn authid(&self) -> &str {
        &self.config.authid
    }

    /// Look up user credentials
    pub fn get_user(&self, username: &str) -> Option<&UserCredentials> {
        self.users.get(username)
    }

    /// Generate a random challenge
    pub fn generate_challenge() -> [u8; CHALLEN] {
        let mut challenge = [0u8; CHALLEN];
        rand::thread_rng().fill_bytes(&mut challenge);
        challenge
    }

    /// Generate a random session key
    pub fn generate_session_key() -> [u8; DESSION] {
        let mut key = [0u8; DESSION];
        rand::thread_rng().fill_bytes(&mut key);
        key
    }

    /// Create a p9sk1 ticket
    ///
    /// Format: type[1] + chal[8] + cuid[28] + suid[28] + key[7] = 72 bytes
    /// The ticket is encrypted with the recipient's DES key using Plan 9's
    /// 7-byte stride encryption.
    pub fn create_ticket(
        ticket_type: u8,
        challenge: &[u8; CHALLEN],
        cuid: &str,
        suid: &str,
        session_key: &[u8; DESSION],
        encryption_key: &[u8; DESSION],
    ) -> [u8; TICKETLEN] {
        let mut ticket = [0u8; TICKETLEN];

        // Build plaintext ticket
        ticket[0] = ticket_type;
        ticket[1..1 + CHALLEN].copy_from_slice(challenge);
        write_fixed_string(&mut ticket[1 + CHALLEN..1 + CHALLEN + ANAMELEN], cuid);
        write_fixed_string(
            &mut ticket[1 + CHALLEN + ANAMELEN..1 + CHALLEN + 2 * ANAMELEN],
            suid,
        );
        ticket[1 + CHALLEN + 2 * ANAMELEN..1 + CHALLEN + 2 * ANAMELEN + DESSION]
            .copy_from_slice(session_key);

        // Encrypt with Plan 9's 7-byte stride DES
        plan9_encrypt(encryption_key, &mut ticket);

        ticket
    }

    /// Decrypt and validate a p9sk1 ticket
    ///
    /// Returns (ticket_type, challenge, cuid, suid, session_key) on success
    pub fn decrypt_ticket(
        encrypted_ticket: &[u8; TICKETLEN],
        decryption_key: &[u8; DESSION],
    ) -> Result<(u8, [u8; CHALLEN], String, String, [u8; DESSION])> {
        let mut ticket = *encrypted_ticket;

        // Decrypt with Plan 9's 7-byte stride DES
        plan9_decrypt(decryption_key, &mut ticket);

        // Parse fields
        let ticket_type = ticket[0];
        let mut challenge = [0u8; CHALLEN];
        challenge.copy_from_slice(&ticket[1..1 + CHALLEN]);
        let cuid = read_fixed_string(&ticket[1 + CHALLEN..1 + CHALLEN + ANAMELEN]);
        let suid = read_fixed_string(&ticket[1 + CHALLEN + ANAMELEN..1 + CHALLEN + 2 * ANAMELEN]);
        let mut session_key = [0u8; DESSION];
        session_key.copy_from_slice(
            &ticket[1 + CHALLEN + 2 * ANAMELEN..1 + CHALLEN + 2 * ANAMELEN + DESSION],
        );

        Ok((ticket_type, challenge, cuid, suid, session_key))
    }

    /// Handle a ticket request (AuthTreq)
    ///
    /// This is called by the auth server when it receives a ticket request.
    /// Returns (client_ticket, server_ticket) on success.
    pub fn handle_ticket_request(
        &self,
        uid: &str,
        hostid: &str,
        challenge: &[u8; CHALLEN],
    ) -> Result<([u8; TICKETLEN], [u8; TICKETLEN])> {
        // Look up user
        let user_creds = self
            .get_user(uid)
            .ok_or_else(|| anyhow::anyhow!("Unknown user: {}", uid))?;

        // For standalone mode, server key = user key (single-user scenario)
        // In real deployment, server would have its own key
        let server_creds = self.get_user(hostid).unwrap_or(user_creds);

        // Generate session key
        let session_key = Self::generate_session_key();

        // Create client ticket (encrypted with user's key)
        let client_ticket = Self::create_ticket(
            AUTH_TC,
            challenge,
            uid,
            hostid,
            &session_key,
            &user_creds.des_key,
        );

        // Create server ticket (encrypted with server's key)
        let server_ticket = Self::create_ticket(
            AUTH_TS,
            challenge,
            uid,
            hostid,
            &session_key,
            &server_creds.des_key,
        );

        Ok((client_ticket, server_ticket))
    }

    /// Verify a client's authenticator
    ///
    /// The authenticator proves the client knows the session key.
    /// Format: type[1] + challenge[8] + id[4] = 13 bytes (but we use 12 for now)
    pub fn verify_authenticator(
        authenticator: &[u8],
        expected_challenge: &[u8; CHALLEN],
        session_key: &[u8; DESSION],
    ) -> Result<()> {
        if authenticator.len() < 12 {
            bail!("Authenticator too short");
        }

        let mut auth = [0u8; 12];
        auth.copy_from_slice(&authenticator[..12]);

        // Decrypt
        plan9_decrypt(session_key, &mut auth);

        // Check type
        if auth[0] != AUTH_AC {
            bail!("Invalid authenticator type: {}", auth[0]);
        }

        // Check challenge (with increment for replay protection)
        let mut expected = [0u8; CHALLEN];
        expected.copy_from_slice(expected_challenge);
        // Client increments challenge by 1
        increment_challenge(&mut expected);

        if auth[1..1 + CHALLEN] != expected {
            bail!("Authenticator challenge mismatch");
        }

        Ok(())
    }

    /// Create a server authenticator response
    pub fn create_authenticator(
        challenge: &[u8; CHALLEN],
        session_key: &[u8; DESSION],
    ) -> [u8; 12] {
        let mut auth = [0u8; 12];
        auth[0] = AUTH_AS;

        // Server increments challenge by 1 from client's value (so +2 from original)
        let mut resp_challenge = *challenge;
        increment_challenge(&mut resp_challenge);
        increment_challenge(&mut resp_challenge);
        auth[1..1 + CHALLEN].copy_from_slice(&resp_challenge);

        // Encrypt
        plan9_encrypt(session_key, &mut auth);

        auth
    }
}

/// Plan 9 passtokey - derives 7-byte DES key from password
///
/// This is the exact algorithm from 9front's passtokey.c:
/// 1. Pad password with spaces to 8 bytes, null terminate
/// 2. Extract 7-byte key using bit-shift algorithm
/// 3. For passwords > 8 bytes, iteratively encrypt remaining chunks
pub fn pass_to_key(password: &str) -> [u8; DESSION] {
    let mut buf = [b' '; ANAMELEN]; // Start with spaces
    let pw_bytes = password.as_bytes();
    let n = pw_bytes.len().min(ANAMELEN - 1);

    // Copy password bytes
    buf[..n].copy_from_slice(&pw_bytes[..n]);
    buf[n] = 0; // Null terminate

    let mut key = [0u8; DESSION];
    let mut t = buf;
    let mut remaining = n;

    loop {
        // Extract 7-byte key using Plan 9's bit-shift algorithm
        // key[i] = (t[i] >> i) + (t[i+1] << (8 - (i+1)))
        for i in 0..DESSION {
            key[i] = (t[i] >> i) | (t[i + 1] << (7 - i));
        }

        if remaining <= 8 {
            break;
        }

        remaining -= 8;
        let mut new_t = [0u8; 8];
        let offset = if remaining < 8 { 8 - remaining } else { 0 };
        let src_start = buf.len() - remaining - offset;
        new_t.copy_from_slice(&buf[src_start..src_start + 8]);

        // Encrypt the next chunk with current key
        plan9_encrypt(&key, &mut new_t);
        t[..8].copy_from_slice(&new_t);

        if remaining < 8 {
            remaining = 8;
        }
    }

    key
}

/// Write a string to a fixed-length buffer, null-terminated
fn write_fixed_string(dest: &mut [u8], value: &str) {
    dest.fill(0);
    let bytes = value.as_bytes();
    let len = bytes.len().min(dest.len() - 1);
    dest[..len].copy_from_slice(&bytes[..len]);
}

/// Read a null-terminated string from a fixed-length buffer
fn read_fixed_string(data: &[u8]) -> String {
    let end = data.iter().position(|&b| b == 0).unwrap_or(data.len());
    String::from_utf8_lossy(&data[..end]).into_owned()
}

/// Increment a challenge value (for replay protection)
fn increment_challenge(challenge: &mut [u8; CHALLEN]) {
    for byte in challenge.iter_mut().rev() {
        let (new_val, overflow) = byte.overflowing_add(1);
        *byte = new_val;
        if !overflow {
            break;
        }
    }
}

fn hex_decode(s: &str) -> Result<Vec<u8>> {
    if s.len() % 2 != 0 {
        bail!("Hex string must have even length");
    }

    (0..s.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&s[i..i + 2], 16)
                .map_err(|e| anyhow::anyhow!("Invalid hex at position {}: {}", i, e))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pass_to_key() {
        // Test with known password
        let key = pass_to_key("password");
        assert_eq!(key.len(), DESSION);

        // Same password should give same key
        let key2 = pass_to_key("password");
        assert_eq!(key, key2);

        // Different password should give different key
        let key3 = pass_to_key("different");
        assert_ne!(key, key3);
    }

    #[test]
    fn test_des56to64() {
        let key7 = [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD];
        let key8 = des56to64(&key7);
        assert_eq!(key8.len(), 8);

        // Verify parity bits (each byte should have odd parity)
        for byte in key8 {
            let ones = byte.count_ones();
            assert_eq!(ones % 2, 1, "Byte {:02x} should have odd parity", byte);
        }
    }

    #[test]
    fn test_plan9_encrypt_decrypt() {
        let key = [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD];
        let original = b"Hello, Plan 9 world! This is a test message.";
        let mut data = original.to_vec();

        plan9_encrypt(&key, &mut data);
        assert_ne!(&data[..], &original[..], "Data should be encrypted");

        plan9_decrypt(&key, &mut data);
        assert_eq!(&data[..], &original[..], "Data should decrypt to original");
    }

    #[test]
    fn test_ticket_round_trip() {
        let key = pass_to_key("testpassword");
        let challenge = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
        let session_key = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11];

        let ticket = AuthModule::create_ticket(
            AUTH_TC,
            &challenge,
            "alice",
            "server",
            &session_key,
            &key,
        );

        let (ttype, chal, cuid, suid, skey) =
            AuthModule::decrypt_ticket(&ticket, &key).expect("Decrypt should succeed");

        assert_eq!(ttype, AUTH_TC);
        assert_eq!(chal, challenge);
        assert_eq!(cuid, "alice");
        assert_eq!(suid, "server");
        assert_eq!(skey, session_key);
    }

    #[test]
    fn test_fixed_string() {
        let mut buf = [0u8; ANAMELEN];
        write_fixed_string(&mut buf, "testuser");
        assert_eq!(read_fixed_string(&buf), "testuser");

        // Test truncation
        write_fixed_string(&mut buf, "this is a very long username that exceeds the buffer");
        assert_eq!(read_fixed_string(&buf).len(), ANAMELEN - 1);
    }

    #[test]
    fn test_increment_challenge() {
        let mut chal = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01];
        increment_challenge(&mut chal);
        assert_eq!(chal, [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02]);

        // Test overflow
        let mut chal2 = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF];
        increment_challenge(&mut chal2);
        assert_eq!(chal2, [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00]);
    }
}
