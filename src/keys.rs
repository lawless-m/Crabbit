// Keys file management for Crabbit
//
// Stores derived credentials (DES keys and PAK hashes) in a text file.
// Plaintext passwords are never stored.

use anyhow::{bail, Result};
use std::collections::HashMap;
use std::io::Write;
use std::path::{Path, PathBuf};

use crate::auth::{pass_to_key, UserCredentials, DESSION};
use crate::authpak::{authpak_hash, PAKHASHLEN};

const KEYS_FILE_VERSION: &str = "v1";
const DES_KEY_HEX_LEN: usize = 14;      // 7 bytes = 14 hex chars
const PAK_HASH_HEX_LEN: usize = 896;    // 448 bytes = 896 hex chars

/// Keys file manager for user credentials
pub struct KeysFile {
    pub path: PathBuf,
    pub users: HashMap<String, UserCredentials>,
}

impl KeysFile {
    /// Create a new empty keys file manager
    pub fn new(path: PathBuf) -> Self {
        KeysFile {
            path,
            users: HashMap::new(),
        }
    }

    /// Load keys from file, creating empty if doesn't exist
    pub fn load(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Ok(KeysFile {
                path: path.to_path_buf(),
                users: HashMap::new(),
            });
        }

        let contents = std::fs::read_to_string(path)?;
        let mut users = HashMap::new();

        for (line_num, line) in contents.lines().enumerate() {
            let line = line.trim();

            // Skip comments and empty lines
            if line.starts_with('#') || line.is_empty() {
                continue;
            }

            let parts: Vec<&str> = line.split(':').collect();
            if parts.len() != 3 {
                bail!(
                    "Invalid line format at line {}: expected username:deskey:pakhash",
                    line_num + 1
                );
            }

            let username = parts[0].to_string();

            // Parse DES key (14 hex chars = 7 bytes)
            if parts[1].len() != DES_KEY_HEX_LEN {
                bail!(
                    "Invalid DES key length at line {}: expected {} hex chars, got {}",
                    line_num + 1,
                    DES_KEY_HEX_LEN,
                    parts[1].len()
                );
            }
            let des_key_vec = hex::decode(parts[1])?;
            let mut des_key = [0u8; DESSION];
            des_key.copy_from_slice(&des_key_vec);

            // Parse PAK hash (896 hex chars = 448 bytes)
            if parts[2].len() != PAK_HASH_HEX_LEN {
                bail!(
                    "Invalid PAK hash length at line {}: expected {} hex chars, got {}",
                    line_num + 1,
                    PAK_HASH_HEX_LEN,
                    parts[2].len()
                );
            }
            let pak_hash_vec = hex::decode(parts[2])?;
            let mut pak_hash = [0u8; PAKHASHLEN];
            pak_hash.copy_from_slice(&pak_hash_vec);

            users.insert(
                username.clone(),
                UserCredentials {
                    username,
                    des_key,
                    pak_hash,
                },
            );
        }

        Ok(KeysFile {
            path: path.to_path_buf(),
            users,
        })
    }

    /// Save keys to file with restricted permissions
    pub fn save(&self) -> Result<()> {
        // Ensure parent directory exists
        if let Some(parent) = self.path.parent() {
            if !parent.exists() {
                std::fs::create_dir_all(parent)?;
            }
        }

        let mut content = format!(
            "# Crabbit keys file {}\n# DO NOT EDIT - managed by crabbit adduser\n",
            KEYS_FILE_VERSION
        );

        for (name, creds) in &self.users {
            content.push_str(&format!(
                "{}:{}:{}\n",
                name,
                hex::encode(&creds.des_key),
                hex::encode(&creds.pak_hash)
            ));
        }

        // Write atomically via temp file
        let temp_path = self.path.with_extension("tmp");

        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&temp_path)?;
            file.write_all(content.as_bytes())?;
            file.sync_all()?;
        }

        #[cfg(not(unix))]
        {
            let mut file = std::fs::File::create(&temp_path)?;
            file.write_all(content.as_bytes())?;
            file.sync_all()?;
        }

        std::fs::rename(&temp_path, &self.path)?;

        Ok(())
    }

    /// Add or update user from password (derives keys, never stores password)
    pub fn add_user(&mut self, username: &str, password: &str) {
        let des_key = pass_to_key(password);
        let pak_hash = authpak_hash(password, username);

        self.users.insert(
            username.to_string(),
            UserCredentials {
                username: username.to_string(),
                des_key,
                pak_hash,
            },
        );
    }

    /// Remove a user
    pub fn remove_user(&mut self, username: &str) -> bool {
        self.users.remove(username).is_some()
    }

    /// Get user credentials
    pub fn get_user(&self, username: &str) -> Option<&UserCredentials> {
        self.users.get(username)
    }

    /// List all usernames
    pub fn list_users(&self) -> Vec<&str> {
        self.users.keys().map(|s| s.as_str()).collect()
    }

    /// Check if a user exists
    pub fn has_user(&self, username: &str) -> bool {
        self.users.contains_key(username)
    }

    /// Get number of users
    pub fn len(&self) -> usize {
        self.users.len()
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.users.is_empty()
    }
}

/// Get the default keys file path
pub fn default_keys_path() -> PathBuf {
    if let Some(home) = dirs_home() {
        home.join(".crabbit").join("keys")
    } else {
        PathBuf::from("/var/lib/crabbit/keys")
    }
}

fn dirs_home() -> Option<PathBuf> {
    std::env::var_os("HOME").map(PathBuf::from)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    #[test]
    fn test_keys_file_roundtrip() {
        let temp_dir = tempdir().unwrap();
        let path = temp_dir.path().join("keys");

        let mut keys = KeysFile::new(path.clone());
        keys.add_user("alice", "alicepass");
        keys.add_user("bob", "bobpass");
        keys.save().unwrap();

        // Reload and verify
        let loaded = KeysFile::load(&path).unwrap();
        assert!(loaded.get_user("alice").is_some());
        assert!(loaded.get_user("bob").is_some());
        assert!(loaded.get_user("charlie").is_none());
        assert_eq!(loaded.len(), 2);
    }

    #[test]
    fn test_keys_derive_correctly() {
        let temp_dir = tempdir().unwrap();
        let path = temp_dir.path().join("keys");

        let mut keys = KeysFile::new(path);
        keys.add_user("glenda", "test1234");

        let creds = keys.get_user("glenda").unwrap();

        // Verify DES key matches pass_to_key output
        assert_eq!(creds.des_key, pass_to_key("test1234"));

        // Verify PAK hash matches authpak_hash output
        assert_eq!(creds.pak_hash, authpak_hash("test1234", "glenda"));
    }

    #[test]
    fn test_keys_file_permissions() {
        let temp_dir = tempdir().unwrap();
        let path = temp_dir.path().join("keys");

        let mut keys = KeysFile::new(path.clone());
        keys.add_user("test", "testpass");
        keys.save().unwrap();

        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let metadata = fs::metadata(&path).unwrap();
            let mode = metadata.mode() & 0o777;
            assert_eq!(mode, 0o600, "Keys file should have mode 0600");
        }
    }

    #[test]
    fn test_remove_user() {
        let temp_dir = tempdir().unwrap();
        let path = temp_dir.path().join("keys");

        let mut keys = KeysFile::new(path);
        keys.add_user("alice", "pass");
        keys.add_user("bob", "pass");

        assert!(keys.has_user("alice"));
        assert!(keys.remove_user("alice"));
        assert!(!keys.has_user("alice"));
        assert!(keys.has_user("bob"));
        assert!(!keys.remove_user("alice")); // Already removed
    }

    #[test]
    fn test_update_user() {
        let temp_dir = tempdir().unwrap();
        let path = temp_dir.path().join("keys");

        let mut keys = KeysFile::new(path);
        keys.add_user("alice", "oldpass");
        let old_key = keys.get_user("alice").unwrap().des_key;

        keys.add_user("alice", "newpass");
        let new_key = keys.get_user("alice").unwrap().des_key;

        assert_ne!(old_key, new_key, "Key should change with new password");
        assert_eq!(keys.len(), 1, "Should still have only one user");
    }

    #[test]
    fn test_load_nonexistent() {
        let temp_dir = tempdir().unwrap();
        let path = temp_dir.path().join("nonexistent");

        let keys = KeysFile::load(&path).unwrap();
        assert!(keys.is_empty());
    }
}
