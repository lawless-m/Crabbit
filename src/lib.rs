// Crabbit library - expose modules for testing and reuse

pub mod auth;
pub mod authpak;
pub mod des9;
pub mod auth_server;
pub mod config;
pub mod keys;
pub mod net_engine;
pub mod ninep;
pub mod wireguard;

#[cfg(test)]
mod passtokey_comparison {
    use crate::auth::pass_to_key;
    
    #[test]
    fn compare_passtokey() {
        for password in &["glenda", "bootes", "password", "test1234", "short"] {
            let key = pass_to_key(password);
            print!("Password: \"{}\"\nKey: [", password);
            for (i, b) in key.iter().enumerate() {
                if i > 0 { print!(", "); }
                print!("0x{:02x}", b);
            }
            println!("]\n");
        }
    }
}
