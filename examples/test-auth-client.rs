// Test client for p9sk1 authentication against 9front's authsrv
//
// Usage: cargo run --example test-auth-client -- <authsrv-addr> <authdom> <user> <password>

use anyhow::Result;
use std::env;
use std::io::{Read, Write};
use std::net::TcpStream;

// Protocol constants
const ANAMELEN: usize = 28;
const DOMLEN: usize = 48;
const CHALLEN: usize = 8;
const TICKETLEN: usize = 72;
const AUTH_TREQ: u8 = 1;
const AUTH_OK: u8 = 4;
const AUTH_ERR: u8 = 5;

fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 5 {
        eprintln!("Usage: {} <authsrv-addr:port> <authdom> <user> <password>", args[0]);
        eprintln!("Example: {} 127.0.0.1:567 9front glenda test1234", args[0]);
        std::process::exit(1);
    }

    let addr = &args[1];
    let authdom = &args[2];
    let user = &args[3];
    let password = &args[4];

    println!("Connecting to auth server at {}...", addr);
    let mut stream = TcpStream::connect(addr)?;
    println!("Connected!");

    // Derive DES key from password
    let user_key = crabbit::auth::pass_to_key(password);
    println!("Derived key from password: {:02x?}", user_key);

    // Build ticket request
    // type[1] + authid[28] + authdom[48] + chal[8] + hostid[28] + uid[28] = 141
    let mut treq = [0u8; 141];
    treq[0] = AUTH_TREQ;

    // authid - who we're asking for tickets (the auth server's identity)
    write_fixed_string(&mut treq[1..1 + ANAMELEN], user);

    // authdom - authentication domain
    write_fixed_string(&mut treq[1 + ANAMELEN..1 + ANAMELEN + DOMLEN], authdom);

    // challenge - random 8 bytes
    let challenge: [u8; CHALLEN] = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
    treq[1 + ANAMELEN + DOMLEN..1 + ANAMELEN + DOMLEN + CHALLEN].copy_from_slice(&challenge);

    // hostid - the server we want to talk to (use same as user for now)
    write_fixed_string(
        &mut treq[1 + ANAMELEN + DOMLEN + CHALLEN..1 + ANAMELEN + DOMLEN + CHALLEN + ANAMELEN],
        user,
    );

    // uid - the user requesting auth
    write_fixed_string(
        &mut treq[1 + ANAMELEN + DOMLEN + CHALLEN + ANAMELEN..],
        user,
    );

    println!("\nSending ticket request:");
    println!("  authid:  {}", user);
    println!("  authdom: {}", authdom);
    println!("  hostid:  {}", user);
    println!("  uid:     {}", user);
    println!("  challenge: {:02x?}", challenge);

    stream.write_all(&treq)?;
    stream.flush()?;

    // Read response
    let mut response_type = [0u8; 1];
    stream.read_exact(&mut response_type)?;

    match response_type[0] {
        AUTH_OK => {
            println!("\nReceived AUTH_OK!");

            // Read both tickets (72 bytes each)
            let mut tickets = [0u8; 2 * TICKETLEN];
            stream.read_exact(&mut tickets)?;

            let client_ticket = &tickets[..TICKETLEN];
            let server_ticket = &tickets[TICKETLEN..];

            println!("Client ticket (encrypted): {:02x?}...", &client_ticket[..16]);
            println!("Server ticket (encrypted): {:02x?}...", &server_ticket[..16]);

            // Try to decrypt client ticket with our key
            let mut ct = [0u8; TICKETLEN];
            ct.copy_from_slice(client_ticket);

            match crabbit::auth::AuthModule::decrypt_ticket(&ct, &user_key) {
                Ok((ttype, chal, cuid, suid, skey)) => {
                    println!("\nDecrypted client ticket:");
                    println!("  type:        {} (expected 65=AuthTc)", ttype);
                    println!("  challenge:   {:02x?}", chal);
                    println!("  cuid:        {}", cuid);
                    println!("  suid:        {}", suid);
                    println!("  session_key: {:02x?}", skey);

                    if chal == challenge {
                        println!("\n✓ Challenge matches! Authentication successful.");
                    } else {
                        println!("\n✗ Challenge mismatch - key derivation may differ from 9front");
                    }
                }
                Err(e) => {
                    println!("\nFailed to decrypt ticket: {}", e);
                    println!("This likely means our key derivation differs from 9front's");
                }
            }
        }
        AUTH_ERR => {
            // Read error message
            let mut buf = [0u8; 256];
            let n = stream.read(&mut buf)?;
            let msg = String::from_utf8_lossy(&buf[..n]);
            println!("\nReceived AUTH_ERR: {}", msg);
        }
        other => {
            println!("\nUnexpected response type: {}", other);
        }
    }

    Ok(())
}

fn write_fixed_string(dest: &mut [u8], value: &str) {
    dest.fill(0);
    let bytes = value.as_bytes();
    let len = bytes.len().min(dest.len() - 1);
    dest[..len].copy_from_slice(&bytes[..len]);
}
