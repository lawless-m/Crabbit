// Plan 9 Authentication Server
//
// TCP server that handles p9sk1 and dp9ik ticket requests.
// Reference: Nawin.Auth/AuthServer.cs and 9front's authsrv(6)

use anyhow::Result;
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use rand::RngCore;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, error, info, warn};

use crate::auth::{AuthModule, ANAMELEN, AUTH_ERR, AUTH_OK, AUTH_TC, AUTH_TREQ, AUTH_TS, CHALLEN, DOMLEN};
use crate::authpak::{authpak_finish, authpak_new, PAKKEYLEN, PAKYLEN};

// Ticket request size: type[1] + authid[28] + authdom[48] + chal[8] + hostid[28] + uid[28] = 141
const TICKREQ_LEN: usize = 1 + ANAMELEN + DOMLEN + CHALLEN + ANAMELEN + ANAMELEN;

// Auth message type for dp9ik
const AUTH_PAK: u8 = 19;

// dp9ik constants
const DP9IK_AESSION: usize = 32;  // dp9ik session key is 32 bytes
const DP9IK_SIGLEN: usize = 8;    // form1 signature length
const DP9IK_COUNTERLEN: usize = 4; // form1 counter length
const DP9IK_TAGSIZE: usize = 16;  // ChaCha20-Poly1305 tag size
// dp9ik ticket: sig[8] + counter[4] + encrypted(chal[8] + cuid[28] + suid[28] + key[32]) + tag[16] = 124 bytes
const DP9IK_TICKETLEN: usize = DP9IK_SIGLEN + DP9IK_COUNTERLEN + CHALLEN + 2 * ANAMELEN + DP9IK_AESSION + DP9IK_TAGSIZE;

// Form1 signatures for ticket types
const FORM1_SIG_TS: &[u8; 8] = b"form1 Ts";
const FORM1_SIG_TC: &[u8; 8] = b"form1 Tc";

// Counter for form1 nonce generation
static FORM1_COUNTER: AtomicU32 = AtomicU32::new(0);

// p9sk1 ticket length
const TICKETLEN: usize = 72;

/// Auth server that listens for p9sk1 ticket requests
pub struct AuthServer {
    listener: TcpListener,
    auth: Arc<AuthModule>,
}

impl AuthServer {
    /// Create a new auth server bound to the given address
    pub async fn bind(addr: &str, auth: Arc<AuthModule>) -> Result<Self> {
        let listener = TcpListener::bind(addr).await?;
        info!("Auth server listening on {}", addr);
        Ok(AuthServer { listener, auth })
    }

    /// Run the auth server, accepting connections until shutdown
    pub async fn run(&self) -> Result<()> {
        loop {
            match self.listener.accept().await {
                Ok((stream, addr)) => {
                    info!("Auth connection from {}", addr);
                    let auth = self.auth.clone();
                    tokio::spawn(async move {
                        if let Err(e) = handle_connection(stream, auth).await {
                            error!("Auth connection error: {}", e);
                        }
                    });
                }
                Err(e) => {
                    error!("Accept error: {}", e);
                }
            }
        }
    }
}

/// Handle a single auth connection (may have multiple requests)
async fn handle_connection(mut stream: TcpStream, auth: Arc<AuthModule>) -> Result<()> {
    // Disable Nagle's algorithm for immediate sends
    stream.set_nodelay(true)?;

    // Loop to handle multiple requests on same connection
    loop {
        info!("Waiting for next request on connection...");
        // Read message type (first byte)
        let mut msg_type = [0u8; 1];
        match stream.read_exact(&mut msg_type).await {
            Ok(_) => {
                info!("Received message type: {}", msg_type[0]);
            }
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                info!("Connection closed by client (EOF)");
                return Ok(());
            }
            Err(e) => {
                warn!("Read error: {}", e);
                return Err(e.into());
            }
        }

        match msg_type[0] {
            AUTH_TREQ => {
                info!("Handling AUTH_TREQ...");
                handle_ticket_request(&mut stream, &auth, msg_type[0]).await?;
                info!("AUTH_TREQ handled, continuing loop");
                // Continue loop for more requests
            }
            AUTH_PAK => {
                // dp9ik PAK exchange
                info!("Handling dp9ik AuthPAK...");
                handle_dp9ik(&mut stream, &auth, msg_type[0]).await?;
                info!("dp9ik handled, continuing loop");
            }
            _ => {
                warn!("Unsupported auth message type: {}", msg_type[0]);
                send_error(&mut stream, &format!("Unsupported auth type: {}", msg_type[0])).await?;
                // Continue loop
            }
        }
    }
}

/// Handle a p9sk1 ticket request (AuthTreq)
///
/// Request format:
///   type[1] + authid[28] + authdom[48] + chal[8] + hostid[28] + uid[28] = 141 bytes
///
/// Response format:
///   AuthOK[1] + clientTicket[72] + serverTicket[72] = 145 bytes
async fn handle_ticket_request(
    stream: &mut TcpStream,
    auth: &AuthModule,
    first_byte: u8,
) -> Result<()> {
    // Read rest of ticket request (140 more bytes after type)
    let mut treq = [0u8; TICKREQ_LEN];
    treq[0] = first_byte;
    stream.read_exact(&mut treq[1..]).await?;

    // Parse ticket request
    let authid = read_fixed_string(&treq[1..1 + ANAMELEN]);
    let authdom = read_fixed_string(&treq[1 + ANAMELEN..1 + ANAMELEN + DOMLEN]);
    let mut challenge = [0u8; CHALLEN];
    challenge.copy_from_slice(&treq[1 + ANAMELEN + DOMLEN..1 + ANAMELEN + DOMLEN + CHALLEN]);
    let hostid = read_fixed_string(
        &treq[1 + ANAMELEN + DOMLEN + CHALLEN..1 + ANAMELEN + DOMLEN + CHALLEN + ANAMELEN],
    );
    let uid = read_fixed_string(
        &treq[1 + ANAMELEN + DOMLEN + CHALLEN + ANAMELEN
            ..1 + ANAMELEN + DOMLEN + CHALLEN + 2 * ANAMELEN],
    );

    debug!(
        "Ticket request: user={}, server={}, domain={}, authid={}",
        uid, hostid, authdom, authid
    );

    // Verify auth domain matches
    if authdom != auth.authdom() {
        warn!("Auth domain mismatch: got {}, expected {}", authdom, auth.authdom());
        return send_error(stream, &format!("Unknown domain: {}", authdom)).await;
    }

    // Handle the ticket request
    match auth.handle_ticket_request(&uid, &hostid, &challenge) {
        Ok((client_ticket, server_ticket)) => {
            debug!("Issuing tickets for user {}", uid);
            debug!("Client ticket: {:02x?}", &client_ticket);
            debug!("Server ticket: {:02x?}", &server_ticket);

            // Send complete response in single write
            let mut response = Vec::with_capacity(145);
            response.push(AUTH_OK);
            response.extend_from_slice(&client_ticket);
            response.extend_from_slice(&server_ticket);
            stream.write_all(&response).await?;
            stream.flush().await?;

            info!("Issued tickets for user {} to server {}", uid, hostid);
            Ok(())
        }
        Err(e) => {
            warn!("Ticket request failed for user {}: {}", uid, e);
            send_error(stream, &e.to_string()).await
        }
    }
}

/// Send an error response
async fn send_error(stream: &mut TcpStream, message: &str) -> Result<()> {
    // Plan 9 expects exactly 64 bytes for error message (see _asrdresp.c)
    let mut error_buf = [0u8; 64];
    let msg_bytes = message.as_bytes();
    let copy_len = msg_bytes.len().min(63); // Leave room for null terminator
    error_buf[..copy_len].copy_from_slice(&msg_bytes[..copy_len]);

    let mut response = vec![AUTH_ERR];
    response.extend_from_slice(&error_buf);
    stream.write_all(&response).await?;
    stream.flush().await?;
    Ok(())
}

/// Read a null-terminated string from a fixed-length buffer
fn read_fixed_string(data: &[u8]) -> String {
    let end = data.iter().position(|&b| b == 0).unwrap_or(data.len());
    String::from_utf8_lossy(&data[..end]).into_owned()
}

/// Write a string to a fixed-length buffer, null-terminated
fn write_fixed_string(dest: &mut [u8], value: &str) {
    dest.fill(0);
    let bytes = value.as_bytes();
    let len = bytes.len().min(dest.len() - 1);
    dest[..len].copy_from_slice(&bytes[..len]);
}

/// Handle dp9ik authentication with PAK exchange
///
/// Protocol:
/// 1. Client -> Auth: ticketreq[141] (type=AuthPAK)
/// 2. Auth -> Client: AuthOK[1]
/// 3. For each identity (authid if set, then hostid):
///    - Auth -> Client: serverY[56]
///    - Client -> Auth: clientY[56]
/// 4. Client -> Auth: ticketreq[141] (type=AuthTreq)
/// 5. Auth -> Client: AuthOK[1] + clientTicket[124] + serverTicket[124]
async fn handle_dp9ik(
    stream: &mut TcpStream,
    auth: &AuthModule,
    first_byte: u8,
) -> Result<()> {
    // Read rest of ticket request (140 more bytes after type)
    let mut treq = [0u8; TICKREQ_LEN];
    treq[0] = first_byte;
    stream.read_exact(&mut treq[1..]).await?;

    // Parse ticket request
    let authid = read_fixed_string(&treq[1..1 + ANAMELEN]);
    let authdom = read_fixed_string(&treq[1 + ANAMELEN..1 + ANAMELEN + DOMLEN]);
    let mut challenge = [0u8; CHALLEN];
    challenge.copy_from_slice(&treq[1 + ANAMELEN + DOMLEN..1 + ANAMELEN + DOMLEN + CHALLEN]);
    let hostid = read_fixed_string(
        &treq[1 + ANAMELEN + DOMLEN + CHALLEN..1 + ANAMELEN + DOMLEN + CHALLEN + ANAMELEN],
    );
    let uid = read_fixed_string(
        &treq[1 + ANAMELEN + DOMLEN + CHALLEN + ANAMELEN
            ..1 + ANAMELEN + DOMLEN + CHALLEN + 2 * ANAMELEN],
    );

    info!(
        "dp9ik PAK request: uid={}, hostid={}, authid={}, dom={}",
        uid, hostid, authid, authdom
    );

    // Verify auth domain matches
    if authdom != auth.authdom() {
        warn!("Auth domain mismatch: got {}, expected {}", authdom, auth.authdom());
        return send_error(stream, &format!("Unknown domain: {}", authdom)).await;
    }

    // Send AuthOK first (before PAK exchanges)
    stream.write_all(&[AUTH_OK]).await?;
    stream.flush().await?;

    let mut pak_key_for_authid: Option<[u8; PAKKEYLEN]> = None;
    let mut pak_key_for_hostid: Option<[u8; PAKKEYLEN]> = None;

    // PAK exchange for identities
    // From 9front pak(): if(tr->hostid[0]){ if(tr->authid[0]) pak1(tr->authid, &akey); pak1(tr->hostid, &hkey); }
    if !hostid.is_empty() {
        if !authid.is_empty() {
            pak_key_for_authid = Some(do_pak_exchange(stream, auth, &authid).await?);
        }
        pak_key_for_hostid = Some(do_pak_exchange(stream, auth, &hostid).await?);
    } else if !uid.is_empty() {
        pak_key_for_hostid = Some(do_pak_exchange(stream, auth, &uid).await?);
    }

    // Now wait for AuthTreq to issue tickets
    let mut treq_buf = [0u8; TICKREQ_LEN];
    stream.read_exact(&mut treq_buf).await?;

    if treq_buf[0] != AUTH_TREQ {
        warn!("dp9ik: Expected AuthTreq, got {}", treq_buf[0]);
        return send_error(stream, &format!("Expected AuthTreq, got {}", treq_buf[0])).await;
    }

    // Parse the AuthTreq
    let treq_challenge = &treq_buf[1 + ANAMELEN + DOMLEN..1 + ANAMELEN + DOMLEN + CHALLEN];
    let treq_uid = read_fixed_string(
        &treq_buf[1 + ANAMELEN + DOMLEN + CHALLEN + ANAMELEN
            ..1 + ANAMELEN + DOMLEN + CHALLEN + 2 * ANAMELEN],
    );

    // Determine which PAK keys to use
    let client_key = pak_key_for_hostid.ok_or_else(|| anyhow::anyhow!("No PAK key for client"))?;
    let server_key = pak_key_for_authid.unwrap_or(client_key);

    // Generate random session key (32 bytes for dp9ik)
    let mut session_key = [0u8; DP9IK_AESSION];
    rand::thread_rng().fill_bytes(&mut session_key);

    // Create tickets
    let mut chal = [0u8; CHALLEN];
    chal.copy_from_slice(treq_challenge);

    let client_ticket = create_dp9ik_ticket(AUTH_TC, &chal, &treq_uid, &treq_uid, &session_key, &client_key)?;
    let server_ticket = create_dp9ik_ticket(AUTH_TS, &chal, &treq_uid, &treq_uid, &session_key, &server_key)?;

    // Send AuthOK + tickets
    let mut response = Vec::with_capacity(1 + 2 * DP9IK_TICKETLEN);
    response.push(AUTH_OK);
    response.extend_from_slice(&client_ticket);
    response.extend_from_slice(&server_ticket);
    stream.write_all(&response).await?;
    stream.flush().await?;

    info!("dp9ik: Issued tickets for user {}", treq_uid);
    Ok(())
}

/// Perform PAK exchange for a single user identity
async fn do_pak_exchange(
    stream: &mut TcpStream,
    auth: &AuthModule,
    user_id: &str,
) -> Result<[u8; PAKKEYLEN]> {
    let user_creds = auth
        .get_user(user_id)
        .ok_or_else(|| anyhow::anyhow!("Unknown user: {}", user_id))?;

    // Generate our Y (auth server acts as SERVER, is_client=false)
    let pak_state = authpak_new(&user_creds.pak_hash, false);

    // Send our Y
    stream.write_all(&pak_state.y).await?;
    stream.flush().await?;

    // Read client's Y
    let mut client_y = [0u8; PAKYLEN];
    stream.read_exact(&mut client_y).await?;

    // Finish PAK and compute shared key
    let pak_key = authpak_finish(&pak_state, &user_creds.pak_hash, &client_y)?;

    debug!("PAK exchange complete for user {}", user_id);
    Ok(pak_key)
}

/// Create a dp9ik ticket using ChaCha20-Poly1305 in form1 format
///
/// Format: sig[8] + counter[4] + encrypted(chal[8] + cuid[28] + suid[28] + key[32]) + tag[16] = 124 bytes
fn create_dp9ik_ticket(
    ticket_type: u8,
    challenge: &[u8; CHALLEN],
    cuid: &str,
    suid: &str,
    session_key: &[u8; DP9IK_AESSION],
    encryption_key: &[u8; PAKKEYLEN],
) -> Result<[u8; DP9IK_TICKETLEN]> {
    // Get signature for this type
    let sig = if ticket_type == AUTH_TS {
        FORM1_SIG_TS
    } else {
        FORM1_SIG_TC
    };

    // Build plaintext: chal[8] + cuid[28] + suid[28] + key[32] = 96 bytes (NO type byte)
    const PLAIN_SIZE: usize = CHALLEN + 2 * ANAMELEN + DP9IK_AESSION;
    let mut plaintext = [0u8; PLAIN_SIZE];
    plaintext[..CHALLEN].copy_from_slice(challenge);
    write_fixed_string(&mut plaintext[CHALLEN..CHALLEN + ANAMELEN], cuid);
    write_fixed_string(&mut plaintext[CHALLEN + ANAMELEN..CHALLEN + 2 * ANAMELEN], suid);
    plaintext[CHALLEN + 2 * ANAMELEN..].copy_from_slice(session_key);

    // Build nonce: sig[8] + counter[4]
    let mut nonce_bytes = [0u8; 12];
    nonce_bytes[..8].copy_from_slice(sig);
    let counter = FORM1_COUNTER.fetch_add(1, Ordering::Relaxed);
    nonce_bytes[8..12].copy_from_slice(&counter.to_le_bytes());

    // Encrypt with ChaCha20-Poly1305
    let cipher = ChaCha20Poly1305::new_from_slice(encryption_key)
        .map_err(|e| anyhow::anyhow!("Failed to create cipher: {}", e))?;
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, plaintext.as_ref())
        .map_err(|e| anyhow::anyhow!("Encryption failed: {}", e))?;

    // Result: sig[8] + counter[4] + ciphertext[96] + tag[16] = 124 bytes
    let mut result = [0u8; DP9IK_TICKETLEN];
    result[..12].copy_from_slice(&nonce_bytes);
    result[12..].copy_from_slice(&ciphertext);

    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{AuthConfig, AuthMode, UserConfig};
    use tokio::io::AsyncWriteExt;

    fn create_test_auth() -> Arc<AuthModule> {
        let config = AuthConfig {
            mode: AuthMode::Standalone,
            authid: "testserver".to_string(),
            authdom: "testdom".to_string(),
            server: None,
            users: vec![UserConfig {
                name: "alice".to_string(),
                key: String::new(),
                password: Some("alicepass".to_string()),
            }],
        };
        Arc::new(AuthModule::new(&config).unwrap())
    }

    #[tokio::test]
    async fn test_auth_server_ticket_request() {
        // Start server on random port
        let auth = create_test_auth();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        // Spawn server handler
        let auth_clone = auth.clone();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            handle_connection(stream, auth_clone).await
        });

        // Connect as client
        let mut client = TcpStream::connect(addr).await.unwrap();

        // Build ticket request
        let mut treq = [0u8; TICKREQ_LEN];
        treq[0] = AUTH_TREQ;
        write_fixed_string(&mut treq[1..1 + ANAMELEN], "testserver");
        write_fixed_string(&mut treq[1 + ANAMELEN..1 + ANAMELEN + DOMLEN], "testdom");
        // challenge
        treq[1 + ANAMELEN + DOMLEN..1 + ANAMELEN + DOMLEN + CHALLEN]
            .copy_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);
        write_fixed_string(
            &mut treq[1 + ANAMELEN + DOMLEN + CHALLEN..1 + ANAMELEN + DOMLEN + CHALLEN + ANAMELEN],
            "testserver",
        );
        write_fixed_string(
            &mut treq[1 + ANAMELEN + DOMLEN + CHALLEN + ANAMELEN
                ..1 + ANAMELEN + DOMLEN + CHALLEN + 2 * ANAMELEN],
            "alice",
        );

        // Send request
        client.write_all(&treq).await.unwrap();
        client.flush().await.unwrap();

        // Read response
        let mut response = [0u8; 1 + 2 * TICKETLEN];
        client.read_exact(&mut response).await.unwrap();

        // Verify response
        assert_eq!(response[0], AUTH_OK);

        // Wait for server to complete
        server.await.unwrap().unwrap();
    }

    fn write_fixed_string(dest: &mut [u8], value: &str) {
        dest.fill(0);
        let bytes = value.as_bytes();
        let len = bytes.len().min(dest.len() - 1);
        dest[..len].copy_from_slice(&bytes[..len]);
    }
}
