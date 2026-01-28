// Plan 9 Authentication Server
//
// TCP server that handles p9sk1 ticket requests.
// Reference: Nawin.Auth/AuthServer.cs and 9front's authsrv(6)

use anyhow::Result;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, error, info, warn};

use crate::auth::{
    AuthModule, ANAMELEN, AUTH_ERR, AUTH_OK, AUTH_TREQ, CHALLEN, DOMLEN, TICKETLEN,
};

// Ticket request size: type[1] + authid[28] + authdom[48] + chal[8] + hostid[28] + uid[28] = 141
const TICKREQ_LEN: usize = 1 + ANAMELEN + DOMLEN + CHALLEN + ANAMELEN + ANAMELEN;

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
            19 => {
                // dp9ik (AuthPAK) - just close connection, let client fall back to p9sk1
                warn!("Unsupported auth message type: 19 (dp9ik) - closing connection");
                return Ok(());
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
