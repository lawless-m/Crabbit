// Auth Server Client - forwards authentication to an external auth server
//
// Used in AuthServer mode to delegate p9sk1/dp9ik auth to Nawin.Auth or another
// Plan 9 compatible auth server.

use anyhow::{bail, Result};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tracing::{debug, info, warn};

use crate::auth::{ANAMELEN, AUTH_ERR, AUTH_OK, AUTH_PAK, AUTH_TREQ, CHALLEN, DOMLEN, TICKETLEN};
use crate::authpak::PAKYLEN;

// dp9ik ticket length (from auth_server.rs)
const DP9IK_TICKETLEN: usize = 124;

// Connection timeout
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const READ_TIMEOUT: Duration = Duration::from_secs(30);

/// Client for connecting to an external Plan 9 auth server
pub struct AuthClient {
    server_addr: String,
}

impl AuthClient {
    pub fn new(server_addr: &str) -> Self {
        AuthClient {
            server_addr: server_addr.to_string(),
        }
    }

    /// Request p9sk1 tickets from the auth server
    ///
    /// Sends a ticket request and returns (client_ticket, server_ticket) on success.
    pub async fn request_tickets(
        &self,
        authid: &str,
        authdom: &str,
        challenge: &[u8; CHALLEN],
        hostid: &str,
        uid: &str,
    ) -> Result<([u8; TICKETLEN], [u8; TICKETLEN])> {
        info!("Connecting to auth server at {}", self.server_addr);

        let mut stream = timeout(CONNECT_TIMEOUT, TcpStream::connect(&self.server_addr))
            .await
            .map_err(|_| anyhow::anyhow!("Connection timeout"))??;

        stream.set_nodelay(true)?;

        // Build ticket request: type[1] + authid[28] + authdom[48] + chal[8] + hostid[28] + uid[28] = 141
        let mut treq = [0u8; 141];
        treq[0] = AUTH_TREQ;
        write_fixed_string(&mut treq[1..1 + ANAMELEN], authid);
        write_fixed_string(&mut treq[1 + ANAMELEN..1 + ANAMELEN + DOMLEN], authdom);
        treq[1 + ANAMELEN + DOMLEN..1 + ANAMELEN + DOMLEN + CHALLEN].copy_from_slice(challenge);
        write_fixed_string(
            &mut treq[1 + ANAMELEN + DOMLEN + CHALLEN..1 + ANAMELEN + DOMLEN + CHALLEN + ANAMELEN],
            hostid,
        );
        write_fixed_string(
            &mut treq[1 + ANAMELEN + DOMLEN + CHALLEN + ANAMELEN..],
            uid,
        );

        debug!("Sending ticket request for user {} to server {}", uid, hostid);
        stream.write_all(&treq).await?;
        stream.flush().await?;

        // Read response: status[1] + (tickets or error)
        let mut status = [0u8; 1];
        timeout(READ_TIMEOUT, stream.read_exact(&mut status))
            .await
            .map_err(|_| anyhow::anyhow!("Read timeout"))??;

        match status[0] {
            AUTH_OK => {
                // Read two tickets
                let mut client_ticket = [0u8; TICKETLEN];
                let mut server_ticket = [0u8; TICKETLEN];

                timeout(READ_TIMEOUT, stream.read_exact(&mut client_ticket))
                    .await
                    .map_err(|_| anyhow::anyhow!("Read timeout"))??;
                timeout(READ_TIMEOUT, stream.read_exact(&mut server_ticket))
                    .await
                    .map_err(|_| anyhow::anyhow!("Read timeout"))??;

                debug!("Received tickets for user {}", uid);
                Ok((client_ticket, server_ticket))
            }
            AUTH_ERR => {
                // Read 64-byte error message
                let mut error_buf = [0u8; 64];
                timeout(READ_TIMEOUT, stream.read_exact(&mut error_buf))
                    .await
                    .map_err(|_| anyhow::anyhow!("Read timeout"))??;

                let error_msg = read_fixed_string(&error_buf);
                warn!("Auth server error: {}", error_msg);
                bail!("Auth server: {}", error_msg)
            }
            _ => {
                bail!("Unexpected auth response type: {}", status[0])
            }
        }
    }

    /// Request dp9ik tickets from the auth server with PAK exchange
    ///
    /// Performs the full dp9ik protocol:
    /// 1. Send AuthPAK request
    /// 2. Exchange Y values for identities
    /// 3. Send AuthTreq for tickets
    pub async fn request_dp9ik_tickets(
        &self,
        authid: &str,
        authdom: &str,
        challenge: &[u8; CHALLEN],
        hostid: &str,
        uid: &str,
        client_pak_y: &[u8; PAKYLEN],
    ) -> Result<(
        [u8; PAKYLEN],                  // Server's Y for PAK
        [u8; DP9IK_TICKETLEN],          // Client ticket
        [u8; DP9IK_TICKETLEN],          // Server ticket
    )> {
        info!("Connecting to auth server at {} for dp9ik", self.server_addr);

        let mut stream = timeout(CONNECT_TIMEOUT, TcpStream::connect(&self.server_addr))
            .await
            .map_err(|_| anyhow::anyhow!("Connection timeout"))??;

        stream.set_nodelay(true)?;

        // Build AuthPAK request: type[1] + authid[28] + authdom[48] + chal[8] + hostid[28] + uid[28] = 141
        let mut treq = [0u8; 141];
        treq[0] = AUTH_PAK;
        write_fixed_string(&mut treq[1..1 + ANAMELEN], authid);
        write_fixed_string(&mut treq[1 + ANAMELEN..1 + ANAMELEN + DOMLEN], authdom);
        treq[1 + ANAMELEN + DOMLEN..1 + ANAMELEN + DOMLEN + CHALLEN].copy_from_slice(challenge);
        write_fixed_string(
            &mut treq[1 + ANAMELEN + DOMLEN + CHALLEN..1 + ANAMELEN + DOMLEN + CHALLEN + ANAMELEN],
            hostid,
        );
        write_fixed_string(
            &mut treq[1 + ANAMELEN + DOMLEN + CHALLEN + ANAMELEN..],
            uid,
        );

        debug!("Sending dp9ik PAK request for user {}", uid);
        stream.write_all(&treq).await?;
        stream.flush().await?;

        // Read AuthOK
        let mut status = [0u8; 1];
        timeout(READ_TIMEOUT, stream.read_exact(&mut status))
            .await
            .map_err(|_| anyhow::anyhow!("Read timeout"))??;

        if status[0] == AUTH_ERR {
            let mut error_buf = [0u8; 64];
            timeout(READ_TIMEOUT, stream.read_exact(&mut error_buf))
                .await
                .map_err(|_| anyhow::anyhow!("Read timeout"))??;
            let error_msg = read_fixed_string(&error_buf);
            bail!("Auth server: {}", error_msg);
        }

        if status[0] != AUTH_OK {
            bail!("Unexpected auth response type: {}", status[0]);
        }

        // PAK exchange - server sends Y first, we respond
        let mut server_y = [0u8; PAKYLEN];
        timeout(READ_TIMEOUT, stream.read_exact(&mut server_y))
            .await
            .map_err(|_| anyhow::anyhow!("Read timeout"))??;

        // Send our Y
        stream.write_all(client_pak_y).await?;
        stream.flush().await?;

        // Now send AuthTreq for tickets
        treq[0] = AUTH_TREQ;
        stream.write_all(&treq).await?;
        stream.flush().await?;

        // Read response
        timeout(READ_TIMEOUT, stream.read_exact(&mut status))
            .await
            .map_err(|_| anyhow::anyhow!("Read timeout"))??;

        if status[0] == AUTH_ERR {
            let mut error_buf = [0u8; 64];
            timeout(READ_TIMEOUT, stream.read_exact(&mut error_buf))
                .await
                .map_err(|_| anyhow::anyhow!("Read timeout"))??;
            let error_msg = read_fixed_string(&error_buf);
            bail!("Auth server: {}", error_msg);
        }

        if status[0] != AUTH_OK {
            bail!("Unexpected auth response type: {}", status[0]);
        }

        // Read dp9ik tickets (124 bytes each)
        let mut client_ticket = [0u8; DP9IK_TICKETLEN];
        let mut server_ticket = [0u8; DP9IK_TICKETLEN];

        timeout(READ_TIMEOUT, stream.read_exact(&mut client_ticket))
            .await
            .map_err(|_| anyhow::anyhow!("Read timeout"))??;
        timeout(READ_TIMEOUT, stream.read_exact(&mut server_ticket))
            .await
            .map_err(|_| anyhow::anyhow!("Read timeout"))??;

        debug!("Received dp9ik tickets for user {}", uid);
        Ok((server_y, client_ticket, server_ticket))
    }

    /// Forward a raw ticket request to the auth server
    ///
    /// This is a simpler approach - just proxy the bytes.
    pub async fn forward_request(&self, request: &[u8]) -> Result<Vec<u8>> {
        let mut stream = timeout(CONNECT_TIMEOUT, TcpStream::connect(&self.server_addr))
            .await
            .map_err(|_| anyhow::anyhow!("Connection timeout"))??;

        stream.set_nodelay(true)?;

        // Send the request
        stream.write_all(request).await?;
        stream.flush().await?;

        // Read response - first byte is status
        let mut response = Vec::new();
        let mut status = [0u8; 1];
        timeout(READ_TIMEOUT, stream.read_exact(&mut status))
            .await
            .map_err(|_| anyhow::anyhow!("Read timeout"))??;

        response.push(status[0]);

        match status[0] {
            AUTH_OK => {
                // Determine response size based on request type
                let expected_len = if request[0] == AUTH_TREQ {
                    2 * TICKETLEN // p9sk1 tickets
                } else {
                    // For dp9ik, this is more complex - would need state machine
                    2 * DP9IK_TICKETLEN
                };

                let mut buf = vec![0u8; expected_len];
                timeout(READ_TIMEOUT, stream.read_exact(&mut buf))
                    .await
                    .map_err(|_| anyhow::anyhow!("Read timeout"))??;
                response.extend_from_slice(&buf);
            }
            AUTH_ERR => {
                let mut error_buf = [0u8; 64];
                timeout(READ_TIMEOUT, stream.read_exact(&mut error_buf))
                    .await
                    .map_err(|_| anyhow::anyhow!("Read timeout"))??;
                response.extend_from_slice(&error_buf);
            }
            _ => {
                // Unknown response, try to read what we can
                let mut buf = [0u8; 1024];
                if let Ok(Ok(n)) = timeout(Duration::from_millis(100), stream.read(&mut buf)).await {
                    response.extend_from_slice(&buf[..n]);
                }
            }
        }

        Ok(response)
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_write_fixed_string() {
        let mut buf = [0u8; 28];
        write_fixed_string(&mut buf, "glenda");
        assert_eq!(&buf[..6], b"glenda");
        assert_eq!(buf[6], 0);
    }

    #[test]
    fn test_read_fixed_string() {
        let mut buf = [0u8; 28];
        buf[..5].copy_from_slice(b"hello");
        assert_eq!(read_fixed_string(&buf), "hello");
    }
}
