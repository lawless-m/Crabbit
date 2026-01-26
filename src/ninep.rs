// 9P2000 Protocol Implementation
// Reference: http://man.cat-v.org/plan_9/5/intro

use anyhow::Result;
use bytes::{Buf, BufMut, Bytes, BytesMut};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;
use tracing::{debug, error, info};

use crate::auth::AuthModule;
use crate::net_engine::NetEngine;

// 9P message types
const TVERSION: u8 = 100;
const RVERSION: u8 = 101;
const TAUTH: u8 = 102;
const RAUTH: u8 = 103;
const TATTACH: u8 = 104;
const RATTACH: u8 = 105;
const RERROR: u8 = 107;
const TFLUSH: u8 = 108;
const RFLUSH: u8 = 109;
const TWALK: u8 = 110;
const RWALK: u8 = 111;
const TOPEN: u8 = 112;
const ROPEN: u8 = 113;
const TCREATE: u8 = 114;
const RCREATE: u8 = 115;
const TREAD: u8 = 116;
const RREAD: u8 = 117;
const TWRITE: u8 = 118;
const RWRITE: u8 = 119;
const TCLUNK: u8 = 120;
const RCLUNK: u8 = 121;
const TREMOVE: u8 = 122;
const RREMOVE: u8 = 123;
const TSTAT: u8 = 124;
const RSTAT: u8 = 125;
const TWSTAT: u8 = 126;
const RWSTAT: u8 = 127;

// QID types
const QTDIR: u8 = 0x80;
const QTFILE: u8 = 0x00;

// Open modes
const OREAD: u8 = 0;
const OWRITE: u8 = 1;
const ORDWR: u8 = 2;

const MAX_MSG_SIZE: u32 = 8192;
const PROTOCOL_VERSION: &str = "9P2000";

#[derive(Debug, Clone)]
pub struct Qid {
    typ: u8,
    version: u32,
    path: u64,
}

impl Qid {
    fn new(typ: u8, path: u64) -> Self {
        Qid {
            typ,
            version: 0,
            path,
        }
    }

    fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8(self.typ);
        buf.put_u32_le(self.version);
        buf.put_u64_le(self.path);
    }

    fn decode(buf: &mut Bytes) -> Result<Self> {
        if buf.remaining() < 13 {
            anyhow::bail!("Not enough bytes for Qid");
        }
        Ok(Qid {
            typ: buf.get_u8(),
            version: buf.get_u32_le(),
            path: buf.get_u64_le(),
        })
    }
}

#[derive(Debug)]
struct Stat {
    size: u16,
    typ: u16,
    dev: u32,
    qid: Qid,
    mode: u32,
    atime: u32,
    mtime: u32,
    length: u64,
    name: String,
    uid: String,
    gid: String,
    muid: String,
}

impl Stat {
    fn encode(&self, buf: &mut BytesMut) {
        let start = buf.len();
        buf.put_u16_le(0); // Size placeholder
        buf.put_u16_le(self.typ);
        buf.put_u32_le(self.dev);
        self.qid.encode(buf);
        buf.put_u32_le(self.mode);
        buf.put_u32_le(self.atime);
        buf.put_u32_le(self.mtime);
        buf.put_u64_le(self.length);
        put_string(buf, &self.name);
        put_string(buf, &self.uid);
        put_string(buf, &self.gid);
        put_string(buf, &self.muid);

        // Fill in size
        let size = (buf.len() - start - 2) as u16;
        buf[start..start + 2].copy_from_slice(&size.to_le_bytes());
    }
}

pub struct Server {
    address: String,
    auth: Arc<AuthModule>,
    net_engine: Arc<NetEngine>,
}

impl Server {
    pub async fn new(
        address: String,
        auth: AuthModule,
        net_engine: NetEngine,
    ) -> Result<Self> {
        Ok(Server {
            address,
            auth: Arc::new(auth),
            net_engine: Arc::new(net_engine),
        })
    }

    pub async fn run(&self) -> Result<()> {
        let listener = TcpListener::bind(&self.address).await?;
        info!("9P server listening on {}", self.address);

        loop {
            match listener.accept().await {
                Ok((stream, addr)) => {
                    info!("New connection from {}", addr);
                    let session = Session::new(
                        stream,
                        Arc::clone(&self.auth),
                        Arc::clone(&self.net_engine),
                    );
                    tokio::spawn(async move {
                        if let Err(e) = session.handle().await {
                            error!("Session error: {}", e);
                        }
                    });
                }
                Err(e) => {
                    error!("Failed to accept connection: {}", e);
                }
            }
        }
    }
}

struct Session {
    stream: TcpStream,
    auth: Arc<AuthModule>,
    net_engine: Arc<NetEngine>,
    fids: Arc<Mutex<HashMap<u32, Fid>>>,
    msize: u32,
}

#[derive(Debug)]
struct Fid {
    qid: Qid,
    path: String,
    open: bool,
}

impl Session {
    fn new(stream: TcpStream, auth: Arc<AuthModule>, net_engine: Arc<NetEngine>) -> Self {
        Session {
            stream,
            auth,
            net_engine,
            fids: Arc::new(Mutex::new(HashMap::new())),
            msize: MAX_MSG_SIZE,
        }
    }

    async fn handle(mut self) -> Result<()> {
        loop {
            // Read message size
            let size = match self.stream.read_u32_le().await {
                Ok(s) => s,
                Err(_) => break, // Connection closed
            };

            if size < 7 || size > self.msize {
                anyhow::bail!("Invalid message size: {}", size);
            }

            // Read rest of message
            let mut buf = vec![0u8; (size - 4) as usize];
            self.stream.read_exact(&mut buf).await?;
            let mut msg = Bytes::from(buf);

            let msg_type = msg.get_u8();
            let tag = msg.get_u16_le();

            debug!("Received message: type={}, tag={}", msg_type, tag);

            let response = match msg_type {
                TVERSION => self.handle_version(tag, msg).await,
                TAUTH => self.handle_auth(tag, msg).await,
                TATTACH => self.handle_attach(tag, msg).await,
                TWALK => self.handle_walk(tag, msg).await,
                TOPEN => self.handle_open(tag, msg).await,
                TREAD => self.handle_read(tag, msg).await,
                TWRITE => self.handle_write(tag, msg).await,
                TCLUNK => self.handle_clunk(tag, msg).await,
                TSTAT => self.handle_stat(tag, msg).await,
                _ => self.error_response(tag, &format!("Unsupported message type: {}", msg_type)),
            };

            self.stream.write_all(&response).await?;
        }

        Ok(())
    }

    async fn handle_version(&mut self, tag: u16, mut msg: Bytes) -> Vec<u8> {
        let msize = msg.get_u32_le();
        let version = get_string(&mut msg);

        debug!("Version request: msize={}, version={}", msize, version);

        // Negotiate message size
        self.msize = msize.min(MAX_MSG_SIZE);

        // Only support 9P2000
        let resp_version = if version == PROTOCOL_VERSION {
            PROTOCOL_VERSION
        } else {
            "unknown"
        };

        let mut response = BytesMut::new();
        response.put_u32_le(0); // Size placeholder
        response.put_u8(RVERSION);
        response.put_u16_le(tag);
        response.put_u32_le(self.msize);
        put_string(&mut response, resp_version);

        let size = response.len() as u32;
        response[0..4].copy_from_slice(&size.to_le_bytes());

        response.to_vec()
    }

    async fn handle_auth(&self, tag: u16, mut msg: Bytes) -> Vec<u8> {
        let _afid = msg.get_u32_le();
        let uname = get_string(&mut msg);
        let _aname = get_string(&mut msg);

        debug!("Auth request: uname={}", uname);

        // For now, return error - we'll implement auth later
        self.error_response(tag, "Authentication not yet implemented")
    }

    async fn handle_attach(&self, tag: u16, mut msg: Bytes) -> Vec<u8> {
        let fid = msg.get_u32_le();
        let _afid = msg.get_u32_le();
        let _uname = get_string(&mut msg);
        let _aname = get_string(&mut msg);

        debug!("Attach request: fid={}", fid);

        // Root qid
        let qid = Qid::new(QTDIR, 0);

        // Store fid
        let mut fids = self.fids.blocking_lock();
        fids.insert(
            fid,
            Fid {
                qid: qid.clone(),
                path: "/".to_string(),
                open: false,
            },
        );

        let mut response = BytesMut::new();
        response.put_u32_le(0); // Size placeholder
        response.put_u8(RATTACH);
        response.put_u16_le(tag);
        qid.encode(&mut response);

        let size = response.len() as u32;
        response[0..4].copy_from_slice(&size.to_le_bytes());

        response.to_vec()
    }

    async fn handle_walk(&self, tag: u16, mut msg: Bytes) -> Vec<u8> {
        let fid = msg.get_u32_le();
        let newfid = msg.get_u32_le();
        let nwname = msg.get_u16_le();

        debug!("Walk request: fid={}, newfid={}, nwname={}", fid, newfid, nwname);

        // For now, simple implementation
        let mut response = BytesMut::new();
        response.put_u32_le(0); // Size placeholder
        response.put_u8(RWALK);
        response.put_u16_le(tag);
        response.put_u16_le(0); // No qids yet

        let size = response.len() as u32;
        response[0..4].copy_from_slice(&size.to_le_bytes());

        response.to_vec()
    }

    async fn handle_open(&self, tag: u16, mut msg: Bytes) -> Vec<u8> {
        let _fid = msg.get_u32_le();
        let _mode = msg.get_u8();

        debug!("Open request");

        self.error_response(tag, "Not implemented")
    }

    async fn handle_read(&self, tag: u16, mut msg: Bytes) -> Vec<u8> {
        let _fid = msg.get_u32_le();
        let _offset = msg.get_u64_le();
        let _count = msg.get_u32_le();

        debug!("Read request");

        self.error_response(tag, "Not implemented")
    }

    async fn handle_write(&self, tag: u16, mut msg: Bytes) -> Vec<u8> {
        let _fid = msg.get_u32_le();
        let _offset = msg.get_u64_le();
        let _count = msg.get_u32_le();

        debug!("Write request");

        self.error_response(tag, "Not implemented")
    }

    async fn handle_clunk(&self, tag: u16, mut msg: Bytes) -> Vec<u8> {
        let fid = msg.get_u32_le();

        debug!("Clunk request: fid={}", fid);

        let mut fids = self.fids.blocking_lock();
        fids.remove(&fid);

        let mut response = BytesMut::new();
        response.put_u32_le(0); // Size placeholder
        response.put_u8(RCLUNK);
        response.put_u16_le(tag);

        let size = response.len() as u32;
        response[0..4].copy_from_slice(&size.to_le_bytes());

        response.to_vec()
    }

    async fn handle_stat(&self, tag: u16, mut msg: Bytes) -> Vec<u8> {
        let _fid = msg.get_u32_le();

        debug!("Stat request");

        self.error_response(tag, "Not implemented")
    }

    fn error_response(&self, tag: u16, error: &str) -> Vec<u8> {
        let mut response = BytesMut::new();
        response.put_u32_le(0); // Size placeholder
        response.put_u8(RERROR);
        response.put_u16_le(tag);
        put_string(&mut response, error);

        let size = response.len() as u32;
        response[0..4].copy_from_slice(&size.to_le_bytes());

        response.to_vec()
    }
}

fn get_string(buf: &mut Bytes) -> String {
    let len = buf.get_u16_le() as usize;
    let bytes = buf.copy_to_bytes(len);
    String::from_utf8_lossy(&bytes).to_string()
}

fn put_string(buf: &mut BytesMut, s: &str) {
    buf.put_u16_le(s.len() as u16);
    buf.put_slice(s.as_bytes());
}
