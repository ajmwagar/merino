#![forbid(unsafe_code)]
#[macro_use]
extern crate serde_derive;
#[macro_use]
extern crate log;
use snafu::Snafu;

use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6, ToSocketAddrs};
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;

/// Version of socks
const SOCKS_VERSION: u8 = 0x05;

const RESERVED: u8 = 0x00;

#[derive(Clone, Debug, PartialEq, Deserialize)]
pub struct User {
    pub username: String,
    password: String,
}

pub struct SocksReply {
    // From rfc 1928 (S6),
    // the server evaluates the request, and returns a reply formed as follows:
    //
    //    +----+-----+-------+------+----------+----------+
    //    |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
    //    +----+-----+-------+------+----------+----------+
    //    | 1  |  1  | X'00' |  1   | Variable |    2     |
    //    +----+-----+-------+------+----------+----------+
    //
    // Where:
    //
    //      o  VER    protocol version: X'05'
    //      o  REP    Reply field:
    //         o  X'00' succeeded
    //         o  X'01' general SOCKS server failure
    //         o  X'02' connection not allowed by ruleset
    //         o  X'03' Network unreachable
    //         o  X'04' Host unreachable
    //         o  X'05' Connection refused
    //         o  X'06' TTL expired
    //         o  X'07' Command not supported
    //         o  X'08' Address type not supported
    //         o  X'09' to X'FF' unassigned
    //      o  RSV    RESERVED
    //      o  ATYP   address type of following address
    //         o  IP V4 address: X'01'
    //         o  DOMAINNAME: X'03'
    //         o  IP V6 address: X'04'
    //      o  BND.ADDR       server bound address
    //      o  BND.PORT       server bound port in network octet order
    //
    buf: [u8; 10],
}

impl SocksReply {
    pub fn new(status: ResponseCode) -> Self {
        let buf = [
            // VER
            SOCKS_VERSION,
            // REP
            status as u8,
            // RSV
            RESERVED,
            // ATYP
            1,
            // BND.ADDR
            0,
            0,
            0,
            0,
            // BND.PORT
            0,
            0,
        ];
        Self { buf }
    }

    pub async fn send<T>(&self, stream: &mut T) -> io::Result<()>
    where
        T: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    {
        stream.write_all(&self.buf[..]).await?;
        Ok(())
    }
}

#[derive(Error, Debug)]
pub enum MerinoError {
    #[error("IO error: {0}")]
    Io(#[from] io::Error),

    #[error("Socks error: {0}")]
    Socks(#[from] ResponseCode),
}

#[derive(Debug, Snafu)]
/// Possible SOCKS5 Response Codes
pub enum ResponseCode {
    Success = 0x00,
    #[snafu(display("SOCKS5 Server Failure"))]
    Failure = 0x01,
    #[snafu(display("SOCKS5 Rule failure"))]
    RuleFailure = 0x02,
    #[snafu(display("network unreachable"))]
    NetworkUnreachable = 0x03,
    #[snafu(display("host unreachable"))]
    HostUnreachable = 0x04,
    #[snafu(display("connection refused"))]
    ConnectionRefused = 0x05,
    #[snafu(display("TTL expired"))]
    TtlExpired = 0x06,
    #[snafu(display("Command not supported"))]
    CommandNotSupported = 0x07,
    #[snafu(display("Addr Type not supported"))]
    AddrTypeNotSupported = 0x08,
}

impl From<MerinoError> for ResponseCode {
    fn from(e: MerinoError) -> Self {
        match e {
            MerinoError::Socks(e) => e,
            MerinoError::Io(_) => ResponseCode::Failure,
        }
    }
}

/// DST.addr variant types
#[derive(PartialEq)]
enum AddrType {
    /// IP V4 address: X'01'
    V4 = 0x01,
    /// DOMAINNAME: X'03'
    Domain = 0x03,
    /// IP V6 address: X'04'
    V6 = 0x04,
}

impl AddrType {
    /// Parse Byte to Command
    fn from(n: usize) -> Option<AddrType> {
        match n {
            1 => Some(AddrType::V4),
            3 => Some(AddrType::Domain),
            4 => Some(AddrType::V6),
            _ => None,
        }
    }

    // /// Return the size of the AddrType
    // fn size(&self) -> u8 {
    //     match self {
    //         AddrType::V4 => 4,
    //         AddrType::Domain => 1,
    //         AddrType::V6 => 16
    //     }
    // }
}

/// SOCK5 CMD Type
#[derive(Debug)]
enum SockCommand {
    Connect = 0x01,
    Bind = 0x02,
    UdpAssosiate = 0x3,
}

impl SockCommand {
    /// Parse Byte to Command
    fn from(n: usize) -> Option<SockCommand> {
        match n {
            1 => Some(SockCommand::Connect),
            2 => Some(SockCommand::Bind),
            3 => Some(SockCommand::UdpAssosiate),
            _ => None,
        }
    }
}

/// Client Authentication Methods
pub enum AuthMethods {
    /// No Authentication
    NoAuth = 0x00,
    // GssApi = 0x01,
    /// Authenticate with a username / password
    UserPass = 0x02,
    /// Cannot authenticate
    NoMethods = 0xFF,
}

pub struct Merino {
    listener: TcpListener,
    users: Arc<Vec<User>>,
    auth_methods: Arc<Vec<u8>>,
    // Timeout for connections
    timeout: Option<Duration>,
}

impl Merino {
    /// Create a new Merino instance
    pub async fn new(
        port: u16,
        ip: &str,
        auth_methods: Vec<u8>,
        users: Vec<User>,
        timeout: Option<Duration>,
    ) -> io::Result<Self> {
        info!("Listening on {}:{}", ip, port);
        Ok(Merino {
            listener: TcpListener::bind((ip, port)).await?,
            auth_methods: Arc::new(auth_methods),
            users: Arc::new(users),
            timeout,
        })
    }

    pub async fn serve(&mut self) {
        info!("Serving Connections...");
        while let Ok((stream, client_addr)) = self.listener.accept().await {
            let users = self.users.clone();
            let auth_methods = self.auth_methods.clone();
            let timeout = self.timeout.clone();
            tokio::spawn(async move {
                let mut client = SOCKClient::new(stream, users, auth_methods, timeout);
                match client.init().await {
                    Ok(_) => {}
                    Err(error) => {
                        error!("Error! {:?}, client: {:?}", error, client_addr);

                        if let Err(e) = SocksReply::new(error.into()).send(&mut client.stream).await
                        {
                            warn!("Failed to send error code: {:?}", e);
                        }

                        if let Err(e) = client.shutdown().await {
                            warn!("Failed to shutdown TcpStream: {:?}", e);
                        };
                    }
                };
            });
        }
    }
}

pub struct SOCKClient<T: AsyncRead + AsyncWrite + Send + Unpin + 'static> {
    stream: T,
    auth_nmethods: u8,
    auth_methods: Arc<Vec<u8>>,
    authed_users: Arc<Vec<User>>,
    socks_version: u8,
    timeout: Option<Duration>,
}

impl<T> SOCKClient<T>
where
    T: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    /// Create a new SOCKClient
    pub fn new(
        stream: T,
        authed_users: Arc<Vec<User>>,
        auth_methods: Arc<Vec<u8>>,
        timeout: Option<Duration>,
    ) -> Self {
        SOCKClient {
            stream,
            auth_nmethods: 0,
            socks_version: 0,
            authed_users,
            auth_methods,
            timeout,
        }
    }

    /// Create a new SOCKClient with no auth
    pub fn new_no_auth(stream: T, timeout: Option<Duration>) -> Self {
        // FIXME: use option here
        let authed_users: Arc<Vec<User>> = Arc::new(Vec::new());
        let mut no_auth: Vec<u8> = Vec::new();
        no_auth.push(AuthMethods::NoAuth as u8);
        let auth_methods: Arc<Vec<u8>> = Arc::new(no_auth);

        SOCKClient {
            stream,
            auth_nmethods: 0,
            socks_version: 0,
            authed_users,
            auth_methods,
            timeout,
        }
    }

    /// Mutable getter for inner stream
    pub fn stream_mut(&mut self) -> &mut T {
        &mut self.stream
    }

    /// Check if username + password pair are valid
    fn authed(&self, user: &User) -> bool {
        self.authed_users.contains(user)
    }

    /// Shutdown a client
    pub async fn shutdown(&mut self) -> io::Result<()> {
        self.stream.shutdown().await?;
        Ok(())
    }

    pub async fn init(&mut self) -> Result<(), MerinoError> {
        debug!("New connection");
        let mut header = [0u8; 2];
        // Read a byte from the stream and determine the version being requested
        self.stream.read_exact(&mut header).await?;

        self.socks_version = header[0];
        self.auth_nmethods = header[1];

        trace!(
            "Version: {} Auth nmethods: {}",
            self.socks_version,
            self.auth_nmethods
        );

        match self.socks_version {
            SOCKS_VERSION => {
                // Authenticate w/ client
                self.auth().await?;
                // Handle requests
                self.handle_client().await?;
            }
            _ => {
                warn!("Init: Unsupported version: SOCKS{}", self.socks_version);
                self.shutdown().await?;
            }
        }

        Ok(())
    }

    async fn auth(&mut self) -> Result<(), MerinoError> {
        debug!("Authenticating");
        // Get valid auth methods
        let methods = self.get_avalible_methods().await?;
        trace!("methods: {:?}", methods);

        let mut response = [0u8; 2];

        // Set the version in the response
        response[0] = SOCKS_VERSION;

        if methods.contains(&(AuthMethods::UserPass as u8)) {
            // Set the default auth method (NO AUTH)
            response[1] = AuthMethods::UserPass as u8;

            debug!("Sending USER/PASS packet");
            self.stream.write_all(&response).await?;

            let mut header = [0u8; 2];

            // Read a byte from the stream and determine the version being requested
            self.stream.read_exact(&mut header).await?;

            // debug!("Auth Header: [{}, {}]", header[0], header[1]);

            // Username parsing
            let ulen = header[1] as usize;

            let mut username = vec![0; ulen];

            self.stream.read_exact(&mut username).await?;

            // Password Parsing
            let mut plen = [0u8; 1];
            self.stream.read_exact(&mut plen).await?;

            let mut password = vec![0; plen[0] as usize];
            self.stream.read_exact(&mut password).await?;

            let username = String::from_utf8_lossy(&username).to_string();
            let password = String::from_utf8_lossy(&password).to_string();

            let user = User { username, password };

            // Authenticate passwords
            if self.authed(&user) {
                debug!("Access Granted. User: {}", user.username);
                let response = [1, ResponseCode::Success as u8];
                self.stream.write_all(&response).await?;
            } else {
                debug!("Access Denied. User: {}", user.username);
                let response = [1, ResponseCode::Failure as u8];
                self.stream.write_all(&response).await?;

                // Shutdown
                self.shutdown().await?;
            }

            Ok(())
        } else if methods.contains(&(AuthMethods::NoAuth as u8)) {
            // set the default auth method (no auth)
            response[1] = AuthMethods::NoAuth as u8;
            debug!("Sending NOAUTH packet");
            self.stream.write_all(&response).await?;
            debug!("NOAUTH sent");
            Ok(())
        } else {
            warn!("Client has no suitable Auth methods!");
            response[1] = AuthMethods::NoMethods as u8;
            self.stream.write_all(&response).await?;
            self.shutdown().await?;

            Err(MerinoError::Socks(ResponseCode::Failure))
        }
    }

    /// Handles a client
    pub async fn handle_client(&mut self) -> Result<usize, MerinoError> {
        debug!("Starting to relay data");

        let req = SOCKSReq::from_stream(&mut self.stream).await?;

        if req.addr_type == AddrType::V6 {}

        // Log Request
        let displayed_addr = pretty_print_addr(&req.addr_type, &req.addr);
        info!(
            "New Request: Command: {:?} Addr: {}, Port: {}",
            req.command, displayed_addr, req.port
        );

        // Respond
        match req.command {
            // Use the Proxy to connect to the specified addr/port
            SockCommand::Connect => {
                debug!("Handling CONNECT Command");

                let sock_addr = addr_to_socket(&req.addr_type, &req.addr, req.port)?;

                trace!("Connecting to: {:?}", sock_addr);

                let time_out = if let Some(time_out) = self.timeout {
                    time_out
                } else {
                    Duration::from_millis(50)
                };

                let mut target =
                    timeout(
                        time_out,
                        async move { TcpStream::connect(&sock_addr[..]).await },
                    )
                    .await
                    .map_err(|_| MerinoError::Socks(ResponseCode::AddrTypeNotSupported))
                    .map_err(|_| MerinoError::Socks(ResponseCode::AddrTypeNotSupported))??;

                trace!("Connected!");

                SocksReply::new(ResponseCode::Success)
                    .send(&mut self.stream)
                    .await?;

                trace!("copy bidirectional");
                match tokio::io::copy_bidirectional(&mut self.stream, &mut target).await {
                    // ignore not connected for shutdown error
                    Err(e) if e.kind() == std::io::ErrorKind::NotConnected => {
                        trace!("already closed");
                        Ok(0)
                    }
                    Err(e) => Err(MerinoError::Io(e)),
                    Ok((_s_to_t, t_to_s)) => Ok(t_to_s as usize),
                }
            }
            SockCommand::Bind => Err(MerinoError::Io(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "Bind not supported",
            ))),
            SockCommand::UdpAssosiate => Err(MerinoError::Io(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "UdpAssosiate not supported",
            ))),
        }
    }

    /// Return the avalible methods based on `self.auth_nmethods`
    async fn get_avalible_methods(&mut self) -> io::Result<Vec<u8>> {
        let mut methods: Vec<u8> = Vec::with_capacity(self.auth_nmethods as usize);
        for _ in 0..self.auth_nmethods {
            let mut method = [0u8; 1];
            self.stream.read_exact(&mut method).await?;
            if self.auth_methods.contains(&method[0]) {
                methods.append(&mut method.to_vec());
            }
        }
        Ok(methods)
    }
}

/// Convert an address and AddrType to a SocketAddr
fn addr_to_socket(addr_type: &AddrType, addr: &[u8], port: u16) -> io::Result<Vec<SocketAddr>> {
    match addr_type {
        AddrType::V6 => {
            let new_addr = (0..8)
                .map(|x| {
                    trace!("{} and {}", x * 2, (x * 2) + 1);
                    (u16::from(addr[(x * 2)]) << 8) | u16::from(addr[(x * 2) + 1])
                })
                .collect::<Vec<u16>>();

            Ok(vec![SocketAddr::from(SocketAddrV6::new(
                Ipv6Addr::new(
                    new_addr[0],
                    new_addr[1],
                    new_addr[2],
                    new_addr[3],
                    new_addr[4],
                    new_addr[5],
                    new_addr[6],
                    new_addr[7],
                ),
                port,
                0,
                0,
            ))])
        }
        AddrType::V4 => Ok(vec![SocketAddr::from(SocketAddrV4::new(
            Ipv4Addr::new(addr[0], addr[1], addr[2], addr[3]),
            port,
        ))]),
        AddrType::Domain => {
            let mut domain = String::from_utf8_lossy(addr).to_string();
            domain.push_str(":");
            domain.push_str(&port.to_string());

            Ok(domain.to_socket_addrs()?.collect())
        }
    }
}

/// Convert an AddrType and address to String
fn pretty_print_addr(addr_type: &AddrType, addr: &[u8]) -> String {
    match addr_type {
        AddrType::Domain => String::from_utf8_lossy(addr).to_string(),
        AddrType::V4 => addr
            .iter()
            .map(std::string::ToString::to_string)
            .collect::<Vec<String>>()
            .join("."),
        AddrType::V6 => {
            let addr_16 = (0..8)
                .map(|x| (u16::from(addr[(x * 2)]) << 8) | u16::from(addr[(x * 2) + 1]))
                .collect::<Vec<u16>>();

            addr_16
                .iter()
                .map(|x| format!("{:x}", x))
                .collect::<Vec<String>>()
                .join(":")
        }
    }
}

/// Proxy User Request
#[allow(dead_code)]
struct SOCKSReq {
    pub version: u8,
    pub command: SockCommand,
    pub addr_type: AddrType,
    pub addr: Vec<u8>,
    pub port: u16,
}

impl SOCKSReq {
    /// Parse a SOCKS Req from a TcpStream
    async fn from_stream<T>(stream: &mut T) -> Result<Self, MerinoError>
    where
        T: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    {
        // From rfc 1928 (S4), the SOCKS request is formed as follows:
        //
        //    +----+-----+-------+------+----------+----------+
        //    |VER | CMD |  RSV  | ATYP | DST.ADDR | DST.PORT |
        //    +----+-----+-------+------+----------+----------+
        //    | 1  |  1  | X'00' |  1   | Variable |    2     |
        //    +----+-----+-------+------+----------+----------+
        //
        // Where:
        //
        //      o  VER    protocol version: X'05'
        //      o  CMD
        //         o  CONNECT X'01'
        //         o  BIND X'02'
        //         o  UDP ASSOCIATE X'03'
        //      o  RSV    RESERVED
        //      o  ATYP   address type of following address
        //         o  IP V4 address: X'01'
        //         o  DOMAINNAME: X'03'
        //         o  IP V6 address: X'04'
        //      o  DST.ADDR       desired destination address
        //      o  DST.PORT desired destination port in network octet
        //         order
        trace!("Server waiting for connect");
        let mut packet = [0u8; 4];
        // Read a byte from the stream and determine the version being requested
        stream.read_exact(&mut packet).await?;
        trace!("Server received {:?}", packet);

        if packet[0] != SOCKS_VERSION {
            warn!("from_stream Unsupported version: SOCKS{}", packet[0]);
            stream.shutdown().await?;
        }

        // Get command
        let command = match SockCommand::from(packet[1] as usize) {
            Some(com) => Ok(com),
            None => {
                warn!("Invalid Command");
                stream.shutdown().await?;
                Err(MerinoError::Socks(ResponseCode::CommandNotSupported))
            }
        }?;

        // DST.address

        let addr_type = match AddrType::from(packet[3] as usize) {
            Some(addr) => Ok(addr),
            None => {
                error!("No Addr");
                stream.shutdown().await?;
                Err(MerinoError::Socks(ResponseCode::AddrTypeNotSupported))
            }
        }?;

        trace!("Getting Addr");
        // Get Addr from addr_type and stream
        let addr: Vec<u8> = match addr_type {
            AddrType::Domain => {
                let mut dlen = [0u8; 1];
                stream.read_exact(&mut dlen).await?;
                let mut domain = vec![0u8; dlen[0] as usize];
                stream.read_exact(&mut domain).await?;
                domain
            }
            AddrType::V4 => {
                let mut addr = [0u8; 4];
                stream.read_exact(&mut addr).await?;
                addr.to_vec()
            }
            AddrType::V6 => {
                let mut addr = [0u8; 16];
                stream.read_exact(&mut addr).await?;
                addr.to_vec()
            }
        };

        // read DST.port
        let mut port = [0u8; 2];
        stream.read_exact(&mut port).await?;

        // Merge two u8s into u16
        let port = (u16::from(port[0]) << 8) | u16::from(port[1]);

        // Return parsed request
        Ok(SOCKSReq {
            version: packet[0],
            command,
            addr_type,
            addr,
            port,
        })
    }
}
