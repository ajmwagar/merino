#[macro_use] extern crate log;
use snafu::{Snafu};

use std::io::prelude::*;
use std::io::copy;
use std::error::Error;
use std::net::{Shutdown, TcpStream, TcpListener, SocketAddr, SocketAddrV4, SocketAddrV6, Ipv4Addr, Ipv6Addr};
use std::{thread};


/// Version of socks
const SOCKS_VERSION: u8 = 0x05;

const RESERVED: u8 = 0x00;

/// Default port of `SOCKS5` Protocool
const SOCKS5_PORT: u16 = 1080;

/// Default port of `SOCKS5` Protocool
const SOCKS5_IP: &str = "127.0.0.1";

// pub enum MerinoError {
//     Io(Box<dyn Error>),
//     Generic(String)
// }

#[derive(Debug, Snafu)]
/// Possible SOCKS5 Response Codes
enum ResponseCode {
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
    AddrTypeNotSupported = 0x08
}

/// DST.addr variant types
#[derive(PartialEq)]
enum AddrType {
    V4 = 0x01,
    Domain = 0x03,
    V6 = 0x04,
}

impl AddrType {
    /// Parse Byte to Command
    fn from(n: usize) -> Option<AddrType> {
        match n {
            1 => Some(AddrType::V4),
            3 => Some(AddrType::Domain),
            4 => Some(AddrType::V6),
            _ => None
        }
    }

    /// Return the size of the AddrType
    fn size(&self) -> u8 {
        match self {
            AddrType::V4 => 4,
            AddrType::Domain => 1,
            AddrType::V6 => 16
        }
    }
}

/// SOCK5 CMD Type
#[derive(Debug)]
enum SockCommand {
    Connect = 0x01,
    Bind = 0x02,
    UdpAssosiate = 0x3
}

impl SockCommand {
    /// Parse Byte to Command
    fn from(n: usize) -> Option<SockCommand> {
        match n {
            1 => Some(SockCommand::Connect),
            2 => Some(SockCommand::Bind),
            3 => Some(SockCommand::UdpAssosiate),
            _ => None
        }
    }
}


/// State of a given connection
enum State {
    Connected,
    Verifying,
    Ready,
    Proxy
}

/// Client Authentication Methods
enum AuthMethods {
    /// No Authentication
    NoAuth = 0x00,
    GssApi = 0x01,
    /// Authenticate with a username / password
    UserPass = 0x02,
    /// Cannot authenticate
    NoMethods = 0xFF
}

pub struct Merino {
    listener: TcpListener,
}

impl Merino {
    /// Create a new Merino instance
    pub fn new(port: u16) -> Result<Self, Box<dyn Error>> {
        info!("Listening on {}:{}", SOCKS5_IP, port);
        Ok(Merino {
            listener: TcpListener::bind(format!("{}:{}", SOCKS5_IP, port))?
        })
    }

    pub fn serve(&mut self) -> Result<(), Box<dyn Error>> {
        info!("Serving Connections...");
        loop {
            match self.listener.accept() {
                Ok((stream, _remote)) => {
                    let mut client = SOCKClient::new(stream);
                    thread::spawn(move || {
                        match client.init() {
                            Ok(_) => {},
                            Err(error) => error!("Error! {}", error)
                        };
                    });
                },
                _ => {}

            }
        }
    }
}

struct SOCKClient {
    stream: TcpStream,
    auth_nmethods: u8,
    socks_version: u8
}

impl SOCKClient {
    /// Create a new SOCKClient
    pub fn new(stream: TcpStream) -> Self {
        SOCKClient {
            stream,
            auth_nmethods: 0,
            socks_version: 0
        }
    }

    fn init(&mut self) -> Result<(), Box<dyn Error>> {
        debug!("New connection from: {}", self.stream.peer_addr()?.ip());
        let mut header = [0u8; 2];
        // Read a byte from the stream and determine the version being requested
        self.stream.read_exact(&mut header)?;

        self.socks_version = header[0];
        self.auth_nmethods = header[1];

        debug!("Version: {} Auth nmethods: {}", self.socks_version, self.auth_nmethods);

        // Handle SOCKS4 requests
        if header[0] != SOCKS_VERSION {
            warn!("Init: Unsupported version: SOCKS{}", self.socks_version);
            self.stream.shutdown(Shutdown::Both);
        }
        // Valid SOCKS5
        else {
            // Authenticate w/ client
            self.auth()?;
            // Handle requests
            self.handle_client()?;
        }

        Ok(())
    }

    fn auth(&mut self) -> Result<(), Box<dyn Error>> {
        debug!("Authenticating w/ {}", self.stream.peer_addr()?.ip());
        // Get valid auth methods
        let mut methods = self.get_avalible_methods();
        debug!("methods: {:?}", methods);

        let mut response = [0u8; 2];

        // Set the version in the response
        response[0] = SOCKS_VERSION;
        if methods.contains(&(AuthMethods::UserPass as u8)) {
            // Set the default auth method (NO AUTH)
            response[1] = AuthMethods::UserPass as u8;

            debug!("Sending USER/PASS packet");
            self.stream.write(&response)?;

            let mut header = [0u8; 2];

            // Read a byte from the stream and determine the version being requested
            self.stream.read_exact(&mut header)?;

            // Username parsing
            let ulen = header[1];
            let mut username = Vec::with_capacity(ulen as usize);
            self.stream.read_exact(&mut username)?;

            // Password Parsing
            let mut plen = [0u8; 1];
            self.stream.read_exact(&mut plen)?;
            let mut password = Vec::with_capacity(plen[0] as usize);
            self.stream.read_exact(&mut password)?;

            // Auth response
            let mut response = [0u8; 2];

            response[0] = SOCKS_VERSION;

            // TODO Add authentication
            response[1] = ResponseCode::Success as u8;

            self.stream.write(&response)?;

        }
        else if methods.contains(&(AuthMethods::NoAuth as u8)) {
            // set the default auth method (no auth)
            response[1] = AuthMethods::NoAuth as u8;
            debug!("Sending NOAUTH packet");
            self.stream.write(&response)?;
        }
        else {
            warn!("No Suitable Auth method: {:?}", methods);
            self.stream.shutdown(Shutdown::Both);
        }


        Ok(())
    }

    /// Handles a client
    pub fn handle_client(&mut self) -> Result<(), Box<dyn Error>> {
        debug!("Handling requests for {}", self.stream.peer_addr()?.ip());
        // Read request
        // loop {
            // Parse Request
            let req = SOCKSReq::from_stream(&mut self.stream)?;
            
            if req.addr_type == AddrType::V6 {
            }

            // Log Request
            let displayed_addr = pretty_print_addr(&req.addr_type, &req.addr);
            info!("New Request: Source: {}, Command: {:?} Addr: {}, Port: {}", 
                  self.stream.peer_addr()?.ip(),
                  req.command, 
                  displayed_addr,
                  req.port
            );


            // Respond
            match req.command {
                // Use the Proxy to connect to the specified addr/port
                SockCommand::Connect => {
                    debug!("Handling CONNECT Command");

                    let sock_addr = addr_to_socket(&req.addr_type, &req.addr, req.port);

                    debug!("Connecting to: {:?}", sock_addr);

                    let target = TcpStream::connect(sock_addr)?;

                    debug!("Connected!");

                     // let local = target.local_addr()?;

                     // let mut response = Vec::with_capacity(7);

                     // response.push(SOCKS_VERSION); // Version
                     // response.push(ResponseCode::Success as u8); // Reply TODO: Error handling
                     // response.push(RESERVED); // Reserved

                     // // Push IP
                     // if local.is_ipv4() {
                     //     response.push(AddrType::V4 as u8);
                     //     let mut ip = format!("{}", local.ip()).split(".").into_iter().map(|x| x.parse::<u8>().unwrap()).collect::<Vec<u8>>();
                     //     response.append(&mut ip);
                     // }
                     // else if local.is_ipv6() {
                     //     response.push(AddrType::V6 as u8);

                     //     let ip = format!("{}", local.ip()).split(":").into_iter().map(|x| x.parse::<u16>().unwrap()).collect::<Vec<u16>>();

                     //     for i in (0..(ip.len() /2)) {
                     //         response.append(&mut u16_to_u8(ip[i]));
                     //     }
                     // }
                    

                     // response.append(&mut u16_to_u8(req.port));

                     // debug!("Sending response: {:?}", response);

                     // self.stream.write(&response);

                    self.stream.write(&[SOCKS_VERSION, ResponseCode::Success as u8, RESERVED, 1, 127, 0, 0, 1, 0, 0]).unwrap();

                    // Copy it all
                    let mut outbound_in = target.try_clone()?;
                    let mut outbound_out = target.try_clone()?;
                    let mut inbound_in = self.stream.try_clone()?;
                    let mut inbound_out = self.stream.try_clone()?;

                    thread::spawn(move || {
                        copy(&mut inbound_in, &mut outbound_out);
                        inbound_in.shutdown(Shutdown::Read);
                        outbound_out.shutdown(Shutdown::Write);
                    });
                    thread::spawn(move || {
                        copy(&mut outbound_in, &mut inbound_out);
                        outbound_in.shutdown(Shutdown::Read);
                        inbound_out.shutdown(Shutdown::Write);
                    });


                },
                SockCommand::Bind => { },
                SockCommand::UdpAssosiate => { },
            }




            // connected = false;
        // }

        Ok(())
    }

    /// Return the avalible methods based on `self.auth_nmethods`
    fn get_avalible_methods(&mut self) -> Vec<u8> {
        let mut methods: Vec<u8> = Vec::with_capacity(self.auth_nmethods as usize);
        for _ in 0..self.auth_nmethods {
            let mut method = [0u8; 1];
            self.stream.read_exact(&mut method);
            methods.append(&mut method.to_vec());
        }
        methods
    }
}

/// Convert an address and AddrType to a SocketAddr
fn addr_to_socket(addr_type: &AddrType, addr: &Vec<u8>, port: u16) -> SocketAddr {
    match addr_type {
        AddrType::V6 => {
            let new_addr = (0..8).into_iter().map(|x| {
                trace!("{} and {}", x * 2, (x * 2) + 1);
                ((addr[(x * 2)] as u16) << 8) | addr[(x * 2) + 1] as u16
            }).collect::<Vec<u16>>();


            SocketAddr::from(
                SocketAddrV6::new(
                    Ipv6Addr::new(
                        new_addr[0], new_addr[1], new_addr[2], new_addr[3], new_addr[4], new_addr[5], new_addr[6], new_addr[7]), 
                    port, 0, 0)
            )
        },
        AddrType::V4 => {
            SocketAddr::from(SocketAddrV4::new(Ipv4Addr::new(addr[0], addr[1], addr[2], addr[3]), port))
        },
        AddrType::Domain => {
            let mut domain = String::from_utf8_lossy(&addr[..]).to_string();
            domain.push_str(&":");
            domain.push_str(&port.to_string());

            domain.parse::<SocketAddr>().unwrap()
        }

    }
}


/// Convert an AddrType and address to String
fn pretty_print_addr(addr_type: &AddrType, addr: &Vec<u8>) -> String {
    match addr_type {
        AddrType::Domain => {
            String::from_utf8_lossy(addr).to_string()
        },
        AddrType::V4 => {
            addr.iter().map(|x| x.to_string()).collect::<Vec<String>>().join(".")
        },
        AddrType::V6 => {
            let addr_16 = (0..8).into_iter().map(|x| {
                ((addr[(x * 2)] as u16) << 8) | addr[(x * 2) + 1] as u16
            }).collect::<Vec<u16>>();

            addr_16.iter().map(|x| format!("{:x}", x)).collect::<Vec<String>>().join(":")
        }
    }
}

/// Proxy User Request
struct SOCKSReq {
    pub version: u8,
    pub command: SockCommand,
    pub addr_type: AddrType,
    pub addr: Vec<u8>,
    pub port: u16
}

impl SOCKSReq {
    /// Parse a SOCKS Req from a TcpStream
    fn from_stream(stream: &mut TcpStream) -> Result<Self, Box<dyn Error>> {
        let mut packet = [0u8; 4];
        // Read a byte from the stream and determine the version being requested
        stream.read_exact(&mut packet)?;

        if packet[0] != SOCKS_VERSION {
            warn!("from_stream Unsupported version: SOCKS{}", packet[0]);
            stream.shutdown(Shutdown::Both)?;

        }

        // Get command
        let mut command: SockCommand = SockCommand::Connect;
        match SockCommand::from(packet[1] as usize) {
            Some(com) => {
                command = com;
                Ok(())
            },
            None => {
                warn!("Invalid Command");
                stream.shutdown(Shutdown::Both)?;
                Err(ResponseCode::CommandNotSupported)
            }
        }?;

        // DST.address

        let mut addr_type: AddrType = AddrType::V6;
        match AddrType::from(packet[3] as usize) {
            Some(addr) => {
                addr_type = addr ;
                Ok(())
            },
            None => {
                error!("No Addr");
                stream.shutdown(Shutdown::Both)?;
                Err(ResponseCode::AddrTypeNotSupported)
            }
        }?;

        debug!("Getting Addr");
        // Get Addr from addr_type and stream
        let addr = match addr_type {
            AddrType::Domain => {
                let mut dlen = [0u8; 1];
                stream.read(&mut dlen).unwrap();

                let mut domain = Vec::with_capacity(dlen[0] as usize);
                stream.read_exact(&mut domain).unwrap();

                domain
            },
            AddrType::V4 => {
                let mut addr = [0u8; 4];
                stream.read_exact(&mut addr);
                addr.to_vec()
            },
            AddrType::V6 => {
                let mut addr = [0u8; 16];
                stream.read_exact(&mut addr);
                addr.to_vec()
            }
        };

        // read DST.port
        let mut port = [0u8; 2];
        stream.read_exact(&mut port);

        // Merge two u8s into u16
        let port = ((port[0] as u16) << 8) | port[1] as u16;


        // Return parsed request
        Ok(SOCKSReq {
            version: packet[0],
            command,
            addr_type,
            addr,
            port
        })

    }
}

// fn u16_to_u8(n: u16) -> Vec<u8> {
//  let mut vec = n.to_be_bytes().to_vec();
//  vec.reverse();
//  vec
// }
