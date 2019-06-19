#[macro_use] extern crate log;

use std::error::Error;
use std::net::{TcpStream, TcpListener, UdpSocket, SocketAddr};
use std::{thread};


/// Default port of `SOCKS5` Protocool
const SOCKS5_PORT: u8 = 1080;

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
    NoAuth,
    GssApi,
    /// Authenticate with a username / password
    UserPass
}

struct Wool {
    clients: Vec<Box<Sock>>
}
