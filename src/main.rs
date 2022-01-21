#![forbid(unsafe_code)]
#[macro_use]
extern crate log;

use merino::*;
use std::env;
use std::error::Error;
use std::path::PathBuf;
use clap::{ArgGroup, Parser};

/// Logo to be printed at when merino is run
const LOGO: &str = r"
                      _
  _ __ ___   ___ _ __(_)_ __   ___
 | '_ ` _ \ / _ \ '__| | '_ \ / _ \
 | | | | | |  __/ |  | | | | | (_) |
 |_| |_| |_|\___|_|  |_|_| |_|\___/

 A SOCKS5 Proxy server written in Rust
";

#[derive(Parser, Debug)]
#[clap(version)]
#[clap(group(
    ArgGroup::new("auth")
        .required(true)
        .args(&["no-auth", "users"]),
))]
struct Opt {
    #[clap(short, long, default_value_t = 1080)]
    /// Set port to listen on
    port: u16,

    #[clap(short, long, default_value = "127.0.0.1")]
    /// Set ip to listen on
    ip: String,

    #[clap(long)]
    /// Allow unauthenticated connections
    no_auth: bool,

    #[clap(short, long)]
    /// CSV File with username/password pairs
    users: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    println!("{}", LOGO);

    let opt = Opt::parse();

    // Setup logging

    //Set the `RUST_LOG` var if none is provided
    if env::var("RUST_LOG").is_err() {
        env::set_var("RUST_LOG", "merino=INFO");
    }

    pretty_env_logger::init_timed();

    // Setup Proxy settings

    let mut auth_methods: Vec<u8> = Vec::new();

    // Allow unauthenticated connections
    if opt.no_auth {
        auth_methods.push(merino::AuthMethods::NoAuth as u8);
    }

    // Enable username/password auth
    let authed_users: Result<Vec<User>, Box<dyn Error>> = match opt.users {
        Some(users_file) => {
            auth_methods.push(AuthMethods::UserPass as u8);
            let file = std::fs::File::open(users_file)?;

            let mut users: Vec<User> = Vec::new();

            let mut rdr = csv::Reader::from_reader(file);
            for result in rdr.deserialize() {
                let record: User = result?;

                trace!("Loaded user: {}", record.username);
                users.push(record);
            }

            Ok(users)
        }
        _ => Ok(Vec::new()),
    };

    let authed_users = authed_users?;

    // Create proxy server
    let mut merino = Merino::new(opt.port, &opt.ip, auth_methods, authed_users, None).await?;

    // Start Proxies
    merino.serve().await;

    Ok(())
}
