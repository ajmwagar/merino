#![forbid(unsafe_code)]
#![cfg_attr(not(debug_assertions), deny(warnings))]
#![warn(clippy::all, rust_2018_idioms)]
#[macro_use]
extern crate log;

use clap::{ArgGroup, Parser};
use merino::*;
use std::env;
use std::error::Error;
use std::os::unix::prelude::MetadataExt;
use std::path::PathBuf;

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
), group(
    ArgGroup::new("log")
        .args(&["verbosity", "quiet"]),
))]
struct Opt {
    #[clap(short, long, default_value_t = 1080)]
    /// Set port to listen on
    port: u16,

    #[clap(short, long, default_value = "127.0.0.1")]
    /// Set ip to listen on
    ip: String,

    #[clap(long)]
    /// Allow insecure configuration
    allow_insecure: bool,

    #[clap(long)]
    /// Allow unauthenticated connections
    no_auth: bool,

    #[clap(short, long)]
    /// CSV File with username/password pairs
    users: Option<PathBuf>,

    /// Log verbosity level. -vv for more verbosity.
    /// Environmental variable `RUST_LOG` overrides this flag!
    #[clap(short, parse(from_occurrences))]
    verbosity: u8,

    /// Do not output any logs (even errors!). Overrides `RUST_LOG`
    #[clap(short)]
    quiet: bool,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    println!("{}", LOGO);

    let opt = Opt::parse();

    // Setup logging
    let log_env = env::var("RUST_LOG");
    if log_env.is_err() {
        let level = match opt.verbosity {
            1 => "merino=DEBUG",
            2 => "merino=TRACE",
            _ => "merino=INFO",
        };
        env::set_var("RUST_LOG", level);
    }

    if !opt.quiet {
        pretty_env_logger::init_timed();
    }

    if log_env.is_ok() && (opt.verbosity != 0) {
        warn!(
            "Log level is overriden by environmental variable to `{}`",
            // It's safe to unwrap() because we checked for is_ok() before
            log_env.unwrap().as_str()
        );
    }

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
            let file = std::fs::File::open(&users_file).unwrap_or_else(|e| {
                error!("Can't open file {:?}: {}", &users_file, e);
                std::process::exit(1);
            });

            let metadata = file.metadata()?;
            // 7 is (S_IROTH | S_IWOTH | S_IXOTH) or the "permisions for others" in unix
            if (metadata.mode() & 7) > 0 && !opt.allow_insecure {
                error!(
                    "Permissions {:o} for {:?} are too open. \
                    It is recommended that your users file is NOT accessible by others. \
                    To override this check, set --allow-insecure",
                    metadata.mode() & 0o777,
                    &users_file
                );
                std::process::exit(1);
            }

            let mut users: Vec<User> = Vec::new();

            let mut rdr = csv::Reader::from_reader(file);
            for result in rdr.deserialize() {
                let record: User = match result {
                    Ok(r) => r,
                    Err(e) => {
                        error!("{}", e);
                        std::process::exit(1);
                    }
                };

                trace!("Loaded user: {}", record.username);
                users.push(record);
            }

            if users.is_empty() {
                error!(
                    "No users loaded from {:?}. Check configuration.",
                    &users_file
                );
                std::process::exit(1);
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
