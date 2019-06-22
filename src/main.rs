// #[macro_use] extern crate log;
// #[macro_use] extern crate structopt;

use structopt::StructOpt;
use merino::*;
use std::error::Error;
use std::env;

const LOGO: &str = r"
                      _
  _ __ ___   ___ _ __(_)_ __   ___
 | '_ ` _ \ / _ \ '__| | '_ \ / _ \
 | | | | | |  __/ |  | | | | | (_) |
 |_| |_| |_|\___|_|  |_|_| |_|\___/

 A SOCKS5 Proxy server written in Rust
";

#[derive(StructOpt, Debug)]
#[structopt(name = "merino")]
/// A SOCKS5 Proxy written in Rust
struct Opt {
    #[structopt(short = "p", long = "port", default_value = "1080")]
    /// Set port to listen on
    port: u16
}

fn main() -> Result<(), Box<dyn Error>> {
    println!("{}", LOGO);

    let opt = Opt::from_args();

    //Set the `RUST_LOG` var if none is provided
    if env::var("RUST_LOG").is_err() {
        env::set_var("RUST_LOG", "merino=INFO");
    }

    pretty_env_logger::init_timed();
    
    let mut merino = Merino::new(opt.port)?;

    merino.serve()?;

    Ok(())
}
