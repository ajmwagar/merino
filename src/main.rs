#[macro_use] extern crate log;
#[macro_use] extern crate structopt;

use structopt::StructOpt;
use merino::*;
use std::error::Error;
use std::env;

#[derive(StructOpt, Debug)]
#[structopt(name = "merino")]
struct Opt {
    /// Activate ssl mode
    #[structopt(long = "ssl")]
    ssl: bool,

    /// Set port to listen on
    #[structopt(short = "p", long = "port", default_value = "1080")]
    port: u16,
}

fn main() -> Result<(), Box<dyn Error>> {
    let opt = Opt::from_args();

    //Set the `RUST_LOG` var if none is provided
    if env::var("RUST_LOG").is_err() {
        env::set_var("RUST_LOG", "merino=INFO");
    }

    pretty_env_logger::init_timed();

    let mut merino = Merino::new()?;

    merino.serve()?;


    Ok(())
}
