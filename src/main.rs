#[macro_use] extern crate log;

#[derive(StructOpt, Debug)]
#[structopt(name = "wool")]
struct Opt {
    /// Activate ssl mode
    #[structopt(long = "ssl")]
    ssl: bool,

    /// Set port to listen on
    #[structopt(short = "p", long = "port", default_value = "1080")]
    port: u16,
}

fn main() {
    let opt = Opt::from_args();

    //Set the `RUST_LOG` var if none is provided
    if env::var("RUST_LOG").is_err() {
        env::set_var("RUST_LOG", "wool=INFO");
    }

    pretty_env_logger::init_timed();

    info!("Hello, World!");
}
