use clap::{ArgAction, Parser};
use diglett::{
    server::{AuthorizeAll, PrintRegisterer, Server},
    wire::keypair,
    Result,
};

/// diglett gateway agent
#[derive(Parser, Debug)]
#[command(author, version = env!("GIT_VERSION"), about, long_about = None)]
struct Args {
    #[arg(short, long, default_value = "0.0.0.0:20000")]
    listen: String,

    /// enable debugging logs
    #[arg(short, long, action=ArgAction::Count)]
    debug: u8,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    simple_logger::SimpleLogger::default()
        .with_level(match args.debug {
            0 => log::LevelFilter::Info,
            1 => log::LevelFilter::Debug,
            _ => log::LevelFilter::Trace,
        })
        .with_utc_timestamps()
        .init()
        .unwrap();

    if let Err(err) = app(args).await {
        eprintln!("{}", err);
        std::process::exit(1);
    }

    Ok(())
}

async fn app(args: Args) -> Result<()> {
    let kp = keypair();
    let server = Server::new(kp, AuthorizeAll, PrintRegisterer);

    server.start(args.listen).await
}
