use clap::{ArgAction, Parser};
use diglett::{server::Server, Result};

/// diglett gateway agent
#[derive(Parser, Debug)]
#[command(author, version = env!("GIT_VERSION"), about, long_about = None)]
struct Args {
    #[arg(short, long, default_value_t = String::from("0.0.0.0:20000"))]
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
    let server = Server::default();

    server.start(args.listen).await
}
