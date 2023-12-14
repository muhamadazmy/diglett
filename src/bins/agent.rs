use clap::{ArgAction, Parser};
use diglett::{agent, wire::Client, Result};
use tokio::net::TcpStream;

/// diglett gateway agent
#[derive(Parser, Debug)]
#[command(author, version = env!("GIT_VERSION"), about, long_about = None)]
struct Args {
    #[arg(short, long)]
    gateway: String,

    /// name to register with the gateway
    #[arg(short, long)]
    name: String,

    /// authentication token as defined by the server
    #[arg(short, long)]
    token: Option<String>,

    /// enable debugging logs
    #[arg(short, long, action=ArgAction::Count)]
    debug: u8,

    backend: String,
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
    let connection = TcpStream::connect(args.gateway).await?;
    let client = Client::new(connection);

    let mut client = client.negotiate().await?;

    agent::register(&mut client, args.name).await?;
    agent::serve(args.backend, client).await?;

    Ok(())
}
