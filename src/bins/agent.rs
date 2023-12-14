use diglett::{agent, wire::Client, Result};
use tokio::net::TcpStream;

#[tokio::main]
async fn main() -> Result<()> {
    simple_logger::SimpleLogger::default()
        .with_level(log::LevelFilter::Debug)
        .with_utc_timestamps()
        .init()
        .unwrap();

    let connection = TcpStream::connect(("127.0.0.1", 20000)).await?;
    let client = Client::new(connection);

    let mut client = client.negotiate().await?;

    agent::register(&mut client, "azmy").await?;
    agent::serve(("127.0.0.1", 9000), client).await?;

    Ok(())
}
