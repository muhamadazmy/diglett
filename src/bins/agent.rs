use std::time::Duration;

use diglett::{
    wire::{Client, Control, Message, Registration},
    Result,
};
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

    println!("handshake completed");

    println!("register 1");
    client
        .control(Control::Register {
            id: Registration::from(1),
            name: "azmy".into(),
        })
        .await?;

    println!("reading okay");
    println!("{:?}", client.read().await?);
    client
        .control(Control::Register {
            id: Registration::from(2),
            name: "awad".into(),
        })
        .await?;

    println!("{:?}", client.read().await?);
    client.control(Control::FinishRegister).await?;

    while let Ok(message) = client.read().await {
        match message {
            Message::Payload { id, data } => {
                log::debug!("received message {}: {:?}", id, data);
            }
            unexpected => {
                log::debug!("received an unexpected message: {:?}", unexpected);
            }
        }
    }
    Ok(())
}
