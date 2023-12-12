use diglett::{
    wire::{Client, Control},
    Result,
};
use tokio::net::TcpStream;

#[tokio::main]
async fn main() -> Result<()> {
    let connection = TcpStream::connect(("127.0.0.1", 20000)).await?;
    let client = Client::new(connection);

    let mut client = client.negotiate().await?;

    println!("handshake completed");

    println!("register 1");
    client
        .control(Control::Register {
            id: 1,
            name: "azmy".into(),
        })
        .await?;

    println!("reading okay");
    println!("{:?}", client.read().await?);
    client
        .control(Control::Register {
            id: 2,
            name: "awad".into(),
        })
        .await?;

    println!("{:?}", client.read().await?);
    client.control(Control::FinishRegister).await?;

    Ok(())
}
