use crate::{
    wire::{self, Control, Message},
    Result,
};
use tokio::net::{TcpListener, TcpStream, ToSocketAddrs};

pub struct Server {}

impl Server {
    pub fn new() -> Self {
        Self {}
    }

    pub async fn start<A: ToSocketAddrs>(self, addr: A) -> Result<()> {
        let listener = TcpListener::bind(addr).await?;

        while let Ok((socket, _)) = listener.accept().await {
            // serve one agent
            tokio::spawn(async move {
                if let Err(err) = handle(socket).await {
                    log::warn!("failed to handle agent connection: {}", err);
                }
            });
        }

        Ok(())
    }
}

async fn handle(stream: TcpStream) -> Result<()> {
    let server = wire::Server::new(stream);
    // upgrade connection
    // this step accept client negotiation (if correct)
    // and then use the connection to forward traffic from now on
    let mut connection = server.accept().await?;

    let mut registrations = vec![];
    while let Ok(message) = connection.receive().await {
        match message {
            Message::Control(Control::Register { id, name }) => {
                registrations.push((id, name));
                connection.control(Control::Ok).await?;
            }
            Message::Control(Control::FinishRegister) => break,
            _ => {
                // got an unexpected control message
                return Err(crate::Error::UnexpectedMessageKind);
            }
        }
    }

    println!("{:?}", registrations);

    Ok(())
}
