use std::{collections::HashMap, sync::Arc};

use diglett::{
    wire::{self, Client, Connection, Control, Message, Registration, Stream},
    Result,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{
        tcp::{OwnedReadHalf, OwnedWriteHalf},
        TcpStream, ToSocketAddrs,
    },
    sync::Mutex,
    task::JoinHandle,
};

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

    println!("register ");
    client
        .control(Control::Register {
            id: Registration::from(1),
            name: "azmy".into(),
        })
        .await?;

    println!("{:?}", client.read().await?);
    client.control(Control::FinishRegister).await?;

    serve(("127.0.0.1", 9000), client).await?;

    Ok(())
}

type Connections = Arc<Mutex<HashMap<Stream, BackendClient>>>;

async fn serve<A: ToSocketAddrs>(backend: A, server: Connection<TcpStream>) -> Result<()> {
    let backend_connections: Connections = Arc::new(Mutex::new(HashMap::default()));

    let (mut server_reader, server_writer) = server.split();

    let server_writer = Arc::new(Mutex::new(server_writer));

    while let Ok(message) = server_reader.read().await {
        match message {
            Message::Payload { id, data } => {
                let mut connections = backend_connections.lock().await;
                let entry = connections.get_mut(&id);

                let client = match entry {
                    Some(client) => client,
                    None => {
                        // open connection and insert it!
                        let stream = match TcpStream::connect(&backend).await {
                            Ok(stream) => stream,
                            Err(err) => {
                                log::error!("failed to establish connection to backend: {}", err);
                                //TODO: we probably need to notify up stream that connection has been rejected
                                continue;
                            }
                        };

                        let (up, down) = stream.into_split();

                        let id_copy = id.clone();
                        let server_writer_copy = Arc::clone(&server_writer);
                        let backend_connections_copy = Arc::clone(&backend_connections);

                        let handler = tokio::spawn(async move {
                            // this starts copy upstream (so from backend connection to server)
                            if let Err(err) =
                                upstream(id_copy, up, Arc::clone(&server_writer_copy)).await
                            {
                                log::error!("failed to forward data upstream: {}", err);
                            }

                            let _ = server_writer_copy
                                .lock()
                                .await
                                .control(Control::Close { id: id_copy })
                                .await;

                            // send a close up stream
                            backend_connections_copy.lock().await.remove(&id_copy);
                        });

                        let client = BackendClient {
                            writer: down,
                            handler,
                        };

                        connections.insert(id, client);
                        connections.get_mut(&id).unwrap()
                    }
                };

                if let Err(err) = client.writer.write_all(&data).await {
                    // drop the connection.
                    log::error!("failed to write data to backend: {}", err);
                    server_writer
                        .lock()
                        .await
                        .control(Control::Close { id: id })
                        .await?;

                    backend_connections.lock().await.remove(&id);
                }
            }
            Message::Control(Control::Close { id }) => {
                backend_connections.lock().await.remove(&id);
            }
            unexpected => {
                log::debug!("received an unexpected message: {:?}", unexpected);
            }
        }
    }

    Ok(())
}

async fn upstream(
    id: Stream,
    mut reader: OwnedReadHalf,
    server_writer: Arc<Mutex<Connection<OwnedWriteHalf>>>,
) -> Result<()> {
    let mut buf: [u8; wire::MAX_PAYLOAD_SIZE] = [0; wire::MAX_PAYLOAD_SIZE];
    loop {
        let count = reader.read(&mut buf).await?;
        if count == 0 {
            return Ok(());
        }

        server_writer.lock().await.write(id, &buf[..count]).await?;
    }
}

struct BackendClient {
    writer: OwnedWriteHalf,
    handler: JoinHandle<()>,
}

impl Drop for BackendClient {
    fn drop(&mut self) {
        self.handler.abort()
    }
}
