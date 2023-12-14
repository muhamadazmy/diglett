use std::{collections::HashMap, sync::Arc};

use crate::{
    wire::{self, Connection, Control, Message, Registration, Stream},
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

pub async fn login<S: Into<String>>(client: &mut Connection<TcpStream>, token: S) -> Result<()> {
    // we only expose the possibility to register one name, but this can easily changed
    // in the future to enable more. but right now we can forward one port per agent

    client.control(Control::Login(token.into())).await?;
    client.read().await?.ok_or_err()
}

pub async fn register<S: Into<String>>(client: &mut Connection<TcpStream>, name: S) -> Result<()> {
    // we only expose the possibility to register one name, but this can easily changed
    // in the future to enable more. but right now we can forward one port per agent

    register_one(client, Registration::from(0), name).await?;
    client.control(Control::FinishRegister).await
}

async fn register_one<S: Into<String>>(
    client: &mut Connection<TcpStream>,
    id: Registration,
    name: S,
) -> Result<()> {
    client
        .control(Control::Register {
            id,
            name: name.into(),
        })
        .await?;

    // wait ok or error
    client.read().await?.ok_or_err()
}

type Connections = Arc<Mutex<HashMap<Stream, BackendClient>>>;

pub async fn serve<A: ToSocketAddrs>(backend: A, server: Connection<TcpStream>) -> Result<()> {
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
                                // tell server that connection has been rejected
                                server_writer
                                    .lock()
                                    .await
                                    .control(Control::Close { id: id })
                                    .await?;

                                continue;
                            }
                        };

                        let (up, down) = stream.into_split();

                        let handler = make_upstream(
                            id,
                            up,
                            Arc::clone(&server_writer),
                            Arc::clone(&backend_connections),
                        );

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
                        .control(Control::Close { id })
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

fn make_upstream(
    id: Stream,
    up: OwnedReadHalf,
    server_writer: Arc<Mutex<Connection<OwnedWriteHalf>>>,
    connections: Connections,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        // this starts copy upstream (so from backend connection to server)
        if let Err(err) = upstream(id, up, Arc::clone(&server_writer)).await {
            log::error!("failed to forward data upstream: {}", err);
        }

        let _ = server_writer
            .lock()
            .await
            .control(Control::Close { id })
            .await;

        // send a close up stream
        connections.lock().await.remove(&id);
    })
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
