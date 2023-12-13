use std::{collections::HashMap, sync::Arc};

use crate::{
    wire::{self, Connection, Control, Message, Stream},
    Result,
};
use tokio::net::{
    tcp::{OwnedReadHalf, OwnedWriteHalf},
    TcpListener, TcpStream, ToSocketAddrs,
};
use tokio::sync::Mutex;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    task::JoinHandle,
};

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
                if let Err(err) = handle_agent(socket).await {
                    println!("failed to handle agent connection: {}", err);
                }
            });
        }

        Ok(())
    }
}

async fn handle_agent(stream: TcpStream) -> Result<()> {
    let server = wire::Server::new(stream);
    // upgrade connection
    // this step accept client negotiation (if correct)
    // and then use the connection to forward traffic from now on
    let mut connection = server.accept().await?;

    // todo: receive authentication token!

    let mut registrations = vec![];
    while let Ok(message) = connection.read().await {
        match message {
            Message::Control(Control::Register { id, name }) => {
                log::debug!("registered: {}: [{}]", id, name);
                registrations.push((id, name));
                connection.control(Control::Ok).await?;
            }
            Message::Control(Control::FinishRegister) => break,
            all => {
                // got an unexpected control message
                println!("unexpected {:?}", all);
                return Err(crate::Error::UnexpectedMessageKind);
            }
        }
    }

    let (agent_reader, agent_writer) = connection.split();

    let agent_writer: AgentWriter = Arc::new(Mutex::new(agent_writer));
    // up map is a map of streams and their write halfs
    // it's used to write data sent from the agent up
    let clients: Clients = Arc::new(Mutex::new(HashMap::default()));

    // start a process that forward all messages received from the agent to their corresponding
    // up streams
    let mut exited = upstream(Arc::clone(&clients), agent_reader).await;

    // assume one registration
    let bind = TcpListener::bind(("127.0.0.1", 0)).await?;

    log::debug!("accepting agent connections over: {:?}", bind.local_addr());
    let registration = &registrations[0];
    println!("{:?}", registrations);

    loop {
        tokio::select! {
            _ = exited.recv() => {
                log::debug!("agent disconnected");
                break;
            }
            accepted = bind.accept() => {
                let (incoming, addr) = match accepted {
                    Ok(accepted) => accepted,
                    Err(err) => {
                        log::error!("error accepting new connections: {}", err);
                        break;
                    }
                };

                let stream_id = Stream::new(registration.0, addr.port());
                let (down, up) = incoming.into_split();

                let agent_writer = Arc::clone(&agent_writer);

                // this will be used to clean up the client connection if the client disconnected!
                let clients_drop = Arc::clone(&clients);

                // before we spawn the downstream, we will acquire the lock first
                // so the upstram does not proceed until we insert this client in the map
                let mut clients = clients.lock().await;

                let handler = tokio::spawn(async move {
                    if let Err(err) = downstream(stream_id, down, agent_writer).await {
                        log::debug!("failed to process down traffic: {}", err);
                    }
                    // also clean up the client connection completely!
                    clients_drop.lock().await.remove(&stream_id);
                });

                clients.insert(
                    stream_id,
                    Client {
                        write: up,
                        handler: handler,
                    },
                );
            }
        };
    }

    log::debug!("todo: clean up");

    Ok(())
}

type AgentWriter = Arc<Mutex<Connection<OwnedWriteHalf>>>;
type Clients = Arc<Mutex<HashMap<Stream, Client>>>;

struct Client {
    handler: JoinHandle<()>,
    write: OwnedWriteHalf,
}

impl Drop for Client {
    fn drop(&mut self) {
        self.handler.abort();
    }
}
// upstream de multiplex incoming traffic from the agent to the clients
// that are connected locally
async fn upstream(
    streams: Clients,
    mut reader: Connection<OwnedReadHalf>,
) -> tokio::sync::mpsc::Receiver<()> {
    let (close, notify) = tokio::sync::mpsc::channel::<()>(1);

    tokio::spawn(async move {
        while let Ok(message) = reader.read().await {
            match message {
                Message::Terminate => return,
                Message::Payload { id, data } => {
                    let mut streams = streams.lock().await;
                    if let Some(client) = streams.get_mut(&id) {
                        // received a message for a stream
                        if let Err(err) = client.write.write_all(&data).await {
                            log::error!("failed to forward traffic up: {}", err);
                            // the socket is probably dead, we probably should drop from map
                            streams.remove(&id);
                        }
                    }
                }
                Message::Control(Control::Close { id }) => {
                    streams.lock().await.remove(&id);
                }
                msg => {
                    log::debug!("received unexpected message: {:?}", msg);
                }
            }
        }

        drop(close);
    });

    notify
}

async fn downstream(id: Stream, mut down: OwnedReadHalf, writer: AgentWriter) -> Result<()> {
    let mut buf: [u8; wire::MAX_PAYLOAD_SIZE] = [0; wire::MAX_PAYLOAD_SIZE];

    loop {
        let n = down.read(&mut buf).await?;
        if n == 0 {
            // hit end of connection. I have to disconnect!
            return Ok(());
        }

        writer.lock().await.write(id, &buf[..n]).await?;
    }
}
