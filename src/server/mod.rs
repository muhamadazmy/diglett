use std::{collections::HashMap, io::ErrorKind, sync::Arc};

use crate::{
    wire::{self, Connection, Control, Message, Stream},
    Error, Result,
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

use self::auth::Authenticate;

pub mod auth;
pub use auth::AuthorizeAll;

pub struct Server<A>
where
    A: Authenticate,
{
    auth: Arc<A>,
}

impl<A> Server<A>
where
    A: Authenticate,
{
    pub fn new(auth: A) -> Self {
        Self {
            auth: Arc::new(auth),
        }
    }

    pub async fn start<D: ToSocketAddrs>(self, addr: D) -> Result<()> {
        let listener = TcpListener::bind(addr).await?;

        while let Ok((socket, _)) = listener.accept().await {
            // serve one agent
            let auth = Arc::clone(&self.auth);
            tokio::spawn(async move {
                if let Err(err) = handle_agent(auth, socket).await {
                    log::trace!("failed to handle agent connection: {}", err);
                }
            });
        }

        Ok(())
    }
}

async fn handle_agent<A: Authenticate>(auth: Arc<A>, stream: TcpStream) -> Result<()> {
    let server = wire::Server::new(stream);
    // upgrade connection
    // this step accept client negotiation (if correct)
    // and then use the connection to forward traffic from now on
    let mut connection = server.accept().await?;

    // 1 - receive login token
    let token = match connection.read().await? {
        Message::Control(Control::Login(token)) => token,
        _ => {
            connection.error(Error::UnexpectedMessage).await?;
            return Err(Error::UnexpectedMessage);
        }
    };

    // 2 - authenticate the agent
    let user = match auth.authenticate(&token).await {
        Ok(user) => user,
        Err(err) => {
            connection.error(&err).await?;
            return Err(err);
        }
    };

    // 3- send okay
    connection.ok().await?;

    // 4- receive all register messages, each successful registration is
    // followed by an okay from the server.
    // 5- wait for final finish-registration message
    let mut registrations = vec![];
    while let Ok(message) = connection.read().await {
        match message {
            Message::Control(Control::Register { id, name }) => {
                if registrations.len() == 1 {
                    // we only allow one registration so far
                    connection
                        .error("only one name registration is allowed")
                        .await?;

                    return Ok(());
                }

                // authorize the domain registration
                match auth.authorize(&user.id, &name).await {
                    Ok(false) => {
                        connection
                            .error("not authorized to use this domain")
                            .await?;

                        return Ok(());
                    }
                    Err(err) => {
                        connection.error(err).await?;

                        return Ok(());
                    }
                    _ => {}
                }

                registrations.push((id, name));
                connection.ok().await?;
            }
            Message::Control(Control::FinishRegister) => break,
            _ => {
                // got an unexpected control message
                connection.error(crate::Error::UnexpectedMessage).await?;
                return Err(crate::Error::UnexpectedMessage);
            }
        }
    }

    if registrations.len() != 1 {
        connection.error("missing name registration").await?;
        return Ok(());
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
    log::trace!("{:?}", registrations);

    loop {
        tokio::select! {
            _ = exited.recv() => {
                log::debug!("agent disconnected");
                break;
            }
            accepted = bind.accept() => {
                log::trace!("accepted client connection for: {}", registration.1);
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
                    log::trace!("staring client [{}] down stream", stream_id);
                    if let Err(err) = downstream(stream_id, down, Arc::clone(&agent_writer)).await {
                        log::debug!("failed to process down traffic: {}", err);
                    }

                    log::trace!("client connection stream [{}] close read", stream_id);

                    // also clean up the client connection completely!
                    clients_drop.lock().await.remove(&stream_id);
                    let _ = agent_writer.lock().await.control(Control::Close { id: stream_id }).await;
                });

                clients.insert(
                    stream_id,
                    Client {
                        write: up,
                        handler,
                    },
                );
            }
        };
    }

    clients.lock().await.clear();

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
                        log::trace!("forwarding [{}] of data from [{}]", data.len(), id);
                        if let Err(err) = client.write.write_all(&data).await {
                            // this error can happen if the client connection has been closed
                            if !err.closed() {
                                log::error!("failed to forward traffic up: {}", err);
                            }
                            log::trace!("client connection stream [{}] write close", id);
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
        let n = match down.read(&mut buf).await {
            Ok(n) => n,
            Err(err) if err.closed() => return Ok(()),
            Err(err) => return Err(err.into()),
        };

        if n == 0 {
            // hit end of connection. I have to disconnect!
            return Ok(());
        }
        log::trace!("forwarding [{}] of data to [{}]", n, id);
        writer.lock().await.write(id, &buf[..n]).await?;
    }
}

trait IsClosed {
    fn closed(&self) -> bool;
}

impl IsClosed for std::io::Error {
    fn closed(&self) -> bool {
        matches!(
            self.kind(),
            ErrorKind::BrokenPipe | ErrorKind::ConnectionReset
        )
    }
}
