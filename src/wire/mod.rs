use crate::{Error, Result};
use binary_layout::prelude::*;
use secp256k1::constants;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{
        tcp::{OwnedReadHalf, OwnedWriteHalf},
        TcpStream,
    },
};

use self::frame::{Frame, Kind};

mod frame;

const MAGIC: u32 = 0x6469676c;
const VERSION: u8 = 1;
const HANDSHAKE_SIZE: usize = 38;

pub type Stream = u32;

define_layout!(handshake, BigEndian, {
    magic: u32,
    version: u8,
    key: [u8; constants::PUBLIC_KEY_SIZE],
    // todo: add token here
});

pub struct Client<S> {
    inner: S,
}

impl<S> Client<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    pub fn new(stream: S) -> Self {
        Client { inner: stream }
    }

    pub async fn negotiate(mut self) -> Result<Connection<S>> {
        let mut buf: [u8; HANDSHAKE_SIZE] = [0; HANDSHAKE_SIZE];
        let mut view = handshake::View::new(&mut buf);
        view.magic_mut().write(MAGIC);
        view.version_mut().write(VERSION);
        self.inner.write_all(&buf).await?;

        self.inner.flush().await?;
        // fall into encryption directly or wait for okay?
        Ok(Connection::new(self.inner))
    }
}

pub struct Server<S> {
    inner: S,
}

impl<S> Server<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    pub fn new(stream: S) -> Self {
        Server { inner: stream }
    }

    pub async fn accept(mut self) -> Result<Connection<S>> {
        let mut buf: [u8; HANDSHAKE_SIZE] = [0; HANDSHAKE_SIZE];
        self.inner.read_exact(&mut buf).await?;
        let view = handshake::View::new(&buf);
        if view.magic().read() != MAGIC {
            return Err(Error::InvalidMagic);
        }

        let version = view.version().read();
        if version != VERSION {
            return Err(Error::InvalidVersion(version));
        }

        Ok(Connection::new(self.inner))
    }
}

#[derive(Debug)]
pub enum Control {
    Ok,
    Error(String),
    Register { id: u16, name: String },
    FinishRegister,
    Close { id: Stream },
}

#[derive(Debug)]
pub enum Message {
    Control(Control),
    Payload { id: Stream, data: Vec<u8> },
    Terminate,
}

pub struct Connection<S> {
    inner: S,
    header_buf: [u8; frame::FRAME_HEADER_SIZE],
    data_buf: [u8; frame::MAX_PAYLOAD_SIZE],
}

impl<S> Connection<S> {
    // this is private because only client or server should
    // be able to create it
    fn new(stream: S) -> Self {
        Connection {
            inner: stream,
            header_buf: [0; frame::FRAME_HEADER_SIZE],
            data_buf: [0; frame::MAX_PAYLOAD_SIZE],
        }
    }
}

impl<S> Connection<S>
where
    S: AsyncWrite + Unpin,
{
    // send a control message to remote side
    pub async fn control(&mut self, ctl: Control) -> Result<()> {
        let frm = match &ctl {
            Control::Ok => Frame {
                kind: Kind::Ok,
                id: 0,
                payload: None,
            },
            Control::Error(msg) => Frame {
                kind: Kind::Error,
                id: 0,
                payload: Some(msg.as_bytes()),
            },
            Control::Register { id, name } => Frame {
                kind: Kind::Register,
                id: *id as u32,
                payload: Some(name.as_bytes()),
            },
            Control::FinishRegister => Frame {
                kind: Kind::FinishRegister,
                id: 0,
                payload: None,
            },
            Control::Close { id } => Frame {
                kind: Kind::Close,
                id: *id,
                payload: None,
            },
        };

        frame::write(&mut self.inner, &mut self.header_buf, frm).await?;

        self.inner.flush().await.map_err(Error::IO)
    }

    /// write data to a specific stream, return number of bytes that
    /// has been written. The caller need to make sure to call this
    /// again until all data is written. It's important that if a lock
    /// is acquired that u give a chance for other writers a chance to
    /// do a write as well.
    pub async fn write(&mut self, id: Stream, data: &[u8]) -> Result<usize> {
        let data = if data.len() > frame::MAX_PAYLOAD_SIZE {
            &data[..frame::MAX_PAYLOAD_SIZE]
        } else {
            data
        };

        frame::write(
            &mut self.inner,
            &mut self.header_buf,
            Frame {
                kind: frame::Kind::Payload,
                id,
                payload: Some(data),
            },
        )
        .await?;
        self.inner.flush().await?;

        Ok(data.len())
    }
}

impl<S> Connection<S>
where
    S: AsyncRead + Unpin,
{
    pub async fn read(&mut self) -> Result<Message> {
        let frm = frame::read(&mut self.inner, &mut self.data_buf).await?;

        let msg = match frm.kind {
            Kind::Ok => Message::Control(Control::Ok),
            Kind::Error => Message::Control(Control::Error(frm.payload_into_string())),
            Kind::Close => Message::Control(Control::Close { id: frm.id }),
            Kind::Register => Message::Control(Control::Register {
                id: frm.id as u16,
                name: frm.payload_into_string(),
            }),
            Kind::FinishRegister => Message::Control(Control::FinishRegister),
            Kind::Terminate => Message::Terminate,
            Kind::Payload => Message::Payload {
                id: frm.id,
                // todo: no copy?
                data: frm.payload_into_vec(),
            },
        };

        Ok(msg)
    }
}

impl Connection<TcpStream> {
    pub fn split(self) -> (Connection<OwnedReadHalf>, Connection<OwnedWriteHalf>) {
        let (read, write) = self.inner.into_split();
        (
            Connection {
                inner: read,
                data_buf: self.data_buf,
                header_buf: self.header_buf,
            },
            Connection {
                inner: write,
                data_buf: [0; frame::MAX_PAYLOAD_SIZE],
                header_buf: [0; frame::FRAME_HEADER_SIZE],
            },
        )
    }
}

#[cfg(test)]
mod test {

    use tokio::task::JoinHandle;

    use crate::Error;

    use super::*;

    #[tokio::test]
    async fn test_negotiate() {
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .unwrap();
        let local = listener.local_addr().unwrap();

        let handler: JoinHandle<Result<()>> = tokio::spawn(async move {
            let (cl, _) = listener.accept().await.map_err(Error::IO)?;
            let server = super::Server::new(cl);
            let mut con = server.accept().await?;

            let msg = con.read().await.unwrap();

            if let Message::Payload { id, data } = msg {
                assert_eq!(id, 20);
                assert_eq!(&data, "hello world".as_bytes());
            } else {
                panic!("expected payload message got: {:?}", msg);
            }

            let msg = con.read().await.unwrap();

            if let Message::Control(Control::Close { id }) = msg {
                assert_eq!(id, 20);
            } else {
                panic!("expected close message");
            }

            let msg = con.read().await.unwrap();

            if let Message::Control(Control::Ok) = msg {
                assert!(true);
            } else {
                panic!("expected ok message");
            }

            Ok(())
        });

        let client = tokio::net::TcpStream::connect(("127.0.0.1", local.port()))
            .await
            .unwrap();
        let client = super::Client::new(client);
        let mut con = client.negotiate().await.unwrap();

        con.write(20, "hello world".as_bytes()).await.unwrap();
        con.control(Control::Close { id: 20 }).await.unwrap();
        con.control(Control::Ok).await.unwrap();

        handler.await.unwrap().unwrap();
    }
}
