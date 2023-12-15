use std::fmt::Display;

use crate::{Error, Result};
use binary_layout::prelude::*;
use secp256k1::{constants, Keypair, PublicKey};
use tokio::{
    io::{AsyncRead, AsyncWrite, AsyncWriteExt},
    net::TcpStream,
};

use self::{
    encrypt::shared,
    frame::{Frame, Kind},
};
pub use types::{Registration, Stream};

mod encrypt;
mod frame;

pub use encrypt::{keypair, Encrypted};
pub use frame::MAX_PAYLOAD_SIZE;

define_layout!(handshake, BigEndian, {
    magic: u32,
    version: u8,
    key: [u8; constants::PUBLIC_KEY_SIZE],
});

pub struct Client<S> {
    inner: S,
    kp: Keypair,
}

impl<S> Client<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    pub fn new(stream: S, kp: Keypair) -> Self {
        Client { inner: stream, kp }
    }

    pub async fn negotiate(mut self) -> Result<Connection<Encrypted<S>>> {
        let mut buf: [u8; frame::HANDSHAKE_SIZE] = [0; frame::HANDSHAKE_SIZE];

        // send the handshake request with self public key
        frame::write_handshake(&mut self.inner, &mut buf, self.kp.public_key().serialize()).await?;

        // read the server handshake and extract public key of server
        let server_pk =
            PublicKey::from_slice(&frame::read_handshake(&mut self.inner, &mut buf).await?)?;

        // compute shared
        let shared = encrypt::shared(&self.kp, server_pk);

        Ok(Connection::new(Encrypted::new(self.inner, shared)))
    }
}

pub struct Server<S> {
    inner: S,
    kp: Keypair,
}

impl<S> Server<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    pub fn new(stream: S, kp: Keypair) -> Self {
        Server { inner: stream, kp }
    }

    pub async fn accept(mut self) -> Result<Connection<Encrypted<S>>> {
        let mut buf: [u8; frame::HANDSHAKE_SIZE] = [0; frame::HANDSHAKE_SIZE];

        // read client handshake request and extract client public key
        let client_pk =
            PublicKey::from_slice(&frame::read_handshake(&mut self.inner, &mut buf).await?)?;

        // send server handshake request with self public key
        frame::write_handshake(&mut self.inner, &mut buf, self.kp.public_key().serialize()).await?;

        // compute shared
        let shared = shared(&self.kp, client_pk);

        Ok(Connection::new(Encrypted::new(self.inner, shared)))
    }
}

#[derive(Debug)]
pub enum Control {
    // An OK control message
    Ok,
    // An error control message
    Error(String),
    // A register control message (unique agent id and name of domain)
    Register { id: Registration, name: String },
    // Tells server that all registrations requests has been provided
    FinishRegister,
    // Close a 'stream' with that stream id
    Close { id: Stream },
    // Send login token to server
    Login(String),
}

#[derive(Debug)]
pub enum Message {
    Control(Control),
    Payload { id: Stream, data: Vec<u8> },
    Terminate,
}

impl Message {
    pub fn ok_or_err(&self) -> Result<()> {
        match self {
            Message::Control(Control::Ok) => Ok(()),
            Message::Control(Control::Error(remote)) => Err(Error::Remote(remote.into())),
            _ => Err(Error::UnexpectedMessage),
        }
    }
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
                id: id.into(),
                payload: Some(name.as_bytes()),
            },
            Control::FinishRegister => Frame {
                kind: Kind::FinishRegister,
                id: 0,
                payload: None,
            },
            Control::Close { id } => Frame {
                kind: Kind::Close,
                id: id.into(),
                payload: None,
            },
            Control::Login(token) => Frame {
                kind: Kind::Login,
                id: 0,
                payload: Some(token.as_bytes()),
            },
        };

        frame::write(&mut self.inner, &mut self.header_buf, frm).await?;

        self.inner.flush().await.map_err(Error::IO)
    }

    /// a shortcut to send an ok control message
    pub async fn ok(&mut self) -> Result<()> {
        self.control(Control::Ok).await
    }

    /// a shortcut to send an err message
    pub async fn error<D: Display>(&mut self, msg: D) -> Result<()> {
        self.control(Control::Error(msg.to_string())).await
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
                id: id.into(),
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
            Kind::Close => Message::Control(Control::Close { id: frm.id.into() }),
            Kind::Register => Message::Control(Control::Register {
                id: Registration::from(frm.id as u16),
                name: frm.payload_into_string(),
            }),
            Kind::FinishRegister => Message::Control(Control::FinishRegister),
            Kind::Terminate => Message::Terminate,
            Kind::Login => Message::Control(Control::Login(frm.payload_into_string())),
            Kind::Payload => Message::Payload {
                id: frm.id.into(),
                // todo: no copy?
                data: frm.payload_into_vec(),
            },
        };

        Ok(msg)
    }
}

impl Connection<TcpStream> {
    pub fn split(
        self,
    ) -> (
        Connection<impl AsyncRead + Unpin>,
        Connection<impl AsyncWrite + Unpin>,
    ) {
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

impl Connection<Encrypted<TcpStream>> {
    pub fn split(
        self,
    ) -> (
        Connection<impl AsyncRead + Unpin>,
        Connection<impl AsyncWrite + Unpin>,
    ) {
        let (read, write) = self.inner.split();
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

mod types {
    use std::fmt::Display;

    #[derive(Debug, PartialEq, Eq, Clone, Copy, Hash)]
    pub struct Registration(u16);

    impl From<u16> for Registration {
        fn from(value: u16) -> Self {
            Self(value)
        }
    }

    impl From<&Registration> for u32 {
        fn from(value: &Registration) -> Self {
            value.0 as u32
        }
    }

    impl Display for Registration {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "{}", self.0)
        }
    }

    #[derive(Debug, PartialEq, Eq, Clone, Copy, Hash)]
    pub struct Stream(u32);

    impl Stream {
        pub fn new(reg: Registration, port: u16) -> Stream {
            let v = (reg.0 as u32) << 16 | port as u32;
            Self(v)
        }

        pub fn registration(&self) -> Registration {
            Registration((self.0 >> 16) as u16)
        }

        pub fn port(&self) -> u16 {
            self.0 as u16
        }
    }

    impl From<&Stream> for u32 {
        fn from(value: &Stream) -> Self {
            value.0
        }
    }

    impl From<Stream> for u32 {
        fn from(value: Stream) -> Self {
            value.0
        }
    }

    impl From<u32> for Stream {
        fn from(value: u32) -> Self {
            Self(value)
        }
    }

    impl Display for Stream {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "({}, {})", self.registration(), self.port())
        }
    }
}
#[cfg(test)]
mod test {

    use tokio::task::JoinHandle;

    use crate::Error;

    use super::*;

    #[test]
    fn stream_id() {
        let id: u32 = 0x11223344;
        let id = Stream::from(id);
        assert_eq!(id.registration(), Registration::from(0x1122));
        assert_eq!(id.port(), 0x3344);
    }

    #[tokio::test]
    async fn test_negotiate() {
        let server_key = keypair();
        let client_key = keypair();

        let listener = tokio::net::TcpListener::bind(("127.0.0.1", 0))
            .await
            .unwrap();
        let local = listener.local_addr().unwrap();

        let handler: JoinHandle<Result<()>> = tokio::spawn(async move {
            let (cl, _) = listener.accept().await.map_err(Error::IO)?;
            let server = super::Server::new(cl, server_key);
            let mut con = server.accept().await?;

            let msg = con.read().await.unwrap();

            if let Message::Payload { id, data } = msg {
                assert_eq!(id, Stream::from(20));
                assert_eq!(&data, "hello world".as_bytes());
            } else {
                panic!("expected payload message got: {:?}", msg);
            }

            let msg = con.read().await.unwrap();

            if let Message::Control(Control::Close { id }) = msg {
                assert_eq!(id, Stream::from(20));
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
        let client = super::Client::new(client, client_key);
        let mut con = client.negotiate().await.unwrap();

        con.write(Stream::from(20), "hello world".as_bytes())
            .await
            .unwrap();
        con.control(Control::Close {
            id: Stream::from(20),
        })
        .await
        .unwrap();
        con.control(Control::Ok).await.unwrap();

        handler.await.unwrap().unwrap();
    }
}
