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

const MAGIC: u32 = 0x6469676c;
const VERSION: u8 = 1;
const HANDSHAKE_SIZE: usize = 38;
const HEADER_SIZE: usize = 7;
const MAX_PAYLOAD_SIZE: usize = u16::MAX as usize;

pub type Stream = u32;

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

#[repr(u8)]
enum Kind {
    // ack message
    Ok = 0,
    // report an error message
    Error = 1,
    // register a new stream
    Register = 2,
    // finish registration and start serving data
    FinishRegister = 3,
    // sending a payload
    Payload = 4,
    // close a stream
    Close = 5,
    // terminating and drop connection
    Terminate = 6,
}

impl TryFrom<u8> for Kind {
    type Error = &'static str;
    fn try_from(value: u8) -> std::result::Result<Self, <Self as TryFrom<u8>>::Error> {
        let result = match value {
            0 => Self::Ok,
            1 => Self::Error,
            2 => Self::Register,
            3 => Self::FinishRegister,
            4 => Self::Payload,
            5 => Self::Close,
            6 => Self::Terminate,
            _ => return Err("invalid header type"),
        };

        Ok(result)
    }
}
pub struct Connection<S> {
    inner: S,
    header_buf: [u8; HEADER_SIZE],
    data_buf: [u8; MAX_PAYLOAD_SIZE],
}

impl<S> Connection<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // this is private because only client or server should
    // be able to create it
    fn new(stream: S) -> Self {
        Connection {
            inner: stream,
            header_buf: [0; HEADER_SIZE],
            data_buf: [0; MAX_PAYLOAD_SIZE],
        }
    }

    async fn write_header(&mut self, kind: Kind, id: Stream, size: u16) -> Result<()> {
        write_header(&mut self.inner, &mut self.header_buf, kind, id, size).await
    }

    // send a control message to remote side
    pub async fn control(&mut self, ctl: Control) -> Result<()> {
        control(&mut self.inner, &mut self.header_buf, ctl).await
    }

    /// write data to a specific stream, return number of bytes that
    /// has been written. The caller need to make sure to call this
    /// again until all data is written. It's important that if a lock
    /// is acquired that u give a chance for other writers a chance to
    /// do a write as well.
    pub async fn write(&mut self, id: Stream, data: &[u8]) -> Result<usize> {
        let data = if data.len() > MAX_PAYLOAD_SIZE {
            &data[..MAX_PAYLOAD_SIZE]
        } else {
            data
        };

        self.write_header(Kind::Payload, id, data.len() as u16)
            .await?;

        self.inner.write_all(data).await?;
        self.inner.flush().await?;

        Ok(data.len())
    }

    /// receive the next message available on the wire
    pub async fn receive(&mut self) -> Result<Message> {
        receive(&mut self.inner, &mut self.header_buf, &mut self.data_buf).await
    }
}

impl Connection<TcpStream> {
    pub fn split(self) -> (ReadHalf, WriteHalf) {
        let (read, write) = self.inner.into_split();
        (
            ReadHalf {
                inner: read,
                data_buf: self.data_buf,
                header_buf: self.header_buf,
            },
            WriteHalf {
                inner: write,
                header_buf: [0; HEADER_SIZE],
            },
        )
    }
}

pub struct ReadHalf {
    inner: OwnedReadHalf,
    header_buf: [u8; HEADER_SIZE],
    data_buf: [u8; MAX_PAYLOAD_SIZE],
}

impl ReadHalf {
    /// receive the next message available on the wire
    pub async fn receive(&mut self) -> Result<Message> {
        receive(&mut self.inner, &mut self.header_buf, &mut self.data_buf).await
    }
}

pub struct WriteHalf {
    inner: OwnedWriteHalf,
    header_buf: [u8; HEADER_SIZE],
}

impl WriteHalf {
    async fn write_header(&mut self, kind: Kind, id: Stream, size: u16) -> Result<()> {
        write_header(&mut self.inner, &mut self.header_buf, kind, id, size).await
    }

    // send a control message to remote side
    pub async fn control(&mut self, ctl: Control) -> Result<()> {
        control(&mut self.inner, &mut self.header_buf, ctl).await
    }

    /// write data to a specific stream, return number of bytes that
    /// has been written. The caller need to make sure to call this
    /// again until all data is written. It's important that if a lock
    /// is acquired that u give a chance for other writers a chance to
    /// do a write as well.
    pub async fn write(&mut self, id: Stream, data: &[u8]) -> Result<usize> {
        let data = if data.len() > MAX_PAYLOAD_SIZE {
            &data[..MAX_PAYLOAD_SIZE]
        } else {
            data
        };

        self.write_header(Kind::Payload, id, data.len() as u16)
            .await?;

        self.inner.write_all(data).await?;
        self.inner.flush().await?;

        Ok(data.len())
    }
}

async fn read_header<R>(
    reader: &mut R,
    buf: &mut [u8; HEADER_SIZE],
) -> Result<(Kind, Stream, usize)>
where
    R: AsyncRead + Unpin,
{
    reader.read_exact(&mut buf[..]).await?;

    let view = header::View::new(&buf[..]);
    let kind = Kind::try_from(view.kind().read()).map_err(|_| Error::InvalidHeader)?;
    let id: Stream = view.id().read();
    let size = view.size().read() as usize;

    Ok((kind, id, size))
}

async fn write_header<W>(
    writer: &mut W,
    buf: &mut [u8; HEADER_SIZE],
    kind: Kind,
    id: Stream,
    size: u16,
) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    let mut view = header::View::new(&mut buf[..]);
    view.kind_mut().write(kind as u8);
    view.id_mut().write(id);
    view.size_mut().write(size);

    writer.write_all(&buf[..]).await.map_err(Error::IO)
}

// send a control message to remote side
async fn control<W>(
    writer: &mut W,
    header_buf: &mut [u8; HEADER_SIZE],
    control: Control,
) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    let payload = match &control {
        Control::Ok => {
            write_header(writer, header_buf, Kind::Ok, 0, 0).await?;
            None
        }
        Control::Error(msg) => {
            let msg = msg.as_bytes();
            write_header(writer, header_buf, Kind::Error, 0, msg.len() as u16).await?;
            Some(msg)
        }
        Control::Close { id } => {
            write_header(writer, header_buf, Kind::Close, *id, 0).await?;
            None
        }
        Control::Register { id, name } => {
            let name = name.as_bytes();
            write_header(
                writer,
                header_buf,
                Kind::Register,
                *id as Stream,
                name.len() as u16,
            )
            .await?;

            Some(name)
        }
        Control::FinishRegister => {
            write_header(writer, header_buf, Kind::FinishRegister, 0, 0).await?;
            None
        }
    };

    if let Some(payload) = payload {
        writer.write_all(payload).await?;
    }

    writer.flush().await.map_err(Error::IO)
}

async fn receive<R>(
    reader: &mut R,
    header_buf: &mut [u8; HEADER_SIZE],
    data_buf: &mut [u8; MAX_PAYLOAD_SIZE],
) -> Result<Message>
where
    R: AsyncRead + Unpin,
{
    let (kind, id, size) = read_header(reader, header_buf).await?;

    if size != 0 {
        reader.read_exact(&mut data_buf[..size]).await?;
    }

    let data = &data_buf[..size];

    let msg = match kind {
        Kind::Ok => Message::Control(Control::Ok),
        Kind::Error => Message::Control(Control::Error(String::from_utf8_lossy(data).into_owned())),
        Kind::Register => {
            let name = String::from_utf8_lossy(&data).into_owned();

            // TODO: we need to separate registration id from stream id
            Message::Control(Control::Register {
                id: id as u16,
                name: name,
            })
        }
        Kind::FinishRegister => Message::Control(Control::FinishRegister),
        Kind::Close => Message::Control(Control::Close { id }),
        Kind::Terminate => Message::Terminate,
        Kind::Payload => Message::Payload {
            id,
            data: data_buf[..size].into(),
        },
    };

    Ok(msg)
}

define_layout!(handshake, BigEndian, {
    magic: u32,
    version: u8,
    key: [u8; constants::PUBLIC_KEY_SIZE],
    // todo: add token here
});

define_layout!(header, BigEndian, {
    kind: u8,
    id: Stream,
    size: u16,
});

#[cfg(test)]
mod test {

    use tokio::task::JoinHandle;

    use crate::Error;

    use super::*;

    #[test]
    fn test_constant() {
        // this to make sure the const matches the size of the view which is an option
        assert_eq!(handshake::SIZE.unwrap(), super::HANDSHAKE_SIZE);
        assert_eq!(header::SIZE.unwrap(), super::HEADER_SIZE);
    }

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

            let msg = con.receive().await.unwrap();

            if let Message::Payload { id, data } = msg {
                assert_eq!(id, 20);
                assert_eq!(&data, "hello world".as_bytes());
            } else {
                panic!("expected payload message got: {:?}", msg);
            }

            let msg = con.receive().await.unwrap();

            if let Message::Control(Control::Close { id }) = msg {
                assert_eq!(id, 20);
            } else {
                panic!("expected close message");
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

        handler.await.unwrap().unwrap();
    }
}
