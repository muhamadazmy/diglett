use binary_layout::prelude::*;
use secp256k1::constants;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::{Error, Result};

use super::encrypt::{decryptor_from_key, encryptor_from_key, CipherCtx, SharedKey};

const MAGIC: u32 = 0x6469676c;
const VERSION: u8 = 1;

pub const HANDSHAKE_SIZE: usize = 38;
pub const FRAME_HEADER_SIZE: usize = 7;
pub const MAX_PAYLOAD_SIZE: usize = u16::MAX as usize;

define_layout!(handshake, BigEndian, {
    magic: u32,
    version: u8,
    key: [u8; constants::PUBLIC_KEY_SIZE],
    // todo: add token here
});

pub async fn write_handshake<W>(
    writer: &mut W,
    buf: &mut [u8; HANDSHAKE_SIZE],
    key: [u8; constants::PUBLIC_KEY_SIZE],
) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    let mut view = handshake::View::new(&mut buf[..]);

    view.magic_mut().write(MAGIC);
    view.version_mut().write(VERSION);
    view.key_mut().copy_from_slice(&key);
    writer.write_all(&buf[..]).await?;

    writer.flush().await.map_err(Error::IO)
}

pub async fn read_handshake<'a, R>(
    reader: &mut R,
    buf: &'a mut [u8; HANDSHAKE_SIZE],
) -> Result<[u8; constants::PUBLIC_KEY_SIZE]>
where
    R: AsyncRead + Unpin,
{
    let mut key: [u8; constants::PUBLIC_KEY_SIZE] = [0; constants::PUBLIC_KEY_SIZE];

    reader.read_exact(&mut buf[..HANDSHAKE_SIZE]).await?;
    let view = handshake::View::new(&buf[..HANDSHAKE_SIZE]);

    if view.magic().read() != MAGIC {
        return Err(Error::InvalidMagic);
    }

    let version = view.version().read();
    if version != VERSION {
        return Err(Error::InvalidVersion(version));
    }

    key.copy_from_slice(view.key());

    Ok(key)
}

define_layout!(frame, BigEndian, {
    kind: u8,
    id: u32,
    size: u16,
});

#[repr(u8)]
pub enum Kind {
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
    // Login message
    Login = 7,
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
            7 => Self::Login,
            _ => return Err("invalid frame type"),
        };

        Ok(result)
    }
}

pub struct Frame {
    pub kind: Kind,
    pub id: u32,
}

#[async_trait::async_trait]
pub trait FrameWriter {
    async fn write<W>(
        &mut self,
        writer: &mut W,
        frm: Frame,
        payload: Option<&'_ mut [u8]>,
    ) -> Result<()>
    where
        W: AsyncWrite + Unpin + Send;
}

#[async_trait::async_trait]
pub trait FrameReader {
    async fn read<'a, R>(&'a mut self, reader: &mut R) -> Result<(Frame, Option<&'a [u8]>)>
    where
        R: AsyncRead + Unpin + Send;
}

pub struct FrameReaderHalf {
    buffer: [u8; MAX_PAYLOAD_SIZE],
    chacha: CipherCtx,
}

impl FrameReaderHalf {
    pub fn new(key: &SharedKey) -> Self {
        Self {
            buffer: [0; MAX_PAYLOAD_SIZE],
            chacha: decryptor_from_key(key).unwrap(),
        }
    }
}

#[async_trait::async_trait]
impl FrameReader for FrameReaderHalf {
    async fn read<'a, R>(&'a mut self, reader: &mut R) -> Result<(Frame, Option<&'a [u8]>)>
    where
        R: AsyncRead + Unpin + Send,
    {
        let header = &mut self.buffer[..FRAME_HEADER_SIZE];
        reader.read_exact(header).await?;

        // decrypt
        self.chacha.cipher_update_inplace(header, header.len())?;

        let view = frame::View::new(header);
        let kind: Kind = view
            .kind()
            .read()
            .try_into()
            .map_err(|_| Error::InvalidHeader)?;
        let id = view.id().read();
        let size = view.size().read() as usize;

        let payload = if size == 0 {
            None
        } else {
            let data = &mut self.buffer[..size];

            reader.read_exact(data).await?;
            self.chacha.cipher_update_inplace(data, data.len())?;

            Some(data as &[u8])
        };

        Ok((Frame { kind, id }, payload))
    }
}

pub struct FrameWriterHalf {
    header: [u8; FRAME_HEADER_SIZE],
    chacha: CipherCtx,
}

impl FrameWriterHalf {
    pub fn new(key: &SharedKey) -> Self {
        Self {
            header: [0; FRAME_HEADER_SIZE],
            chacha: encryptor_from_key(key).unwrap(),
        }
    }
}

#[async_trait::async_trait]
impl FrameWriter for FrameWriterHalf {
    async fn write<W>(
        &mut self,
        writer: &mut W,
        frm: Frame,
        payload: Option<&'_ mut [u8]>,
    ) -> Result<()>
    where
        W: AsyncWrite + Unpin + Send,
    {
        let mut view = frame::View::new(&mut self.header[..]);
        view.kind_mut().write(frm.kind as u8);
        view.id_mut().write(frm.id);
        if let Some(data) = &payload {
            view.size_mut().write(data.len() as u16);
        } else {
            view.size_mut().write(0);
        }

        // encrypt header
        self.chacha
            .cipher_update_inplace(&mut self.header[..], FRAME_HEADER_SIZE)?;
        writer.write_all(&self.header[..]).await?;
        if let Some(data) = payload {
            self.chacha.cipher_update_inplace(data, data.len())?;
            writer.write_all(data).await?;
        }

        Ok(())
    }
}

pub struct FrameStream {
    read_half: FrameReaderHalf,
    write_half: FrameWriterHalf,
}

impl FrameStream {
    pub fn new(key: &SharedKey) -> FrameStream {
        Self {
            read_half: FrameReaderHalf::new(key),
            write_half: FrameWriterHalf::new(key),
        }
    }

    pub fn split(self) -> (FrameReaderHalf, FrameWriterHalf) {
        (self.read_half, self.write_half)
    }
}

#[async_trait::async_trait]
impl FrameReader for FrameStream {
    async fn read<'a, R>(&'a mut self, reader: &mut R) -> Result<(Frame, Option<&'a [u8]>)>
    where
        R: AsyncRead + Unpin + Send,
    {
        self.read_half.read(reader).await
    }
}

#[async_trait::async_trait]
impl FrameWriter for FrameStream {
    async fn write<W>(
        &mut self,
        writer: &mut W,
        frm: Frame,
        payload: Option<&'_ mut [u8]>,
    ) -> Result<()>
    where
        W: AsyncWrite + Unpin + Send,
    {
        self.write_half.write(writer, frm, payload).await
    }
}

#[cfg(test)]
mod test {
    use super::frame;
    #[test]
    fn test_constant() {
        // this to make sure the const matches the size of the view which is an option
        assert_eq!(frame::SIZE.unwrap(), super::FRAME_HEADER_SIZE);
    }
}
