use secp256k1::{ecdh, rand, Keypair, PublicKey, Secp256k1};
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;

pub const SHARED_KEY_LEN: usize = 64;

use sha2::{Digest, Sha512};
type Hasher = Sha512;

/// generates a random new keypair
pub fn keypair() -> Keypair {
    let secp = Secp256k1::new();
    let (sk, _) = secp.generate_keypair(&mut rand::thread_rng());
    Keypair::from_secret_key(&secp, &sk)
}

/// generate a shared key from secure key and a public key
pub fn shared(kp: &Keypair, pk: PublicKey) -> [u8; SHARED_KEY_LEN] {
    // we take the x coordinate of the secret point.
    let point = &ecdh::shared_secret_point(&pk, &kp.secret_key());

    let mut sh = Hasher::new();
    sh.update(point);

    sh.finalize().into()
}

pub struct Encrypted<I> {
    inner: I,
}

impl<I> Encrypted<I> {
    pub fn new(inner: I) -> Self {
        Self { inner }
    }
}

impl<I> AsyncRead for Encrypted<I>
where
    I: AsyncRead,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let inner = unsafe { self.map_unchecked_mut(|f| &mut f.inner) };
        inner.poll_read(cx, buf)
    }
}

impl<I> AsyncWrite for Encrypted<I>
where
    I: AsyncWrite,
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        let inner = unsafe { self.map_unchecked_mut(|f| &mut f.inner) };
        inner.poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), std::io::Error>> {
        let inner = unsafe { self.map_unchecked_mut(|f| &mut f.inner) };
        inner.poll_flush(cx)
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        let inner = unsafe { self.map_unchecked_mut(|f| &mut f.inner) };
        inner.poll_flush(cx)
    }
}

impl Encrypted<TcpStream> {
    pub fn split(self) -> (Encrypted<impl AsyncRead>, Encrypted<impl AsyncWrite>) {
        let (read, write) = self.inner.into_split();
        (Encrypted::new(read), Encrypted::new(write))
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn shared_keys() {
        let server_kp = keypair();
        let client_kp = keypair();

        let server_key = shared(&server_kp, client_kp.public_key());
        let client_key = shared(&client_kp, server_kp.public_key());

        assert_eq!(server_key, client_key);
    }
}
