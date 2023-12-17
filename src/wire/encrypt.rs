use chacha20::cipher::{KeyIvInit, StreamCipher, StreamCipherSeek};
use chacha20::ChaCha20;
use secp256k1::{ecdh, rand, Keypair, PublicKey, Secp256k1};
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;

pub const SHARED_KEY_LEN: usize = 64;

use sha2::{Digest, Sha512};
type Hasher = Sha512;

pub type SharedKey = [u8; SHARED_KEY_LEN];

/// generates a random new keypair
pub fn keypair() -> Keypair {
    let secp = Secp256k1::new();
    let (sk, _) = secp.generate_keypair(&mut rand::thread_rng());
    Keypair::from_secret_key(&secp, &sk)
}

/// generate a shared key from secure key and a public key
pub fn shared(kp: &Keypair, pk: PublicKey) -> SharedKey {
    // we take the x coordinate of the secret point.
    let point = &ecdh::shared_secret_point(&pk, &kp.secret_key());

    let mut sh = Hasher::new();
    sh.update(point);

    sh.finalize().into()
}

pub fn chacha_from_key(key: &SharedKey) -> ChaCha20 {
    let mut k: [u8; 32] = [0; 32];
    let mut iv: [u8; 12] = [0; 12];
    k.copy_from_slice(&key[..32]);
    iv.copy_from_slice(&key[32..44]);

    ChaCha20::new(&k.into(), &iv.into())
}

pub struct Encrypted<I> {
    inner: I,
    key: [u8; SHARED_KEY_LEN],
    cipher: ChaCha20,
}

impl<I> Encrypted<I> {
    pub fn new(inner: I, key: [u8; SHARED_KEY_LEN]) -> Self {
        let mut k: [u8; 32] = [0; 32];
        let mut iv: [u8; 12] = [0; 12];
        k.copy_from_slice(&key[..32]);
        iv.copy_from_slice(&key[32..44]);

        let cipher = ChaCha20::new(&k.into(), &iv.into());

        Self { inner, key, cipher }
    }
}

impl<I> AsyncRead for Encrypted<I>
where
    I: AsyncRead + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let mut this = self.as_mut();
        let inner = Pin::new(&mut this.inner);

        //let inner = unsafe { self.map_unchecked_mut(|f| &mut f.inner) };

        match inner.poll_read(cx, buf) {
            Poll::Ready(Ok(())) => {
                self.get_mut().cipher.apply_keystream(buf.filled_mut());
                Poll::Ready(Ok(()))
            }
            any => any,
        }
    }
}

impl<I> AsyncWrite for Encrypted<I>
where
    I: AsyncWrite + Unpin,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        let mut this = self.as_mut();

        let cipher = &mut this.cipher;
        let mut buf = Vec::from(buf);
        let current = cipher.current_pos::<usize>();

        cipher.apply_keystream(&mut buf);
        let inner = Pin::new(&mut this.inner);

        match inner.poll_write(cx, &buf) {
            Poll::Ready(Ok(n)) => {
                if buf.len() > n {
                    // partial write. we need to seek the cipher
                    let cipher = &mut this.cipher;
                    log::debug!(
                        "partial write, seek cipher from {} to {}",
                        current,
                        current + n
                    );
                    cipher.seek(current + n);
                }

                Poll::Ready(Ok(n))
            }
            Poll::Pending => {
                let cipher = &mut this.cipher;
                cipher.seek(current);
                Poll::Pending
            }
            any => any,
        }
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
        (
            Encrypted::new(read, self.key),
            Encrypted::new(write, self.key),
        )
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

    #[tokio::test]
    async fn encryption() {
        use rand::Rng;
        use sha2::Digest;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let key: [u8; SHARED_KEY_LEN] = [0x42; SHARED_KEY_LEN];
        let f = tokio::fs::File::create("/tmp/encrypted.test")
            .await
            .unwrap();

        let mut rng = rand::thread_rng();
        let mut buf: [u8; u16::MAX as usize] = [0; u16::MAX as usize];

        let mut sha = sha2::Sha256::new();
        let mut enc = Encrypted::new(f, key);
        for _ in 0..200 {
            rng.fill(&mut buf[..]);
            sha.update(&buf[..]);
            enc.write_all(&buf).await.unwrap();
        }

        let h1 = sha.finalize();

        let f = tokio::fs::File::open("/tmp/encrypted.test").await.unwrap();
        let mut sha = sha2::Sha256::new();
        let mut enc = Encrypted::new(f, key);
        for _ in 0..200 {
            enc.read_exact(&mut buf[..]).await.unwrap();
            sha.update(&buf);
        }

        let h2 = sha.finalize();

        assert_eq!(h1, h2);
    }
}
