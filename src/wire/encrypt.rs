use crate::Result;
use openssl::cipher::Cipher;
pub use openssl::cipher_ctx::CipherCtx;
use secp256k1::{ecdh, rand, Keypair, PublicKey, Secp256k1};

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

pub(crate) fn encryptor_from_key(key: &SharedKey) -> Result<CipherCtx> {
    let mut ctx = CipherCtx::new()?;

    ctx.encrypt_init(
        Some(Cipher::chacha20()),
        Some(&key[..32]),
        Some(&key[32..48]),
    )?;

    Ok(ctx)
}

pub(crate) fn decryptor_from_key(key: &SharedKey) -> Result<CipherCtx> {
    let mut ctx = CipherCtx::new()?;

    ctx.decrypt_init(
        Some(Cipher::chacha20()),
        Some(&key[..32]),
        Some(&key[32..48]),
    )?;

    Ok(ctx)
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
