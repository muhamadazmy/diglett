pub mod agent;
pub mod server;
pub mod wire;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("invalid wire magic number")]
    InvalidMagic,

    #[error("invalid wire version: {0}")]
    InvalidVersion(u8),

    #[error("received an invalid header")]
    InvalidHeader,

    #[error("received unexpected message")]
    UnexpectedMessage,

    #[error("remote error: {0}")]
    Remote(String),

    #[error("authentication error: {0}")]
    AuthenticationError(String),

    #[error("key exchange error: {0}")]
    Encryption(#[from] secp256k1::Error),

    #[error("openssl error: {0}")]
    OpenSSLError(#[from] openssl::error::Error),

    #[error("openssl error stack : {0}")]
    OpenSSLErrorStack(#[from] openssl::error::ErrorStack),

    #[error("io error: {0}")]
    IO(#[from] std::io::Error),
}
