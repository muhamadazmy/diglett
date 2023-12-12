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

    #[error("io error: {0}")]
    IO(#[from] std::io::Error),
}
