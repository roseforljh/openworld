use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("protocol error: {0}")]
    Protocol(String),

    #[error("config error: {0}")]
    Config(String),

    #[error("DNS resolution failed: {0}")]
    DnsResolution(String),

    #[error("connection refused: {0}")]
    ConnectionRefused(String),

    #[error("unsupported: {0}")]
    Unsupported(String),

    #[error("authentication failed: {0}")]
    AuthFailed(String),

    #[error("{0}")]
    Other(#[from] anyhow::Error),
}

impl From<Error> for std::io::Error {
    fn from(e: Error) -> Self {
        std::io::Error::other(e.to_string())
    }
}
