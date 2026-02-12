use thiserror::Error;

#[derive(Error, Debug)]
pub enum ProxyError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("protocol error: {0}")]
    Protocol(String),

    #[error("config error: {0}")]
    Config(String),

    #[error("DNS resolution failed: {0}")]
    DnsResolutionFailed(String),

    #[error("connection refused: {0}")]
    ConnectionRefused(String),

    #[error("connection timeout: {0}")]
    ConnectionTimeout(String),

    #[error("TLS handshake failed: {0}")]
    TlsHandshakeFailed(String),

    #[error("authentication failed: {0}")]
    AuthenticationFailed(String),

    #[error("circuit breaker open: {0}")]
    CircuitBreakerOpen(String),

    #[error("rate limited: {0}")]
    RateLimited(String),

    #[error("cancelled")]
    Cancelled,

    #[error("unsupported: {0}")]
    Unsupported(String),

    #[error("{0}")]
    Other(#[from] anyhow::Error),
}

impl ProxyError {
    /// Whether this error is transient and the operation should be retried.
    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            ProxyError::ConnectionTimeout(_)
                | ProxyError::DnsResolutionFailed(_)
                | ProxyError::Io(_)
        )
    }

    /// Whether this error suggests switching to a different outbound node.
    pub fn should_switch_node(&self) -> bool {
        matches!(
            self,
            ProxyError::ConnectionRefused(_)
                | ProxyError::ConnectionTimeout(_)
                | ProxyError::TlsHandshakeFailed(_)
                | ProxyError::CircuitBreakerOpen(_)
        )
    }

    /// Whether this error is a permanent failure (no point retrying).
    pub fn is_permanent(&self) -> bool {
        matches!(
            self,
            ProxyError::Config(_)
                | ProxyError::Unsupported(_)
                | ProxyError::AuthenticationFailed(_)
                | ProxyError::Cancelled
        )
    }

    /// Try to extract a ProxyError from an anyhow::Error, or classify
    /// the underlying error heuristically (e.g. io::Error kinds).
    pub fn classify(err: &anyhow::Error) -> ProxyErrorKind {
        if let Some(pe) = err.downcast_ref::<ProxyError>() {
            return pe.kind();
        }
        if let Some(io_err) = err.downcast_ref::<std::io::Error>() {
            return match io_err.kind() {
                std::io::ErrorKind::ConnectionRefused => ProxyErrorKind::ConnectionRefused,
                std::io::ErrorKind::ConnectionReset
                | std::io::ErrorKind::ConnectionAborted
                | std::io::ErrorKind::BrokenPipe => ProxyErrorKind::ConnectionRefused,
                std::io::ErrorKind::TimedOut => ProxyErrorKind::ConnectionTimeout,
                _ => ProxyErrorKind::Io,
            };
        }
        ProxyErrorKind::Other
    }

    /// Get the kind/category of this error.
    pub fn kind(&self) -> ProxyErrorKind {
        match self {
            ProxyError::Io(_) => ProxyErrorKind::Io,
            ProxyError::Protocol(_) => ProxyErrorKind::Protocol,
            ProxyError::Config(_) => ProxyErrorKind::Config,
            ProxyError::DnsResolutionFailed(_) => ProxyErrorKind::DnsResolutionFailed,
            ProxyError::ConnectionRefused(_) => ProxyErrorKind::ConnectionRefused,
            ProxyError::ConnectionTimeout(_) => ProxyErrorKind::ConnectionTimeout,
            ProxyError::TlsHandshakeFailed(_) => ProxyErrorKind::TlsHandshakeFailed,
            ProxyError::AuthenticationFailed(_) => ProxyErrorKind::AuthenticationFailed,
            ProxyError::CircuitBreakerOpen(_) => ProxyErrorKind::CircuitBreakerOpen,
            ProxyError::RateLimited(_) => ProxyErrorKind::RateLimited,
            ProxyError::Cancelled => ProxyErrorKind::Cancelled,
            ProxyError::Unsupported(_) => ProxyErrorKind::Unsupported,
            ProxyError::Other(_) => ProxyErrorKind::Other,
        }
    }
}

/// Lightweight error category for pattern matching without borrowing the error.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProxyErrorKind {
    Io,
    Protocol,
    Config,
    DnsResolutionFailed,
    ConnectionRefused,
    ConnectionTimeout,
    TlsHandshakeFailed,
    AuthenticationFailed,
    CircuitBreakerOpen,
    RateLimited,
    Cancelled,
    Unsupported,
    Other,
}

impl ProxyErrorKind {
    pub fn is_retryable(self) -> bool {
        matches!(
            self,
            ProxyErrorKind::ConnectionTimeout
                | ProxyErrorKind::DnsResolutionFailed
                | ProxyErrorKind::Io
        )
    }

    pub fn should_switch_node(self) -> bool {
        matches!(
            self,
            ProxyErrorKind::ConnectionRefused
                | ProxyErrorKind::ConnectionTimeout
                | ProxyErrorKind::TlsHandshakeFailed
                | ProxyErrorKind::CircuitBreakerOpen
        )
    }

    pub fn is_permanent(self) -> bool {
        matches!(
            self,
            ProxyErrorKind::Config
                | ProxyErrorKind::Unsupported
                | ProxyErrorKind::AuthenticationFailed
                | ProxyErrorKind::Cancelled
        )
    }

    pub fn as_str(self) -> &'static str {
        match self {
            ProxyErrorKind::Io => "IO",
            ProxyErrorKind::Protocol => "PROTOCOL",
            ProxyErrorKind::Config => "CONFIG",
            ProxyErrorKind::DnsResolutionFailed => "DNS_FAILED",
            ProxyErrorKind::ConnectionRefused => "CONN_REFUSED",
            ProxyErrorKind::ConnectionTimeout => "CONN_TIMEOUT",
            ProxyErrorKind::TlsHandshakeFailed => "TLS_FAILED",
            ProxyErrorKind::AuthenticationFailed => "AUTH_FAILED",
            ProxyErrorKind::CircuitBreakerOpen => "CIRCUIT_OPEN",
            ProxyErrorKind::RateLimited => "RATE_LIMITED",
            ProxyErrorKind::Cancelled => "CANCELLED",
            ProxyErrorKind::Unsupported => "UNSUPPORTED",
            ProxyErrorKind::Other => "OTHER",
        }
    }
}

impl From<ProxyError> for std::io::Error {
    fn from(e: ProxyError) -> Self {
        std::io::Error::other(e.to_string())
    }
}
