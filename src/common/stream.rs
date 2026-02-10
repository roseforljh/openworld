use tokio::io::{AsyncRead, AsyncWrite};

/// 代理流类型别名：任何实现了 AsyncRead + AsyncWrite + Send + Unpin 的类型
pub type ProxyStream = Box<dyn AsyncStream>;

/// 异步流 trait，组合 AsyncRead + AsyncWrite
pub trait AsyncStream: AsyncRead + AsyncWrite + Send + Unpin {}

/// 为所有满足约束的类型自动实现 AsyncStream
impl<T: AsyncRead + AsyncWrite + Send + Unpin> AsyncStream for T {}
