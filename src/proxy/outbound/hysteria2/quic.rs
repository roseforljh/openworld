use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use anyhow::Result;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// QUIC 连接管理器
pub struct QuicManager {
    server_addr: String,
    server_port: u16,
    sni: String,
    allow_insecure: bool,
    endpoint: Option<quinn::Endpoint>,
    connection: Option<quinn::Connection>,
    authenticated: bool,
}

impl QuicManager {
    pub fn new(
        server_addr: String,
        server_port: u16,
        sni: String,
        allow_insecure: bool,
    ) -> Result<Self> {
        Ok(Self {
            server_addr,
            server_port,
            sni,
            allow_insecure,
            endpoint: None,
            connection: None,
            authenticated: false,
        })
    }

    /// 获取 QUIC 连接（复用已有连接或创建新连接）
    /// 返回 (connection, is_new) - is_new 表示是否为新建连接（需要认证）
    pub async fn get_connection(&mut self) -> Result<(quinn::Connection, bool)> {
        // 检查现有连接是否可用
        if let Some(ref conn) = self.connection {
            if conn.close_reason().is_none() {
                return Ok((conn.clone(), false));
            }
        }

        // 创建新连接，重置认证状态
        let conn = self.create_connection().await?;
        self.connection = Some(conn.clone());
        self.authenticated = false;
        Ok((conn, true))
    }

    /// 标记当前连接已认证
    pub fn mark_authenticated(&mut self) {
        self.authenticated = true;
    }

    /// 当前连接是否已认证
    pub fn is_authenticated(&self) -> bool {
        self.authenticated
    }

    async fn create_connection(&mut self) -> Result<quinn::Connection> {
        // 构建 TLS 配置（复用 common::tls）
        let tls_config = crate::common::tls::build_tls_config(self.allow_insecure, None)?;
        let mut client_config = quinn::ClientConfig::new(Arc::new(
            quinn::crypto::rustls::QuicClientConfig::try_from(tls_config)?,
        ));

        // 启用 datagram 支持（UDP 代理需要）
        let mut transport_config = quinn::TransportConfig::default();
        transport_config.max_idle_timeout(Some(
            quinn::IdleTimeout::try_from(std::time::Duration::from_secs(30)).unwrap(),
        ));
        transport_config.keep_alive_interval(Some(std::time::Duration::from_secs(15)));
        transport_config.datagram_receive_buffer_size(Some(1350 * 256));
        client_config.transport_config(Arc::new(transport_config));

        // 创建 endpoint
        let mut endpoint = quinn::Endpoint::client("0.0.0.0:0".parse::<SocketAddr>()?)?;
        endpoint.set_default_client_config(client_config);

        // 解析服务器地址
        let addr_str = format!("{}:{}", self.server_addr, self.server_port);
        let server_addr: SocketAddr = tokio::net::lookup_host(&addr_str)
            .await?
            .next()
            .ok_or_else(|| anyhow::anyhow!("failed to resolve {}", addr_str))?;

        // 连接
        let conn = endpoint.connect(server_addr, &self.sni)?.await?;
        tracing::debug!(addr = %server_addr, "QUIC connection established");

        self.endpoint = Some(endpoint);
        Ok(conn)
    }
}

/// 将 QUIC 双向流包装为 AsyncRead + AsyncWrite
pub struct QuicBiStream {
    send: quinn::SendStream,
    recv: quinn::RecvStream,
}

impl QuicBiStream {
    pub fn new(send: quinn::SendStream, recv: quinn::RecvStream) -> Self {
        Self { send, recv }
    }
}

impl AsyncRead for QuicBiStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.recv).poll_read(cx, buf)
    }
}

impl AsyncWrite for QuicBiStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        tokio::io::AsyncWrite::poll_write(Pin::new(&mut self.send), cx, buf)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        tokio::io::AsyncWrite::poll_flush(Pin::new(&mut self.send), cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<()>> {
        tokio::io::AsyncWrite::poll_shutdown(Pin::new(&mut self.send), cx)
    }
}
