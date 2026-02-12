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
    endpoint: quinn::Endpoint,
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
        // Build TLS config with 0-RTT support and h3 ALPN
        let mut tls_config =
            crate::common::tls::build_tls_config(allow_insecure, Some(&["h3"]))?;
        tls_config.enable_early_data = true;

        let quic_crypto = quinn::crypto::rustls::QuicClientConfig::try_from(tls_config)?;
        let mut client_config = quinn::ClientConfig::new(Arc::new(quic_crypto));

        let mut transport_config = quinn::TransportConfig::default();
        transport_config.max_idle_timeout(Some(
            quinn::IdleTimeout::try_from(std::time::Duration::from_secs(30)).unwrap(),
        ));
        transport_config.keep_alive_interval(Some(std::time::Duration::from_secs(15)));
        transport_config.datagram_receive_buffer_size(Some(1350 * 256));
        client_config.transport_config(Arc::new(transport_config));

        let mut endpoint = quinn::Endpoint::client("0.0.0.0:0".parse::<SocketAddr>()?)?;
        endpoint.set_default_client_config(client_config);

        Ok(Self {
            server_addr,
            server_port,
            sni,
            endpoint,
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

    async fn create_connection(&self) -> Result<quinn::Connection> {
        let addr_str = format!("{}:{}", self.server_addr, self.server_port);
        let server_addr: SocketAddr = tokio::net::lookup_host(&addr_str)
            .await?
            .next()
            .ok_or_else(|| anyhow::anyhow!("failed to resolve {}", addr_str))?;

        let connecting = self.endpoint.connect(server_addr, &self.sni)?;

        // Try 0-RTT for faster connection establishment
        match connecting.into_0rtt() {
            Ok((conn, zero_rtt_accepted)) => {
                tracing::debug!(addr = %server_addr, "QUIC 0-RTT connection initiated");
                tokio::spawn(async move {
                    let accepted = zero_rtt_accepted.await;
                    tracing::debug!(accepted = accepted, "QUIC 0-RTT acceptance result");
                });
                Ok(conn)
            }
            Err(connecting) => {
                let conn = connecting.await?;
                tracing::debug!(addr = %server_addr, "QUIC 1-RTT connection established");
                Ok(conn)
            }
        }
    }

    /// Rebind endpoint to a new UDP socket for connection migration
    pub fn rebind(&self, socket: std::net::UdpSocket) -> std::io::Result<()> {
        self.endpoint.rebind(socket)?;
        tracing::debug!("QUIC endpoint rebound for connection migration");
        Ok(())
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

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        tokio::io::AsyncWrite::poll_flush(Pin::new(&mut self.send), cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        tokio::io::AsyncWrite::poll_shutdown(Pin::new(&mut self.send), cx)
    }
}
