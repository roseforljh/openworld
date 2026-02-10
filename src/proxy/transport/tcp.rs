use anyhow::Result;
use async_trait::async_trait;
use tokio::net::TcpStream;

use crate::common::{Address, ProxyStream};

use super::StreamTransport;

/// 纯 TCP 传输（无加密）
pub struct TcpTransport {
    server_addr: String,
    server_port: u16,
}

impl TcpTransport {
    pub fn new(server_addr: String, server_port: u16) -> Self {
        Self {
            server_addr,
            server_port,
        }
    }
}

#[async_trait]
impl StreamTransport for TcpTransport {
    async fn connect(&self, _addr: &Address) -> Result<ProxyStream> {
        let addr = format!("{}:{}", self.server_addr, self.server_port);
        let tcp = TcpStream::connect(&addr).await?;
        Ok(Box::new(tcp))
    }
}
