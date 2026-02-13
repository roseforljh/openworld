use anyhow::Result;
use async_trait::async_trait;

use crate::common::{Address, DialerConfig, ProxyStream};

use super::StreamTransport;

/// 纯 TCP 传输（无加密）
pub struct TcpTransport {
    server_addr: String,
    server_port: u16,
    dialer_config: Option<DialerConfig>,
}

impl TcpTransport {
    pub fn new(server_addr: String, server_port: u16, dialer_config: Option<DialerConfig>) -> Self {
        Self {
            server_addr,
            server_port,
            dialer_config,
        }
    }
}

#[async_trait]
impl StreamTransport for TcpTransport {
    async fn connect(&self, _addr: &Address) -> Result<ProxyStream> {
        let tcp = super::dial_tcp(
            &self.server_addr,
            self.server_port,
            &self.dialer_config,
            None,
        )
        .await?;
        Ok(Box::new(tcp))
    }
}
