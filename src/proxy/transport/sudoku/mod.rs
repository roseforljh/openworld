/// Sudoku 传输层
///
/// 将 Sudoku 流量混淆协议集成为 OpenWorld 的传输层选项。

pub mod grid;
pub mod layout;
pub mod table;
pub mod conn;
pub mod crypto;
pub mod handshake;
pub mod httpmask;

use std::sync::Arc;

use anyhow::Result;
use async_trait::async_trait;

use crate::common::{Address, DialerConfig, ProxyStream};
use super::StreamTransport;

/// Sudoku 传输层配置
pub struct SudokuTransportConfig {
    pub key: String,
    pub aead_method: String,
    pub table_type: String,
    pub custom_table: String,
    pub padding_min: u8,
    pub padding_max: u8,
    pub enable_pure_downlink: bool,
    pub disable_http_mask: bool,
    pub http_mask_host: String,
    pub http_mask_path_root: String,
}

/// Sudoku 传输层
pub struct SudokuTransport {
    server_addr: String,
    server_port: u16,
    config: handshake::SudokuConfig,
    dialer_config: Option<DialerConfig>,
}

impl SudokuTransport {
    pub fn new(
        server_addr: String,
        server_port: u16,
        transport_config: &SudokuTransportConfig,
        dialer_config: Option<DialerConfig>,
    ) -> Result<Self> {
        let tbl = table::Table::new(
            &transport_config.key,
            &transport_config.table_type,
            &transport_config.custom_table,
        )
        .map_err(|e| anyhow::anyhow!("Sudoku table 构建失败: {}", e))?;

        let config = handshake::SudokuConfig {
            key: transport_config.key.clone(),
            aead_method: transport_config.aead_method.clone(),
            table: Arc::new(tbl),
            padding_min: transport_config.padding_min,
            padding_max: transport_config.padding_max,
            enable_pure_downlink: transport_config.enable_pure_downlink,
            disable_http_mask: transport_config.disable_http_mask,
            http_mask_host: transport_config.http_mask_host.clone(),
            http_mask_path_root: transport_config.http_mask_path_root.clone(),
        };

        Ok(SudokuTransport {
            server_addr,
            server_port,
            config,
            dialer_config,
        })
    }
}

#[async_trait]
impl StreamTransport for SudokuTransport {
    async fn connect(&self, addr: &Address) -> Result<ProxyStream> {
        // 建立 TCP 连接
        let tcp = super::dial_tcp(&self.server_addr, self.server_port, &self.dialer_config).await?;
        // 将 TcpStream 包装为 ProxyStream
        let stream: ProxyStream = Box::new(tcp);

        // 解析目标地址
        let (target_host, target_port) = match addr {
            Address::Domain(domain, port) => (domain.clone(), *port),
            Address::Ip(sock) => (sock.ip().to_string(), sock.port()),
        };

        // 执行 Sudoku 握手
        handshake::client_handshake(stream, &self.config, &target_host, target_port).await
    }
}
