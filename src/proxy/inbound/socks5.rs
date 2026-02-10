use std::net::SocketAddr;

use anyhow::{bail, Result};
use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::debug;

use crate::common::{Address, ProxyStream};
use crate::proxy::{InboundHandler, InboundResult, Network, Session};

pub struct Socks5Inbound {
    tag: String,
}

impl Socks5Inbound {
    pub fn new(tag: String) -> Self {
        Self { tag }
    }
}

#[async_trait]
impl InboundHandler for Socks5Inbound {
    fn tag(&self) -> &str {
        &self.tag
    }

    async fn handle(&self, stream: ProxyStream, source: SocketAddr) -> Result<InboundResult> {
        let mut stream = stream;

        // === 阶段 1: 方法协商 ===
        // 读取版本号
        let ver = read_u8(&mut stream).await?;
        if ver != 0x05 {
            bail!("unsupported SOCKS version: 0x{:02x}", ver);
        }

        // 读取方法数量和方法列表
        let nmethods = read_u8(&mut stream).await? as usize;
        let mut methods = vec![0u8; nmethods];
        stream.read_exact(&mut methods).await?;

        // 回复：选择无认证 (0x00)
        stream.write_all(&[0x05, 0x00]).await?;

        // === 阶段 2: 请求 ===
        let ver = read_u8(&mut stream).await?;
        if ver != 0x05 {
            bail!("invalid SOCKS5 request version: 0x{:02x}", ver);
        }

        let cmd = read_u8(&mut stream).await?;
        if cmd != 0x01 {
            // 仅支持 CONNECT
            // 回复命令不支持
            stream
                .write_all(&[0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await?;
            bail!("unsupported SOCKS5 command: 0x{:02x}", cmd);
        }

        let _rsv = read_u8(&mut stream).await?; // 保留字段

        // 读取地址类型
        let atyp = read_u8(&mut stream).await?;
        let target = match atyp {
            0x01 => {
                // IPv4
                let mut addr = [0u8; 4];
                stream.read_exact(&mut addr).await?;
                let port = read_u16_be(&mut stream).await?;
                Address::from_socks5(0x01, &addr, port)?
            }
            0x03 => {
                // Domain
                let len = read_u8(&mut stream).await? as usize;
                let mut domain = vec![0u8; len];
                stream.read_exact(&mut domain).await?;
                let port = read_u16_be(&mut stream).await?;
                Address::from_socks5(0x03, &domain, port)?
            }
            0x04 => {
                // IPv6
                let mut addr = [0u8; 16];
                stream.read_exact(&mut addr).await?;
                let port = read_u16_be(&mut stream).await?;
                Address::from_socks5(0x04, &addr, port)?
            }
            _ => {
                stream
                    .write_all(&[0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                    .await?;
                bail!("unsupported SOCKS5 address type: 0x{:02x}", atyp);
            }
        };

        debug!(target = %target, "SOCKS5 CONNECT request");

        // 回复成功
        // +----+-----+-------+------+----------+----------+
        // |VER | REP |  RSV  | ATYP | BND.ADDR | BND.PORT |
        // +----+-----+-------+------+----------+----------+
        stream
            .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
            .await?;

        let session = Session {
            target,
            source: Some(source),
            inbound_tag: self.tag.clone(),
            network: Network::Tcp,
        };

        Ok(InboundResult { session, stream })
    }
}

async fn read_u8(stream: &mut ProxyStream) -> Result<u8> {
    let mut buf = [0u8; 1];
    stream.read_exact(&mut buf).await?;
    Ok(buf[0])
}

async fn read_u16_be(stream: &mut ProxyStream) -> Result<u16> {
    let mut buf = [0u8; 2];
    stream.read_exact(&mut buf).await?;
    Ok(u16::from_be_bytes(buf))
}
