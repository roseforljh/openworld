use anyhow::Result;
use async_trait::async_trait;
use tokio::net::TcpStream;
use tracing::debug;

use crate::common::{Address, BoxUdpTransport, Dialer, DialerConfig, ProxyStream};
use crate::config::types::OutboundConfig;
use crate::proxy::{OutboundHandler, Session};

/// Tor 出站：通过本地 SOCKS5 代理连接 Tor 网络
pub struct TorOutbound {
    tag: String,
    socks_host: String,
    socks_port: u16,
    dialer_config: Option<DialerConfig>,
}

impl TorOutbound {
    pub fn new(config: &OutboundConfig) -> Result<Self> {
        let socks_port = config.settings.socks_port.unwrap_or(9050);
        let socks_host = config
            .settings
            .address
            .as_deref()
            .unwrap_or("127.0.0.1")
            .to_string();
        let socks_addr = format!("{}:{}", socks_host, socks_port);

        debug!(tag = config.tag, addr = %socks_addr, "tor outbound created");

        Ok(Self {
            tag: config.tag.clone(),
            socks_host,
            socks_port,
            dialer_config: config.settings.dialer.clone(),
        })
    }

    /// 执行 SOCKS5 握手连接到 Tor 代理
    async fn socks5_connect(&self, target: &Address) -> Result<TcpStream> {
        let dialer = match &self.dialer_config {
            Some(cfg) => Dialer::new(cfg.clone()),
            None => Dialer::default_dialer(),
        };
        let stream = dialer
            .connect_host(&self.socks_host, self.socks_port)
            .await
            .map_err(|e| {
                anyhow::anyhow!(
                    "failed to connect to tor socks5 at {}:{}: {}",
                    self.socks_host,
                    self.socks_port,
                    e
                )
            })?;

        // SOCKS5 握手: 无认证
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut stream = stream;

        // 发送: VER(5) NMETHODS(1) METHOD(0=NoAuth)
        stream.write_all(&[0x05, 0x01, 0x00]).await?;

        // 接收: VER(5) METHOD(0)
        let mut resp = [0u8; 2];
        stream.read_exact(&mut resp).await?;
        if resp[0] != 0x05 || resp[1] != 0x00 {
            anyhow::bail!("tor socks5 auth failed: {:?}", resp);
        }

        // 发送 CONNECT 请求
        let mut req = vec![0x05, 0x01, 0x00]; // VER, CMD=CONNECT, RSV
        match target {
            Address::Ip(addr) => {
                match addr.ip() {
                    std::net::IpAddr::V4(v4) => {
                        req.push(0x01); // ATYP=IPv4
                        req.extend_from_slice(&v4.octets());
                    }
                    std::net::IpAddr::V6(v6) => {
                        req.push(0x04); // ATYP=IPv6
                        req.extend_from_slice(&v6.octets());
                    }
                }
                req.extend_from_slice(&addr.port().to_be_bytes());
            }
            Address::Domain(domain, port) => {
                req.push(0x03); // ATYP=Domain
                req.push(domain.len() as u8);
                req.extend_from_slice(domain.as_bytes());
                req.extend_from_slice(&port.to_be_bytes());
            }
        }
        stream.write_all(&req).await?;

        // 接收 CONNECT 响应
        let mut resp = [0u8; 4];
        stream.read_exact(&mut resp).await?;
        if resp[1] != 0x00 {
            anyhow::bail!("tor socks5 connect failed: reply={}", resp[1]);
        }

        // 跳过绑定地址
        match resp[3] {
            0x01 => {
                let mut buf = [0u8; 6];
                stream.read_exact(&mut buf).await?;
            }
            0x03 => {
                let mut len = [0u8; 1];
                stream.read_exact(&mut len).await?;
                let mut buf = vec![0u8; len[0] as usize + 2];
                stream.read_exact(&mut buf).await?;
            }
            0x04 => {
                let mut buf = [0u8; 18];
                stream.read_exact(&mut buf).await?;
            }
            _ => {}
        }

        debug!(tag = self.tag, "tor socks5 connect established");
        Ok(stream)
    }
}

#[async_trait]
impl OutboundHandler for TorOutbound {
    fn tag(&self) -> &str {
        &self.tag
    }

    async fn connect(&self, session: &Session) -> Result<ProxyStream> {
        let stream = self.socks5_connect(&session.target).await?;
        Ok(Box::new(stream))
    }

    async fn connect_udp(&self, _session: &Session) -> Result<BoxUdpTransport> {
        anyhow::bail!("tor does not support UDP")
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::types::OutboundSettings;

    #[test]
    fn tor_outbound_creation_default_port() {
        let config = OutboundConfig {
            tag: "tor".to_string(),
            protocol: "tor".to_string(),
            settings: OutboundSettings::default(),
        };
        let outbound = TorOutbound::new(&config).unwrap();
        assert_eq!(outbound.tag(), "tor");
        assert_eq!(outbound.socks_host, "127.0.0.1");
        assert_eq!(outbound.socks_port, 9050);
    }

    #[test]
    fn tor_outbound_creation_custom_port() {
        let config = OutboundConfig {
            tag: "tor-custom".to_string(),
            protocol: "tor".to_string(),
            settings: OutboundSettings {
                address: Some("192.168.1.1".to_string()),
                socks_port: Some(9150),
                ..Default::default()
            },
        };
        let outbound = TorOutbound::new(&config).unwrap();
        assert_eq!(outbound.socks_host, "192.168.1.1");
        assert_eq!(outbound.socks_port, 9150);
    }

    #[test]
    fn tor_socks5_address_building() {
        let config = OutboundConfig {
            tag: "tor-addr".to_string(),
            protocol: "tor".to_string(),
            settings: OutboundSettings {
                socks_port: Some(9050),
                ..Default::default()
            },
        };
        let outbound = TorOutbound::new(&config).unwrap();
        assert_eq!(outbound.socks_port, 9050);
    }
}
