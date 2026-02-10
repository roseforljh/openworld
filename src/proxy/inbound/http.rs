use std::net::SocketAddr;

use anyhow::{bail, Result};
use async_trait::async_trait;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tracing::debug;

use crate::common::{Address, ProxyStream};
use crate::proxy::{InboundHandler, InboundResult, Network, Session};

pub struct HttpInbound {
    tag: String,
}

impl HttpInbound {
    pub fn new(tag: String) -> Self {
        Self { tag }
    }
}

#[async_trait]
impl InboundHandler for HttpInbound {
    fn tag(&self) -> &str {
        &self.tag
    }

    async fn handle(&self, stream: ProxyStream, source: SocketAddr) -> Result<InboundResult> {
        let mut reader = BufReader::new(stream);

        // 读取请求行
        let mut request_line = String::new();
        reader.read_line(&mut request_line).await?;
        let request_line = request_line.trim();

        // 解析 "CONNECT host:port HTTP/1.1"
        let parts: Vec<&str> = request_line.split_whitespace().collect();
        if parts.len() < 3 {
            bail!("invalid HTTP request line: {}", request_line);
        }

        let method = parts[0];
        if method != "CONNECT" {
            bail!("unsupported HTTP method: {}, only CONNECT is supported", method);
        }

        let target_str = parts[1];
        let target = parse_connect_target(target_str)?;

        debug!(target = %target, "HTTP CONNECT request");

        // 读取并丢弃所有 headers（直到空行）
        loop {
            let mut line = String::new();
            reader.read_line(&mut line).await?;
            if line.trim().is_empty() {
                break;
            }
        }

        // 回复 200 Connection Established
        let mut stream = reader.into_inner();
        stream
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await?;

        let session = Session {
            target,
            source: Some(source),
            inbound_tag: self.tag.clone(),
            network: Network::Tcp,
            sniff: false,
        };

        Ok(InboundResult { session, stream, udp_transport: None })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_domain() {
        let addr = parse_connect_target("example.com:443").unwrap();
        assert_eq!(addr, Address::Domain("example.com".to_string(), 443));
    }

    #[test]
    fn parse_ipv4() {
        let addr = parse_connect_target("127.0.0.1:8080").unwrap();
        assert_eq!(addr, Address::Ip("127.0.0.1:8080".parse().unwrap()));
    }

    #[test]
    fn parse_ipv6_bracket() {
        let addr = parse_connect_target("[::1]:443").unwrap();
        assert_eq!(addr, Address::Ip("[::1]:443".parse().unwrap()));
    }

    #[test]
    fn parse_no_port() {
        assert!(parse_connect_target("example.com").is_err());
    }

    #[test]
    fn parse_invalid_port() {
        assert!(parse_connect_target("example.com:abc").is_err());
    }

    #[test]
    fn parse_empty() {
        assert!(parse_connect_target("").is_err());
    }
}

/// 解析 CONNECT 目标地址 "host:port"
fn parse_connect_target(s: &str) -> Result<Address> {
    // 尝试解析为 SocketAddr（处理 IP 地址情况）
    if let Ok(addr) = s.parse::<SocketAddr>() {
        return Ok(Address::Ip(addr));
    }

    // 解析为 host:port
    let (host, port_str) = s
        .rsplit_once(':')
        .ok_or_else(|| anyhow::anyhow!("invalid CONNECT target: {}", s))?;

    let port: u16 = port_str.parse()?;

    // 尝试解析为 IP
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        return Ok(Address::Ip(SocketAddr::new(ip, port)));
    }

    // 域名
    Ok(Address::Domain(host.to_string(), port))
}
