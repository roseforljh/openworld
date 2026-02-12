use std::net::SocketAddr;

use anyhow::{bail, Result};
use async_trait::async_trait;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tracing::debug;

use crate::common::{Address, ProxyStream};
use crate::proxy::{InboundHandler, InboundResult, Network, Session};

pub struct HttpInbound {
    tag: String,
    /// 认证用户列表 (username, password)，为空则不要求认证
    auth_users: Vec<(String, String)>,
}

impl HttpInbound {
    pub fn new(tag: String) -> Self {
        Self { tag, auth_users: Vec::new() }
    }

    pub fn with_auth(mut self, users: Vec<(String, String)>) -> Self {
        self.auth_users = users;
        self
    }

    /// 验证 Basic 认证头
    fn verify_basic_auth(&self, auth_value: &str) -> bool {
        let encoded = auth_value.strip_prefix("Basic ").or_else(|| auth_value.strip_prefix("basic "));
        let encoded = match encoded {
            Some(e) => e.trim(),
            None => return false,
        };
        use base64::Engine;
        let decoded = match base64::engine::general_purpose::STANDARD.decode(encoded) {
            Ok(d) => d,
            Err(_) => return false,
        };
        let credential = match String::from_utf8(decoded) {
            Ok(s) => s,
            Err(_) => return false,
        };
        let (username, password) = match credential.split_once(':') {
            Some((u, p)) => (u, p),
            None => return false,
        };
        self.auth_users.iter().any(|(u, p)| u == username && p == password)
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
            bail!(
                "unsupported HTTP method: {}, only CONNECT is supported",
                method
            );
        }

        let target_str = parts[1];
        let target = parse_connect_target(target_str)?;

        debug!(target = %target, "HTTP CONNECT request");

        // 读取 headers，检查认证
        let mut proxy_auth: Option<String> = None;
        loop {
            let mut line = String::new();
            reader.read_line(&mut line).await?;
            if line.trim().is_empty() {
                break;
            }
            // 提取 Proxy-Authorization header（大小写不敏感）
            let lower = line.to_ascii_lowercase();
            if let Some(pos) = lower.find("proxy-authorization:") {
                let value_start = pos + "proxy-authorization:".len();
                proxy_auth = Some(line[value_start..].trim().to_string());
            }
        }

        // 验证认证
        if !self.auth_users.is_empty() {
            let authenticated = if let Some(ref auth_value) = proxy_auth {
                self.verify_basic_auth(auth_value)
            } else {
                false
            };

            if !authenticated {
                let mut stream = reader.into_inner();
                stream.write_all(
                    b"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"proxy\"\r\nContent-Length: 0\r\n\r\n"
                ).await?;
                bail!("HTTP proxy auth failed");
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
            detected_protocol: None,
        };

        Ok(InboundResult {
            session,
            stream,
            udp_transport: None,
        })
    }
}

#[cfg(test)]
#[allow(clippy::items_after_test_module)]
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
