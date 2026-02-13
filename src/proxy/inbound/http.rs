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
        let request_line = request_line.trim().to_string();

        // 解析 "METHOD target HTTP/1.x"
        let parts: Vec<&str> = request_line.split_whitespace().collect();
        if parts.len() < 3 {
            bail!("无效的 HTTP 请求行: {}", request_line);
        }

        let method = parts[0];
        let http_version = parts[2];

        // 读取所有 headers
        let mut headers = Vec::new();
        let mut proxy_auth: Option<String> = None;
        let mut host_header: Option<String> = None;
        let mut content_length: usize = 0;
        loop {
            let mut line = String::new();
            reader.read_line(&mut line).await?;
            if line.trim().is_empty() {
                break;
            }
            let lower = line.to_ascii_lowercase();
            if lower.starts_with("proxy-authorization:") {
                let value = line["proxy-authorization:".len()..].trim().to_string();
                proxy_auth = Some(value);
                continue; // 不转发 Proxy-Authorization
            }
            if lower.starts_with("proxy-connection:") {
                continue; // 不转发 Proxy-Connection
            }
            if lower.starts_with("host:") {
                host_header = Some(line["host:".len()..].trim().to_string());
            }
            if lower.starts_with("content-length:") {
                if let Ok(len) = line["content-length:".len()..].trim().parse::<usize>() {
                    content_length = len;
                }
            }
            headers.push(line);
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
                bail!("HTTP 代理认证失败");
            }
        }

        if method.eq_ignore_ascii_case("CONNECT") {
            // ─── CONNECT 隧道模式 ───
            let target = parse_connect_target(parts[1])?;
            debug!(target = %target, "HTTP CONNECT 请求");

            let mut stream = reader.into_inner();
            stream.write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n").await?;

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
        } else {
            // ─── 普通 HTTP 请求（GET/POST/PUT/DELETE/HEAD/OPTIONS/PATCH 等）───
            let raw_url = parts[1];
            let (target, relative_path) = parse_http_url(raw_url, host_header.as_deref())?;

            debug!(method = method, target = %target, path = %relative_path, "HTTP 正向代理请求");

            // 重构请求：绝对 URL → 相对路径
            let mut reconstructed = format!("{} {} {}\r\n", method, relative_path, http_version);
            for h in &headers {
                reconstructed.push_str(h);
                // headers 自带换行符
            }
            reconstructed.push_str("\r\n");

            // 如果有请求体（POST 等），也要读取
            let mut body_data = Vec::new();
            if content_length > 0 {
                body_data.resize(content_length, 0);
                use tokio::io::AsyncReadExt;
                reader.read_exact(&mut body_data).await?;
            }

            // 将重构的请求 + body 预置到流前面
            let mut prefix = reconstructed.into_bytes();
            prefix.extend_from_slice(&body_data);

            let inner_stream = reader.into_inner();
            let prefixed_stream = crate::common::PrefixedStream::new(prefix, inner_stream);

            let session = Session {
                target,
                source: Some(source),
                inbound_tag: self.tag.clone(),
                network: Network::Tcp,
                sniff: false,
                detected_protocol: Some("http".to_string()),
            };

            Ok(InboundResult {
                session,
                stream: Box::new(prefixed_stream),
                udp_transport: None,
            })
        }
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

/// 解析 HTTP 正向代理的绝对 URL，提取目标地址和相对路径
///
/// 输入: "http://example.com:8080/path?q=1" → (Address::Domain("example.com", 8080), "/path?q=1")
/// 输入: "http://example.com/path" → (Address::Domain("example.com", 80), "/path")
/// 输入: "/path" (相对路径) + Host header → (Address from Host, "/path")
fn parse_http_url(url: &str, host_header: Option<&str>) -> Result<(Address, String)> {
    // 已经是相对路径，从 Host header 获取目标
    if url.starts_with('/') {
        let host = host_header
            .ok_or_else(|| anyhow::anyhow!("相对路径 URL 但缺少 Host header"))?;
        let target = parse_host_port(host, 80)?;
        return Ok((target, url.to_string()));
    }

    // 绝对 URL: http://host[:port]/path
    let without_scheme = url
        .strip_prefix("http://")
        .or_else(|| url.strip_prefix("HTTP://"))
        .ok_or_else(|| anyhow::anyhow!("HTTP 正向代理仅支持 http:// URL, 收到: {}", url))?;

    let (host_port, path) = match without_scheme.find('/') {
        Some(pos) => (&without_scheme[..pos], &without_scheme[pos..]),
        None => (without_scheme, "/"),
    };

    let target = parse_host_port(host_port, 80)?;
    Ok((target, path.to_string()))
}

/// 解析 host[:port] 字符串，支持默认端口
fn parse_host_port(s: &str, default_port: u16) -> Result<Address> {
    // host:port
    if let Some((host, port_str)) = s.rsplit_once(':') {
        // 排除 IPv6 (如 [::1]:80 — 但这种情况下 rsplit_once 会在 ] 后面分割)
        if let Ok(port) = port_str.parse::<u16>() {
            if let Ok(ip) = host.parse::<std::net::IpAddr>() {
                return Ok(Address::Ip(SocketAddr::new(ip, port)));
            }
            return Ok(Address::Domain(host.to_string(), port));
        }
    }

    // 没有端口号，使用默认端口
    if let Ok(ip) = s.parse::<std::net::IpAddr>() {
        return Ok(Address::Ip(SocketAddr::new(ip, default_port)));
    }
    Ok(Address::Domain(s.to_string(), default_port))
}

#[cfg(test)]
mod http_url_tests {
    use super::*;

    #[test]
    fn parse_absolute_url_with_port() {
        let (addr, path) = parse_http_url("http://example.com:8080/path?q=1", None).unwrap();
        assert_eq!(addr, Address::Domain("example.com".to_string(), 8080));
        assert_eq!(path, "/path?q=1");
    }

    #[test]
    fn parse_absolute_url_default_port() {
        let (addr, path) = parse_http_url("http://example.com/index.html", None).unwrap();
        assert_eq!(addr, Address::Domain("example.com".to_string(), 80));
        assert_eq!(path, "/index.html");
    }

    #[test]
    fn parse_absolute_url_no_path() {
        let (addr, path) = parse_http_url("http://example.com", None).unwrap();
        assert_eq!(addr, Address::Domain("example.com".to_string(), 80));
        assert_eq!(path, "/");
    }

    #[test]
    fn parse_relative_with_host() {
        let (addr, path) = parse_http_url("/api/v1", Some("api.example.com:3000")).unwrap();
        assert_eq!(addr, Address::Domain("api.example.com".to_string(), 3000));
        assert_eq!(path, "/api/v1");
    }

    #[test]
    fn parse_relative_without_host_fails() {
        assert!(parse_http_url("/path", None).is_err());
    }

    #[test]
    fn parse_https_url_fails() {
        assert!(parse_http_url("https://example.com/", None).is_err());
    }
}
