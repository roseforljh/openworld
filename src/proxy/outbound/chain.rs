use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::debug;

use crate::common::{Address, ProxyStream};
use crate::config::types::{OutboundConfig, OutboundSettings};
use crate::proxy::outbound::trojan::protocol as trojan_protocol;
use crate::proxy::outbound::vless::{protocol as vless_protocol, vision as vless_vision, XRV};
use crate::proxy::{OutboundHandler, Session};
use crate::proxy::group::health::HealthChecker;

/// A proxy chain that routes traffic through a series of outbound proxies.
/// The chain connects through each proxy in order: A -> B -> C -> target.
pub struct ProxyChain {
    tag: String,
    chain: Vec<Arc<dyn OutboundHandler>>,
}

impl ProxyChain {
    pub fn new(tag: String, chain: Vec<Arc<dyn OutboundHandler>>) -> Result<Self> {
        if chain.is_empty() {
            anyhow::bail!("proxy chain requires at least one outbound");
        }
        Ok(Self { tag, chain })
    }

    pub fn chain_tags(&self) -> Vec<&str> {
        self.chain.iter().map(|h| h.tag()).collect()
    }

    pub fn chain_len(&self) -> usize {
        self.chain.len()
    }

    /// 逐跳健康检查：chain[0] → chain[1] → ... → target
    /// 任意一跳失败则标记整条链为不可用
    pub async fn health_check(&self, url: &str, timeout_ms: u64) -> ChainHealthResult {
        let timeout = Duration::from_millis(timeout_ms);
        let mut hop_results = Vec::new();

        for (idx, proxy) in self.chain.iter().enumerate() {
            let latency = HealthChecker::test_proxy(proxy.as_ref(), url, timeout).await;
            let hop_name = proxy.tag().to_string();
            let healthy = latency.is_some();

            debug!(
                chain = self.tag,
                hop = idx,
                proxy = hop_name,
                latency = ?latency,
                "chain health check hop"
            );

            hop_results.push(HopResult {
                name: hop_name,
                latency,
                healthy,
            });

            if !healthy {
                // 一跳失败，整条链不可用
                return ChainHealthResult {
                    chain_tag: self.tag.clone(),
                    healthy: false,
                    hops: hop_results,
                    total_latency: None,
                };
            }
        }

        let total: u64 = hop_results.iter().filter_map(|h| h.latency).sum();
        ChainHealthResult {
            chain_tag: self.tag.clone(),
            healthy: true,
            hops: hop_results,
            total_latency: Some(total),
        }
    }

    fn build_hop_session(base: &Session, target: Address) -> Session {
        Session {
            target,
            source: base.source,
            inbound_tag: base.inbound_tag.clone(),
            network: base.network,
            sniff: base.sniff,
            detected_protocol: None,
        }
    }

    fn config_path() -> String {
        if let Ok(path) = std::env::var("OPENWORLD_CONFIG_PATH") {
            if !path.trim().is_empty() {
                return path;
            }
        }

        std::env::args()
            .nth(1)
            .unwrap_or_else(|| "config.yaml".to_string())
    }

    fn load_outbound_config_map() -> Result<HashMap<String, OutboundConfig>> {
        let path = Self::config_path();
        let config = crate::config::load_config(&path)?;

        Ok(config
            .outbounds
            .into_iter()
            .map(|ob| (ob.tag.clone(), ob))
            .collect())
    }

    fn resolve_hop_server_target(outbound: &OutboundConfig) -> Result<Address> {
        let protocol = outbound.protocol.to_lowercase();
        let settings = &outbound.settings;

        match protocol.as_str() {
            "tor" => {
                let host = settings
                    .address
                    .clone()
                    .unwrap_or_else(|| "127.0.0.1".to_string());
                let port = settings.socks_port.unwrap_or(9050);
                Ok(Address::Domain(host, port))
            }
            "direct" => anyhow::bail!(
                "chain hop '{}' uses direct and has no server endpoint",
                outbound.tag
            ),
            _ => {
                let address = settings.address.as_ref().ok_or_else(|| {
                    anyhow::anyhow!(
                        "chain hop '{}' missing address in outbound settings",
                        outbound.tag
                    )
                })?;
                let port = settings.port.ok_or_else(|| {
                    anyhow::anyhow!(
                        "chain hop '{}' missing port in outbound settings",
                        outbound.tag
                    )
                })?;
                Ok(Address::Domain(address.clone(), port))
            }
        }
    }

    async fn connect_intermediate_hop(
        stream: ProxyStream,
        outbound: &OutboundConfig,
        session: &Session,
    ) -> Result<ProxyStream> {
        let protocol = outbound.protocol.to_lowercase();
        match protocol.as_str() {
            "http" | "https" => {
                Self::http_connect_over_stream(stream, &session.target, &outbound.settings).await
            }
            "tor" => Self::socks5_connect_over_stream(stream, &session.target).await,
            "vless" => Self::vless_connect_over_stream(stream, &session.target, &outbound.settings).await,
            "trojan" => {
                Self::trojan_connect_over_stream(stream, &session.target, &outbound.settings).await
            }
            other => anyhow::bail!(
                "chain intermediate hop '{}' protocol '{}' is not supported yet",
                outbound.tag,
                other
            ),
        }
    }

    async fn http_connect_over_stream(
        mut stream: ProxyStream,
        target: &Address,
        settings: &OutboundSettings,
    ) -> Result<ProxyStream> {
        let target_str = match target {
            Address::Domain(domain, port) => format!("{}:{}", domain, port),
            Address::Ip(addr) => addr.to_string(),
        };

        let mut request = format!("CONNECT {} HTTP/1.1\r\nHost: {}\r\n", target_str, target_str);

        if let (Some(user), Some(pass)) = (&settings.uuid, &settings.password) {
            use base64::Engine;
            let cred = base64::engine::general_purpose::STANDARD.encode(format!("{}:{}", user, pass));
            request.push_str(&format!("Proxy-Authorization: Basic {}\r\n", cred));
        }

        request.push_str("\r\n");
        stream.write_all(request.as_bytes()).await?;

        let mut header = Vec::with_capacity(512);
        let mut buf = [0u8; 1];
        while header.len() < 16 * 1024 {
            let n = stream.read(&mut buf).await?;
            if n == 0 {
                anyhow::bail!("http CONNECT failed: unexpected EOF");
            }
            header.push(buf[0]);
            if header.ends_with(b"\r\n\r\n") {
                break;
            }
        }

        if !header.ends_with(b"\r\n\r\n") {
            anyhow::bail!("http CONNECT failed: response header too large");
        }

        let header_text = String::from_utf8_lossy(&header);
        let status_line = header_text.lines().next().unwrap_or_default();
        let status_code = status_line
            .split_whitespace()
            .nth(1)
            .and_then(|s| s.parse::<u16>().ok())
            .ok_or_else(|| anyhow::anyhow!("http CONNECT failed: invalid response '{}'", status_line))?;

        if status_code != 200 {
            anyhow::bail!("http CONNECT failed: {}", status_line);
        }

        Ok(stream)
    }

    async fn socks5_connect_over_stream(mut stream: ProxyStream, target: &Address) -> Result<ProxyStream> {
        stream.write_all(&[0x05, 0x01, 0x00]).await?;

        let mut auth_resp = [0u8; 2];
        stream.read_exact(&mut auth_resp).await?;
        if auth_resp != [0x05, 0x00] {
            anyhow::bail!("SOCKS5 auth failed: {:?}", auth_resp);
        }

        let mut req = vec![0x05, 0x01, 0x00];
        match target {
            Address::Ip(addr) => {
                match addr.ip() {
                    std::net::IpAddr::V4(v4) => {
                        req.push(0x01);
                        req.extend_from_slice(&v4.octets());
                    }
                    std::net::IpAddr::V6(v6) => {
                        req.push(0x04);
                        req.extend_from_slice(&v6.octets());
                    }
                }
                req.extend_from_slice(&addr.port().to_be_bytes());
            }
            Address::Domain(domain, port) => {
                req.push(0x03);
                req.push(domain.len() as u8);
                req.extend_from_slice(domain.as_bytes());
                req.extend_from_slice(&port.to_be_bytes());
            }
        }

        stream.write_all(&req).await?;

        let mut resp = [0u8; 4];
        stream.read_exact(&mut resp).await?;
        if resp[1] != 0x00 {
            anyhow::bail!("SOCKS5 CONNECT failed: reply={}", resp[1]);
        }

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

        Ok(stream)
    }

    async fn maybe_wrap_tls(
        stream: ProxyStream,
        settings: &OutboundSettings,
        mut tls_config: crate::config::types::TlsConfig,
    ) -> Result<ProxyStream> {
        let transport = settings.effective_transport();
        if transport.transport_type != "tcp" && !transport.transport_type.is_empty() {
            anyhow::bail!(
                "chain intermediate hop only supports tcp transport, got '{}'",
                transport.transport_type
            );
        }

        if tls_config.sni.is_none() {
            tls_config.sni = settings.address.clone();
        }

        if !tls_config.enabled {
            return Ok(stream);
        }

        if tls_config.security == "reality" {
            anyhow::bail!("chain intermediate hop does not support reality transport");
        }

        let alpn_holder = tls_config
            .alpn
            .as_ref()
            .map(|v| v.iter().map(|s| s.as_str()).collect::<Vec<_>>());
        let client_config = crate::common::tls::build_tls_config(
            tls_config.allow_insecure,
            alpn_holder.as_deref(),
        )?;

        let sni = tls_config.sni.ok_or_else(|| anyhow::anyhow!("TLS SNI is required"))?;
        let server_name = rustls::pki_types::ServerName::try_from(sni)?;
        let connector = tokio_rustls::TlsConnector::from(Arc::new(client_config));
        let tls_stream = connector.connect(server_name, stream).await?;
        Ok(Box::new(tls_stream))
    }

    async fn vless_connect_over_stream(
        stream: ProxyStream,
        target: &Address,
        settings: &OutboundSettings,
    ) -> Result<ProxyStream> {
        let flow = settings.flow.clone();
        let mut tls_config = settings.effective_tls();
        if !tls_config.enabled && settings.security.is_some() {
            tls_config.enabled = true;
        }
        if flow.as_deref() == Some(XRV) && tls_config.alpn.is_none() {
            tls_config.alpn = Some(vec!["h2".to_string(), "http/1.1".to_string()]);
        }

        let mut stream = Self::maybe_wrap_tls(stream, settings, tls_config).await?;

        let uuid_str = settings
            .uuid
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("vless chain hop missing uuid"))?;
        let uuid = uuid_str.parse::<uuid::Uuid>()?;

        vless_protocol::write_request(
            &mut stream,
            &uuid,
            target,
            flow.as_deref(),
            vless_protocol::CMD_TCP,
        )
        .await?;

        vless_protocol::read_response(&mut stream).await?;

        if flow.as_deref() == Some(XRV) {
            Ok(Box::new(vless_vision::VisionStream::new(stream, uuid)))
        } else {
            Ok(stream)
        }
    }

    async fn trojan_connect_over_stream(
        stream: ProxyStream,
        target: &Address,
        settings: &OutboundSettings,
    ) -> Result<ProxyStream> {
        let mut tls_config = settings.effective_tls();
        if !tls_config.enabled && settings.security.is_none() {
            tls_config.enabled = true;
        }
        if !tls_config.enabled && settings.security.as_deref() == Some("tls") {
            tls_config.enabled = true;
        }

        let mut stream = Self::maybe_wrap_tls(stream, settings, tls_config).await?;

        let password = settings
            .password
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("trojan chain hop missing password"))?;
        let password_hash = trojan_protocol::password_hash(password);

        trojan_protocol::write_request(
            &mut stream,
            &password_hash,
            target,
            trojan_protocol::CMD_CONNECT,
        )
        .await?;

        Ok(stream)
    }
}

/// 链健康检查结果
#[derive(Debug, Clone)]
pub struct ChainHealthResult {
    pub chain_tag: String,
    pub healthy: bool,
    pub hops: Vec<HopResult>,
    pub total_latency: Option<u64>,
}

/// 单跳健康检查结果
#[derive(Debug, Clone)]
pub struct HopResult {
    pub name: String,
    pub latency: Option<u64>,
    pub healthy: bool,
}

#[async_trait]
impl OutboundHandler for ProxyChain {
    fn tag(&self) -> &str {
        &self.tag
    }

    async fn connect(&self, session: &Session) -> Result<ProxyStream> {
        if self.chain.len() == 1 {
            return self.chain[0].connect(session).await;
        }

        let config_map = Self::load_outbound_config_map()?;
        let last = self.chain.len() - 1;

        let first_next_tag = self.chain[1].tag();
        let first_next_outbound = config_map.get(first_next_tag).ok_or_else(|| {
            anyhow::anyhow!(
                "chain '{}' cannot resolve config for next hop '{}'",
                self.tag,
                first_next_tag
            )
        })?;
        let first_target = Self::resolve_hop_server_target(first_next_outbound)?;
        let first_session = Self::build_hop_session(session, first_target);

        debug!(chain = self.tag, hop = 0, proxy = self.chain[0].tag(), target = %first_session.target, "chain connect hop");

        let mut stream = self.chain[0].connect(&first_session).await?;

        for idx in 1..=last {
            let hop = &self.chain[idx];
            let hop_outbound = config_map.get(hop.tag()).ok_or_else(|| {
                anyhow::anyhow!(
                    "chain '{}' cannot resolve config for hop '{}'",
                    self.tag,
                    hop.tag()
                )
            })?;

            let hop_target = if idx == last {
                session.target.clone()
            } else {
                let next_tag = self.chain[idx + 1].tag();
                let next_outbound = config_map.get(next_tag).ok_or_else(|| {
                    anyhow::anyhow!(
                        "chain '{}' cannot resolve config for next hop '{}'",
                        self.tag,
                        next_tag
                    )
                })?;
                Self::resolve_hop_server_target(next_outbound)?
            };

            let hop_session = Self::build_hop_session(session, hop_target);

            debug!(chain = self.tag, hop = idx, proxy = hop.tag(), target = %hop_session.target, "chain connect hop");

            stream = Self::connect_intermediate_hop(stream, hop_outbound, &hop_session).await?;
        }

        Ok(stream)
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proxy::outbound::direct::DirectOutbound;

    #[test]
    fn proxy_chain_creation() {
        let direct1 = Arc::new(DirectOutbound::new("hop1".to_string())) as Arc<dyn OutboundHandler>;
        let direct2 = Arc::new(DirectOutbound::new("hop2".to_string())) as Arc<dyn OutboundHandler>;
        let chain = ProxyChain::new("chain".to_string(), vec![direct1, direct2]).unwrap();
        assert_eq!(chain.tag(), "chain");
        assert_eq!(chain.chain_len(), 2);
        assert_eq!(chain.chain_tags(), vec!["hop1", "hop2"]);
    }

    #[test]
    fn proxy_chain_empty_fails() {
        let result = ProxyChain::new("empty".to_string(), vec![]);
        assert!(result.is_err());
    }

    #[test]
    fn proxy_chain_single_hop() {
        let direct = Arc::new(DirectOutbound::new("hop1".to_string())) as Arc<dyn OutboundHandler>;
        let chain = ProxyChain::new("single".to_string(), vec![direct]).unwrap();
        assert_eq!(chain.chain_len(), 1);
    }

    #[tokio::test]
    async fn proxy_chain_health_check_all_pass() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        // Spawn a minimal HTTP server
        let accept_handle = tokio::spawn(async move {
            loop {
                if let Ok((mut stream, _)) = listener.accept().await {
                    use tokio::io::{AsyncReadExt, AsyncWriteExt};
                    let mut buf = [0u8; 1024];
                    let _ = stream.read(&mut buf).await;
                    let _ = stream.write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n").await;
                }
            }
        });

        let direct = Arc::new(DirectOutbound::new("direct".to_string())) as Arc<dyn OutboundHandler>;
        let chain = ProxyChain::new("chain".to_string(), vec![direct]).unwrap();
        let url = format!("http://127.0.0.1:{}/generate_204", addr.port());
        let result = chain.health_check(&url, 5000).await;
        assert!(result.healthy);
        assert_eq!(result.hops.len(), 1);
        assert!(result.hops[0].healthy);
        assert!(result.total_latency.is_some());

        accept_handle.abort();
    }

    #[tokio::test]
    async fn proxy_chain_health_check_hop_fails() {
        let direct = Arc::new(DirectOutbound::new("direct".to_string())) as Arc<dyn OutboundHandler>;
        let chain = ProxyChain::new("chain".to_string(), vec![direct]).unwrap();
        // Use an unreachable URL with short timeout to trigger failure
        let result = chain.health_check("http://192.0.2.1:1/fail", 100).await;
        assert!(!result.healthy);
        assert!(result.total_latency.is_none());
        assert!(!result.hops.is_empty());
        assert!(!result.hops[0].healthy);
    }

    #[tokio::test]
    async fn proxy_chain_connect() {
        use crate::common::Address;
        use crate::proxy::Network;
        use std::net::SocketAddr;

        let direct = Arc::new(DirectOutbound::new("direct".to_string())) as Arc<dyn OutboundHandler>;
        let chain = ProxyChain::new("chain".to_string(), vec![direct]).unwrap();

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let session = Session {
            target: Address::Ip(addr),
            source: Some("127.0.0.1:12345".parse::<SocketAddr>().unwrap()),
            inbound_tag: "test".to_string(),
            network: Network::Tcp,
            sniff: false,
            detected_protocol: None,
        };
        let result = chain.connect(&session).await;
        assert!(result.is_ok());
    }
}
