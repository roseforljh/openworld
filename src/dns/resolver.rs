use std::net::IpAddr;
use std::sync::Arc;

use anyhow::Result;
use async_trait::async_trait;
use hickory_resolver::config::{
    NameServerConfig, NameServerConfigGroup, Protocol, ResolverConfig, ResolverOpts,
};
use hickory_resolver::TokioAsyncResolver;
use tracing::{debug, info};

use crate::config::types::DnsConfig;

use super::fakeip::FakeIpPool;
use super::DnsResolver;

/// 系统 DNS 解析器（使用 tokio::net::lookup_host）
pub struct SystemResolver;

#[async_trait]
impl DnsResolver for SystemResolver {
    async fn resolve(&self, host: &str) -> Result<Vec<IpAddr>> {
        let addrs: Vec<IpAddr> = tokio::net::lookup_host(format!("{}:0", host))
            .await?
            .map(|a| a.ip())
            .collect();
        if addrs.is_empty() {
            anyhow::bail!("DNS resolution failed: no addresses for {}", host);
        }
        debug!(host = host, count = addrs.len(), "system DNS resolved");
        Ok(addrs)
    }
}

/// 基于 hickory-resolver 的 DNS 解析器
pub struct HickoryResolver {
    resolver: TokioAsyncResolver,
}

impl HickoryResolver {
    pub fn new(address: &str) -> Result<Self> {
        let (config, opts) = parse_dns_address(address)?;
        let resolver = TokioAsyncResolver::tokio(config, opts);
        info!(address = address, "Hickory DNS resolver created");
        Ok(Self { resolver })
    }
}

#[async_trait]
impl DnsResolver for HickoryResolver {
    async fn resolve(&self, host: &str) -> Result<Vec<IpAddr>> {
        let response = self.resolver.lookup_ip(host).await?;
        let addrs: Vec<IpAddr> = response.iter().collect();
        if addrs.is_empty() {
            anyhow::bail!("DNS resolution failed: no addresses for {}", host);
        }
        debug!(host = host, count = addrs.len(), "hickory DNS resolved");
        Ok(addrs)
    }
}

/// 域名分流解析器
pub struct SplitResolver {
    /// (域名后缀列表, 解析器)
    rules: Vec<(Vec<String>, Arc<dyn DnsResolver>)>,
    /// 默认解析器
    default: Arc<dyn DnsResolver>,
}

impl SplitResolver {
    pub fn new(
        rules: Vec<(Vec<String>, Arc<dyn DnsResolver>)>,
        default: Arc<dyn DnsResolver>,
    ) -> Self {
        Self { rules, default }
    }

    fn find_resolver(&self, host: &str) -> &dyn DnsResolver {
        let host_lower = host.to_lowercase();
        for (suffixes, resolver) in &self.rules {
            for suffix in suffixes {
                let suffix_lower = suffix.to_lowercase();
                if host_lower == suffix_lower || host_lower.ends_with(&format!(".{}", suffix_lower))
                {
                    return resolver.as_ref();
                }
            }
        }
        self.default.as_ref()
    }
}

#[async_trait]
impl DnsResolver for SplitResolver {
    async fn resolve(&self, host: &str) -> Result<Vec<IpAddr>> {
        self.find_resolver(host).resolve(host).await
    }
}

/// 解析 DNS 地址配置字符串，返回 ResolverConfig
fn parse_dns_address(address: &str) -> Result<(ResolverConfig, ResolverOpts)> {
    let mut opts = ResolverOpts::default();
    opts.use_hosts_file = false;

    if let Some(quic_addr) = address.strip_prefix("quic://") {
        // DNS over QUIC (RFC 9250)
        let (ip, port) = parse_ip_port(quic_addr, 853)?;
        let ns = NameServerConfig {
            socket_addr: std::net::SocketAddr::new(ip, port),
            protocol: Protocol::Quic,
            tls_dns_name: Some(ip.to_string()),
            trust_negative_responses: true,
            tls_config: None,
            bind_addr: None,
        };
        let config =
            ResolverConfig::from_parts(None, vec![], NameServerConfigGroup::from(vec![ns]));
        Ok((config, opts))
    } else if let Some(tls_addr) = address.strip_prefix("tls://") {
        // DNS over TLS
        let (ip, port) = parse_ip_port(tls_addr, 853)?;
        let ns = NameServerConfig {
            socket_addr: std::net::SocketAddr::new(ip, port),
            protocol: Protocol::Tls,
            tls_dns_name: Some(ip.to_string()),
            trust_negative_responses: true,
            tls_config: None,
            bind_addr: None,
        };
        let config =
            ResolverConfig::from_parts(None, vec![], NameServerConfigGroup::from(vec![ns]));
        Ok((config, opts))
    } else if address.starts_with("https://") {
        // DNS over HTTPS
        let parsed = reqwest::Url::parse(address)
            .map_err(|e| anyhow::anyhow!("invalid DoH URL '{}': {}", address, e))?;
        let host = parsed
            .host_str()
            .ok_or_else(|| anyhow::anyhow!("DoH URL missing host: {}", address))?
            .trim_start_matches('[')
            .trim_end_matches(']')
            .to_string();
        let port = parsed.port().unwrap_or(443);

        let ip: IpAddr = match host.parse() {
            Ok(ip) => ip,
            Err(_) => match host.as_str() {
                "dns.google" | "dns.google.com" => "8.8.8.8".parse().unwrap(),
                "cloudflare-dns.com" => "1.1.1.1".parse().unwrap(),
                "dns.alidns.com" => "223.5.5.5".parse().unwrap(),
                _ => anyhow::bail!(
                    "DoH host '{}' is not a known provider; use IP address instead",
                    host
                ),
            },
        };

        let tls_name = if host.parse::<IpAddr>().is_ok() {
            None
        } else {
            Some(host.clone())
        };

        let ns = NameServerConfig {
            socket_addr: std::net::SocketAddr::new(ip, port),
            protocol: Protocol::Https,
            tls_dns_name: tls_name,
            trust_negative_responses: true,
            tls_config: None,
            bind_addr: None,
        };
        let config =
            ResolverConfig::from_parts(None, vec![], NameServerConfigGroup::from(vec![ns]));
        Ok((config, opts))
    } else {
        // UDP DNS
        let (ip, port) = parse_ip_port(address, 53)?;
        let group = NameServerConfigGroup::from_ips_clear(&[ip], port, true);
        let config = ResolverConfig::from_parts(None, vec![], group);
        Ok((config, opts))
    }
}

/// 解析 "ip" 或 "ip:port" 或 "[ipv6]" 或 "[ipv6]:port" 格式
fn parse_ip_port(s: &str, default_port: u16) -> Result<(IpAddr, u16)> {
    if let Ok(ip) = s.parse::<IpAddr>() {
        return Ok((ip, default_port));
    }
    // 尝试 ip:port 或 [ipv6]:port
    if let Ok(addr) = s.parse::<std::net::SocketAddr>() {
        return Ok((addr.ip(), addr.port()));
    }
    // 尝试 [ipv6] 无端口
    let stripped = s.trim_start_matches('[').trim_end_matches(']');
    if let Ok(ip) = stripped.parse::<IpAddr>() {
        return Ok((ip, default_port));
    }
    anyhow::bail!("invalid DNS address: {}", s)
}

/// FakeIP 解析器：将域名解析为 FakeIP
pub struct FakeIpResolver {
    inner: Box<dyn DnsResolver>,
    pool: Arc<FakeIpPool>,
}

impl FakeIpResolver {
    pub fn new(inner: Box<dyn DnsResolver>, pool: Arc<FakeIpPool>) -> Self {
        Self { inner, pool }
    }
}

#[async_trait]
impl DnsResolver for FakeIpResolver {
    async fn resolve(&self, host: &str) -> Result<Vec<IpAddr>> {
        if self.pool.is_excluded(host) {
            return self.inner.resolve(host).await;
        }

        let fake_ip = self.pool.allocate(host).await;
        Ok(vec![fake_ip])
    }
}

/// 根据配置构建 DNS 解析器
pub fn build_resolver(config: &DnsConfig) -> Result<Box<dyn DnsResolver>> {
    let inner: Box<dyn DnsResolver> = match config.mode.as_str() {
        "race" => {
            // 竞速模式：所有 servers 并发查询，取最快结果
            let mut resolvers: Vec<Box<dyn DnsResolver>> = Vec::new();
            for server in &config.servers {
                resolvers.push(Box::new(HickoryResolver::new(&server.address)?));
            }
            if resolvers.is_empty() {
                info!("no DNS servers configured, using system resolver");
                Box::new(SystemResolver)
            } else {
                Box::new(super::hosts::RaceResolver::new(resolvers))
            }
        }
        "fallback" => {
            // Fallback 模式：先查 nameserver，若结果在过滤范围则查 fallback
            let primary = build_nameserver_resolver(&config.servers)?;
            if config.fallback.is_empty() {
                primary
            } else {
                let fallback = build_nameserver_resolver(&config.fallback)?;
                let filter_cidrs = config
                    .fallback_filter
                    .as_ref()
                    .map(|f| f.ip_cidr.clone())
                    .unwrap_or_default();
                let filter_domains = config
                    .fallback_filter
                    .as_ref()
                    .map(|f| f.domain.clone())
                    .unwrap_or_default();
                Box::new(FallbackResolver::new(
                    primary,
                    fallback,
                    filter_cidrs,
                    filter_domains,
                ))
            }
        }
        _ => {
            // split 模式（默认）：按域名分流
            build_nameserver_resolver(&config.servers)?
        }
    };

    // 包装 HOSTS 层
    let with_hosts: Box<dyn DnsResolver> = if config.hosts.is_empty() {
        inner
    } else {
        let mut hosts_map = std::collections::HashMap::new();
        for (hostname, ip_str) in &config.hosts {
            if let Ok(ip) = ip_str.parse::<IpAddr>() {
                hosts_map
                    .entry(hostname.to_lowercase())
                    .or_insert_with(Vec::new)
                    .push(ip);
            }
        }
        info!(count = hosts_map.len(), "DNS hosts mappings loaded");
        Box::new(super::hosts::HostsResolver::new(inner, hosts_map))
    };

    // 可选包装 FakeIP 层
    let with_fake_ip: Box<dyn DnsResolver> = if let Some(fake_cfg) = &config.fake_ip {
        let pool = Arc::new(FakeIpPool::new(
            &fake_cfg.ipv4_range,
            fake_cfg.ipv6_range.as_deref(),
            fake_cfg.exclude.clone(),
        ));
        info!(range = fake_cfg.ipv4_range, "DNS FakeIP enabled");
        Box::new(FakeIpResolver::new(with_hosts, pool))
    } else {
        with_hosts
    };

    // 包装缓存层
    Ok(Box::new(super::cache::CachedResolver::new(
        with_fake_ip,
        config.cache_ttl,
        config.negative_cache_ttl,
        config.cache_size,
    )))
}

/// 从服务器列表构建解析器（split 模式或单服务器）
fn build_nameserver_resolver(servers: &[crate::config::types::DnsServerConfig]) -> Result<Box<dyn DnsResolver>> {
    if servers.is_empty() {
        info!("no DNS servers configured, using system resolver");
        return Ok(Box::new(SystemResolver));
    }

    if servers.len() == 1 && servers[0].domains.is_empty() {
        return Ok(Box::new(HickoryResolver::new(&servers[0].address)?));
    }

    let mut rules: Vec<(Vec<String>, Arc<dyn DnsResolver>)> = Vec::new();
    let mut default: Option<Arc<dyn DnsResolver>> = None;

    for server in servers {
        let resolver: Arc<dyn DnsResolver> = Arc::new(HickoryResolver::new(&server.address)?);
        if server.domains.is_empty() {
            if default.is_none() {
                default = Some(resolver);
            }
        } else {
            rules.push((server.domains.clone(), resolver));
        }
    }

    let default = default.unwrap_or_else(|| {
        if let Some((_, resolver)) = rules.last() {
            resolver.clone()
        } else {
            Arc::new(SystemResolver)
        }
    });

    Ok(Box::new(SplitResolver::new(rules, default)))
}

/// Fallback 解析器：先查 primary，若结果在过滤范围则查 fallback
pub struct FallbackResolver {
    primary: Box<dyn DnsResolver>,
    fallback: Box<dyn DnsResolver>,
    filter_cidrs: Vec<ipnet::IpNet>,
    filter_domains: Vec<String>,
}

impl FallbackResolver {
    pub fn new(
        primary: Box<dyn DnsResolver>,
        fallback: Box<dyn DnsResolver>,
        filter_cidr_strs: Vec<String>,
        filter_domains: Vec<String>,
    ) -> Self {
        let filter_cidrs: Vec<ipnet::IpNet> = filter_cidr_strs
            .iter()
            .filter_map(|s| s.parse().ok())
            .collect();
        Self {
            primary,
            fallback,
            filter_cidrs,
            filter_domains,
        }
    }

    fn should_fallback_ip(&self, addrs: &[IpAddr]) -> bool {
        if self.filter_cidrs.is_empty() {
            return false;
        }
        addrs.iter().any(|ip| {
            self.filter_cidrs.iter().any(|net| net.contains(ip))
        })
    }

    fn should_fallback_domain(&self, host: &str) -> bool {
        let host_lower = host.to_lowercase();
        self.filter_domains.iter().any(|d| {
            let d_lower = d.to_lowercase();
            host_lower == d_lower || host_lower.ends_with(&format!(".{}", d_lower))
        })
    }
}

#[async_trait]
impl DnsResolver for FallbackResolver {
    async fn resolve(&self, host: &str) -> Result<Vec<IpAddr>> {
        // 域名匹配时直接走 fallback
        if self.should_fallback_domain(host) {
            debug!(host = host, "DNS fallback: domain filter match");
            return self.fallback.resolve(host).await;
        }

        match self.primary.resolve(host).await {
            Ok(addrs) if self.should_fallback_ip(&addrs) => {
                debug!(host = host, "DNS fallback: IP filter match");
                self.fallback.resolve(host).await
            }
            Ok(addrs) => Ok(addrs),
            Err(_) => {
                debug!(host = host, "DNS fallback: primary failed");
                self.fallback.resolve(host).await
            }
        }
    }
}

/// EDNS Client Subnet (ECS) option 编码/解码工具 (RFC 7871)
pub mod ecs {
    use std::net::IpAddr;

    /// ECS option code in EDNS OPT RR
    pub const ECS_OPTION_CODE: u16 = 8;

    /// 解析 CIDR 格式的 ECS 配置 (如 "1.2.3.0/24")
    pub fn parse_ecs_subnet(s: &str) -> anyhow::Result<EcsOption> {
        let net: ipnet::IpNet = s
            .parse()
            .map_err(|e| anyhow::anyhow!("invalid ECS subnet '{}': {}", s, e))?;
        Ok(EcsOption {
            family: match net.addr() {
                IpAddr::V4(_) => 1,
                IpAddr::V6(_) => 2,
            },
            source_prefix_length: net.prefix_len(),
            scope_prefix_length: 0,
            address: net.addr(),
        })
    }

    /// ECS option 数据结构
    #[derive(Debug, Clone, PartialEq)]
    pub struct EcsOption {
        /// Address family: 1 = IPv4, 2 = IPv6
        pub family: u16,
        /// Source prefix length
        pub source_prefix_length: u8,
        /// Scope prefix length (response only, set to 0 in queries)
        pub scope_prefix_length: u8,
        /// Client subnet address
        pub address: IpAddr,
    }

    impl EcsOption {
        /// 编码 ECS option 为 EDNS OPT RR 的 RDATA 格式
        pub fn encode(&self) -> Vec<u8> {
            let addr_bytes = match self.address {
                IpAddr::V4(v4) => v4.octets().to_vec(),
                IpAddr::V6(v6) => v6.octets().to_vec(),
            };
            // 按前缀长度截取地址字节（去除尾部零字节）
            let prefix_bytes = (self.source_prefix_length as usize + 7) / 8;
            let truncated = &addr_bytes[..prefix_bytes.min(addr_bytes.len())];

            let mut buf = Vec::with_capacity(4 + truncated.len());
            buf.extend_from_slice(&self.family.to_be_bytes());
            buf.push(self.source_prefix_length);
            buf.push(self.scope_prefix_length);
            buf.extend_from_slice(truncated);
            buf
        }

        /// 从 EDNS OPT RDATA 解码 ECS option
        pub fn decode(data: &[u8]) -> anyhow::Result<Self> {
            if data.len() < 4 {
                anyhow::bail!("ECS option too short: {} bytes", data.len());
            }
            let family = u16::from_be_bytes([data[0], data[1]]);
            let source_prefix_length = data[2];
            let scope_prefix_length = data[3];
            let addr_data = &data[4..];

            let address = match family {
                1 => {
                    let mut octets = [0u8; 4];
                    let copy_len = addr_data.len().min(4);
                    octets[..copy_len].copy_from_slice(&addr_data[..copy_len]);
                    IpAddr::V4(std::net::Ipv4Addr::from(octets))
                }
                2 => {
                    let mut octets = [0u8; 16];
                    let copy_len = addr_data.len().min(16);
                    octets[..copy_len].copy_from_slice(&addr_data[..copy_len]);
                    IpAddr::V6(std::net::Ipv6Addr::from(octets))
                }
                _ => anyhow::bail!("unsupported ECS address family: {}", family),
            };

            Ok(Self {
                family,
                source_prefix_length,
                scope_prefix_length,
                address,
            })
        }
    }

    /// 构建包含 ECS option 的 EDNS OPT RR 负载
    /// 返回完整的 OPT RDATA（option-code + option-length + option-data）
    pub fn build_ecs_opt_rdata(ecs: &EcsOption) -> Vec<u8> {
        let option_data = ecs.encode();
        let option_length = option_data.len() as u16;

        let mut buf = Vec::with_capacity(4 + option_data.len());
        buf.extend_from_slice(&ECS_OPTION_CODE.to_be_bytes());
        buf.extend_from_slice(&option_length.to_be_bytes());
        buf.extend_from_slice(&option_data);
        buf
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn system_resolver_localhost() {
        let resolver = SystemResolver;
        let addrs = resolver.resolve("localhost").await.unwrap();
        assert!(!addrs.is_empty());
        assert!(addrs.iter().any(|a| a.is_loopback()));
    }

    #[tokio::test]
    async fn split_resolver_routes_correctly() {
        // Mock resolver 返回固定 IP
        struct MockResolver(IpAddr);

        #[async_trait]
        impl DnsResolver for MockResolver {
            async fn resolve(&self, _host: &str) -> Result<Vec<IpAddr>> {
                Ok(vec![self.0])
            }
        }

        let cn_resolver = Arc::new(MockResolver("1.1.1.1".parse().unwrap()));
        let default_resolver = Arc::new(MockResolver("8.8.8.8".parse().unwrap()));

        let split = SplitResolver::new(
            vec![(vec!["cn".to_string(), "baidu.com".to_string()], cn_resolver)],
            default_resolver,
        );

        // 匹配 cn 后缀
        let addrs = split.resolve("test.cn").await.unwrap();
        assert_eq!(addrs[0], "1.1.1.1".parse::<IpAddr>().unwrap());

        // 匹配 baidu.com 后缀
        let addrs = split.resolve("www.baidu.com").await.unwrap();
        assert_eq!(addrs[0], "1.1.1.1".parse::<IpAddr>().unwrap());

        // 不匹配，走默认
        let addrs = split.resolve("google.com").await.unwrap();
        assert_eq!(addrs[0], "8.8.8.8".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn parse_udp_address() {
        let (config, _) = parse_dns_address("223.5.5.5").unwrap();
        assert!(!config.name_servers().is_empty());
    }

    #[test]
    fn parse_udp_address_with_port() {
        let (config, _) = parse_dns_address("223.5.5.5:5353").unwrap();
        assert!(!config.name_servers().is_empty());
    }

    #[test]
    fn parse_tls_address() {
        let (config, _) = parse_dns_address("tls://1.1.1.1").unwrap();
        let ns = &config.name_servers()[0];
        assert_eq!(ns.protocol, Protocol::Tls);
    }

    #[test]
    fn parse_https_address() {
        let (config, _) = parse_dns_address("https://dns.google/dns-query").unwrap();
        let ns = &config.name_servers()[0];
        assert_eq!(ns.protocol, Protocol::Https);
        assert_eq!(ns.socket_addr.port(), 443);
    }

    #[test]
    fn parse_https_address_with_port() {
        let (config, _) = parse_dns_address("https://dns.google:444/dns-query").unwrap();
        let ns = &config.name_servers()[0];
        assert_eq!(ns.protocol, Protocol::Https);
        assert_eq!(ns.socket_addr.port(), 444);
    }

    #[test]
    fn parse_https_address_ipv6() {
        let (config, _) = parse_dns_address("https://[2606:4700:4700::1111]/dns-query").unwrap();
        let ns = &config.name_servers()[0];
        assert_eq!(ns.protocol, Protocol::Https);
        assert!(ns.socket_addr.ip().is_ipv6());
    }

    #[test]
    fn parse_invalid_address() {
        assert!(parse_dns_address("not-an-ip").is_err());
    }

    #[test]
    fn build_resolver_empty_config() {
        let config = DnsConfig {
            servers: vec![],
            cache_size: 1024,
            cache_ttl: 300,
            negative_cache_ttl: 30,
            hosts: Default::default(),
            fake_ip: None,
            mode: "split".to_string(),
            fallback: vec![],
            fallback_filter: None,
            edns_client_subnet: None,
        };
        assert!(build_resolver(&config).is_ok());
    }

    #[test]
    fn dns_config_defaults_include_negative_ttl() {
        let yaml = r#"
servers:
  - address: 1.1.1.1
"#;
        let config: DnsConfig = serde_yml::from_str(yaml).unwrap();
        assert_eq!(config.cache_ttl, 300);
        assert_eq!(config.cache_size, 1024);
        assert_eq!(config.negative_cache_ttl, 30);
    }

    #[tokio::test]
    async fn fakeip_resolver_allocates_fake_ip() {
        struct MockResolver;

        #[async_trait]
        impl DnsResolver for MockResolver {
            async fn resolve(&self, _host: &str) -> Result<Vec<IpAddr>> {
                Ok(vec!["8.8.8.8".parse().unwrap()])
            }
        }

        let pool = Arc::new(FakeIpPool::new("198.18.0.0/15", None, vec![]));
        let resolver = FakeIpResolver::new(Box::new(MockResolver), pool.clone());

        let addrs = resolver.resolve("example.com").await.unwrap();
        assert_eq!(addrs.len(), 1);
        assert!(pool.is_fake_ip(addrs[0]));
        assert_eq!(pool.lookup(addrs[0]).await.as_deref(), Some("example.com"));
    }

    #[tokio::test]
    async fn fakeip_resolver_respects_exclude_list() {
        struct MockResolver;

        #[async_trait]
        impl DnsResolver for MockResolver {
            async fn resolve(&self, _host: &str) -> Result<Vec<IpAddr>> {
                Ok(vec!["8.8.8.8".parse().unwrap()])
            }
        }

        let pool = Arc::new(FakeIpPool::new("198.18.0.0/15", None, vec!["local".to_string()]));
        let resolver = FakeIpResolver::new(Box::new(MockResolver), pool.clone());

        let addrs = resolver.resolve("router.local").await.unwrap();
        assert_eq!(addrs, vec!["8.8.8.8".parse::<IpAddr>().unwrap()]);
        assert!(pool.lookup("8.8.8.8".parse().unwrap()).await.is_none());
    }

    #[test]
    fn parse_quic_address() {
        let (config, _) = parse_dns_address("quic://1.1.1.1").unwrap();
        let ns = &config.name_servers()[0];
        assert_eq!(ns.protocol, Protocol::Quic);
        assert_eq!(ns.socket_addr.port(), 853);
    }

    #[test]
    fn parse_quic_address_with_port() {
        let (config, _) = parse_dns_address("quic://8.8.8.8:8853").unwrap();
        let ns = &config.name_servers()[0];
        assert_eq!(ns.protocol, Protocol::Quic);
        assert_eq!(ns.socket_addr.port(), 8853);
    }

    #[test]
    fn parse_quic_address_ipv6() {
        let (config, _) = parse_dns_address("quic://[2606:4700:4700::1111]").unwrap();
        let ns = &config.name_servers()[0];
        assert_eq!(ns.protocol, Protocol::Quic);
        assert!(ns.socket_addr.ip().is_ipv6());
        assert_eq!(ns.socket_addr.port(), 853);
    }

    #[test]
    fn ecs_parse_ipv4_subnet() {
        let ecs = ecs::parse_ecs_subnet("1.2.3.0/24").unwrap();
        assert_eq!(ecs.family, 1);
        assert_eq!(ecs.source_prefix_length, 24);
        assert_eq!(ecs.scope_prefix_length, 0);
        assert_eq!(ecs.address, "1.2.3.0".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn ecs_parse_ipv6_subnet() {
        let ecs = ecs::parse_ecs_subnet("2001:db8::/32").unwrap();
        assert_eq!(ecs.family, 2);
        assert_eq!(ecs.source_prefix_length, 32);
        assert_eq!(ecs.address, "2001:db8::".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn ecs_encode_decode_roundtrip_v4() {
        let original = ecs::parse_ecs_subnet("192.168.1.0/24").unwrap();
        let encoded = original.encode();
        let decoded = ecs::EcsOption::decode(&encoded).unwrap();
        assert_eq!(decoded.family, original.family);
        assert_eq!(decoded.source_prefix_length, original.source_prefix_length);
        assert_eq!(decoded.scope_prefix_length, original.scope_prefix_length);
    }

    #[test]
    fn ecs_encode_decode_roundtrip_v6() {
        let original = ecs::parse_ecs_subnet("2001:db8:abcd::/48").unwrap();
        let encoded = original.encode();
        let decoded = ecs::EcsOption::decode(&encoded).unwrap();
        assert_eq!(decoded.family, original.family);
        assert_eq!(decoded.source_prefix_length, original.source_prefix_length);
    }

    #[test]
    fn ecs_encode_prefix_truncation() {
        let ecs = ecs::parse_ecs_subnet("10.0.0.0/8").unwrap();
        let encoded = ecs.encode();
        // family(2) + source_prefix(1) + scope_prefix(1) + addr_bytes(1) = 5
        assert_eq!(encoded.len(), 5);
        assert_eq!(encoded[4], 10); // 只保留第一个字节
    }

    #[test]
    fn ecs_opt_rdata_structure() {
        let ecs = ecs::parse_ecs_subnet("1.2.3.0/24").unwrap();
        let rdata = ecs::build_ecs_opt_rdata(&ecs);
        // option-code(2) + option-length(2) + family(2) + source(1) + scope(1) + addr(3) = 11
        assert_eq!(u16::from_be_bytes([rdata[0], rdata[1]]), ecs::ECS_OPTION_CODE);
        let option_len = u16::from_be_bytes([rdata[2], rdata[3]]);
        assert_eq!(option_len as usize, rdata.len() - 4);
    }

    #[test]
    fn ecs_decode_too_short() {
        assert!(ecs::EcsOption::decode(&[0, 1]).is_err());
    }

    #[test]
    fn ecs_parse_invalid_subnet() {
        assert!(ecs::parse_ecs_subnet("not-a-cidr").is_err());
    }

    #[test]
    fn dns_config_with_ecs() {
        let yaml = r#"
servers:
  - address: 1.1.1.1
edns-client-subnet: "1.2.3.0/24"
"#;
        let config: DnsConfig = serde_yml::from_str(yaml).unwrap();
        assert_eq!(config.edns_client_subnet.as_deref(), Some("1.2.3.0/24"));
    }
}
