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
                if host_lower == suffix_lower
                    || host_lower.ends_with(&format!(".{}", suffix_lower))
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

    if let Some(tls_addr) = address.strip_prefix("tls://") {
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
        let config = ResolverConfig::from_parts(
            None,
            vec![],
            NameServerConfigGroup::from(vec![ns]),
        );
        Ok((config, opts))
    } else if address.starts_with("https://") {
        // DNS over HTTPS
        let url = address.to_string();
        // 从 URL 提取 host
        let host = url
            .strip_prefix("https://")
            .unwrap()
            .split('/')
            .next()
            .unwrap_or("dns.google");
        let ip: IpAddr = match host.parse() {
            Ok(ip) => ip,
            Err(_) => {
                // 如果是域名，先用系统 DNS 解析一下
                // 这里简化处理，只支持常见 DoH 提供商
                match host {
                    "dns.google" | "dns.google.com" => "8.8.8.8".parse().unwrap(),
                    "cloudflare-dns.com" | "1.1.1.1" => "1.1.1.1".parse().unwrap(),
                    "dns.alidns.com" => "223.5.5.5".parse().unwrap(),
                    _ => anyhow::bail!(
                        "DoH host '{}' is not a known provider; use IP address instead",
                        host
                    ),
                }
            }
        };
        let ns = NameServerConfig {
            socket_addr: std::net::SocketAddr::new(ip, 443),
            protocol: Protocol::Https,
            tls_dns_name: Some(host.to_string()),
            trust_negative_responses: true,
            tls_config: None,
            bind_addr: None,
        };
        let config = ResolverConfig::from_parts(
            None,
            vec![],
            NameServerConfigGroup::from(vec![ns]),
        );
        Ok((config, opts))
    } else {
        // UDP DNS
        let (ip, port) = parse_ip_port(address, 53)?;
        let group = NameServerConfigGroup::from_ips_clear(&[ip], port, true);
        let config = ResolverConfig::from_parts(None, vec![], group);
        Ok((config, opts))
    }
}

/// 解析 "ip" 或 "ip:port" 格式
fn parse_ip_port(s: &str, default_port: u16) -> Result<(IpAddr, u16)> {
    if let Ok(ip) = s.parse::<IpAddr>() {
        return Ok((ip, default_port));
    }
    // 尝试 ip:port
    if let Ok(addr) = s.parse::<std::net::SocketAddr>() {
        return Ok((addr.ip(), addr.port()));
    }
    anyhow::bail!("invalid DNS address: {}", s)
}

/// 根据配置构建 DNS 解析器
pub fn build_resolver(config: &DnsConfig) -> Result<Box<dyn DnsResolver>> {
    if config.servers.is_empty() {
        info!("no DNS servers configured, using system resolver");
        return Ok(Box::new(SystemResolver));
    }

    // 只有一个无域名限制的服务器
    if config.servers.len() == 1 && config.servers[0].domains.is_empty() {
        return Ok(Box::new(HickoryResolver::new(&config.servers[0].address)?));
    }

    // 构建 SplitResolver
    let mut rules: Vec<(Vec<String>, Arc<dyn DnsResolver>)> = Vec::new();
    let mut default: Option<Arc<dyn DnsResolver>> = None;

    for server in &config.servers {
        let resolver: Arc<dyn DnsResolver> =
            Arc::new(HickoryResolver::new(&server.address)?);

        if server.domains.is_empty() {
            if default.is_none() {
                default = Some(resolver);
            }
        } else {
            rules.push((server.domains.clone(), resolver));
        }
    }

    let default = default.unwrap_or_else(|| {
        // 如果没有无域名限制的服务器，用最后一个作为默认
        if let Some((_, resolver)) = rules.last() {
            resolver.clone()
        } else {
            Arc::new(SystemResolver)
        }
    });

    Ok(Box::new(SplitResolver::new(rules, default)))
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
    }

    #[test]
    fn parse_invalid_address() {
        assert!(parse_dns_address("not-an-ip").is_err());
    }

    #[test]
    fn build_resolver_empty_config() {
        let config = DnsConfig { servers: vec![] };
        assert!(build_resolver(&config).is_ok());
    }
}
