use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;

use anyhow::Result;
use async_trait::async_trait;
use tracing::debug;

use super::DnsResolver;

/// HOSTS 静态域名映射解析器
pub struct HostsResolver {
    inner: Box<dyn DnsResolver>,
    hosts: HashMap<String, Vec<IpAddr>>,
}

impl HostsResolver {
    pub fn new(inner: Box<dyn DnsResolver>, hosts: HashMap<String, Vec<IpAddr>>) -> Self {
        Self { inner, hosts }
    }

    /// 从 hosts 文件格式字符串解析
    pub fn parse_hosts_file(content: &str) -> HashMap<String, Vec<IpAddr>> {
        let mut hosts = HashMap::new();
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 2 {
                continue;
            }
            let ip: IpAddr = match parts[0].parse() {
                Ok(ip) => ip,
                Err(_) => continue,
            };
            for &hostname in &parts[1..] {
                if hostname.starts_with('#') {
                    break;
                }
                hosts
                    .entry(hostname.to_lowercase())
                    .or_insert_with(Vec::new)
                    .push(ip);
            }
        }
        hosts
    }
}

#[async_trait]
impl DnsResolver for HostsResolver {
    async fn resolve(&self, host: &str) -> Result<Vec<IpAddr>> {
        let host_lower = host.to_lowercase();
        if let Some(addrs) = self.hosts.get(&host_lower) {
            debug!(host = host, count = addrs.len(), "hosts file hit");
            return Ok(addrs.clone());
        }
        self.inner.resolve(host).await
    }
}

/// 并发竞速解析器：向多个上游并发查询，取最先返回的成功结果
pub struct RaceResolver {
    resolvers: Vec<Arc<dyn DnsResolver>>,
}

impl RaceResolver {
    pub fn new(resolvers: Vec<Box<dyn DnsResolver>>) -> Self {
        Self {
            resolvers: resolvers.into_iter().map(|r| Arc::from(r)).collect(),
        }
    }
}

#[async_trait]
impl DnsResolver for RaceResolver {
    async fn resolve(&self, host: &str) -> Result<Vec<IpAddr>> {
        if self.resolvers.is_empty() {
            anyhow::bail!("no DNS resolvers configured");
        }
        if self.resolvers.len() == 1 {
            return self.resolvers[0].resolve(host).await;
        }

        let host = host.to_string();
        let (tx, mut rx) = tokio::sync::mpsc::channel(self.resolvers.len());

        for (i, resolver) in self.resolvers.iter().enumerate() {
            let tx = tx.clone();
            let host = host.clone();
            let resolver = resolver.clone();
            tokio::spawn(async move {
                let result = resolver.resolve(&host).await;
                let _ = tx.send((i, result)).await;
            });
        }
        drop(tx);

        let mut last_err = None;
        while let Some((idx, result)) = rx.recv().await {
            match result {
                Ok(addrs) if !addrs.is_empty() => {
                    debug!(host = host, resolver_idx = idx, "race DNS resolved (winner)");
                    return Ok(addrs);
                }
                Ok(_) => {
                    last_err = Some(anyhow::anyhow!("empty response from resolver {}", idx));
                }
                Err(e) => {
                    last_err = Some(e);
                }
            }
        }

        Err(last_err.unwrap_or_else(|| anyhow::anyhow!("all DNS resolvers failed for {}", host)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    struct MockResolver(Vec<IpAddr>);

    #[async_trait]
    impl DnsResolver for MockResolver {
        async fn resolve(&self, _host: &str) -> Result<Vec<IpAddr>> {
            Ok(self.0.clone())
        }
    }

    struct FailResolver;

    #[async_trait]
    impl DnsResolver for FailResolver {
        async fn resolve(&self, _host: &str) -> Result<Vec<IpAddr>> {
            anyhow::bail!("mock fail")
        }
    }

    struct SlowMockResolver {
        delay_ms: u64,
        result: Vec<IpAddr>,
        call_count: Arc<AtomicUsize>,
    }

    #[async_trait]
    impl DnsResolver for SlowMockResolver {
        async fn resolve(&self, _host: &str) -> Result<Vec<IpAddr>> {
            self.call_count.fetch_add(1, Ordering::Relaxed);
            tokio::time::sleep(std::time::Duration::from_millis(self.delay_ms)).await;
            Ok(self.result.clone())
        }
    }

    #[test]
    fn parse_hosts_file_basic() {
        let content = r#"
# comment line
127.0.0.1 localhost
::1       localhost ip6-localhost
192.168.1.1 myrouter.local
"#;
        let hosts = HostsResolver::parse_hosts_file(content);
        assert_eq!(hosts.get("localhost").unwrap().len(), 2);
        assert!(hosts.get("myrouter.local").is_some());
    }

    #[test]
    fn parse_hosts_file_inline_comment() {
        let content = "127.0.0.1 test.local # my test host\n";
        let hosts = HostsResolver::parse_hosts_file(content);
        assert!(hosts.contains_key("test.local"));
        assert!(!hosts.contains_key("#"));
    }

    #[tokio::test]
    async fn hosts_resolver_hit() {
        let mut hosts = HashMap::new();
        hosts.insert(
            "myhost.local".to_string(),
            vec!["10.0.0.1".parse().unwrap()],
        );
        let resolver = HostsResolver::new(
            Box::new(MockResolver(vec!["8.8.8.8".parse().unwrap()])),
            hosts,
        );

        let addrs = resolver.resolve("myhost.local").await.unwrap();
        assert_eq!(addrs, vec!["10.0.0.1".parse::<IpAddr>().unwrap()]);
    }

    #[tokio::test]
    async fn hosts_resolver_miss_falls_through() {
        let resolver = HostsResolver::new(
            Box::new(MockResolver(vec!["8.8.8.8".parse().unwrap()])),
            HashMap::new(),
        );

        let addrs = resolver.resolve("google.com").await.unwrap();
        assert_eq!(addrs, vec!["8.8.8.8".parse::<IpAddr>().unwrap()]);
    }

    #[tokio::test]
    async fn hosts_resolver_case_insensitive() {
        let mut hosts = HashMap::new();
        hosts.insert("myhost".to_string(), vec!["10.0.0.1".parse().unwrap()]);
        let resolver = HostsResolver::new(Box::new(FailResolver), hosts);

        let addrs = resolver.resolve("MyHost").await.unwrap();
        assert_eq!(addrs, vec!["10.0.0.1".parse::<IpAddr>().unwrap()]);
    }

    #[tokio::test]
    async fn race_resolver_takes_fastest() {
        let slow_count = Arc::new(AtomicUsize::new(0));
        let fast_count = Arc::new(AtomicUsize::new(0));

        let resolvers: Vec<Box<dyn DnsResolver>> = vec![
            Box::new(SlowMockResolver {
                delay_ms: 200,
                result: vec!["1.1.1.1".parse().unwrap()],
                call_count: slow_count.clone(),
            }),
            Box::new(SlowMockResolver {
                delay_ms: 10,
                result: vec!["8.8.8.8".parse().unwrap()],
                call_count: fast_count.clone(),
            }),
        ];

        let race = RaceResolver::new(resolvers);
        let addrs = race.resolve("test.com").await.unwrap();
        // 快的先返回
        assert_eq!(addrs, vec!["8.8.8.8".parse::<IpAddr>().unwrap()]);
    }

    #[tokio::test]
    async fn race_resolver_fallback_on_first_fail() {
        let resolvers: Vec<Box<dyn DnsResolver>> = vec![
            Box::new(FailResolver),
            Box::new(MockResolver(vec!["8.8.8.8".parse().unwrap()])),
        ];
        let race = RaceResolver::new(resolvers);
        let addrs = race.resolve("test.com").await.unwrap();
        assert_eq!(addrs, vec!["8.8.8.8".parse::<IpAddr>().unwrap()]);
    }

    #[tokio::test]
    async fn race_resolver_all_fail() {
        let resolvers: Vec<Box<dyn DnsResolver>> =
            vec![Box::new(FailResolver), Box::new(FailResolver)];
        let race = RaceResolver::new(resolvers);
        assert!(race.resolve("test.com").await.is_err());
    }
}
