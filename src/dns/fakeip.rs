use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::atomic::{AtomicU32, Ordering};

use tokio::sync::RwLock;
use tracing::debug;

/// FakeIP 池：分配虚拟 IP 并维护双向映射
pub struct FakeIpPool {
    /// IPv4 池起始地址（如 198.18.0.0）
    ipv4_base: u32,
    /// IPv4 池大小
    ipv4_size: u32,
    /// 当前 IPv4 分配偏移
    ipv4_offset: AtomicU32,
    /// IPv6 池起始前缀（如 fc00::）
    ipv6_prefix: u128,
    /// 当前 IPv6 分配偏移
    ipv6_offset: AtomicU32,
    /// 域名 → FakeIP 映射
    domain_to_ip: RwLock<HashMap<String, IpAddr>>,
    /// FakeIP → 域名 反查映射
    ip_to_domain: RwLock<HashMap<IpAddr, String>>,
    /// 不使用 FakeIP 的域名列表（后缀匹配）
    exclude_domains: Vec<String>,
}

impl FakeIpPool {
    pub fn new(
        ipv4_cidr: &str,
        ipv6_prefix: Option<&str>,
        exclude_domains: Vec<String>,
    ) -> Self {
        let (ipv4_base, ipv4_size) = parse_ipv4_cidr(ipv4_cidr);
        let ipv6_pre = ipv6_prefix
            .and_then(|s| parse_ipv6_prefix(s))
            .unwrap_or(0xfc00_0000_0000_0000_0000_0000_0000_0000u128);

        Self {
            ipv4_base,
            ipv4_size,
            ipv4_offset: AtomicU32::new(1), // skip .0
            ipv6_prefix: ipv6_pre,
            ipv6_offset: AtomicU32::new(1),
            domain_to_ip: RwLock::new(HashMap::new()),
            ip_to_domain: RwLock::new(HashMap::new()),
            exclude_domains,
        }
    }

    /// 为域名分配一个 FakeIP（如果已分配则返回已有的）
    pub async fn allocate(&self, domain: &str) -> IpAddr {
        let domain_lower = domain.to_lowercase();

        // 已有映射直接返回
        {
            let map = self.domain_to_ip.read().await;
            if let Some(&ip) = map.get(&domain_lower) {
                return ip;
            }
        }

        // 分配新的 IPv4
        let offset = self.ipv4_offset.fetch_add(1, Ordering::Relaxed);
        let actual_offset = offset % self.ipv4_size;
        let ip_u32 = self.ipv4_base.wrapping_add(actual_offset);
        let ip = IpAddr::V4(Ipv4Addr::from(ip_u32));

        let mut d2i = self.domain_to_ip.write().await;
        let mut i2d = self.ip_to_domain.write().await;

        // double-check
        if let Some(&existing) = d2i.get(&domain_lower) {
            return existing;
        }

        // 如果 IP 已被其他域名占用（环绕），先清理旧映射
        if let Some(old_domain) = i2d.remove(&ip) {
            d2i.remove(&old_domain);
        }

        d2i.insert(domain_lower.clone(), ip);
        i2d.insert(ip, domain_lower.clone());

        debug!(domain = domain_lower, ip = %ip, "FakeIP allocated");
        ip
    }

    /// 为域名分配一个 FakeIP v6
    pub async fn allocate_v6(&self, domain: &str) -> IpAddr {
        let domain_lower = domain.to_lowercase();
        let key = format!("v6:{}", domain_lower);

        {
            let map = self.domain_to_ip.read().await;
            if let Some(&ip) = map.get(&key) {
                return ip;
            }
        }

        let offset = self.ipv6_offset.fetch_add(1, Ordering::Relaxed);
        let ip_u128 = self.ipv6_prefix | (offset as u128);
        let ip = IpAddr::V6(Ipv6Addr::from(ip_u128));

        let mut d2i = self.domain_to_ip.write().await;
        let mut i2d = self.ip_to_domain.write().await;

        if let Some(&existing) = d2i.get(&key) {
            return existing;
        }

        if let Some(old_key) = i2d.remove(&ip) {
            d2i.remove(&old_key);
        }

        d2i.insert(key.clone(), ip);
        i2d.insert(ip, key);

        debug!(domain = domain_lower, ip = %ip, "FakeIP v6 allocated");
        ip
    }

    /// 反查：FakeIP → 域名
    pub async fn lookup(&self, ip: IpAddr) -> Option<String> {
        let i2d = self.ip_to_domain.read().await;
        i2d.get(&ip).map(|s| {
            // 去掉 v6: 前缀
            s.strip_prefix("v6:").unwrap_or(s).to_string()
        })
    }

    /// 检查 IP 是否在 FakeIP 池范围内
    pub fn is_fake_ip(&self, ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(v4) => {
                let ip_u32 = u32::from(v4);
                ip_u32 >= self.ipv4_base && ip_u32 < self.ipv4_base.saturating_add(self.ipv4_size)
            }
            IpAddr::V6(v6) => {
                let ip_u128 = u128::from(v6);
                // 检查前缀是否匹配（前 64 位）
                (ip_u128 >> 64) == (self.ipv6_prefix >> 64)
            }
        }
    }

    /// 检查域名是否在排除列表中
    pub fn is_excluded(&self, domain: &str) -> bool {
        let domain_lower = domain.to_lowercase();
        self.exclude_domains.iter().any(|suffix| {
            let suffix_lower = suffix.to_lowercase();
            domain_lower == suffix_lower || domain_lower.ends_with(&format!(".{}", suffix_lower))
        })
    }

    /// 获取当前映射数量
    pub async fn len(&self) -> usize {
        self.domain_to_ip.read().await.len()
    }

    pub async fn is_empty(&self) -> bool {
        self.domain_to_ip.read().await.is_empty()
    }
}

fn parse_ipv4_cidr(cidr: &str) -> (u32, u32) {
    if let Some((ip_str, prefix_str)) = cidr.split_once('/') {
        if let (Ok(ip), Ok(prefix)) = (ip_str.parse::<Ipv4Addr>(), prefix_str.parse::<u32>()) {
            let base = u32::from(ip);
            let size = if prefix >= 32 { 1 } else { 1u32 << (32 - prefix) };
            return (base, size);
        }
    }
    // 默认 198.18.0.0/15
    (u32::from(Ipv4Addr::new(198, 18, 0, 0)), 1u32 << 17) // /15 = 131072
}

fn parse_ipv6_prefix(s: &str) -> Option<u128> {
    let addr_str = s.split('/').next()?;
    let addr: Ipv6Addr = addr_str.parse().ok()?;
    Some(u128::from(addr))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn fakeip_allocate_and_lookup() {
        let pool = FakeIpPool::new("198.18.0.0/15", None, vec![]);

        let ip1 = pool.allocate("google.com").await;
        let ip2 = pool.allocate("github.com").await;
        assert_ne!(ip1, ip2);

        // 同域名返回同 IP
        let ip1_again = pool.allocate("google.com").await;
        assert_eq!(ip1, ip1_again);

        // 反查
        let domain = pool.lookup(ip1).await.unwrap();
        assert_eq!(domain, "google.com");

        let domain2 = pool.lookup(ip2).await.unwrap();
        assert_eq!(domain2, "github.com");
    }

    #[tokio::test]
    async fn fakeip_is_fake_ip() {
        let pool = FakeIpPool::new("198.18.0.0/15", None, vec![]);

        let ip = pool.allocate("test.com").await;
        assert!(pool.is_fake_ip(ip));

        let real_ip: IpAddr = "1.1.1.1".parse().unwrap();
        assert!(!pool.is_fake_ip(real_ip));
    }

    #[tokio::test]
    async fn fakeip_exclude_domains() {
        let pool = FakeIpPool::new(
            "198.18.0.0/15",
            None,
            vec!["local".to_string(), "lan".to_string()],
        );

        assert!(pool.is_excluded("mypc.local"));
        assert!(pool.is_excluded("router.lan"));
        assert!(!pool.is_excluded("google.com"));
    }

    #[tokio::test]
    async fn fakeip_ipv4_range() {
        let pool = FakeIpPool::new("10.0.0.0/24", None, vec![]);

        for i in 0..10 {
            let ip = pool.allocate(&format!("host{}.com", i)).await;
            assert!(pool.is_fake_ip(ip));
            if let IpAddr::V4(v4) = ip {
                assert_eq!(v4.octets()[0], 10);
                assert_eq!(v4.octets()[1], 0);
                assert_eq!(v4.octets()[2], 0);
            } else {
                panic!("expected v4");
            }
        }
    }

    #[tokio::test]
    async fn fakeip_v6_allocate() {
        let pool = FakeIpPool::new("198.18.0.0/15", Some("fc00::"), vec![]);

        let ip = pool.allocate_v6("google.com").await;
        assert!(ip.is_ipv6());
        assert!(pool.is_fake_ip(ip));

        let domain = pool.lookup(ip).await.unwrap();
        assert_eq!(domain, "google.com");
    }

    #[tokio::test]
    async fn fakeip_unknown_lookup_returns_none() {
        let pool = FakeIpPool::new("198.18.0.0/15", None, vec![]);
        let result = pool.lookup("1.2.3.4".parse().unwrap()).await;
        assert!(result.is_none());
    }

    #[test]
    fn parse_cidr_default() {
        let (base, size) = parse_ipv4_cidr("198.18.0.0/15");
        assert_eq!(Ipv4Addr::from(base), Ipv4Addr::new(198, 18, 0, 0));
        assert_eq!(size, 131072); // 2^17
    }

    #[test]
    fn parse_cidr_small() {
        let (base, size) = parse_ipv4_cidr("10.0.0.0/24");
        assert_eq!(Ipv4Addr::from(base), Ipv4Addr::new(10, 0, 0, 0));
        assert_eq!(size, 256);
    }
}
