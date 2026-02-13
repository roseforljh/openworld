use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use anyhow::Result;
use async_trait::async_trait;

use crate::common::{BoxUdpTransport, ProxyStream};
use crate::proxy::{OutboundHandler, Session};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LbStrategy {
    RoundRobin,
    Random,
    ConsistentHash,
    Sticky,
}

impl LbStrategy {
    pub fn from_str_opt(s: Option<&str>) -> Self {
        match s {
            Some("random") => LbStrategy::Random,
            Some("consistent-hash" | "consistent-hashing") => LbStrategy::ConsistentHash,
            Some("sticky") => LbStrategy::Sticky,
            _ => LbStrategy::RoundRobin,
        }
    }
}

pub struct LoadBalanceGroup {
    name: String,
    proxies: Vec<Arc<dyn OutboundHandler>>,
    proxy_names: Vec<String>,
    counter: AtomicUsize,
    strategy: LbStrategy,
}

impl LoadBalanceGroup {
    pub fn new(
        name: String,
        proxies: Vec<Arc<dyn OutboundHandler>>,
        proxy_names: Vec<String>,
        strategy: LbStrategy,
    ) -> Self {
        Self {
            name,
            proxies,
            proxy_names,
            counter: AtomicUsize::new(0),
            strategy,
        }
    }

    fn select_index(&self, session: &Session) -> usize {
        let len = self.proxies.len();
        if len == 0 {
            return 0;
        }
        match self.strategy {
            LbStrategy::RoundRobin => self.counter.fetch_add(1, Ordering::Relaxed) % len,
            LbStrategy::Random => {
                // Simple fast random using counter + time-based seed
                let seed = self.counter.fetch_add(1, Ordering::Relaxed).wrapping_add(
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .subsec_nanos() as usize,
                );
                seed % len
            }
            LbStrategy::ConsistentHash => {
                let key = format!("{}", session.target);
                consistent_hash(&key, len)
            }
            LbStrategy::Sticky => {
                let key = session
                    .source
                    .map(|s| s.ip().to_string())
                    .unwrap_or_else(|| format!("{}", session.target));
                consistent_hash(&key, len)
            }
        }
    }

    pub fn proxy_names(&self) -> &[String] {
        &self.proxy_names
    }

    pub fn strategy(&self) -> LbStrategy {
        self.strategy
    }
}

/// Jump consistent hash (Google, 2014) - fast, uniform, minimal disruption on resize.
fn consistent_hash(key: &str, buckets: usize) -> usize {
    let mut hasher = DefaultHasher::new();
    key.hash(&mut hasher);
    let mut h = hasher.finish();

    let mut b: i64 = -1;
    let mut j: i64 = 0;
    while j < buckets as i64 {
        b = j;
        h = h.wrapping_mul(2862933555777941757).wrapping_add(1);
        j = ((b.wrapping_add(1) as f64) * ((1i64 << 31) as f64)
            / ((h >> 33).wrapping_add(1) as f64)) as i64;
    }
    b as usize
}

#[async_trait]
impl OutboundHandler for LoadBalanceGroup {
    fn tag(&self) -> &str {
        &self.name
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    async fn connect(&self, session: &Session) -> Result<ProxyStream> {
        let idx = self.select_index(session);
        self.proxies[idx].connect(session).await
    }

    async fn connect_udp(&self, session: &Session) -> Result<BoxUdpTransport> {
        let idx = self.select_index(session);
        self.proxies[idx].connect_udp(session).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn consistent_hash_stable() {
        let idx1 = consistent_hash("example.com:443", 5);
        let idx2 = consistent_hash("example.com:443", 5);
        assert_eq!(idx1, idx2);
    }

    #[test]
    fn consistent_hash_distributes() {
        let mut counts = [0u32; 5];
        for i in 0..1000 {
            let key = format!("host-{}.example.com:443", i);
            let idx = consistent_hash(&key, 5);
            counts[idx] += 1;
        }
        // Each bucket should get at least some hits
        for c in &counts {
            assert!(*c > 50, "uneven distribution: {:?}", counts);
        }
    }

    #[test]
    fn consistent_hash_minimal_disruption() {
        // When adding a bucket, most keys should stay in the same bucket
        let mut same = 0;
        for i in 0..1000 {
            let key = format!("target-{}", i);
            let old = consistent_hash(&key, 5);
            let new = consistent_hash(&key, 6);
            if old == new {
                same += 1;
            }
        }
        // At least 60% should remain stable (theoretical: ~83%)
        assert!(
            same > 600,
            "too much disruption: {} stayed same out of 1000",
            same
        );
    }

    #[test]
    fn strategy_from_str() {
        assert_eq!(LbStrategy::from_str_opt(None), LbStrategy::RoundRobin);
        assert_eq!(
            LbStrategy::from_str_opt(Some("round-robin")),
            LbStrategy::RoundRobin
        );
        assert_eq!(LbStrategy::from_str_opt(Some("random")), LbStrategy::Random);
        assert_eq!(
            LbStrategy::from_str_opt(Some("consistent-hash")),
            LbStrategy::ConsistentHash
        );
        assert_eq!(
            LbStrategy::from_str_opt(Some("consistent-hashing")),
            LbStrategy::ConsistentHash
        );
        assert_eq!(LbStrategy::from_str_opt(Some("sticky")), LbStrategy::Sticky);
    }
}
