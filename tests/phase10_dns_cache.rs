//! Phase 5: DNS 缓存集成测试

use std::net::IpAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use anyhow::Result;
use async_trait::async_trait;

use openworld::dns::DnsResolver;
use openworld::dns::cache::CachedResolver;

struct MockResolver {
    count: Arc<AtomicUsize>,
    result: Vec<IpAddr>,
}

#[async_trait]
impl DnsResolver for MockResolver {
    async fn resolve(&self, _host: &str) -> Result<Vec<IpAddr>> {
        self.count.fetch_add(1, Ordering::SeqCst);
        Ok(self.result.clone())
    }
}

#[tokio::test]
async fn dns_cache_prevents_duplicate_queries() {
    let count = Arc::new(AtomicUsize::new(0));
    let resolver = CachedResolver::new(
        Box::new(MockResolver {
            count: count.clone(),
            result: vec!["8.8.8.8".parse().unwrap()],
        }),
        300,
        1024,
    );

    // 连续查询同一域名 10 次
    for _ in 0..10 {
        let addrs = resolver.resolve("google.com").await.unwrap();
        assert_eq!(addrs[0], "8.8.8.8".parse::<IpAddr>().unwrap());
    }

    // 只应该有 1 次实际查询
    assert_eq!(count.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn dns_cache_different_domains() {
    let count = Arc::new(AtomicUsize::new(0));
    let resolver = CachedResolver::new(
        Box::new(MockResolver {
            count: count.clone(),
            result: vec!["1.1.1.1".parse().unwrap()],
        }),
        300,
        1024,
    );

    resolver.resolve("a.com").await.unwrap();
    resolver.resolve("b.com").await.unwrap();
    resolver.resolve("c.com").await.unwrap();

    // 3 个不同域名 = 3 次实际查询
    assert_eq!(count.load(Ordering::SeqCst), 3);

    // 再次查询已缓存的域名
    resolver.resolve("a.com").await.unwrap();
    resolver.resolve("b.com").await.unwrap();
    assert_eq!(count.load(Ordering::SeqCst), 3); // 不增加
}

#[tokio::test]
async fn dns_cache_eviction_under_pressure() {
    let count = Arc::new(AtomicUsize::new(0));
    let resolver = CachedResolver::new(
        Box::new(MockResolver {
            count: count.clone(),
            result: vec!["10.0.0.1".parse().unwrap()],
        }),
        300,
        3, // 非常小的缓存
    );

    // 填满缓存
    resolver.resolve("x.com").await.unwrap();
    resolver.resolve("y.com").await.unwrap();
    resolver.resolve("z.com").await.unwrap();
    assert_eq!(count.load(Ordering::SeqCst), 3);

    // 超出容量
    resolver.resolve("w.com").await.unwrap();
    assert_eq!(count.load(Ordering::SeqCst), 4);

    // 之前的某些条目可能已被清除
    // w.com 刚缓存，应该命中
    resolver.resolve("w.com").await.unwrap();
    assert_eq!(count.load(Ordering::SeqCst), 4);
}

#[tokio::test]
async fn dns_cache_resolver_trait_compatibility() {
    // 验证 CachedResolver 实现了 DnsResolver trait
    let count = Arc::new(AtomicUsize::new(0));
    let resolver: Box<dyn DnsResolver> = Box::new(CachedResolver::new(
        Box::new(MockResolver {
            count: count.clone(),
            result: vec!["127.0.0.1".parse().unwrap()],
        }),
        300,
        1024,
    ));

    let addrs = resolver.resolve("localhost").await.unwrap();
    assert_eq!(addrs.len(), 1);
}
