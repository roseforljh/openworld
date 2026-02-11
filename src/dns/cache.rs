use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

const INFLIGHT_WAIT_TIMEOUT: Duration = Duration::from_secs(5);

use anyhow::Result;
use async_trait::async_trait;
use tokio::sync::{Mutex, Notify, RwLock};
use tracing::debug;

use super::DnsResolver;

#[derive(Debug, Clone, Default)]
pub struct DnsCacheStats {
    pub cache_hit: u64,
    pub cache_miss: u64,
    pub negative_hit: u64,
}

enum CacheValue {
    Positive(Vec<IpAddr>),
    Negative(String),
}

struct CacheEntry {
    value: CacheValue,
    expires_at: Instant,
}

/// 带缓存的 DNS 解析器包装器（正/负缓存 + 过期策略 + 并发去重）
pub struct CachedResolver {
    inner: Box<dyn DnsResolver>,
    cache: RwLock<HashMap<String, CacheEntry>>,
    /// 简化 LRU：队尾最新，队首最旧
    order: Mutex<VecDeque<String>>,
    /// 并发去重：同 host 只让一个请求打到上游
    inflight: Mutex<HashMap<String, Arc<Notify>>>,
    ttl: Duration,
    negative_ttl: Duration,
    max_entries: usize,
    cache_hit: AtomicU64,
    cache_miss: AtomicU64,
    negative_hit: AtomicU64,
}

impl CachedResolver {
    pub fn new(
        inner: Box<dyn DnsResolver>,
        ttl_secs: u64,
        negative_ttl_secs: u64,
        max_entries: usize,
    ) -> Self {
        Self {
            inner,
            cache: RwLock::new(HashMap::new()),
            order: Mutex::new(VecDeque::new()),
            inflight: Mutex::new(HashMap::new()),
            ttl: Duration::from_secs(ttl_secs),
            negative_ttl: Duration::from_secs(negative_ttl_secs),
            max_entries,
            cache_hit: AtomicU64::new(0),
            cache_miss: AtomicU64::new(0),
            negative_hit: AtomicU64::new(0),
        }
    }

    async fn touch_order(&self, host: &str) {
        let mut order = self.order.lock().await;
        if let Some(pos) = order.iter().position(|h| h == host) {
            order.remove(pos);
        }
        order.push_back(host.to_string());
    }

    async fn evict_if_needed(&self) {
        // 先清理过期条目
        let now = Instant::now();
        {
            let mut cache = self.cache.write().await;
            cache.retain(|_, entry| entry.expires_at > now);
        }

        let mut order = self.order.lock().await;
        let mut cache = self.cache.write().await;

        // 去掉 order 中已经不存在的 key
        order.retain(|k| cache.contains_key(k));

        while cache.len() > self.max_entries {
            if let Some(oldest) = order.pop_front() {
                cache.remove(&oldest);
            } else {
                break;
            }
        }
    }

    async fn read_cache(&self, host: &str) -> Option<Result<Vec<IpAddr>>> {
        let cache = self.cache.read().await;
        let entry = cache.get(host)?;
        if entry.expires_at <= Instant::now() {
            return None;
        }

        let result = match &entry.value {
            CacheValue::Positive(addrs) => {
                self.cache_hit.fetch_add(1, Ordering::Relaxed);
                debug!(host = host, count = addrs.len(), "DNS positive cache hit");
                Ok(addrs.clone())
            }
            CacheValue::Negative(msg) => {
                self.negative_hit.fetch_add(1, Ordering::Relaxed);
                debug!(host = host, reason = msg, "DNS negative cache hit");
                Err(anyhow::anyhow!(
                    "DNS cached negative response for {}: {}",
                    host,
                    msg
                ))
            }
        };

        drop(cache);
        self.touch_order(host).await;
        Some(result)
    }

    pub fn stats(&self) -> DnsCacheStats {
        DnsCacheStats {
            cache_hit: self.cache_hit.load(Ordering::Relaxed),
            cache_miss: self.cache_miss.load(Ordering::Relaxed),
            negative_hit: self.negative_hit.load(Ordering::Relaxed),
        }
    }
}

#[async_trait]
impl DnsResolver for CachedResolver {
    async fn resolve(&self, host: &str) -> Result<Vec<IpAddr>> {
        // 1. 读锁检查缓存（正/负）
        if let Some(result) = self.read_cache(host).await {
            return result;
        }
        self.cache_miss.fetch_add(1, Ordering::Relaxed);

        // 2. 并发去重：同 host 只有一个任务执行真实解析
        let (notify, is_leader) = {
            let mut inflight = self.inflight.lock().await;
            if let Some(n) = inflight.get(host) {
                (n.clone(), false)
            } else {
                let n = Arc::new(Notify::new());
                inflight.insert(host.to_string(), n.clone());
                (n, true)
            }
        };

        if !is_leader {
            let waited = tokio::time::timeout(INFLIGHT_WAIT_TIMEOUT, notify.notified()).await;

            // leader 完成（或超时）后重读缓存
            if let Some(result) = self.read_cache(host).await {
                return result;
            }

            // 若等待超时，尝试清理可能残留的 inflight（leader 被取消等场景）
            if waited.is_err() {
                let mut inflight = self.inflight.lock().await;
                if let Some(current) = inflight.get(host) {
                    if Arc::ptr_eq(current, &notify) {
                        inflight.remove(host);
                    }
                }
            }

            // leader 失败/取消或超时时兜底直连解析，避免无限等待
            return self.inner.resolve(host).await;
        }

        // 3. leader 执行真实解析（保证 inflight cleanup + notify）
        let result = self.inner.resolve(host).await;

        // 4. 写入缓存（成功写正缓存；失败按 negative_ttl 写负缓存）
        {
            let mut cache = self.cache.write().await;
            match &result {
                Ok(addrs) => {
                    cache.insert(
                        host.to_string(),
                        CacheEntry {
                            value: CacheValue::Positive(addrs.clone()),
                            expires_at: Instant::now() + self.ttl,
                        },
                    );
                }
                Err(err) if self.negative_ttl > Duration::ZERO => {
                    cache.insert(
                        host.to_string(),
                        CacheEntry {
                            value: CacheValue::Negative(err.to_string()),
                            expires_at: Instant::now() + self.negative_ttl,
                        },
                    );
                }
                Err(_) => {}
            }
        }
        self.touch_order(host).await;
        self.evict_if_needed().await;

        // 5. 通知等待者（无论成功失败）
        {
            let mut inflight = self.inflight.lock().await;
            inflight.remove(host);
        }
        notify.notify_waiters();

        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    struct CountingResolver {
        count: Arc<AtomicUsize>,
        result: Vec<IpAddr>,
    }

    #[async_trait]
    impl DnsResolver for CountingResolver {
        async fn resolve(&self, _host: &str) -> Result<Vec<IpAddr>> {
            self.count.fetch_add(1, Ordering::SeqCst);
            Ok(self.result.clone())
        }
    }

    struct FailingResolver {
        count: Arc<AtomicUsize>,
    }

    #[async_trait]
    impl DnsResolver for FailingResolver {
        async fn resolve(&self, _host: &str) -> Result<Vec<IpAddr>> {
            self.count.fetch_add(1, Ordering::SeqCst);
            anyhow::bail!("mock dns failure")
        }
    }

    struct SlowCountingResolver {
        count: Arc<AtomicUsize>,
        result: Vec<IpAddr>,
    }

    #[async_trait]
    impl DnsResolver for SlowCountingResolver {
        async fn resolve(&self, _host: &str) -> Result<Vec<IpAddr>> {
            self.count.fetch_add(1, Ordering::SeqCst);
            tokio::time::sleep(Duration::from_millis(80)).await;
            Ok(self.result.clone())
        }
    }

    #[tokio::test]
    async fn cache_hit() {
        let count = Arc::new(AtomicUsize::new(0));
        let resolver = CachedResolver::new(
            Box::new(CountingResolver {
                count: count.clone(),
                result: vec!["1.2.3.4".parse().unwrap()],
            }),
            300,
            30,
            1024,
        );

        // 第一次查询
        let addrs = resolver.resolve("example.com").await.unwrap();
        assert_eq!(addrs, vec!["1.2.3.4".parse::<IpAddr>().unwrap()]);
        assert_eq!(count.load(Ordering::SeqCst), 1);

        // 第二次查询应该命中缓存
        let addrs = resolver.resolve("example.com").await.unwrap();
        assert_eq!(addrs, vec!["1.2.3.4".parse::<IpAddr>().unwrap()]);
        assert_eq!(count.load(Ordering::SeqCst), 1); // 没有增加

        // 不同域名应该触发新查询
        let _ = resolver.resolve("other.com").await.unwrap();
        assert_eq!(count.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn negative_cache_hit() {
        let count = Arc::new(AtomicUsize::new(0));
        let resolver = CachedResolver::new(
            Box::new(FailingResolver {
                count: count.clone(),
            }),
            300,
            60,
            1024,
        );

        assert!(resolver.resolve("bad.example").await.is_err());
        assert_eq!(count.load(Ordering::SeqCst), 1);

        // 第二次应命中负缓存，不再访问上游
        assert!(resolver.resolve("bad.example").await.is_err());
        assert_eq!(count.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn concurrent_dedup_same_host() {
        let count = Arc::new(AtomicUsize::new(0));
        let resolver = Arc::new(CachedResolver::new(
            Box::new(SlowCountingResolver {
                count: count.clone(),
                result: vec!["1.2.3.4".parse().unwrap()],
            }),
            300,
            30,
            1024,
        ));

        let mut tasks = Vec::new();
        for _ in 0..8 {
            let r = resolver.clone();
            tasks.push(tokio::spawn(async move {
                r.resolve("dedup.example").await.unwrap()
            }));
        }

        for task in tasks {
            let addrs = task.await.unwrap();
            assert_eq!(addrs, vec!["1.2.3.4".parse::<IpAddr>().unwrap()]);
        }

        assert_eq!(count.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn cache_max_entries() {
        let count = Arc::new(AtomicUsize::new(0));
        let resolver = CachedResolver::new(
            Box::new(CountingResolver {
                count: count.clone(),
                result: vec!["1.2.3.4".parse().unwrap()],
            }),
            300,
            30,
            5, // 小容量便于测试
        );

        // 填满缓存
        for i in 0..5 {
            resolver.resolve(&format!("host{}.com", i)).await.unwrap();
        }
        assert_eq!(count.load(Ordering::SeqCst), 5);

        // 超过容量时应该触发清理
        resolver.resolve("overflow.com").await.unwrap();
        assert_eq!(count.load(Ordering::SeqCst), 6);
    }
}
