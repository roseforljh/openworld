use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

const INFLIGHT_WAIT_TIMEOUT: Duration = Duration::from_secs(5);
/// Prefetch threshold: refresh when TTL remaining < 30% of original TTL
const PREFETCH_THRESHOLD_RATIO: f64 = 0.3;
/// Minimum TTL before prefetch (seconds)
const MIN_PREFETCH_TTL_SECS: u64 = 30;

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
    /// Original TTL for prefetch calculation
    original_ttl: Duration,
    /// Access count for popularity tracking
    access_count: AtomicU64,
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

        // Track access count for prefetch priority
        entry.access_count.fetch_add(1, Ordering::Relaxed);

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

    /// Check if an entry should be prefetched (TTL approaching expiry and frequently accessed)
    pub async fn should_prefetch(&self, host: &str) -> bool {
        let cache = self.cache.read().await;
        if let Some(entry) = cache.get(host) {
            let now = Instant::now();
            let remaining = entry.expires_at.saturating_duration_since(now);
            let threshold = Duration::from_secs(
                (entry.original_ttl.as_secs() as f64 * PREFETCH_THRESHOLD_RATIO) as u64
            );
            
            // Prefetch if:
            // 1. TTL remaining < 30% of original TTL
            // 2. TTL remaining > minimum (don't prefetch if already very close to expiry)
            // 3. Entry has been accessed at least 2 times (popular)
            let access_count = entry.access_count.load(Ordering::Relaxed);
            let should = remaining < threshold 
                && remaining.as_secs() >= MIN_PREFETCH_TTL_SECS
                && access_count >= 2;
            
            if should {
                debug!(
                    host = host,
                    remaining_secs = remaining.as_secs(),
                    original_ttl_secs = entry.original_ttl.as_secs(),
                    access_count = access_count,
                    "DNS prefetch candidate"
                );
            }
            return should;
        }
        false
    }

    /// Get list of hosts that need prefetching
    pub async fn get_prefetch_candidates(&self) -> Vec<String> {
        let cache = self.cache.read().await;
        let now = Instant::now();
        let mut candidates = Vec::new();

        for (host, entry) in cache.iter() {
            if matches!(entry.value, CacheValue::Positive(_)) {
                let remaining = entry.expires_at.saturating_duration_since(now);
                let threshold = Duration::from_secs(
                    (entry.original_ttl.as_secs() as f64 * PREFETCH_THRESHOLD_RATIO) as u64
                );
                let access_count = entry.access_count.load(Ordering::Relaxed);
                
                if remaining < threshold 
                    && remaining.as_secs() >= MIN_PREFETCH_TTL_SECS
                    && access_count >= 2
                {
                    candidates.push(host.clone());
                }
            }
        }
        candidates
    }

    pub fn stats(&self) -> DnsCacheStats {
        DnsCacheStats {
            cache_hit: self.cache_hit.load(Ordering::Relaxed),
            cache_miss: self.cache_miss.load(Ordering::Relaxed),
            negative_hit: self.negative_hit.load(Ordering::Relaxed),
        }
    }

    pub async fn clear(&self) {
        self.cache.write().await.clear();
        self.order.lock().await.clear();
        self.inflight.lock().await.clear();
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
                            original_ttl: self.ttl,
                            access_count: AtomicU64::new(1),
                        },
                    );
                }
                Err(err) if self.negative_ttl > Duration::ZERO => {
                    cache.insert(
                        host.to_string(),
                        CacheEntry {
                            value: CacheValue::Negative(err.to_string()),
                            expires_at: Instant::now() + self.negative_ttl,
                            original_ttl: self.negative_ttl,
                            access_count: AtomicU64::new(1),
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

    async fn flush_cache(&self) {
        self.clear().await;
    }
    
    fn as_any(&self) -> &dyn std::any::Any {
        self
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
