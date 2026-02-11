use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Result;
use async_trait::async_trait;
use tokio::sync::{Mutex, Notify, RwLock};
use tracing::debug;

use super::DnsResolver;

struct CacheEntry {
    addrs: Vec<IpAddr>,
    expires_at: Instant,
}

/// 带缓存的 DNS 解析器包装器
pub struct CachedResolver {
    inner: Box<dyn DnsResolver>,
    cache: RwLock<HashMap<String, CacheEntry>>,
    /// 简化 LRU：队尾最新，队首最旧
    order: Mutex<VecDeque<String>>,
    /// 并发去重：同 host 只让一个请求打到上游
    inflight: Mutex<HashMap<String, Arc<Notify>>>,
    ttl: Duration,
    max_entries: usize,
}

impl CachedResolver {
    pub fn new(inner: Box<dyn DnsResolver>, ttl_secs: u64, max_entries: usize) -> Self {
        Self {
            inner,
            cache: RwLock::new(HashMap::new()),
            order: Mutex::new(VecDeque::new()),
            inflight: Mutex::new(HashMap::new()),
            ttl: Duration::from_secs(ttl_secs),
            max_entries,
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
}

#[async_trait]
impl DnsResolver for CachedResolver {
    async fn resolve(&self, host: &str) -> Result<Vec<IpAddr>> {
        // 1. 读锁检查缓存
        {
            let cache = self.cache.read().await;
            if let Some(entry) = cache.get(host) {
                if entry.expires_at > Instant::now() {
                    let addrs = entry.addrs.clone();
                    debug!(host = host, "DNS cache hit");
                    drop(cache);
                    self.touch_order(host).await;
                    return Ok(addrs);
                }
            }
        }

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
            notify.notified().await;
            // leader 完成后重读缓存
            let cache = self.cache.read().await;
            if let Some(entry) = cache.get(host) {
                if entry.expires_at > Instant::now() {
                    let addrs = entry.addrs.clone();
                    debug!(host = host, "DNS cache hit after wait");
                    drop(cache);
                    self.touch_order(host).await;
                    return Ok(addrs);
                }
            }
            // 理论上不应走到这里，兜底直接解析
            return self.inner.resolve(host).await;
        }

        // 3. leader 执行真实解析
        let result = self.inner.resolve(host).await;

        // 4. 写入缓存（仅成功结果）
        if let Ok(addrs) = &result {
            {
                let mut cache = self.cache.write().await;
                cache.insert(
                    host.to_string(),
                    CacheEntry {
                        addrs: addrs.clone(),
                        expires_at: Instant::now() + self.ttl,
                    },
                );
            }
            self.touch_order(host).await;
            self.evict_if_needed().await;
        }

        // 5. 通知等待者
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

    #[tokio::test]
    async fn cache_hit() {
        let count = Arc::new(AtomicUsize::new(0));
        let resolver = CachedResolver::new(
            Box::new(CountingResolver {
                count: count.clone(),
                result: vec!["1.2.3.4".parse().unwrap()],
            }),
            300,
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
    async fn cache_max_entries() {
        let count = Arc::new(AtomicUsize::new(0));
        let resolver = CachedResolver::new(
            Box::new(CountingResolver {
                count: count.clone(),
                result: vec!["1.2.3.4".parse().unwrap()],
            }),
            300,
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
