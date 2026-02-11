use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use tokio::sync::Mutex;

use crate::common::ProxyStream;

/// 出站 TCP 连接池
pub struct ConnectionPool {
    pools: Mutex<HashMap<String, VecDeque<PooledConn>>>,
    total_idle: AtomicUsize,
    max_idle_per_host: usize,
    idle_timeout: Duration,
}

struct PooledConn {
    stream: ProxyStream,
    #[allow(dead_code)]
    created_at: Instant,
    last_used: Instant,
}

impl ConnectionPool {
    pub fn new(max_idle_per_host: usize, idle_timeout_secs: u64) -> Self {
        Self {
            pools: Mutex::new(HashMap::new()),
            total_idle: AtomicUsize::new(0),
            max_idle_per_host: max_idle_per_host.max(1),
            idle_timeout: Duration::from_secs(idle_timeout_secs),
        }
    }

    pub fn with_defaults() -> Self {
        Self::new(10, 60)
    }

    pub async fn get(&self, target: &str) -> Option<ProxyStream> {
        let mut pools = self.pools.lock().await;
        let queue = pools.get_mut(target)?;

        let mut result = None;
        while let Some(conn) = queue.pop_front() {
            self.total_idle.fetch_sub(1, Ordering::Relaxed);
            if conn.last_used.elapsed() < self.idle_timeout {
                result = Some(conn.stream);
                break;
            }
        }

        if queue.is_empty() {
            pools.remove(target);
        }

        result
    }

    pub async fn put(&self, target: &str, stream: ProxyStream) {
        let mut pools = self.pools.lock().await;
        let queue = pools.entry(target.to_string()).or_default();

        if queue.len() >= self.max_idle_per_host {
            queue.pop_front();
            self.total_idle.fetch_sub(1, Ordering::Relaxed);
        }

        queue.push_back(PooledConn {
            stream,
            created_at: Instant::now(),
            last_used: Instant::now(),
        });
        self.total_idle.fetch_add(1, Ordering::Relaxed);
    }

    pub fn idle_count(&self) -> usize {
        self.total_idle.load(Ordering::Relaxed)
    }

    pub async fn target_count(&self) -> usize {
        self.pools.lock().await.len()
    }

    pub async fn cleanup(&self) -> usize {
        let mut pools = self.pools.lock().await;
        let mut cleaned = 0;
        let timeout = self.idle_timeout;

        let keys: Vec<String> = pools.keys().cloned().collect();
        for key in keys {
            if let Some(queue) = pools.get_mut(&key) {
                let before = queue.len();
                queue.retain(|conn| conn.last_used.elapsed() < timeout);
                let removed = before - queue.len();
                cleaned += removed;
            }
            if pools.get(&key).map_or(true, |q| q.is_empty()) {
                pools.remove(&key);
            }
        }

        self.total_idle.fetch_sub(cleaned, Ordering::Relaxed);
        cleaned
    }

    pub async fn clear(&self) {
        let mut pools = self.pools.lock().await;
        pools.clear();
        self.total_idle.store(0, Ordering::Relaxed);
    }
}

/// 出站绑定接口配置
#[derive(Debug, Clone)]
pub struct BindInterface {
    pub interface_name: Option<String>,
    pub bind_addr: Option<std::net::IpAddr>,
    pub routing_mark: Option<u32>,
}

impl BindInterface {
    pub fn none() -> Self {
        Self {
            interface_name: None,
            bind_addr: None,
            routing_mark: None,
        }
    }

    pub fn with_interface(name: &str) -> Self {
        Self {
            interface_name: Some(name.to_string()),
            bind_addr: None,
            routing_mark: None,
        }
    }

    pub fn with_bind_addr(addr: std::net::IpAddr) -> Self {
        Self {
            interface_name: None,
            bind_addr: Some(addr),
            routing_mark: None,
        }
    }

    pub fn has_binding(&self) -> bool {
        self.interface_name.is_some() || self.bind_addr.is_some() || self.routing_mark.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;

    fn make_stream() -> ProxyStream {
        let (s, _) = duplex(1024);
        Box::new(s)
    }

    #[tokio::test]
    async fn pool_basic_put_get() {
        let pool = ConnectionPool::with_defaults();
        assert_eq!(pool.idle_count(), 0);

        pool.put("example.com:443", make_stream()).await;
        assert_eq!(pool.idle_count(), 1);
        assert_eq!(pool.target_count().await, 1);

        let conn = pool.get("example.com:443").await;
        assert!(conn.is_some());
        assert_eq!(pool.idle_count(), 0);
    }

    #[tokio::test]
    async fn pool_get_nonexistent() {
        let pool = ConnectionPool::with_defaults();
        assert!(pool.get("nonexistent:80").await.is_none());
    }

    #[tokio::test]
    async fn pool_multiple_targets() {
        let pool = ConnectionPool::with_defaults();

        pool.put("a.com:443", make_stream()).await;
        pool.put("b.com:443", make_stream()).await;
        pool.put("a.com:443", make_stream()).await;

        assert_eq!(pool.idle_count(), 3);
        assert_eq!(pool.target_count().await, 2);
    }

    #[tokio::test]
    async fn pool_max_idle_per_host() {
        let pool = ConnectionPool::new(2, 60);

        pool.put("x.com:80", make_stream()).await;
        pool.put("x.com:80", make_stream()).await;
        pool.put("x.com:80", make_stream()).await; // evicts oldest

        assert_eq!(pool.idle_count(), 2);
    }

    #[tokio::test]
    async fn pool_expired_connections() {
        let pool = ConnectionPool::new(10, 0); // 0 second timeout

        pool.put("expire.com:443", make_stream()).await;
        tokio::time::sleep(Duration::from_millis(10)).await;

        // expired connection should not be returned
        assert!(pool.get("expire.com:443").await.is_none());
    }

    #[tokio::test]
    async fn pool_cleanup() {
        let pool = ConnectionPool::new(10, 0);

        pool.put("a.com:80", make_stream()).await;
        pool.put("b.com:80", make_stream()).await;
        tokio::time::sleep(Duration::from_millis(10)).await;

        let cleaned = pool.cleanup().await;
        assert_eq!(cleaned, 2);
        assert_eq!(pool.idle_count(), 0);
    }

    #[tokio::test]
    async fn pool_clear() {
        let pool = ConnectionPool::with_defaults();
        pool.put("a.com:80", make_stream()).await;
        pool.put("b.com:80", make_stream()).await;

        pool.clear().await;
        assert_eq!(pool.idle_count(), 0);
        assert_eq!(pool.target_count().await, 0);
    }

    #[test]
    fn bind_interface_none() {
        let b = BindInterface::none();
        assert!(!b.has_binding());
    }

    #[test]
    fn bind_interface_with_name() {
        let b = BindInterface::with_interface("eth0");
        assert!(b.has_binding());
        assert_eq!(b.interface_name.unwrap(), "eth0");
    }

    #[test]
    fn bind_interface_with_addr() {
        let b = BindInterface::with_bind_addr("192.168.1.1".parse().unwrap());
        assert!(b.has_binding());
        assert_eq!(b.bind_addr.unwrap().to_string(), "192.168.1.1");
    }
}
