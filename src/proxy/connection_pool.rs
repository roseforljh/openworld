//! TCP 连接池
//!
//! 为出站代理复用 TCP 连接，减少握手开销。
//! 支持最大空闲数量、连接超时、自动清理。

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::net::TcpStream;
use tokio::sync::Mutex;

/// 池中的空闲连接
struct PooledConn {
    stream: TcpStream,
    created_at: Instant,
    last_used: Instant,
}

/// 连接池配置
#[derive(Debug, Clone)]
pub struct PoolConfig {
    /// 每个目标的最大空闲连接数
    pub max_idle_per_host: usize,
    /// 空闲连接最大存活时间
    pub idle_timeout: Duration,
    /// 连接最大存活时间（从创建算起）
    pub max_lifetime: Duration,
    /// 清理间隔
    pub cleanup_interval: Duration,
}

impl Default for PoolConfig {
    fn default() -> Self {
        Self {
            max_idle_per_host: 8,
            idle_timeout: Duration::from_secs(90),
            max_lifetime: Duration::from_secs(300),
            cleanup_interval: Duration::from_secs(30),
        }
    }
}

/// 连接池键：目标地址
#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub struct PoolKey {
    pub host: String,
    pub port: u16,
}

impl PoolKey {
    pub fn new(host: impl Into<String>, port: u16) -> Self {
        Self {
            host: host.into(),
            port,
        }
    }
}

impl std::fmt::Display for PoolKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.host, self.port)
    }
}

/// TCP 连接池
pub struct ConnectionPool {
    config: PoolConfig,
    conns: Mutex<HashMap<PoolKey, VecDeque<PooledConn>>>,
}

impl ConnectionPool {
    pub fn new(config: PoolConfig) -> Arc<Self> {
        Arc::new(Self {
            config,
            conns: Mutex::new(HashMap::new()),
        })
    }

    pub fn with_defaults() -> Arc<Self> {
        Self::new(PoolConfig::default())
    }

    /// 尝试获取一个可复用的连接
    pub async fn get(&self, key: &PoolKey) -> Option<TcpStream> {
        let mut conns = self.conns.lock().await;
        let queue = conns.get_mut(key)?;
        let now = Instant::now();

        // 从队列尾部取（LIFO，最近使用的连接更可能存活）
        while let Some(entry) = queue.pop_back() {
            // 检查是否过期
            if now.duration_since(entry.last_used) > self.config.idle_timeout {
                continue;
            }
            if now.duration_since(entry.created_at) > self.config.max_lifetime {
                continue;
            }
            // 连接可能已被 peer 关闭，但无法零成本检测
            // 如果已失效，调用方的首次 I/O 会立即报错并回退到新连接
            tracing::debug!(key = %key, "connection pool hit");
            return Some(entry.stream);
        }

        // 清空空队列
        if queue.is_empty() {
            conns.remove(key);
        }

        None
    }

    /// 归还连接到池中
    pub async fn put(&self, key: PoolKey, stream: TcpStream) {
        let mut conns = self.conns.lock().await;
        let queue = conns.entry(key).or_insert_with(VecDeque::new);

        // 如果已满就丢弃最旧的
        if queue.len() >= self.config.max_idle_per_host {
            queue.pop_front();
        }

        queue.push_back(PooledConn {
            stream,
            created_at: Instant::now(),
            last_used: Instant::now(),
        });
    }

    /// 清理过期连接
    pub async fn cleanup(&self) {
        let mut conns = self.conns.lock().await;
        let now = Instant::now();
        let mut empty_keys = Vec::new();

        for (key, queue) in conns.iter_mut() {
            queue.retain(|entry| {
                now.duration_since(entry.last_used) <= self.config.idle_timeout
                    && now.duration_since(entry.created_at) <= self.config.max_lifetime
            });
            if queue.is_empty() {
                empty_keys.push(key.clone());
            }
        }

        for key in empty_keys {
            conns.remove(&key);
        }
    }

    /// 获取池统计
    pub async fn stats(&self) -> PoolStats {
        let conns = self.conns.lock().await;
        let mut total = 0;
        let mut hosts = 0;
        for queue in conns.values() {
            hosts += 1;
            total += queue.len();
        }
        PoolStats {
            idle_connections: total,
            hosts,
        }
    }

    /// 启动定时清理任务
    pub fn spawn_cleanup(
        self: &Arc<Self>,
        cancel: tokio_util::sync::CancellationToken,
    ) -> tokio::task::JoinHandle<()> {
        let pool = Arc::clone(self);
        let interval = pool.config.cleanup_interval;
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            ticker.tick().await;
            loop {
                tokio::select! {
                    _ = cancel.cancelled() => break,
                    _ = ticker.tick() => {
                        pool.cleanup().await;
                    }
                }
            }
        })
    }

    /// 清空所有连接
    pub async fn clear(&self) {
        let mut conns = self.conns.lock().await;
        conns.clear();
    }
}

/// 池统计数据
#[derive(Debug, Clone)]
pub struct PoolStats {
    pub idle_connections: usize,
    pub hosts: usize,
}

// ═══════════════════════════════════════════════════════════════════════════
// 测试
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn pool_put_and_get() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let accept_handle = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            stream
        });

        let client = TcpStream::connect(addr).await.unwrap();
        let _server = accept_handle.await.unwrap();

        let pool = ConnectionPool::with_defaults();
        let key = PoolKey::new("127.0.0.1", addr.port());
        pool.put(key.clone(), client).await;

        let stats = pool.stats().await;
        assert_eq!(stats.idle_connections, 1);
        assert_eq!(stats.hosts, 1);

        let retrieved = pool.get(&key).await;
        assert!(retrieved.is_some());

        let stats = pool.stats().await;
        assert_eq!(stats.idle_connections, 0);
    }

    #[tokio::test]
    async fn pool_max_idle_eviction() {
        let pool = ConnectionPool::new(PoolConfig {
            max_idle_per_host: 2,
            ..Default::default()
        });
        let key = PoolKey::new("test.host", 443);

        // 创建 3 个连接
        for _ in 0..3 {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let handle = tokio::spawn(async move {
                listener.accept().await.unwrap();
            });
            let stream = TcpStream::connect(addr).await.unwrap();
            pool.put(key.clone(), stream).await;
            handle.await.unwrap();
        }

        let stats = pool.stats().await;
        // max_idle_per_host = 2，所以只保留 2 个
        assert_eq!(stats.idle_connections, 2);
    }

    #[tokio::test]
    async fn pool_cleanup_expired() {
        let pool = ConnectionPool::new(PoolConfig {
            idle_timeout: Duration::from_millis(50),
            ..Default::default()
        });
        let key = PoolKey::new("expiring.host", 80);

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move {
            listener.accept().await.unwrap();
        });
        let stream = TcpStream::connect(addr).await.unwrap();
        pool.put(key.clone(), stream).await;
        handle.await.unwrap();

        // 等待过期
        tokio::time::sleep(Duration::from_millis(100)).await;
        pool.cleanup().await;

        let stats = pool.stats().await;
        assert_eq!(stats.idle_connections, 0);
    }

    #[tokio::test]
    async fn pool_clear() {
        let pool = ConnectionPool::with_defaults();
        let key = PoolKey::new("clear.host", 8080);

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move {
            listener.accept().await.unwrap();
        });
        let stream = TcpStream::connect(addr).await.unwrap();
        pool.put(key, stream).await;
        handle.await.unwrap();

        pool.clear().await;
        let stats = pool.stats().await;
        assert_eq!(stats.idle_connections, 0);
        assert_eq!(stats.hosts, 0);
    }

    #[test]
    fn pool_key_display() {
        let key = PoolKey::new("example.com", 443);
        assert_eq!(key.to_string(), "example.com:443");
    }

    #[test]
    fn pool_config_defaults() {
        let config = PoolConfig::default();
        assert_eq!(config.max_idle_per_host, 8);
        assert_eq!(config.idle_timeout, Duration::from_secs(90));
        assert_eq!(config.max_lifetime, Duration::from_secs(300));
    }
}
