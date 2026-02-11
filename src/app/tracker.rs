use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use tokio::sync::RwLock;
use tracing::debug;

use crate::proxy::Session;

static NEXT_ID: AtomicU64 = AtomicU64::new(1);

/// 连接信息
#[derive(Debug, Clone)]
pub struct ConnectionInfo {
    pub id: u64,
    pub target: String,
    pub inbound_tag: String,
    pub outbound_tag: String,
    pub route_tag: String,
    pub matched_rule: String,
    pub start_time: Instant,
    pub upload: u64,
    pub download: u64,
    pub source: Option<std::net::SocketAddr>,
    pub network: String,
}

/// 流量快照
#[derive(Debug, Clone, Default)]
pub struct TrafficSnapshot {
    pub total_up: u64,
    pub total_down: u64,
    pub active_count: usize,
}

/// 连接跟踪器
pub struct ConnectionTracker {
    connections: RwLock<HashMap<u64, TrackedConnection>>,
    total_upload: AtomicU64,
    total_download: AtomicU64,
    route_stats: Mutex<HashMap<String, u64>>,
    error_stats: Mutex<HashMap<String, u64>>,
    latency_ring: Mutex<VecDeque<u64>>,
    latency_capacity: usize,
}

struct TrackedConnection {
    info: ConnectionInfo,
    upload: Arc<AtomicU64>,
    download: Arc<AtomicU64>,
}

impl Default for ConnectionTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl ConnectionTracker {
    pub fn new() -> Self {
        Self {
            connections: RwLock::new(HashMap::new()),
            total_upload: AtomicU64::new(0),
            total_download: AtomicU64::new(0),
            route_stats: Mutex::new(HashMap::new()),
            error_stats: Mutex::new(HashMap::new()),
            latency_ring: Mutex::new(VecDeque::new()),
            latency_capacity: 2048,
        }
    }

    /// 开始跟踪一个连接，返回 ConnectionGuard
    pub async fn track(
        &self,
        session: &Session,
        outbound_tag: &str,
        route_tag: &str,
        matched_rule: Option<&str>,
    ) -> ConnectionGuard<'_> {
        let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
        let upload = Arc::new(AtomicU64::new(0));
        let download = Arc::new(AtomicU64::new(0));

        let info = ConnectionInfo {
            id,
            target: session.target.to_string(),
            inbound_tag: session.inbound_tag.clone(),
            outbound_tag: outbound_tag.to_string(),
            route_tag: route_tag.to_string(),
            matched_rule: matched_rule.unwrap_or("MATCH").to_string(),
            start_time: Instant::now(),
            upload: 0,
            download: 0,
            source: session.source,
            network: match session.network {
                crate::proxy::Network::Tcp => "tcp".to_string(),
                crate::proxy::Network::Udp => "udp".to_string(),
            },
        };

        let tracked = TrackedConnection {
            info,
            upload: upload.clone(),
            download: download.clone(),
        };

        self.record_route_hit(route_tag);

        self.connections.write().await.insert(id, tracked);
        debug!(
            conn_id = id,
            target = %session.target,
            outbound_tag = outbound_tag,
            route_tag = route_tag,
            "connection tracked"
        );

        ConnectionGuard {
            id,
            upload,
            download,
            tracker: self,
        }
    }

    /// 列出所有活跃连接
    pub async fn list(&self) -> Vec<ConnectionInfo> {
        let conns = self.connections.read().await;
        conns
            .values()
            .map(|tc| {
                let mut info = tc.info.clone();
                info.upload = tc.upload.load(Ordering::Relaxed);
                info.download = tc.download.load(Ordering::Relaxed);
                info
            })
            .collect()
    }

    /// 获取流量快照
    pub fn snapshot(&self) -> TrafficSnapshot {
        TrafficSnapshot {
            total_up: self.total_upload.load(Ordering::Relaxed),
            total_down: self.total_download.load(Ordering::Relaxed),
            active_count: 0, // 需要 async，这里用 try_read
        }
    }

    /// 获取流量快照（异步版本）
    pub async fn snapshot_async(&self) -> TrafficSnapshot {
        let conns = self.connections.read().await;
        TrafficSnapshot {
            total_up: self.total_upload.load(Ordering::Relaxed),
            total_down: self.total_download.load(Ordering::Relaxed),
            active_count: conns.len(),
        }
    }

    /// 关闭指定连接（从跟踪中移除）
    pub async fn close(&self, id: u64) -> bool {
        self.connections.write().await.remove(&id).is_some()
    }

    /// 记录一次路由命中
    pub fn record_route_hit(&self, route_tag: &str) {
        if let Ok(mut stats) = self.route_stats.lock() {
            *stats.entry(route_tag.to_string()).or_insert(0) += 1;
        }
    }

    /// 记录一次连接级错误
    pub fn record_error(&self, code: &str) {
        if let Ok(mut stats) = self.error_stats.lock() {
            *stats.entry(code.to_string()).or_insert(0) += 1;
        }
    }

    /// 记录一次连接延迟（毫秒）
    pub fn record_latency_ms(&self, latency_ms: u64) {
        if let Ok(mut ring) = self.latency_ring.lock() {
            ring.push_back(latency_ms);
            while ring.len() > self.latency_capacity {
                ring.pop_front();
            }
        }
    }

    /// 获取路由命中统计
    pub fn route_stats(&self) -> HashMap<String, u64> {
        self.route_stats
            .lock()
            .map(|m| m.clone())
            .unwrap_or_default()
    }

    /// 获取错误码统计
    pub fn error_stats(&self) -> HashMap<String, u64> {
        self.error_stats
            .lock()
            .map(|m| m.clone())
            .unwrap_or_default()
    }

    /// 获取连接时延分位（毫秒）
    pub fn latency_percentiles_ms(&self) -> Option<(u64, u64, u64)> {
        let mut values: Vec<u64> = self
            .latency_ring
            .lock()
            .map(|v| v.iter().copied().collect())
            .unwrap_or_default();
        if values.is_empty() {
            return None;
        }
        values.sort_unstable();

        let p_at = |p: f64| -> u64 {
            let idx = ((values.len() as f64 - 1.0) * p).round() as usize;
            values[idx]
        };

        Some((p_at(0.50), p_at(0.95), p_at(0.99)))
    }

    /// 关闭所有连接
    pub async fn close_all(&self) -> usize {
        let mut conns = self.connections.write().await;
        let count = conns.len();
        conns.clear();
        count
    }
}

/// 连接守卫，Drop 时自动从 tracker 移除
pub struct ConnectionGuard<'a> {
    id: u64,
    pub upload: Arc<AtomicU64>,
    pub download: Arc<AtomicU64>,
    tracker: &'a ConnectionTracker,
}

impl<'a> ConnectionGuard<'a> {
    pub fn id(&self) -> u64 {
        self.id
    }

    /// 记录上传字节数
    pub fn add_upload(&self, bytes: u64) {
        self.upload.fetch_add(bytes, Ordering::Relaxed);
    }

    /// 记录下载字节数
    pub fn add_download(&self, bytes: u64) {
        self.download.fetch_add(bytes, Ordering::Relaxed);
    }
}

impl<'a> Drop for ConnectionGuard<'a> {
    fn drop(&mut self) {
        let id = self.id;
        let tracker = self.tracker;
        // 由于 Drop 不是 async，使用 try_write 尝试同步移除
        // 如果锁被占用，连接信息会在下次清理时移除
        if let Ok(mut conns) = tracker.connections.try_write() {
            if let Some(tc) = conns.remove(&id) {
                let up = tc.upload.load(Ordering::Relaxed);
                let down = tc.download.load(Ordering::Relaxed);
                tracker.total_upload.fetch_add(up, Ordering::Relaxed);
                tracker.total_download.fetch_add(down, Ordering::Relaxed);
            }
        }
    }
}
