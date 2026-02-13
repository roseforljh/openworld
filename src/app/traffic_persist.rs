//! 流量统计持久化
//!
//! 将连接统计数据定期写入磁盘 JSON 文件，支持跨重启保留。
//! 轻量级实现，避免引入 SQLite/RocksDB 等重依赖。

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

/// 持久化的流量统计摘要
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TrafficStats {
    /// 累计上行字节
    pub total_upload: u64,
    /// 累计下行字节
    pub total_download: u64,
    /// 累计连接数
    pub total_connections: u64,
    /// 各出站代理的流量统计
    pub per_proxy: std::collections::HashMap<String, ProxyTraffic>,
    /// 最后写入时间戳（Unix 秒）
    pub last_saved: u64,
}

/// 单个代理的流量统计
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProxyTraffic {
    pub upload: u64,
    pub download: u64,
    pub connections: u64,
}

/// 流量统计持久化管理器
pub struct TrafficPersistence {
    path: PathBuf,
    stats: Arc<RwLock<TrafficStats>>,
}

impl TrafficPersistence {
    /// 创建管理器，立即从磁盘加载历史数据
    pub fn new(path: PathBuf) -> Self {
        let stats = Self::load_from_disk(&path).unwrap_or_default();
        Self {
            path,
            stats: Arc::new(RwLock::new(stats)),
        }
    }

    /// 获取当前统计数据快照
    pub async fn snapshot(&self) -> TrafficStats {
        self.stats.read().await.clone()
    }

    /// 记录一次连接的流量
    pub async fn record(&self, proxy_tag: &str, upload: u64, download: u64) {
        let mut stats = self.stats.write().await;
        stats.total_upload += upload;
        stats.total_download += download;
        stats.total_connections += 1;

        let entry = stats.per_proxy.entry(proxy_tag.to_string()).or_default();
        entry.upload += upload;
        entry.download += download;
        entry.connections += 1;
    }

    /// 批量记录
    pub async fn record_batch(&self, records: &[(&str, u64, u64)]) {
        let mut stats = self.stats.write().await;
        for &(proxy_tag, upload, download) in records {
            stats.total_upload += upload;
            stats.total_download += download;
            stats.total_connections += 1;

            let entry = stats.per_proxy.entry(proxy_tag.to_string()).or_default();
            entry.upload += upload;
            entry.download += download;
            entry.connections += 1;
        }
    }

    /// 持久化到磁盘
    pub async fn save(&self) -> Result<(), String> {
        let mut stats = self.stats.read().await.clone();
        stats.last_saved = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let json =
            serde_json::to_string_pretty(&stats).map_err(|e| format!("serialize failed: {}", e))?;

        // 原子写入：先写临时文件再重命名
        let tmp_path = self.path.with_extension("tmp");
        std::fs::write(&tmp_path, &json).map_err(|e| format!("write tmp failed: {}", e))?;
        std::fs::rename(&tmp_path, &self.path).map_err(|e| format!("rename failed: {}", e))?;

        tracing::debug!(bytes = json.len(), "traffic stats saved");
        Ok(())
    }

    /// 清零统计
    pub async fn reset(&self) {
        let mut stats = self.stats.write().await;
        *stats = TrafficStats::default();
    }

    /// 启动定时保存任务
    pub fn spawn_periodic_save(
        self: &Arc<Self>,
        interval: Duration,
        cancel: tokio_util::sync::CancellationToken,
    ) -> tokio::task::JoinHandle<()> {
        let this = Arc::clone(self);
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            ticker.tick().await; // 跳过首次立即触发

            loop {
                tokio::select! {
                    _ = cancel.cancelled() => {
                        // 退出前最后保存一次
                        if let Err(e) = this.save().await {
                            tracing::warn!(error = %e, "final traffic stats save failed");
                        }
                        break;
                    }
                    _ = ticker.tick() => {
                        if let Err(e) = this.save().await {
                            tracing::warn!(error = %e, "periodic traffic stats save failed");
                        }
                    }
                }
            }
        })
    }

    /// 从磁盘加载
    fn load_from_disk(path: &PathBuf) -> Option<TrafficStats> {
        let data = std::fs::read_to_string(path).ok()?;
        serde_json::from_str(&data).ok()
    }

    /// 获取 JSON 格式的统计数据
    pub async fn to_json(&self) -> String {
        let stats = self.stats.read().await;
        serde_json::to_string(&*stats).unwrap_or_else(|_| "{}".to_string())
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// 测试
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn record_and_snapshot() {
        let tmp = std::env::temp_dir().join("openworld_test_traffic.json");
        let _ = std::fs::remove_file(&tmp);

        let persistence = TrafficPersistence::new(tmp.clone());
        persistence.record("proxy-a", 1000, 2000).await;
        persistence.record("proxy-b", 500, 800).await;
        persistence.record("proxy-a", 300, 400).await;

        let snap = persistence.snapshot().await;
        assert_eq!(snap.total_upload, 1800);
        assert_eq!(snap.total_download, 3200);
        assert_eq!(snap.total_connections, 3);
        assert_eq!(snap.per_proxy["proxy-a"].upload, 1300);
        assert_eq!(snap.per_proxy["proxy-a"].connections, 2);
        assert_eq!(snap.per_proxy["proxy-b"].download, 800);

        let _ = std::fs::remove_file(&tmp);
    }

    #[tokio::test]
    async fn save_and_reload() {
        let tmp = std::env::temp_dir().join("openworld_test_traffic_persist.json");
        let _ = std::fs::remove_file(&tmp);

        // 写入
        {
            let p = TrafficPersistence::new(tmp.clone());
            p.record("ss-jp", 10000, 20000).await;
            p.save().await.unwrap();
        }

        // 重载
        {
            let p = TrafficPersistence::new(tmp.clone());
            let snap = p.snapshot().await;
            assert_eq!(snap.total_upload, 10000);
            assert_eq!(snap.total_download, 20000);
            assert_eq!(snap.per_proxy["ss-jp"].connections, 1);
        }

        let _ = std::fs::remove_file(&tmp);
    }

    #[tokio::test]
    async fn reset_clears_all() {
        let tmp = std::env::temp_dir().join("openworld_test_traffic_reset.json");
        let _ = std::fs::remove_file(&tmp);

        let p = TrafficPersistence::new(tmp.clone());
        p.record("proxy-x", 999, 888).await;
        p.reset().await;

        let snap = p.snapshot().await;
        assert_eq!(snap.total_upload, 0);
        assert_eq!(snap.total_connections, 0);
        assert!(snap.per_proxy.is_empty());

        let _ = std::fs::remove_file(&tmp);
    }

    #[tokio::test]
    async fn batch_record() {
        let tmp = std::env::temp_dir().join("openworld_test_traffic_batch.json");
        let _ = std::fs::remove_file(&tmp);

        let p = TrafficPersistence::new(tmp.clone());
        p.record_batch(&[("a", 100, 200), ("b", 300, 400), ("a", 50, 60)])
            .await;

        let snap = p.snapshot().await;
        assert_eq!(snap.total_upload, 450);
        assert_eq!(snap.total_download, 660);
        assert_eq!(snap.per_proxy["a"].upload, 150);

        let _ = std::fs::remove_file(&tmp);
    }

    #[tokio::test]
    async fn to_json_format() {
        let tmp = std::env::temp_dir().join("openworld_test_traffic_json.json");
        let _ = std::fs::remove_file(&tmp);

        let p = TrafficPersistence::new(tmp.clone());
        p.record("test", 100, 200).await;

        let json = p.to_json().await;
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["total_upload"], 100);
        assert_eq!(parsed["total_download"], 200);

        let _ = std::fs::remove_file(&tmp);
    }
}
