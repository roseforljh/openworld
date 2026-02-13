/// V2Ray Stats API — 兼容 V2Ray gRPC 统计接口。
///
/// 提供入站/出站流量统计和用户流量统计，
/// 兼容 V2Ray 的 Stats Service gRPC API。
///
/// ## API 端点 (通过 REST API 暴露)
/// - `GET /v2ray/stats` — 查询所有统计项
/// - `GET /v2ray/stats/{name}` — 查询指定统计项
/// - `POST /v2ray/stats/reset` — 重置统计
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use serde::Serialize;
use tracing::debug;

/// V2Ray 统计服务
pub struct StatsService {
    /// 统计计数器表：name -> counter
    counters: tokio::sync::RwLock<HashMap<String, Arc<StatCounter>>>,
}

/// 单个统计计数器
pub struct StatCounter {
    value: AtomicU64,
}

/// 统计查询结果
#[derive(Debug, Serialize)]
pub struct StatResult {
    pub name: String,
    pub value: u64,
}

/// 统计查询响应
#[derive(Debug, Serialize)]
pub struct StatsResponse {
    pub stat: Vec<StatResult>,
}

impl StatCounter {
    pub fn new() -> Self {
        Self {
            value: AtomicU64::new(0),
        }
    }

    pub fn add(&self, delta: u64) {
        self.value.fetch_add(delta, Ordering::Relaxed);
    }

    pub fn get(&self) -> u64 {
        self.value.load(Ordering::Relaxed)
    }

    pub fn reset(&self) -> u64 {
        self.value.swap(0, Ordering::Relaxed)
    }
}

impl StatsService {
    pub fn new() -> Self {
        Self {
            counters: tokio::sync::RwLock::new(HashMap::new()),
        }
    }

    /// 注册入站流量统计
    pub async fn register_inbound(&self, tag: &str) {
        let mut counters = self.counters.write().await;
        let uplink = format!("inbound>>>{}>>>traffic>>>uplink", tag);
        let downlink = format!("inbound>>>{}>>>traffic>>>downlink", tag);
        counters
            .entry(uplink)
            .or_insert_with(|| Arc::new(StatCounter::new()));
        counters
            .entry(downlink)
            .or_insert_with(|| Arc::new(StatCounter::new()));
        debug!(tag = tag, "V2Ray stats: inbound registered");
    }

    /// 注册出站流量统计
    pub async fn register_outbound(&self, tag: &str) {
        let mut counters = self.counters.write().await;
        let uplink = format!("outbound>>>{}>>>traffic>>>uplink", tag);
        let downlink = format!("outbound>>>{}>>>traffic>>>downlink", tag);
        counters
            .entry(uplink)
            .or_insert_with(|| Arc::new(StatCounter::new()));
        counters
            .entry(downlink)
            .or_insert_with(|| Arc::new(StatCounter::new()));
        debug!(tag = tag, "V2Ray stats: outbound registered");
    }

    /// 注册用户流量统计
    pub async fn register_user(&self, email: &str) {
        let mut counters = self.counters.write().await;
        let uplink = format!("user>>>{}>>>traffic>>>uplink", email);
        let downlink = format!("user>>>{}>>>traffic>>>downlink", email);
        counters
            .entry(uplink)
            .or_insert_with(|| Arc::new(StatCounter::new()));
        counters
            .entry(downlink)
            .or_insert_with(|| Arc::new(StatCounter::new()));
    }

    /// 获取计数器引用（用于高频更新）
    pub async fn get_counter(&self, name: &str) -> Option<Arc<StatCounter>> {
        let counters = self.counters.read().await;
        counters.get(name).cloned()
    }

    /// 记录入站上行流量
    pub async fn record_inbound_uplink(&self, tag: &str, bytes: u64) {
        let name = format!("inbound>>>{}>>>traffic>>>uplink", tag);
        if let Some(counter) = self.get_counter(&name).await {
            counter.add(bytes);
        }
    }

    /// 记录入站下行流量  
    pub async fn record_inbound_downlink(&self, tag: &str, bytes: u64) {
        let name = format!("inbound>>>{}>>>traffic>>>downlink", tag);
        if let Some(counter) = self.get_counter(&name).await {
            counter.add(bytes);
        }
    }

    /// 记录出站上行流量
    pub async fn record_outbound_uplink(&self, tag: &str, bytes: u64) {
        let name = format!("outbound>>>{}>>>traffic>>>uplink", tag);
        if let Some(counter) = self.get_counter(&name).await {
            counter.add(bytes);
        }
    }

    /// 记录出站下行流量
    pub async fn record_outbound_downlink(&self, tag: &str, bytes: u64) {
        let name = format!("outbound>>>{}>>>traffic>>>downlink", tag);
        if let Some(counter) = self.get_counter(&name).await {
            counter.add(bytes);
        }
    }

    /// 查询统计（V2Ray Stats Service: GetStats）
    pub async fn get_stats(&self, name: &str, reset: bool) -> Option<StatResult> {
        let counters = self.counters.read().await;
        counters.get(name).map(|counter| {
            let value = if reset {
                counter.reset()
            } else {
                counter.get()
            };
            StatResult {
                name: name.to_string(),
                value,
            }
        })
    }

    /// 查询所有统计（V2Ray Stats Service: QueryStats）
    pub async fn query_stats(&self, pattern: Option<&str>, reset: bool) -> StatsResponse {
        let counters = self.counters.read().await;
        let stat: Vec<StatResult> = counters
            .iter()
            .filter(|(name, _)| pattern.map(|p| name.contains(p)).unwrap_or(true))
            .map(|(name, counter)| {
                let value = if reset {
                    counter.reset()
                } else {
                    counter.get()
                };
                StatResult {
                    name: name.clone(),
                    value,
                }
            })
            .collect();
        StatsResponse { stat }
    }

    /// 获取系统统计信息
    pub async fn sys_stats(&self) -> SysStatsResponse {
        SysStatsResponse {
            num_goroutine: tokio::runtime::Handle::current().metrics().num_workers() as u32,
            num_gc: 0, // Rust 无 GC
            alloc: current_memory_alloc(),
            total_alloc: current_memory_alloc(),
            sys: current_memory_alloc(),
            mallocs: 0,
            frees: 0,
            live_objects: 0,
            uptime: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as u32,
        }
    }
}

/// V2Ray SysStats 响应
#[derive(Debug, Serialize)]
pub struct SysStatsResponse {
    #[serde(rename = "NumGoroutine")]
    pub num_goroutine: u32,
    #[serde(rename = "NumGC")]
    pub num_gc: u32,
    #[serde(rename = "Alloc")]
    pub alloc: u64,
    #[serde(rename = "TotalAlloc")]
    pub total_alloc: u64,
    #[serde(rename = "Sys")]
    pub sys: u64,
    #[serde(rename = "Mallocs")]
    pub mallocs: u64,
    #[serde(rename = "Frees")]
    pub frees: u64,
    #[serde(rename = "LiveObjects")]
    pub live_objects: u64,
    #[serde(rename = "Uptime")]
    pub uptime: u32,
}

fn current_memory_alloc() -> u64 {
    // 简单实现：读取进程 RSS
    #[cfg(target_os = "linux")]
    {
        std::fs::read_to_string("/proc/self/statm")
            .ok()
            .and_then(|s| {
                s.split_whitespace()
                    .nth(1)
                    .and_then(|v| v.parse::<u64>().ok())
            })
            .map(|pages| pages * 4096)
            .unwrap_or(0)
    }
    #[cfg(not(target_os = "linux"))]
    {
        0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn stats_service_basic() {
        let svc = StatsService::new();
        svc.register_outbound("proxy").await;

        svc.record_outbound_uplink("proxy", 1000).await;
        svc.record_outbound_uplink("proxy", 500).await;
        svc.record_outbound_downlink("proxy", 2000).await;

        let up = svc
            .get_stats("outbound>>>proxy>>>traffic>>>uplink", false)
            .await
            .unwrap();
        assert_eq!(up.value, 1500);

        let down = svc
            .get_stats("outbound>>>proxy>>>traffic>>>downlink", false)
            .await
            .unwrap();
        assert_eq!(down.value, 2000);
    }

    #[tokio::test]
    async fn stats_reset() {
        let svc = StatsService::new();
        svc.register_outbound("proxy").await;
        svc.record_outbound_uplink("proxy", 1000).await;

        let result = svc
            .get_stats("outbound>>>proxy>>>traffic>>>uplink", true)
            .await
            .unwrap();
        assert_eq!(result.value, 1000);

        // After reset, should be 0
        let result = svc
            .get_stats("outbound>>>proxy>>>traffic>>>uplink", false)
            .await
            .unwrap();
        assert_eq!(result.value, 0);
    }

    #[tokio::test]
    async fn query_stats_filter() {
        let svc = StatsService::new();
        svc.register_inbound("tun").await;
        svc.register_outbound("proxy").await;
        svc.record_inbound_uplink("tun", 100).await;
        svc.record_outbound_uplink("proxy", 200).await;

        let resp = svc.query_stats(Some("inbound"), false).await;
        assert!(resp.stat.iter().all(|s| s.name.contains("inbound")));
    }

    #[test]
    fn counter_atomic() {
        let counter = StatCounter::new();
        counter.add(100);
        counter.add(200);
        assert_eq!(counter.get(), 300);
        assert_eq!(counter.reset(), 300);
        assert_eq!(counter.get(), 0);
    }

    #[tokio::test]
    async fn sys_stats_no_panic() {
        let svc = StatsService::new();
        let stats = svc.sys_stats().await;
        // num_goroutine may be 0 in test context, so we just check it exists
        let _ = stats.num_goroutine;
    }
}
