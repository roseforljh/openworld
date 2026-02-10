use std::sync::Arc;

use anyhow::Result;
use async_trait::async_trait;
use tokio::sync::RwLock;
use tracing::info;

use crate::common::{BoxUdpTransport, ProxyStream};
use crate::proxy::{OutboundHandler, Session};

use super::health::HealthChecker;

/// 自动选择代理组（按延迟最低选择）
pub struct UrlTestGroup {
    name: String,
    proxies: Vec<Arc<dyn OutboundHandler>>,
    proxy_names: Vec<String>,
    selected: RwLock<usize>,
    health: Arc<HealthChecker>,
    tolerance: u64,
}

impl UrlTestGroup {
    pub fn new(
        name: String,
        proxies: Vec<Arc<dyn OutboundHandler>>,
        proxy_names: Vec<String>,
        url: String,
        interval: u64,
        tolerance: u64,
    ) -> Self {
        let health = Arc::new(HealthChecker::new(
            proxies.clone(),
            proxy_names.clone(),
            url,
            interval,
        ));

        // 启动后台健康检查
        let health_clone = health.clone();
        let group_name = name.clone();
        tokio::spawn(async move {
            health_clone.run_loop(group_name).await;
        });

        Self {
            name,
            proxies,
            proxy_names,
            selected: RwLock::new(0),
            health,
            tolerance,
        }
    }

    /// 根据最新延迟数据选择最佳代理
    async fn update_selection(&self) {
        let latencies = self.health.latencies().await;
        let current_idx = *self.selected.read().await;
        let current_name = &self.proxy_names[current_idx];

        let current_latency = latencies.get(current_name).copied().flatten();

        let mut best_idx = None;
        let mut best_latency = u64::MAX;

        for (idx, name) in self.proxy_names.iter().enumerate() {
            if let Some(Some(lat)) = latencies.get(name) {
                if *lat < best_latency {
                    best_latency = *lat;
                    best_idx = Some(idx);
                }
            }
        }

        if let Some(best) = best_idx {
            // 只在延迟差超过容差时切换
            let should_switch = match current_latency {
                Some(cur) => cur > best_latency + self.tolerance,
                None => true, // 当前代理无延迟数据，切换
            };

            if should_switch && best != current_idx {
                *self.selected.write().await = best;
                info!(
                    group = self.name,
                    from = self.proxy_names[current_idx],
                    to = self.proxy_names[best],
                    latency = best_latency,
                    "url-test auto-switched"
                );
            }
        }
    }

    pub async fn selected_name(&self) -> String {
        self.update_selection().await;
        let idx = *self.selected.read().await;
        self.proxy_names[idx].clone()
    }

    pub fn proxy_names(&self) -> &[String] {
        &self.proxy_names
    }

    pub fn health(&self) -> &Arc<HealthChecker> {
        &self.health
    }
}

#[async_trait]
impl OutboundHandler for UrlTestGroup {
    fn tag(&self) -> &str {
        &self.name
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    async fn connect(&self, session: &Session) -> Result<ProxyStream> {
        self.update_selection().await;
        let idx = *self.selected.read().await;
        self.proxies[idx].connect(session).await
    }

    async fn connect_udp(&self, session: &Session) -> Result<BoxUdpTransport> {
        self.update_selection().await;
        let idx = *self.selected.read().await;
        self.proxies[idx].connect_udp(session).await
    }
}
