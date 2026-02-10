use std::sync::Arc;

use anyhow::Result;
use async_trait::async_trait;
use tracing::debug;

use crate::common::{BoxUdpTransport, ProxyStream};
use crate::proxy::{OutboundHandler, Session};

use super::health::HealthChecker;

/// 故障转移代理组：按顺序尝试，使用第一个可用的代理
pub struct FallbackGroup {
    name: String,
    proxies: Vec<Arc<dyn OutboundHandler>>,
    proxy_names: Vec<String>,
    health: Arc<HealthChecker>,
}

impl FallbackGroup {
    pub fn new(
        name: String,
        proxies: Vec<Arc<dyn OutboundHandler>>,
        proxy_names: Vec<String>,
        url: String,
        interval: u64,
    ) -> Self {
        let health = Arc::new(HealthChecker::new(
            proxies.clone(),
            proxy_names.clone(),
            url,
            interval,
        ));

        let health_clone = health.clone();
        let group_name = name.clone();
        tokio::spawn(async move {
            health_clone.run_loop(group_name).await;
        });

        Self {
            name,
            proxies,
            proxy_names,
            health,
        }
    }

    /// 返回第一个健康的代理索引
    async fn first_available(&self) -> usize {
        let latencies = self.health.latencies().await;
        for (idx, name) in self.proxy_names.iter().enumerate() {
            if let Some(Some(_)) = latencies.get(name) {
                return idx;
            }
        }
        // 全部不可用时回退到第一个
        0
    }

    pub async fn selected_name(&self) -> String {
        let idx = self.first_available().await;
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
impl OutboundHandler for FallbackGroup {
    fn tag(&self) -> &str {
        &self.name
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    async fn connect(&self, session: &Session) -> Result<ProxyStream> {
        let idx = self.first_available().await;
        debug!(
            group = self.name,
            selected = self.proxy_names[idx],
            "fallback connecting"
        );
        self.proxies[idx].connect(session).await
    }

    async fn connect_udp(&self, session: &Session) -> Result<BoxUdpTransport> {
        let idx = self.first_available().await;
        self.proxies[idx].connect_udp(session).await
    }
}
