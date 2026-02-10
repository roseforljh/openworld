use std::sync::Arc;

use anyhow::Result;
use async_trait::async_trait;
use tokio::sync::RwLock;
use tracing::info;

use crate::common::{BoxUdpTransport, ProxyStream};
use crate::proxy::{OutboundHandler, Session};

/// 手动选择代理组
pub struct SelectorGroup {
    name: String,
    proxies: Vec<Arc<dyn OutboundHandler>>,
    proxy_names: Vec<String>,
    selected: RwLock<usize>,
}

impl SelectorGroup {
    pub fn new(
        name: String,
        proxies: Vec<Arc<dyn OutboundHandler>>,
        proxy_names: Vec<String>,
    ) -> Self {
        Self {
            name,
            proxies,
            proxy_names,
            selected: RwLock::new(0),
        }
    }

    pub async fn select(&self, name: &str) -> bool {
        if let Some(idx) = self.proxy_names.iter().position(|n| n == name) {
            *self.selected.write().await = idx;
            info!(group = self.name, selected = name, "proxy group selection changed");
            true
        } else {
            false
        }
    }

    pub async fn selected_name(&self) -> String {
        let idx = *self.selected.read().await;
        self.proxy_names[idx].clone()
    }

    pub fn proxy_names(&self) -> &[String] {
        &self.proxy_names
    }
}

#[async_trait]
impl OutboundHandler for SelectorGroup {
    fn tag(&self) -> &str {
        &self.name
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    async fn connect(&self, session: &Session) -> Result<ProxyStream> {
        let idx = *self.selected.read().await;
        self.proxies[idx].connect(session).await
    }

    async fn connect_udp(&self, session: &Session) -> Result<BoxUdpTransport> {
        let idx = *self.selected.read().await;
        self.proxies[idx].connect_udp(session).await
    }
}
