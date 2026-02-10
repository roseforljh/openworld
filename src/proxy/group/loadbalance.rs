use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use anyhow::Result;
use async_trait::async_trait;

use crate::common::{BoxUdpTransport, ProxyStream};
use crate::proxy::{OutboundHandler, Session};

/// 负载均衡代理组：轮询分配
pub struct LoadBalanceGroup {
    name: String,
    proxies: Vec<Arc<dyn OutboundHandler>>,
    proxy_names: Vec<String>,
    counter: AtomicUsize,
}

impl LoadBalanceGroup {
    pub fn new(
        name: String,
        proxies: Vec<Arc<dyn OutboundHandler>>,
        proxy_names: Vec<String>,
    ) -> Self {
        Self {
            name,
            proxies,
            proxy_names,
            counter: AtomicUsize::new(0),
        }
    }

    fn next_index(&self) -> usize {
        let idx = self.counter.fetch_add(1, Ordering::Relaxed);
        idx % self.proxies.len()
    }

    pub fn proxy_names(&self) -> &[String] {
        &self.proxy_names
    }
}

#[async_trait]
impl OutboundHandler for LoadBalanceGroup {
    fn tag(&self) -> &str {
        &self.name
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    async fn connect(&self, session: &Session) -> Result<ProxyStream> {
        let idx = self.next_index();
        self.proxies[idx].connect(session).await
    }

    async fn connect_udp(&self, session: &Session) -> Result<BoxUdpTransport> {
        let idx = self.next_index();
        self.proxies[idx].connect_udp(session).await
    }
}
