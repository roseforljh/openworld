use std::collections::HashMap;
use std::sync::Arc;

use anyhow::Result;
use tracing::info;

use crate::config::types::OutboundConfig;
use crate::proxy::outbound::direct::DirectOutbound;
use crate::proxy::outbound::hysteria2::Hysteria2Outbound;
use crate::proxy::outbound::vless::VlessOutbound;
use crate::proxy::OutboundHandler;

pub struct OutboundManager {
    handlers: HashMap<String, Arc<dyn OutboundHandler>>,
}

impl OutboundManager {
    pub fn new(configs: &[OutboundConfig]) -> Result<Self> {
        let mut handlers: HashMap<String, Arc<dyn OutboundHandler>> = HashMap::new();

        for config in configs {
            let handler: Arc<dyn OutboundHandler> = match config.protocol.as_str() {
                "direct" => Arc::new(DirectOutbound::new(config.tag.clone())),
                "vless" => Arc::new(VlessOutbound::new(config)?),
                "hysteria2" => Arc::new(Hysteria2Outbound::new(config)?),
                other => anyhow::bail!("unsupported outbound protocol: {}", other),
            };
            info!(tag = config.tag, protocol = config.protocol, "outbound registered");
            handlers.insert(config.tag.clone(), handler);
        }

        Ok(Self { handlers })
    }

    pub fn get(&self, tag: &str) -> Option<Arc<dyn OutboundHandler>> {
        self.handlers.get(tag).cloned()
    }

    pub fn list(&self) -> &HashMap<String, Arc<dyn OutboundHandler>> {
        &self.handlers
    }
}
