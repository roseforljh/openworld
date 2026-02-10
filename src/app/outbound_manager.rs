use std::collections::HashMap;
use std::sync::Arc;

use anyhow::Result;
use tracing::info;

use crate::config::types::{OutboundConfig, ProxyGroupConfig};
use crate::proxy::group;
use crate::proxy::group::selector::SelectorGroup;
use crate::proxy::group::urltest::UrlTestGroup;
use crate::proxy::group::fallback::FallbackGroup;
use crate::proxy::group::health::HealthChecker;
use crate::proxy::outbound::direct::DirectOutbound;
use crate::proxy::outbound::hysteria2::Hysteria2Outbound;
use crate::proxy::outbound::vless::VlessOutbound;
use crate::proxy::OutboundHandler;

/// 代理组元数据
pub struct GroupMeta {
    pub group_type: String,
    pub proxy_names: Vec<String>,
}

pub struct OutboundManager {
    handlers: HashMap<String, Arc<dyn OutboundHandler>>,
    /// 代理组元数据（组名 -> 元数据）
    group_metas: HashMap<String, GroupMeta>,
}

impl OutboundManager {
    pub fn new(
        configs: &[OutboundConfig],
        group_configs: &[ProxyGroupConfig],
    ) -> Result<Self> {
        let mut handlers: HashMap<String, Arc<dyn OutboundHandler>> = HashMap::new();
        let mut group_metas: HashMap<String, GroupMeta> = HashMap::new();

        // 1. 注册基础出站
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

        // 2. 注册代理组
        let groups = group::build_proxy_groups(group_configs, &handlers)?;
        for (name, handler) in groups {
            info!(name = name, "proxy group registered");
            handlers.insert(name.clone(), handler);
        }

        // 3. 存储组元数据
        for config in group_configs {
            group_metas.insert(
                config.name.clone(),
                GroupMeta {
                    group_type: config.group_type.clone(),
                    proxy_names: config.proxies.clone(),
                },
            );
        }

        Ok(Self {
            handlers,
            group_metas,
        })
    }

    pub fn get(&self, tag: &str) -> Option<Arc<dyn OutboundHandler>> {
        self.handlers.get(tag).cloned()
    }

    pub fn list(&self) -> &HashMap<String, Arc<dyn OutboundHandler>> {
        &self.handlers
    }

    /// 获取代理组元数据
    pub fn group_meta(&self, name: &str) -> Option<&GroupMeta> {
        self.group_metas.get(name)
    }

    /// 判断是否为代理组
    pub fn is_group(&self, name: &str) -> bool {
        self.group_metas.contains_key(name)
    }

    /// 获取代理组当前选中的代理名称
    pub async fn group_selected(&self, name: &str) -> Option<String> {
        let handler = self.handlers.get(name)?;
        let any = handler.as_any();

        if let Some(selector) = any.downcast_ref::<SelectorGroup>() {
            return Some(selector.selected_name().await);
        }
        if let Some(urltest) = any.downcast_ref::<UrlTestGroup>() {
            return Some(urltest.selected_name().await);
        }
        if let Some(fallback) = any.downcast_ref::<FallbackGroup>() {
            return Some(fallback.selected_name().await);
        }
        // load-balance 没有固定选中
        None
    }

    /// 切换 selector 类型代理组的选中代理
    pub async fn select_proxy(&self, group_name: &str, proxy_name: &str) -> bool {
        let handler = match self.handlers.get(group_name) {
            Some(h) => h,
            None => return false,
        };

        match handler.as_any().downcast_ref::<SelectorGroup>() {
            Some(selector) => selector.select(proxy_name).await,
            None => false,
        }
    }

    /// 测试代理延迟
    pub async fn test_delay(
        &self,
        proxy_name: &str,
        url: &str,
        timeout_ms: u64,
    ) -> Option<u64> {
        let handler = self.handlers.get(proxy_name)?;
        let timeout = std::time::Duration::from_millis(timeout_ms);
        HealthChecker::test_proxy(handler.as_ref(), url, timeout).await
    }
}
