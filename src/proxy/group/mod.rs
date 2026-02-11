pub mod fallback;
pub mod health;
pub mod latency_weighted;
pub mod loadbalance;
pub mod persistence;
pub mod selector;
pub mod sticky;
pub mod urltest;

use std::collections::HashMap;
use std::sync::Arc;

use anyhow::Result;

use crate::config::types::ProxyGroupConfig;
use crate::proxy::OutboundHandler;

/// 构建代理组，返回 (name, handler) 列表
/// `existing` 包含已注册的 outbound + 已构建的 group
pub fn build_proxy_groups(
    configs: &[ProxyGroupConfig],
    existing: &HashMap<String, Arc<dyn OutboundHandler>>,
) -> Result<Vec<(String, Arc<dyn OutboundHandler>)>> {
    let mut result = Vec::new();

    for config in configs {
        // 收集该 group 引用的所有代理
        let mut proxies: Vec<Arc<dyn OutboundHandler>> = Vec::new();
        let mut proxy_names: Vec<String> = Vec::new();

        for name in &config.proxies {
            // 从 existing + 本批次已构建的 group 中查找
            let handler = existing
                .get(name)
                .or_else(|| {
                    result
                        .iter()
                        .find(|(n, _)| n == name)
                        .map(|(_, h): &(String, Arc<dyn OutboundHandler>)| h)
                })
                .ok_or_else(|| {
                    anyhow::anyhow!(
                        "proxy-group '{}' references unknown proxy '{}'",
                        config.name,
                        name
                    )
                })?;
            proxies.push(handler.clone());
            proxy_names.push(name.clone());
        }

        if proxies.is_empty() {
            anyhow::bail!("proxy-group '{}' has no proxies", config.name);
        }

        let handler: Arc<dyn OutboundHandler> = match config.group_type.as_str() {
            "selector" => Arc::new(selector::SelectorGroup::new(
                config.name.clone(),
                proxies,
                proxy_names,
            )),
            "url-test" => Arc::new(urltest::UrlTestGroup::new(
                config.name.clone(),
                proxies,
                proxy_names,
                config
                    .url
                    .clone()
                    .unwrap_or_else(|| "http://www.gstatic.com/generate_204".to_string()),
                config.interval,
                config.tolerance,
            )),
            "fallback" => Arc::new(fallback::FallbackGroup::new(
                config.name.clone(),
                proxies,
                proxy_names,
                config
                    .url
                    .clone()
                    .unwrap_or_else(|| "http://www.gstatic.com/generate_204".to_string()),
                config.interval,
            )),
            "load-balance" => Arc::new(loadbalance::LoadBalanceGroup::new(
                config.name.clone(),
                proxies,
                proxy_names,
            )),
            other => anyhow::bail!(
                "unsupported proxy-group type '{}' for group '{}'",
                other,
                config.name
            ),
        };

        result.push((config.name.clone(), handler));
    }

    Ok(result)
}
