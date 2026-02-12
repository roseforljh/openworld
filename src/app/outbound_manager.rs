use std::collections::HashMap;
use std::sync::Arc;

use anyhow::Result;
use tracing::info;

use crate::config::types::{OutboundConfig, ProxyGroupConfig};
use crate::proxy::group;
use crate::proxy::group::fallback::FallbackGroup;
use crate::proxy::group::health::HealthChecker;
use crate::proxy::group::selector::SelectorGroup;
use crate::proxy::group::urltest::UrlTestGroup;
use crate::proxy::outbound::chain::ProxyChain;
use crate::proxy::outbound::direct::DirectOutbound;
use crate::proxy::outbound::reject::{BlackholeOutbound, RejectOutbound};
use crate::proxy::outbound::hysteria2::Hysteria2Outbound;
use crate::proxy::outbound::shadowsocks::ShadowsocksOutbound;
use crate::proxy::outbound::trojan::TrojanOutbound;
use crate::proxy::outbound::tuic::TuicOutbound;
use crate::proxy::outbound::vless::VlessOutbound;
use crate::proxy::outbound::vmess::VmessOutbound;
use crate::proxy::outbound::wireguard::WireGuardOutbound;
use crate::proxy::outbound::http::HttpOutbound;
use crate::proxy::outbound::socks5::Socks5Outbound;
use crate::proxy::outbound::ssh::SshOutbound;
use crate::proxy::outbound::naive::NaiveOutbound;
use crate::proxy::outbound::hysteria_v1::HysteriaV1Outbound;
use crate::proxy::outbound::tor::TorOutbound;
use crate::proxy::outbound::masque::MasqueOutbound;
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
    pub fn new(configs: &[OutboundConfig], group_configs: &[ProxyGroupConfig]) -> Result<Self> {
        let mut handlers: HashMap<String, Arc<dyn OutboundHandler>> = HashMap::new();
        let mut group_metas: HashMap<String, GroupMeta> = HashMap::new();
        let config_map: HashMap<&str, &OutboundConfig> =
            configs.iter().map(|cfg| (cfg.tag.as_str(), cfg)).collect();

        // 1. 注册基础出站
        for config in configs {
            if config.protocol == "chain" {
                continue;
            }

            let handler: Arc<dyn OutboundHandler> = match config.protocol.as_str() {
                "direct" => Arc::new(DirectOutbound::new(config.tag.clone()).with_dialer(config.settings.dialer.clone())),
                "vless" => Arc::new(VlessOutbound::new(config)?),
                "hysteria2" => Arc::new(Hysteria2Outbound::new(config)?),
                "hysteria" | "hysteria1" => Arc::new(HysteriaV1Outbound::new(config)?),
                "shadowsocks" | "ss" => Arc::new(ShadowsocksOutbound::new(config)?),
                "trojan" => Arc::new(TrojanOutbound::new(config)?),
                "vmess" => Arc::new(VmessOutbound::new(config)?),
                "wireguard" | "wg" => Arc::new(WireGuardOutbound::new(config)?),
                "http" | "https" => Arc::new(HttpOutbound::new(config)?),
                "socks5" | "socks" => Arc::new(Socks5Outbound::new(config)?),
                "ssh" => Arc::new(SshOutbound::new(config)?),
                "tuic" => Arc::new(TuicOutbound::new(config)?),
                "tor" => Arc::new(TorOutbound::new(config)?),
                "reject" | "block" => Arc::new(RejectOutbound::new(config.tag.clone())),
                "naive" | "naiveproxy" => Arc::new(NaiveOutbound::new(config)?),
                "blackhole" => Arc::new(BlackholeOutbound::new(config.tag.clone())),
                "masque" => Arc::new(MasqueOutbound::new(config)?),
                other => anyhow::bail!("unsupported outbound protocol: {}", other),
            };
            info!(
                tag = config.tag,
                protocol = config.protocol,
                "outbound registered"
            );
            handlers.insert(config.tag.clone(), handler);
        }

        for config in configs {
            if config.protocol != "chain" {
                continue;
            }

            let chain_tags = config
                .settings
                .chain
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("chain outbound '{}' requires settings.chain", config.tag))?;
            if chain_tags.is_empty() {
                anyhow::bail!("chain outbound '{}' requires non-empty settings.chain", config.tag);
            }

            let mut chain = Vec::with_capacity(chain_tags.len());
            for hop_tag in chain_tags {
                if hop_tag == &config.tag {
                    anyhow::bail!("chain outbound '{}' cannot contain itself", config.tag);
                }

                let hop_cfg = config_map.get(hop_tag.as_str()).ok_or_else(|| {
                    anyhow::anyhow!(
                        "chain outbound '{}' references unknown hop '{}'",
                        config.tag,
                        hop_tag
                    )
                })?;

                if hop_cfg.protocol == "chain" {
                    anyhow::bail!(
                        "chain outbound '{}' does not support chain hop '{}'",
                        config.tag,
                        hop_tag
                    );
                }

                let hop = handlers.get(hop_tag).cloned().ok_or_else(|| {
                    anyhow::anyhow!(
                        "chain outbound '{}' hop '{}' is not initialized",
                        config.tag,
                        hop_tag
                    )
                })?;
                chain.push(hop);
            }

            let handler: Arc<dyn OutboundHandler> =
                Arc::new(ProxyChain::new(config.tag.clone(), chain)?);
            info!(tag = config.tag, protocol = config.protocol, "outbound registered");
            handlers.insert(config.tag.clone(), handler);
        }

        let groups = group::build_proxy_groups(group_configs, &handlers)?;
        for (name, handler) in groups {
            info!(name = name, "proxy group registered");
            handlers.insert(name.clone(), handler);
        }

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
    pub async fn test_delay(&self, proxy_name: &str, url: &str, timeout_ms: u64) -> Option<u64> {
        let handler = self.handlers.get(proxy_name)?;
        let timeout = std::time::Duration::from_millis(timeout_ms);
        HealthChecker::test_proxy(handler.as_ref(), url, timeout).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::types::OutboundSettings;

    #[test]
    fn outbound_manager_registers_ssh() {
        let outbounds = vec![OutboundConfig {
            tag: "ssh-out".to_string(),
            protocol: "ssh".to_string(),
            settings: OutboundSettings {
                address: Some("127.0.0.1".to_string()),
                port: Some(22),
                username: Some("root".to_string()),
                password: Some("pw".to_string()),
                ..Default::default()
            },
        }];

        let manager = OutboundManager::new(&outbounds, &[]).unwrap();
        assert!(manager.get("ssh-out").is_some());
    }

    #[test]
    fn outbound_manager_registers_tuic() {
        let outbounds = vec![OutboundConfig {
            tag: "tuic-out".to_string(),
            protocol: "tuic".to_string(),
            settings: OutboundSettings {
                address: Some("127.0.0.1".to_string()),
                port: Some(443),
                uuid: Some("550e8400-e29b-41d4-a716-446655440000".to_string()),
                password: Some("pw".to_string()),
                ..Default::default()
            },
        }];

        let manager = OutboundManager::new(&outbounds, &[]).unwrap();
        assert!(manager.get("tuic-out").is_some());
    }

    #[test]
    fn outbound_manager_registers_chain() {
        let outbounds = vec![
            OutboundConfig {
                tag: "direct-a".to_string(),
                protocol: "direct".to_string(),
                settings: OutboundSettings::default(),
            },
            OutboundConfig {
                tag: "chain-out".to_string(),
                protocol: "chain".to_string(),
                settings: OutboundSettings {
                    chain: Some(vec!["direct-a".to_string()]),
                    ..Default::default()
                },
            },
        ];

        let manager = OutboundManager::new(&outbounds, &[]).unwrap();
        assert!(manager.get("chain-out").is_some());
    }

    #[test]
    fn outbound_manager_chain_unknown_hop_fails() {
        let outbounds = vec![OutboundConfig {
            tag: "chain-out".to_string(),
            protocol: "chain".to_string(),
            settings: OutboundSettings {
                chain: Some(vec!["missing-hop".to_string()]),
                ..Default::default()
            },
        }];

        assert!(OutboundManager::new(&outbounds, &[]).is_err());
    }
}
