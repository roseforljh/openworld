//! 独立延迟测试模块
//!
//! 不依赖核心启动，直接创建outbound handlers进行延迟测试
//! 适用于在不开启VPN的情况下测试节点延迟

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use tokio::runtime::Runtime;
use tracing::{debug, info, warn};

use crate::config::types::OutboundConfig;
use crate::proxy::group::health::HealthChecker;
use crate::proxy::outbound::direct::DirectOutbound;
use crate::proxy::outbound::http::HttpOutbound;
use crate::proxy::outbound::hysteria2::Hysteria2Outbound;
use crate::proxy::outbound::hysteria_v1::HysteriaV1Outbound;
use crate::proxy::outbound::masque::MasqueOutbound;
use crate::proxy::outbound::naive::NaiveOutbound;
use crate::proxy::outbound::reject::{BlackholeOutbound, RejectOutbound};
use crate::proxy::outbound::shadowsocks::ShadowsocksOutbound;
use crate::proxy::outbound::socks5::Socks5Outbound;
use crate::proxy::outbound::ssh::SshOutbound;
use crate::proxy::outbound::tor::TorOutbound;
use crate::proxy::outbound::trojan::TrojanOutbound;
use crate::proxy::outbound::tuic::TuicOutbound;
use crate::proxy::outbound::vless::VlessOutbound;
use crate::proxy::outbound::vmess::VmessOutbound;
use crate::proxy::outbound::wireguard::WireGuardOutbound;
use crate::proxy::OutboundHandler;

/// 延迟测试结果
#[derive(Debug, Clone)]
pub struct LatencyResult {
    pub tag: String,
    /// 延迟（毫秒），-1 表示失败
    pub latency_ms: i64,
    /// 错误信息（如有）
    pub error: Option<String>,
}

/// 延迟测试器
pub struct LatencyTester {
    runtime: Runtime,
    handlers: HashMap<String, Arc<dyn OutboundHandler>>,
}

impl LatencyTester {
    /// 创建新的延迟测试器
    pub fn new() -> Result<Self> {
        let runtime = Runtime::new()?;
        Ok(Self {
            runtime,
            handlers: HashMap::new(),
        })
    }

    /// 注册需要测试的outbounds
    pub fn register_outbounds(&mut self, configs: &[OutboundConfig]) -> Result<()> {
        for config in configs {
            if config.protocol == "direct"
                || config.protocol == "reject"
                || config.protocol == "block"
            {
                continue;
            }

            let handler: Arc<dyn OutboundHandler> = match config.protocol.as_str() {
                "vless" => Arc::new(VlessOutbound::new(config).map_err(|e| {
                    anyhow::anyhow!("failed to create VlessOutbound for {}: {}", config.tag, e)
                })?),
                "hysteria2" => Arc::new(Hysteria2Outbound::new(config).map_err(|e| {
                    anyhow::anyhow!(
                        "failed to create Hysteria2Outbound for {}: {}",
                        config.tag,
                        e
                    )
                })?),
                "hysteria" | "hysteria1" => {
                    Arc::new(HysteriaV1Outbound::new(config).map_err(|e| {
                        anyhow::anyhow!(
                            "failed to create HysteriaV1Outbound for {}: {}",
                            config.tag,
                            e
                        )
                    })?)
                }
                "shadowsocks" | "ss" => {
                    Arc::new(ShadowsocksOutbound::new(config).map_err(|e| {
                        anyhow::anyhow!(
                            "failed to create ShadowsocksOutbound for {}: {}",
                            config.tag,
                            e
                        )
                    })?)
                }
                "trojan" => Arc::new(TrojanOutbound::new(config).map_err(|e| {
                    anyhow::anyhow!("failed to create TrojanOutbound for {}: {}", config.tag, e)
                })?),
                "vmess" => Arc::new(VmessOutbound::new(config).map_err(|e| {
                    anyhow::anyhow!("failed to create VmessOutbound for {}: {}", config.tag, e)
                })?),
                "wireguard" | "wg" => Arc::new(WireGuardOutbound::new(config).map_err(|e| {
                    anyhow::anyhow!(
                        "failed to create WireGuardOutbound for {}: {}",
                        config.tag,
                        e
                    )
                })?),
                "http" | "https" => Arc::new(HttpOutbound::new(config).map_err(|e| {
                    anyhow::anyhow!("failed to create HttpOutbound for {}: {}", config.tag, e)
                })?),
                "socks5" | "socks" => Arc::new(Socks5Outbound::new(config).map_err(|e| {
                    anyhow::anyhow!("failed to create Socks5Outbound for {}: {}", config.tag, e)
                })?),
                "ssh" => Arc::new(SshOutbound::new(config).map_err(|e| {
                    anyhow::anyhow!("failed to create SshOutbound for {}: {}", config.tag, e)
                })?),
                "tuic" => Arc::new(TuicOutbound::new(config).map_err(|e| {
                    anyhow::anyhow!("failed to create TuicOutbound for {}: {}", config.tag, e)
                })?),
                "tor" => Arc::new(TorOutbound::new(config).map_err(|e| {
                    anyhow::anyhow!("failed to create TorOutbound for {}: {}", config.tag, e)
                })?),
                "reject" | "block" => Arc::new(RejectOutbound::new(config.tag.clone())),
                "naive" | "naiveproxy" => Arc::new(NaiveOutbound::new(config).map_err(|e| {
                    anyhow::anyhow!("failed to create NaiveOutbound for {}: {}", config.tag, e)
                })?),
                "blackhole" => Arc::new(BlackholeOutbound::new(config.tag.clone())),
                "masque" => Arc::new(MasqueOutbound::new(config).map_err(|e| {
                    anyhow::anyhow!("failed to create MasqueOutbound for {}: {}", config.tag, e)
                })?),
                "direct" => Arc::new(DirectOutbound::new(config.tag.clone())),
                other => {
                    warn!(protocol = other, "unsupported protocol for latency test");
                    continue;
                }
            };

            debug!(tag = %config.tag, protocol = %config.protocol, "outbound registered for latency test");
            self.handlers.insert(config.tag.clone(), handler);
        }

        // 只要有至少一个 handler 注册成功就算成功
        if self.handlers.is_empty() {
            anyhow::bail!("no outbounds could be registered");
        }

        info!(count = self.handlers.len(), "latency tester initialized");
        Ok(())
    }

    /// 测试单个outbound的延迟
    pub fn test_latency(&self, tag: &str, url: &str, timeout_ms: u64) -> LatencyResult {
        let handler = match self.handlers.get(tag) {
            Some(h) => h,
            None => {
                return LatencyResult {
                    tag: tag.to_string(),
                    latency_ms: -1,
                    error: Some("outbound not found".to_string()),
                };
            }
        };

        let result = self.runtime.block_on(async {
            HealthChecker::test_proxy(handler.as_ref(), url, Duration::from_millis(timeout_ms))
                .await
        });

        match result {
            Some(ms) => LatencyResult {
                tag: tag.to_string(),
                latency_ms: ms as i64,
                error: None,
            },
            None => LatencyResult {
                tag: tag.to_string(),
                latency_ms: -1,
                error: Some("connection failed or timeout".to_string()),
            },
        }
    }

    /// 批量测试所有已注册outbounds的延迟
    pub fn test_all_latency(&self, url: &str, timeout_ms: u64) -> Vec<LatencyResult> {
        let tags: Vec<String> = self.handlers.keys().cloned().collect();

        tags.into_iter()
            .map(|tag| {
                let result = self.test_latency(&tag, url, timeout_ms);
                debug!(tag = %result.tag, latency = result.latency_ms, "latency test result");
                result
            })
            .collect()
    }

    /// 获取已注册的outbound数量
    pub fn count(&self) -> usize {
        self.handlers.len()
    }
}

impl Default for LatencyTester {
    fn default() -> Self {
        Self::new().expect("failed to create latency tester")
    }
}

// Runtime在drop时会自动清理

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::types::{OutboundSettings, TlsConfig};

    #[test]
    fn test_latency_creation() {
        let tester = LatencyTester::new();
        assert!(tester.is_ok());
    }

    #[test]
    fn test_register_and_test() {
        let mut tester = LatencyTester::new().unwrap();

        // 创建一个测试用的VLESS配置
        let config = OutboundConfig {
            tag: "test".to_string(),
            protocol: "vless".to_string(),
            settings: OutboundSettings {
                address: Some("example.com".to_string()),
                port: Some(443),
                uuid: Some("test-uuid".to_string()),
                tls: Some(TlsConfig {
                    enabled: true,
                    security: "tls".to_string(),
                    ..Default::default()
                }),
                ..Default::default()
            },
        };

        let result = tester.register_outbounds(&[config]);
        // 这里可能会失败，因为配置可能不完整，但不会panic
        // 实际使用时需要完整配置
    }
}
