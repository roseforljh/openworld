pub mod android;
pub mod benchmark;
pub mod cert;
pub mod dispatcher;
pub mod ffi;
pub mod inbound_manager;
pub mod ops;
pub mod outbound_manager;
pub mod proxy_provider;
pub mod release;
pub mod resilience;
pub mod security;
pub mod service;
pub mod tracker;

use anyhow::Result;
use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use crate::config::subscription::ProxyNode;
use crate::config::types::{ApiConfig, OutboundConfig, OutboundSettings, ProxyGroupConfig};
use crate::config::Config;
use crate::dns::{self, DnsResolver, SystemResolver};
use crate::router::Router;

use dispatcher::Dispatcher;
use inbound_manager::InboundManager;
use outbound_manager::OutboundManager;
use proxy_provider::{ProxyProviderManager, SubscriptionManager};
use tracker::ConnectionTracker;

pub struct App {
    inbound_manager: InboundManager,
    dispatcher: Arc<Dispatcher>,
    _resolver: Arc<dyn DnsResolver>,
    cancel_token: CancellationToken,
    api_config: Option<ApiConfig>,
    config_path: Option<String>,
    log_broadcaster: Option<crate::api::log_broadcast::LogBroadcaster>,
    subscription_manager: Option<Arc<SubscriptionManager>>,
    provider_manager: Option<Arc<ProxyProviderManager>>,
    base_outbounds: Arc<Vec<OutboundConfig>>,
    proxy_groups: Arc<Vec<ProxyGroupConfig>>,
}

impl App {
    pub async fn new(
        config: Config,
        config_path: Option<String>,
        log_broadcaster: Option<crate::api::log_broadcast::LogBroadcaster>,
    ) -> Result<Self> {
        // Phase 9: Security audit before constructing components
        security::validate_and_warn(&config)?;

        let cancel_token = CancellationToken::new();
        let router = Arc::new(Router::new(&config.router)?);
        let outbound_manager = Arc::new(OutboundManager::new(
            &config.outbounds,
            &config.proxy_groups,
        )?);
        let resolver: Arc<dyn DnsResolver> = match config.dns.as_ref() {
            Some(dns_config) => Arc::from(dns::build_resolver(dns_config)?),
            None => Arc::new(SystemResolver),
        };
        let tracker = Arc::new(ConnectionTracker::new());
        let dispatcher = Arc::new(Dispatcher::new(
            router,
            outbound_manager,
            tracker,
            resolver.clone(),
        ));
        let inbound_manager =
            InboundManager::new(&config.inbounds, dispatcher.clone(), cancel_token.clone())?;

        let (subscription_manager, provider_manager) = if config.subscriptions.is_empty() {
            (None, None)
        } else {
            let provider_manager = Arc::new(ProxyProviderManager::new());
            let subscription_manager = Arc::new(SubscriptionManager::new(provider_manager.clone()));
            for sub in config.subscriptions.clone() {
                subscription_manager.add_subscription(sub).await;
            }
            (Some(subscription_manager), Some(provider_manager))
        };

        Ok(Self {
            inbound_manager,
            dispatcher,
            _resolver: resolver,
            cancel_token,
            api_config: config.api,
            config_path,
            log_broadcaster,
            subscription_manager,
            provider_manager,
            base_outbounds: Arc::new(config.outbounds),
            proxy_groups: Arc::new(config.proxy_groups),
        })
    }

    pub async fn run(self) -> Result<()> {
        info!("OpenWorld started");

        self.spawn_rule_provider_refresh_tasks().await;

        // 启动 API 服务器（如果配置了）
        let _api_handle = if let Some(ref api_config) = self.api_config {
            let broadcaster = self
                .log_broadcaster
                .clone()
                .unwrap_or_else(|| crate::api::log_broadcast::LogBroadcaster::new(256));
            Some(crate::api::start(
                api_config,
                self.dispatcher.clone(),
                self.config_path.clone(),
                broadcaster,
            )?)
        } else {
            None
        };

        let cancel_token = self.cancel_token.clone();
        let tracker = self.dispatcher.tracker().clone();

        let _subscription_task = if let (Some(subscription_manager), Some(provider_manager)) = (
            self.subscription_manager.clone(),
            self.provider_manager.clone(),
        ) {
            let dispatcher = self.dispatcher.clone();
            let cancel = cancel_token.clone();
            let base_outbounds = self.base_outbounds.clone();
            let proxy_groups = self.proxy_groups.clone();

            Some(tokio::spawn(async move {
                let mut interval = tokio::time::interval(Duration::from_secs(30));
                interval.tick().await;

                loop {
                    tokio::select! {
                        _ = cancel.cancelled() => {
                            break;
                        }
                        _ = interval.tick() => {
                            let now = std::time::SystemTime::now()
                                .duration_since(std::time::UNIX_EPOCH)
                                .unwrap_or_default()
                                .as_secs();
                            let subscriptions = subscription_manager.list_subscriptions().await;

                            for sub in subscriptions {
                                if !sub.enabled {
                                    continue;
                                }

                                let state = provider_manager.get_state(&sub.name).await;
                                let should_update = state
                                    .and_then(|s| s.last_updated)
                                    .map(|last| now.saturating_sub(last) >= sub.interval_secs)
                                    .unwrap_or(true);

                                if !should_update {
                                    continue;
                                }

                                match provider_manager.update_http_provider(&sub.name).await {
                                    Ok(node_count) => {
                                        info!(subscription = sub.name, nodes = node_count, "subscription updated");
                                        match build_outbound_manager_with_subscriptions(
                                            base_outbounds.as_ref(),
                                            proxy_groups.as_ref(),
                                            &provider_manager,
                                        ).await {
                                            Ok(new_om) => {
                                                dispatcher.update_outbound_manager(Arc::new(new_om)).await;
                                            }
                                            Err(e) => {
                                                warn!(error = %e, "failed to rebuild outbound manager from subscriptions");
                                            }
                                        }
                                    }
                                    Err(e) => {
                                        warn!(subscription = sub.name, error = %e, "subscription update failed");
                                    }
                                }
                            }
                        }
                    }
                }
            }))
        } else {
            None
        };

        tokio::select! {
            result = self.inbound_manager.run() => {
                result
            }
            _ = tokio::signal::ctrl_c() => {
                info!("received Ctrl+C, shutting down...");
                cancel_token.cancel();
                let closed = tracker.close_all().await;
                info!(connections = closed, "all connections closed");
                Ok(())
            }
        }
    }

    pub async fn shutdown(&self) {
        info!("initiating graceful shutdown");
        self.cancel_token.cancel();
        let closed = self.dispatcher.tracker().close_all().await;
        info!(connections = closed, "all connections closed");
    }

    pub fn dispatcher(&self) -> &Arc<Dispatcher> {
        &self.dispatcher
    }

    pub fn cancel_token(&self) -> &CancellationToken {
        &self.cancel_token
    }

    async fn spawn_rule_provider_refresh_tasks(&self) {
        let router = self.dispatcher.router().await;
        let provider_entries: Vec<(String, u64)> = router
            .providers()
            .iter()
            .filter_map(|(name, provider)| {
                if provider.should_periodic_refresh() {
                    Some((name.clone(), provider.interval_secs()))
                } else {
                    None
                }
            })
            .collect();
        drop(router);

        for (provider_name, interval_secs) in provider_entries {
            let dispatcher = self.dispatcher.clone();
            let cancel_token = self.cancel_token.clone();

            tokio::spawn(async move {
                let mut interval = tokio::time::interval(Duration::from_secs(interval_secs));
                interval.tick().await;

                loop {
                    tokio::select! {
                        _ = cancel_token.cancelled() => {
                            break;
                        }
                        _ = interval.tick() => {
                            let provider_opt = {
                                let current_router = dispatcher.router().await;
                                current_router.providers().get(&provider_name).cloned()
                            };

                            let provider = match provider_opt {
                                Some(p) => p,
                                None => {
                                    warn!(provider = provider_name.as_str(), "rule-provider not found during periodic refresh");
                                    continue;
                                }
                            };

                            if provider.lazy() && !provider.is_loaded() {
                                continue;
                            }

                            let provider_for_refresh = provider.clone();
                            let refresh_result = tokio::task::spawn_blocking(move || {
                                provider_for_refresh.refresh_http_provider()
                            }).await;

                            match refresh_result {
                                Ok(Ok(changed)) => {
                                    if changed {
                                        let current_router = dispatcher.router().await;
                                        dispatcher.update_router(current_router).await;
                                        info!(provider = provider_name.as_str(), "rule-provider refreshed and router hot-swapped");
                                    }
                                }
                                Ok(Err(e)) => {
                                    warn!(provider = provider_name.as_str(), error = %e, "rule-provider periodic refresh failed");
                                }
                                Err(e) => {
                                    warn!(provider = provider_name.as_str(), error = %e, "rule-provider refresh task join error");
                                }
                            }
                        }
                    }
                }
            });
        }
    }
}

fn node_to_outbound_config(provider: &str, node: &ProxyNode) -> Option<OutboundConfig> {
    let mut settings = OutboundSettings {
        address: Some(node.address.clone()),
        port: Some(node.port),
        ..OutboundSettings::default()
    };

    match node.protocol.as_str() {
        "ss" | "shadowsocks" => {
            settings.method = node
                .settings
                .get("cipher")
                .cloned()
                .or_else(|| node.settings.get("method").cloned());
            settings.password = node.settings.get("password").cloned();
            settings.plugin = node.settings.get("plugin").cloned();
            settings.plugin_opts = node.settings.get("plugin_opts").cloned();
        }
        "trojan" => {
            settings.password = node.settings.get("password").cloned();
            settings.sni = node.settings.get("sni").cloned();
            settings.security = node.settings.get("security").cloned();
        }
        "vless" => {
            settings.uuid = node.settings.get("uuid").cloned();
            settings.flow = node.settings.get("flow").cloned();
            settings.security = node.settings.get("security").cloned();
            settings.sni = node.settings.get("sni").cloned();
        }
        "vmess" => {
            settings.uuid = node.settings.get("uuid").cloned();
            settings.alter_id = node
                .settings
                .get("alter_id")
                .and_then(|s| s.parse::<u16>().ok());
            settings.security = node.settings.get("security").cloned();
            settings.sni = node.settings.get("sni").cloned();
        }
        "hysteria2" => {
            settings.password = node.settings.get("password").cloned();
            settings.sni = node.settings.get("sni").cloned();
        }
        _ => return None,
    }

    Some(OutboundConfig {
        tag: format!("sub-{}-{}", provider, node.to_outbound_tag()),
        protocol: match node.protocol.as_str() {
            "ss" => "shadowsocks".to_string(),
            other => other.to_string(),
        },
        settings,
    })
}

async fn build_outbound_manager_with_subscriptions(
    base_outbounds: &[OutboundConfig],
    proxy_groups: &[ProxyGroupConfig],
    provider_manager: &ProxyProviderManager,
) -> Result<OutboundManager> {
    let mut merged = base_outbounds.to_vec();
    let mut tags: HashSet<String> = merged.iter().map(|o| o.tag.clone()).collect();

    for (provider, node) in provider_manager.all_provider_nodes().await {
        if let Some(outbound) = node_to_outbound_config(&provider, &node) {
            if tags.insert(outbound.tag.clone()) {
                merged.push(outbound);
            }
        }
    }

    OutboundManager::new(&merged, proxy_groups)
}
