pub mod access_log;
pub mod android;
pub mod auth;
pub mod benchmark;
pub mod cert;
pub mod clash_mode;
pub mod dispatcher;
pub mod ffi;
pub mod inbound_manager;
pub mod latency_test;
pub mod ops;
pub mod outbound_manager;
pub mod platform;
pub mod proxy_provider;
pub mod release;
pub mod resilience;
pub mod security;
pub mod service;
pub mod system_proxy;
pub mod tracker;
pub mod traffic_persist;

use anyhow::Result;
use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

use crate::config::subscription::ProxyNode;
use crate::config::types::{
    ApiConfig, DerpConfig, OutboundConfig, OutboundSettings, ProxyGroupConfig,
};
use crate::config::Config;
use crate::dns::{self, DnsResolver, SystemResolver};
#[cfg(target_os = "windows")]
use crate::proxy::inbound::tun_device::WindowsProxyState;
use crate::proxy::inbound::tun_device::{
    FirewallBackend, SystemProxy, TransparentProxyConfig, TransparentProxyManager,
    TransparentProxyMode,
};
use crate::router::geo_update::{GeoUpdateConfig, GeoUpdater};
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
    geo_updater: Option<Arc<GeoUpdater>>,
    system_proxy: Option<SystemProxy>,
    transparent_proxy_manager: Option<TransparentProxyManager>,
    derp_config: Option<DerpConfig>,
    #[cfg(target_os = "windows")]
    windows_proxy_state: Option<WindowsProxyState>,
}

impl App {
    pub async fn new(
        config: Config,
        config_path: Option<String>,
        log_broadcaster: Option<crate::api::log_broadcast::LogBroadcaster>,
    ) -> Result<Self> {
        // Phase 9: Security audit before constructing components
        security::validate_and_warn(&config)?;

        // Ensure geo databases exist (download if URLs configured and files missing)
        crate::router::geo_update::ensure_databases(
            config.router.geoip_db.as_deref(),
            config.router.geoip_url.as_deref(),
            config.router.geosite_db.as_deref(),
            config.router.geosite_url.as_deref(),
        )
        .await;

        let cancel_token = CancellationToken::new();
        let router = Arc::new(Router::new(&config.router)?);
        let outbound_manager = Arc::new(OutboundManager::new(
            &config.outbounds,
            &config.proxy_groups,
        )?);
        let (resolver, fakeip_pool): (
            Arc<dyn DnsResolver>,
            Option<Arc<crate::dns::fakeip::FakeIpPool>>,
        ) = match config.dns.as_ref() {
            Some(dns_config) => {
                let (r, pool) = dns::build_resolver(dns_config)?;
                (Arc::from(r), pool)
            }
            None => (Arc::new(SystemResolver), None),
        };
        let tracker = Arc::new(ConnectionTracker::new());
        let dispatcher = Arc::new(Dispatcher::new(
            router,
            outbound_manager,
            tracker,
            resolver.clone(),
            fakeip_pool,
            cancel_token.clone(),
        ));
        let inbound_manager = InboundManager::new(
            &config.inbounds,
            dispatcher.clone(),
            cancel_token.clone(),
            config.max_connections,
        )?;

        let system_proxy = build_system_proxy_from_inbounds(&config.inbounds);
        let transparent_proxy_manager =
            build_transparent_proxy_manager_from_inbounds(&config.inbounds);
        #[cfg(target_os = "windows")]
        let windows_proxy_state = None;

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

        let geo_updater = if config.router.geo_auto_update {
            Some(Arc::new(GeoUpdater::new(GeoUpdateConfig {
                geoip_path: config.router.geoip_db.clone(),
                geoip_url: config.router.geoip_url.clone(),
                geosite_path: config.router.geosite_db.clone(),
                geosite_url: config.router.geosite_url.clone(),
                interval_secs: config.router.geo_update_interval,
                auto_update: true,
            })))
        } else {
            None
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
            geo_updater,
            system_proxy,
            transparent_proxy_manager,
            derp_config: config.derp,
            #[cfg(target_os = "windows")]
            windows_proxy_state,
        })
    }

    #[allow(unused_mut)]
    pub async fn run(mut self) -> Result<()> {
        info!("OpenWorld started");

        #[cfg(target_os = "windows")]
        {
            if self.system_proxy.is_some() {
                self.windows_proxy_state = Some(SystemProxy::capture_windows_state());
            }
        }

        if let Some(system_proxy) = &self.system_proxy {
            if let Err(e) = system_proxy.apply() {
                warn!(error = %e, "failed to apply system proxy");
            }
        }

        if let Some(manager) = &self.transparent_proxy_manager {
            if let Err(e) = manager.apply() {
                warn!(error = %e, "failed to apply transparent proxy firewall rules");
            }
        }

        self.spawn_rule_provider_refresh_tasks().await;
        self.dispatcher
            .spawn_pool_cleanup(self.cancel_token.clone())
            .await;
        self.dispatcher
            .spawn_dns_prefetch(self.cancel_token.clone())
            .await;

        let _geo_updater_handle = self.geo_updater.as_ref().map(|u| u.clone().start());

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
                None, // SSM: SS 入站引用（TODO: 从入站列表获取）
            )?)
        } else {
            None
        };

        // 启动 DERP 中继服务（如果配置了）
        let _derp_handle = if let Some(ref derp_config) = self.derp_config {
            if derp_config.enabled {
                Some(Self::start_derp_server(derp_config.clone()))
            } else {
                None
            }
        } else {
            None
        };

        // Hot reload: file watcher + SIGHUP (Unix)
        if let Some(ref path) = self.config_path {
            #[cfg(feature = "cli")]
            spawn_config_watcher(
                self.dispatcher.clone(),
                path.clone(),
                self.cancel_token.clone(),
            );
            #[cfg(unix)]
            spawn_sighup_reload(
                self.dispatcher.clone(),
                path.clone(),
                self.cancel_token.clone(),
            );
        }

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

        let run_result = tokio::select! {
            result = self.inbound_manager.run() => {
                result
            }
            _ = shutdown_signal() => {
                info!("received shutdown signal, initiating graceful shutdown...");
                cancel_token.cancel();

                // Wait for active connections to finish (up to 30s)
                let active = tracker.snapshot_async().await.active_count;
                if active > 0 {
                    info!(connections = active, "waiting for active connections to finish...");
                    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
                    loop {
                        tokio::time::sleep(Duration::from_millis(200)).await;
                        let remaining = tracker.snapshot_async().await.active_count;
                        if remaining == 0 {
                            info!("all connections finished gracefully");
                            break;
                        }
                        if tokio::time::Instant::now() >= deadline {
                            warn!(connections = remaining, "grace period expired, force closing");
                            break;
                        }
                    }
                }

                let closed = tracker.close_all().await;
                if closed > 0 {
                    info!(connections = closed, "remaining connections force closed");
                }
                info!("shutdown complete");
                Ok(())
            }
        };

        if let Some(manager) = &self.transparent_proxy_manager {
            if let Err(e) = manager.cleanup() {
                warn!(error = %e, "failed to cleanup transparent proxy firewall rules");
            }
        }

        if let Some(system_proxy) = &self.system_proxy {
            #[cfg(target_os = "windows")]
            {
                if let Some(state) = &self.windows_proxy_state {
                    if let Err(e) = SystemProxy::restore_windows_state(state) {
                        warn!(error = %e, "failed to restore previous windows system proxy state, fallback to disable");
                        if let Err(e2) = system_proxy.disable() {
                            warn!(error = %e2, "failed to disable system proxy");
                        }
                    }
                } else if let Err(e) = system_proxy.disable() {
                    warn!(error = %e, "failed to disable system proxy");
                }
            }
            #[cfg(not(target_os = "windows"))]
            {
                if let Err(e) = system_proxy.disable() {
                    warn!(error = %e, "failed to disable system proxy");
                }
            }
        }

        run_result
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

    /// 启动 DERP 中继服务（独立 HTTP 服务）
    fn start_derp_server(config: DerpConfig) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            use crate::derp::server::DerpServer;

            // 解析私钥或生成新的
            let server = if let Some(ref key_hex) = config.private_key {
                let bytes: Vec<u8> = (0..key_hex.len())
                    .step_by(2)
                    .filter_map(|i| u8::from_str_radix(&key_hex[i..i + 2], 16).ok())
                    .collect();
                if bytes.len() == 32 {
                    let mut key = [0u8; 32];
                    key.copy_from_slice(&bytes);
                    Arc::new(DerpServer::with_key(key))
                } else {
                    warn!("DERP 私钥格式错误，将自动生成新密钥");
                    Arc::new(DerpServer::new())
                }
            } else {
                Arc::new(DerpServer::new())
            };

            let bind_addr = format!("0.0.0.0:{}", config.port);
            let listener = match tokio::net::TcpListener::bind(&bind_addr).await {
                Ok(l) => l,
                Err(e) => {
                    tracing::error!(addr = bind_addr, error = %e, "DERP 服务绑定失败");
                    return;
                }
            };

            let region_id = config.region_id;
            let region_name = config.region_name.clone();

            info!(
                addr = bind_addr,
                region_id = region_id,
                region_name = region_name,
                "DERP 中继服务已启动"
            );

            // 预构建 JSON 响应体
            let info_body = format!(
                "{{\"type\":\"derp\",\"region\":{},\"name\":\"{}\"}}",
                region_id, region_name
            );
            let info_body = Arc::new(info_body);

            loop {
                let (stream, peer_addr) = match listener.accept().await {
                    Ok(s) => s,
                    Err(e) => {
                        warn!(error = %e, "DERP 接受连接失败");
                        continue;
                    }
                };

                let server = server.clone();
                let info_body = info_body.clone();
                tokio::spawn(async move {
                    // 简易 HTTP 升级：读取 HTTP 请求头，发送 101 响应
                    let mut stream = stream;
                    let mut buf = vec![0u8; 4096];
                    let n = match tokio::io::AsyncReadExt::read(&mut stream, &mut buf).await {
                        Ok(n) => n,
                        Err(_) => return,
                    };

                    let request = String::from_utf8_lossy(&buf[..n]);

                    // 检查是否为 DERP 升级请求
                    if request.contains("GET /derp") || request.contains("GET / ") {
                        // 发送 HTTP 101 Switching Protocols 响应
                        let response = "HTTP/1.1 101 Switching Protocols\r\n\
                            Upgrade: DERP\r\n\
                            Connection: Upgrade\r\n\
                            \r\n";
                        if let Err(e) =
                            tokio::io::AsyncWriteExt::write_all(&mut stream, response.as_bytes())
                                .await
                        {
                            warn!(error = %e, "DERP 发送升级响应失败");
                            return;
                        }

                        debug!(peer = %peer_addr, "DERP HTTP 升级完成");
                        server.handle_client(stream).await;
                    } else {
                        // 非 DERP 请求，返回 200 + 简单信息
                        let response = format!(
                            "HTTP/1.1 200 OK\r\n\
                            Content-Type: application/json\r\n\
                            Content-Length: {}\r\n\
                            \r\n{}",
                            info_body.len(),
                            &*info_body
                        );
                        let _ =
                            tokio::io::AsyncWriteExt::write_all(&mut stream, response.as_bytes())
                                .await;
                    }
                });
            }
        })
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

fn build_system_proxy_from_inbounds(
    inbounds: &[crate::config::types::InboundConfig],
) -> Option<SystemProxy> {
    for inbound in inbounds {
        if inbound.protocol != "tun" || !inbound.settings.set_system_proxy {
            continue;
        }

        let mut proxy = SystemProxy::new("127.0.0.1".to_string(), inbound.port);
        if !inbound.settings.system_proxy_bypass.is_empty() {
            proxy = proxy.with_bypass(inbound.settings.system_proxy_bypass.clone());
        }
        if let Some(socks_port) = inbound.settings.system_proxy_socks_port {
            proxy = proxy.with_socks_port(socks_port);
        }
        return Some(proxy);
    }
    None
}

fn build_transparent_proxy_manager_from_inbounds(
    inbounds: &[crate::config::types::InboundConfig],
) -> Option<TransparentProxyManager> {
    for inbound in inbounds {
        if !inbound.settings.auto_route {
            continue;
        }

        let mode = match inbound.protocol.as_str() {
            "redirect" => TransparentProxyMode::Redirect,
            "tproxy" => match inbound.settings.network.as_deref() {
                Some("udp") => TransparentProxyMode::TProxyUdp,
                _ => TransparentProxyMode::TProxyTcp,
            },
            _ => continue,
        };

        let backend = match inbound.settings.route_backend.as_deref() {
            Some("nftables") => FirewallBackend::Nftables,
            _ => FirewallBackend::Iptables,
        };

        let cfg = TransparentProxyConfig::new(inbound.port, mode)
            .with_backend(backend)
            .with_cgroup_path(inbound.settings.cgroup_path.clone())
            .with_tproxy_routing(inbound.settings.tproxy_mark, inbound.settings.tproxy_table);
        return Some(TransparentProxyManager::new(cfg));
    }

    None
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::types::{InboundConfig, InboundSettings, SniffingConfig};

    #[test]
    fn build_system_proxy_from_tun_inbound() {
        let inbounds = vec![InboundConfig {
            tag: "tun-in".to_string(),
            protocol: "tun".to_string(),
            listen: "openworld-tun".to_string(),
            port: 7890,
            sniffing: SniffingConfig::default(),
            settings: InboundSettings {
                set_system_proxy: true,
                system_proxy_bypass: vec!["example.com".to_string()],
                system_proxy_socks_port: Some(7891),
                ..Default::default()
            },
            max_connections: None,
        }];

        let proxy = build_system_proxy_from_inbounds(&inbounds).unwrap();
        assert_eq!(proxy.proxy_port(), 7890);
        assert_eq!(proxy.socks_port(), Some(7891));
        assert_eq!(proxy.bypass_list(), &["example.com"]);
    }

    #[test]
    fn build_transparent_proxy_from_tproxy_inbound() {
        let inbounds = vec![InboundConfig {
            tag: "tproxy-in".to_string(),
            protocol: "tproxy".to_string(),
            listen: "0.0.0.0".to_string(),
            port: 7894,
            sniffing: SniffingConfig::default(),
            settings: InboundSettings {
                network: Some("udp".to_string()),
                auto_route: true,
                route_backend: Some("nftables".to_string()),
                cgroup_path: Some("/sys/fs/cgroup/openworld".to_string()),
                tproxy_mark: 9,
                tproxy_table: 109,
                ..Default::default()
            },
            max_connections: None,
        }];

        let manager = build_transparent_proxy_manager_from_inbounds(&inbounds).unwrap();
        let apply_cmds = manager.generate_apply_commands();

        #[cfg(target_os = "linux")]
        assert!(!apply_cmds.is_empty());

        #[cfg(not(target_os = "linux"))]
        {
            let _ = apply_cmds;
        }
    }
}

/// Reload config: rebuild Router, OutboundManager, and DNS resolver, hot-swap into Dispatcher.
async fn do_reload_config(dispatcher: &Arc<Dispatcher>, config_path: &str) {
    info!(path = config_path, "reloading config");
    let config = match crate::config::load_config(config_path) {
        Ok(c) => c,
        Err(e) => {
            warn!(error = %e, "config reload failed: parse error");
            return;
        }
    };
    let new_router = match crate::router::Router::new(&config.router) {
        Ok(r) => Arc::new(r),
        Err(e) => {
            warn!(error = %e, "config reload failed: router build error");
            return;
        }
    };
    let new_om = match OutboundManager::new(&config.outbounds, &config.proxy_groups) {
        Ok(om) => Arc::new(om),
        Err(e) => {
            warn!(error = %e, "config reload failed: outbound manager build error");
            return;
        }
    };

    // Rebuild DNS resolver if DNS config is present
    if let Some(ref dns_config) = config.dns {
        match crate::dns::resolver::build_resolver(dns_config) {
            Ok((new_resolver, _fakeip_pool)) => {
                dispatcher.update_resolver(new_resolver.into()).await;
                info!("DNS resolver reloaded");
            }
            Err(e) => {
                warn!(error = %e, "config reload: DNS rebuild failed, keeping old resolver");
            }
        }
    }

    dispatcher.update_router(new_router).await;
    dispatcher.update_outbound_manager(new_om).await;
    info!("config reloaded successfully");
}

/// Spawn SIGHUP-triggered config reload task (Unix only).
#[cfg(unix)]
fn spawn_sighup_reload(
    dispatcher: Arc<Dispatcher>,
    config_path: String,
    cancel: CancellationToken,
) {
    tokio::spawn(async move {
        use tokio::signal::unix::{signal, SignalKind};
        let mut sighup = signal(SignalKind::hangup()).expect("failed to register SIGHUP");
        loop {
            tokio::select! {
                _ = cancel.cancelled() => break,
                _ = sighup.recv() => {
                    info!("received SIGHUP, triggering config reload");
                    do_reload_config(&dispatcher, &config_path).await;
                }
            }
        }
    });
}

/// Spawn file watcher that reloads config when the file changes.
#[cfg(feature = "cli")]
fn spawn_config_watcher(
    dispatcher: Arc<Dispatcher>,
    config_path: String,
    cancel: CancellationToken,
) {
    use notify::{Config as NotifyConfig, RecommendedWatcher, RecursiveMode, Watcher};
    use std::sync::mpsc;

    let (tx, rx) = mpsc::channel();
    let mut watcher = match RecommendedWatcher::new(tx, NotifyConfig::default()) {
        Ok(w) => w,
        Err(e) => {
            warn!(error = %e, "failed to create file watcher");
            return;
        }
    };

    let watch_path = std::path::Path::new(&config_path)
        .parent()
        .unwrap_or(std::path::Path::new("."))
        .to_path_buf();
    let file_name = std::path::Path::new(&config_path)
        .file_name()
        .map(|n| n.to_os_string());

    if let Err(e) = watcher.watch(&watch_path, RecursiveMode::NonRecursive) {
        warn!(error = %e, path = %watch_path.display(), "failed to watch config directory");
        return;
    }

    info!(path = config_path.as_str(), "config file watcher started");

    tokio::spawn(async move {
        let _watcher = watcher; // keep alive
        let mut debounce = tokio::time::Instant::now();

        loop {
            tokio::select! {
                _ = cancel.cancelled() => break,
                _ = tokio::time::sleep(Duration::from_millis(500)) => {
                    // Check for events
                    let mut changed = false;
                    while let Ok(event) = rx.try_recv() {
                        if let Ok(event) = event {
                            let is_target = file_name.as_ref().map_or(true, |name| {
                                event.paths.iter().any(|p| {
                                    p.file_name().map(|n| n == name.as_os_str()).unwrap_or(false)
                                })
                            });
                            if is_target && event.kind.is_modify() {
                                changed = true;
                            }
                        }
                    }
                    if changed && debounce.elapsed() > Duration::from_secs(2) {
                        debounce = tokio::time::Instant::now();
                        info!("config file changed, triggering reload");
                        do_reload_config(&dispatcher, &config_path).await;
                    }
                }
            }
        }
    });
}

/// Wait for shutdown signal (Ctrl+C on all platforms, SIGTERM on Unix).
async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{signal, SignalKind};
        let mut sigterm = signal(SignalKind::terminate()).expect("failed to register SIGTERM");
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = sigterm.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to register Ctrl+C");
    }
}
