use std::sync::Arc;

use anyhow::Result;
use tokio::net::TcpListener;
use tokio::time::Duration;
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};

use crate::common::traffic::ConnectionLimiter;
use crate::config::types::InboundConfig;
use crate::proxy::inbound::http::HttpInbound;
use crate::proxy::inbound::mixed::MixedInbound;
use crate::proxy::inbound::shadowsocks::ShadowsocksInbound;
use crate::proxy::inbound::socks5::Socks5Inbound;
use crate::proxy::inbound::transparent::{RedirectInbound, TProxyInbound};
use crate::proxy::inbound::trojan::TrojanInbound;
use crate::proxy::inbound::tun::TunInbound;
use crate::proxy::inbound::vless::VlessInbound;
use crate::proxy::inbound::vmess::VmessInbound;
use crate::proxy::InboundHandler;

use super::dispatcher::Dispatcher;

use crate::proxy::inbound::tun_stack::{TunStack, TunStackConfig};

enum InboundEntry {
    Tcp {
        tag: String,
        handler: Arc<dyn InboundHandler>,
        listen: String,
        port: u16,
        sniff: bool,
        per_inbound_limiter: Option<Arc<ConnectionLimiter>>,
    },
    Tun {
        handler: Arc<TunInbound>,
        sniff: bool,
    },
}

pub struct InboundManager {
    entries: Vec<InboundEntry>,
    dispatcher: Arc<Dispatcher>,
    cancel_token: CancellationToken,
    global_limiter: Arc<ConnectionLimiter>,
}

impl InboundManager {
    pub fn new(
        configs: &[InboundConfig],
        dispatcher: Arc<Dispatcher>,
        cancel_token: CancellationToken,
        max_connections: u32,
    ) -> Result<Self> {
        let global_limiter = Arc::new(ConnectionLimiter::new(max_connections));
        let mut entries = Vec::new();

        for config in configs {
            let auth_users: Vec<(String, String)> = config.settings.auth.as_ref()
                .map(|users| users.iter().map(|u| (u.username.clone(), u.password.clone())).collect())
                .unwrap_or_default();

            let per_inbound_limiter = config.max_connections.map(|max| {
                Arc::new(ConnectionLimiter::new(max))
            });

            match config.protocol.as_str() {
                "socks5" => {
                    let handler: Arc<dyn InboundHandler> = Arc::new(
                        Socks5Inbound::new(config.tag.clone(), config.listen.clone())
                            .with_auth(auth_users)
                    );
                    entries.push(InboundEntry::Tcp {
                        tag: config.tag.clone(),
                        handler,
                        listen: config.listen.clone(),
                        port: config.port,
                        sniff: config.sniffing.enabled,
                        per_inbound_limiter: per_inbound_limiter.clone(),
                    });
                }
                "http" => {
                    let handler: Arc<dyn InboundHandler> = Arc::new(
                        HttpInbound::new(config.tag.clone())
                            .with_auth(auth_users)
                    );
                    entries.push(InboundEntry::Tcp {
                        tag: config.tag.clone(),
                        handler,
                        listen: config.listen.clone(),
                        port: config.port,
                        sniff: config.sniffing.enabled,
                        per_inbound_limiter: per_inbound_limiter.clone(),
                    });
                }
                "mixed" => {
                    let handler: Arc<dyn InboundHandler> = Arc::new(
                        MixedInbound::new(config.tag.clone(), config.listen.clone())
                            .with_auth(auth_users)
                    );
                    entries.push(InboundEntry::Tcp {
                        tag: config.tag.clone(),
                        handler,
                        listen: config.listen.clone(),
                        port: config.port,
                        sniff: config.sniffing.enabled,
                        per_inbound_limiter: per_inbound_limiter.clone(),
                    });
                }
                "shadowsocks" | "ss" => {
                    let handler: Arc<dyn InboundHandler> = Arc::new(ShadowsocksInbound::new(config)?);
                    entries.push(InboundEntry::Tcp {
                        tag: config.tag.clone(),
                        handler,
                        listen: config.listen.clone(),
                        port: config.port,
                        sniff: config.sniffing.enabled,
                        per_inbound_limiter: per_inbound_limiter.clone(),
                    });
                }
                "vless" => {
                    let handler: Arc<dyn InboundHandler> = Arc::new(VlessInbound::new(config)?);
                    entries.push(InboundEntry::Tcp {
                        tag: config.tag.clone(),
                        handler,
                        listen: config.listen.clone(),
                        port: config.port,
                        sniff: config.sniffing.enabled,
                        per_inbound_limiter: per_inbound_limiter.clone(),
                    });
                }
                "trojan" => {
                    let handler: Arc<dyn InboundHandler> = Arc::new(TrojanInbound::new(config)?);
                    entries.push(InboundEntry::Tcp {
                        tag: config.tag.clone(),
                        handler,
                        listen: config.listen.clone(),
                        port: config.port,
                        sniff: config.sniffing.enabled,
                        per_inbound_limiter: per_inbound_limiter.clone(),
                    });
                }
                "vmess" => {
                    let handler: Arc<dyn InboundHandler> = Arc::new(VmessInbound::new(config)?);
                    entries.push(InboundEntry::Tcp {
                        tag: config.tag.clone(),
                        handler,
                        listen: config.listen.clone(),
                        port: config.port,
                        sniff: config.sniffing.enabled,
                        per_inbound_limiter: per_inbound_limiter.clone(),
                    });
                }
                "redirect" => {
                    let handler: Arc<dyn InboundHandler> = Arc::new(RedirectInbound::new(config)?);
                    entries.push(InboundEntry::Tcp {
                        tag: config.tag.clone(),
                        handler,
                        listen: config.listen.clone(),
                        port: config.port,
                        sniff: true,
                        per_inbound_limiter: per_inbound_limiter.clone(),
                    });
                }
                "tproxy" => {
                    let handler: Arc<dyn InboundHandler> = Arc::new(TProxyInbound::new(config)?);
                    entries.push(InboundEntry::Tcp {
                        tag: config.tag.clone(),
                        handler,
                        listen: config.listen.clone(),
                        port: config.port,
                        sniff: true,
                        per_inbound_limiter: per_inbound_limiter.clone(),
                    });
                }
                "tun" => {
                    let name = if config.listen.is_empty() {
                        "openworld-tun".to_string()
                    } else {
                        config.listen.clone()
                    };
                    let dns_hijack_enabled = if config.settings.dns_hijack.is_empty() {
                        true
                    } else {
                        config
                            .settings
                            .dns_hijack
                            .iter()
                            .any(|rule| rule.starts_with("udp://") && rule.ends_with(":53"))
                    };
                    let handler = Arc::new(
                        TunInbound::new(config.tag.clone(), name)
                            .with_dns_hijack(dns_hijack_enabled),
                    );
                    entries.push(InboundEntry::Tun {
                        handler,
                        sniff: config.sniffing.enabled,
                    });
                }
                "hysteria2" => {
                    anyhow::bail!(
                        "hysteria2 inbound '{}' is not wired into InboundHandler pipeline yet",
                        config.tag
                    );
                }
                other => anyhow::bail!("unsupported inbound protocol: {}", other),
            }
        }

        Ok(Self {
            entries,
            dispatcher,
            cancel_token,
            global_limiter,
        })
    }

    pub async fn run(self) -> Result<()> {
        let mut handles = Vec::new();

        for entry in self.entries {
            match entry {
                InboundEntry::Tcp {
                    tag,
                    handler,
                    listen,
                    port,
                    sniff,
                    per_inbound_limiter,
                } => {
                    let dispatcher = self.dispatcher.clone();
                    let handler = handler.clone();
                    let bind_addr = format!("{}:{}", listen, port);
                    let cancel = self.cancel_token.clone();
                    let global_limiter = self.global_limiter.clone();

                    let handle = tokio::spawn(async move {
                        let listener = match TcpListener::bind(&bind_addr).await {
                            Ok(l) => l,
                            Err(e) => {
                                error!(addr = bind_addr, error = %e, "failed to bind");
                                return;
                            }
                        };

                        info!(tag = handler.tag(), addr = bind_addr, "inbound listening");

                        loop {
                            let global_max = global_limiter.max_connections().max(1) as u64;
                            let global_active = global_limiter.active_count();
                            if global_active.saturating_mul(100) >= global_max.saturating_mul(90) {
                                let backpressure_delay = if global_active >= global_max { 50 } else { 10 };
                                tokio::select! {
                                    _ = tokio::time::sleep(Duration::from_millis(backpressure_delay)) => {}
                                    _ = cancel.cancelled() => {
                                        info!(tag = tag, "inbound shutting down");
                                        break;
                                    }
                                }
                            }

                            tokio::select! {
                                result = listener.accept() => {
                                    let (tcp_stream, source) = match result {
                                        Ok(v) => v,
                                        Err(e) => {
                                            error!(error = %e, "accept failed");
                                            continue;
                                        }
                                    };

                                    let global_guard = match global_limiter.try_acquire() {
                                        Some(g) => g,
                                        None => {
                                            warn!(
                                                source = %source,
                                                max = global_limiter.max_connections(),
                                                active = global_limiter.active_count(),
                                                "global connection limit reached, dropping"
                                            );
                                            continue;
                                        }
                                    };

                                    let inbound_guard = if let Some(ref limiter) = per_inbound_limiter {
                                        match limiter.try_acquire() {
                                            Some(g) => Some(g),
                                            None => {
                                                warn!(
                                                    source = %source,
                                                    tag = tag,
                                                    max = limiter.max_connections(),
                                                    active = limiter.active_count(),
                                                    "per-inbound connection limit reached, dropping"
                                                );
                                                continue;
                                            }
                                        }
                                    } else {
                                        None
                                    };

                                    let handler = handler.clone();
                                    let dispatcher = dispatcher.clone();

                                    tokio::spawn(async move {
                                        let _global_guard = global_guard;
                                        let _inbound_guard = inbound_guard;
                                        let stream = Box::new(tcp_stream);
                                        match handler.handle(stream, source).await {
                                            Ok(mut result) => {
                                                result.session.sniff = sniff;
                                                if let Err(e) = dispatcher.dispatch(result).await {
                                                    error!(
                                                        source = %source,
                                                        error = %e,
                                                        "dispatch failed"
                                                    );
                                                }
                                            }
                                            Err(e) => {
                                                error!(
                                                    source = %source,
                                                    error = %e,
                                                    "inbound handle failed"
                                                );
                                            }
                                        }
                                    });
                                }
                                _ = cancel.cancelled() => {
                                    info!(tag = tag, "inbound shutting down");
                                    break;
                                }
                            }
                        }
                    });

                    handles.push(handle);
                }
                InboundEntry::Tun { handler, sniff } => {
                    let handler = handler.clone();
                    let dispatcher = self.dispatcher.clone();
                    let cancel = self.cancel_token.clone();
                    let sniff = sniff;
                    let dns_hijack_enabled = handler.dns_hijack_enabled();
                    let handle = tokio::spawn(async move {
                        // 尝试创建 TUN 设备并使用 TunStack 处理
                        let tun_config = crate::proxy::inbound::tun_device::TunConfig {
                            name: handler.name().to_string(),
                            ..Default::default()
                        };
                        match crate::proxy::inbound::tun_device::create_platform_tun_device(&tun_config) {
                            Ok(device) => {
                                let stack_config = TunStackConfig {
                                    inbound_tag: handler.tag().to_string(),
                                    sniff,
                                    dns_hijack_enabled: dns_hijack_enabled,
                                    ..Default::default()
                                };
                                let stack = Arc::new(TunStack::new(stack_config));
                                info!(
                                    tag = handler.tag(),
                                    device = device.name(),
                                    "TUN inbound started with userspace TCP/IP stack"
                                );
                                if let Err(e) = stack.run(device, dispatcher, cancel).await {
                                    error!(tag = handler.tag(), error = %e, "TUN stack failed");
                                }
                            }
                            Err(e) => {
                                // 回退到旧的 TunInbound 处理方式
                                info!(
                                    tag = handler.tag(),
                                    error = %e,
                                    "TUN device creation failed, falling back to basic handler"
                                );
                                if let Err(e) = handler.run(dispatcher, cancel).await {
                                    error!(tag = handler.tag(), error = %e, "tun inbound failed");
                                }
                            }
                        }
                    });
                    handles.push(handle);
                }
            }
        }

        for handle in handles {
            let _ = handle.await;
        }

        Ok(())
    }
}
