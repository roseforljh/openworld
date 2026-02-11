use std::sync::Arc;

use anyhow::Result;
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;
use tracing::{error, info};

use crate::config::types::InboundConfig;
use crate::proxy::inbound::http::HttpInbound;
use crate::proxy::inbound::mixed::MixedInbound;
use crate::proxy::inbound::shadowsocks::ShadowsocksInbound;
use crate::proxy::inbound::socks5::Socks5Inbound;
use crate::proxy::inbound::trojan::TrojanInbound;
use crate::proxy::inbound::tun::TunInbound;
use crate::proxy::inbound::vless::VlessInbound;
use crate::proxy::InboundHandler;

use super::dispatcher::Dispatcher;

enum InboundEntry {
    Tcp {
        handler: Arc<dyn InboundHandler>,
        listen: String,
        port: u16,
        sniff: bool,
    },
    Tun {
        handler: Arc<TunInbound>,
    },
}

pub struct InboundManager {
    entries: Vec<InboundEntry>,
    dispatcher: Arc<Dispatcher>,
    cancel_token: CancellationToken,
}

impl InboundManager {
    pub fn new(
        configs: &[InboundConfig],
        dispatcher: Arc<Dispatcher>,
        cancel_token: CancellationToken,
    ) -> Result<Self> {
        let mut entries = Vec::new();

        for config in configs {
            match config.protocol.as_str() {
                "socks5" => {
                    let handler: Arc<dyn InboundHandler> = Arc::new(Socks5Inbound::new(
                        config.tag.clone(),
                        config.listen.clone(),
                    ));
                    entries.push(InboundEntry::Tcp {
                        handler,
                        listen: config.listen.clone(),
                        port: config.port,
                        sniff: config.sniffing.enabled,
                    });
                }
                "http" => {
                    let handler: Arc<dyn InboundHandler> = Arc::new(HttpInbound::new(config.tag.clone()));
                    entries.push(InboundEntry::Tcp {
                        handler,
                        listen: config.listen.clone(),
                        port: config.port,
                        sniff: config.sniffing.enabled,
                    });
                }
                "mixed" => {
                    let handler: Arc<dyn InboundHandler> =
                        Arc::new(MixedInbound::new(config.tag.clone(), config.listen.clone()));
                    entries.push(InboundEntry::Tcp {
                        handler,
                        listen: config.listen.clone(),
                        port: config.port,
                        sniff: config.sniffing.enabled,
                    });
                }
                "shadowsocks" | "ss" => {
                    let handler: Arc<dyn InboundHandler> = Arc::new(ShadowsocksInbound::new(config)?);
                    entries.push(InboundEntry::Tcp {
                        handler,
                        listen: config.listen.clone(),
                        port: config.port,
                        sniff: config.sniffing.enabled,
                    });
                }
                "vless" => {
                    let handler: Arc<dyn InboundHandler> = Arc::new(VlessInbound::new(config)?);
                    entries.push(InboundEntry::Tcp {
                        handler,
                        listen: config.listen.clone(),
                        port: config.port,
                        sniff: config.sniffing.enabled,
                    });
                }
                "trojan" => {
                    let handler: Arc<dyn InboundHandler> = Arc::new(TrojanInbound::new(config)?);
                    entries.push(InboundEntry::Tcp {
                        handler,
                        listen: config.listen.clone(),
                        port: config.port,
                        sniff: config.sniffing.enabled,
                    });
                }
                "tun" => {
                    let name = if config.listen.is_empty() {
                        "openworld-tun".to_string()
                    } else {
                        config.listen.clone()
                    };
                    let handler = Arc::new(TunInbound::new(config.tag.clone(), name));
                    entries.push(InboundEntry::Tun { handler });
                }
                other => anyhow::bail!("unsupported inbound protocol: {}", other),
            }
        }

        Ok(Self {
            entries,
            dispatcher,
            cancel_token,
        })
    }

    pub async fn run(self) -> Result<()> {
        let mut handles = Vec::new();

        for entry in self.entries {
            match entry {
                InboundEntry::Tcp {
                    handler,
                    listen,
                    port,
                    sniff,
                } => {
                    let dispatcher = self.dispatcher.clone();
                    let handler = handler.clone();
                    let bind_addr = format!("{}:{}", listen, port);
                    let cancel = self.cancel_token.clone();

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
                            tokio::select! {
                                result = listener.accept() => {
                                    let (tcp_stream, source) = match result {
                                        Ok(v) => v,
                                        Err(e) => {
                                            error!(error = %e, "accept failed");
                                            continue;
                                        }
                                    };

                                    let handler = handler.clone();
                                    let dispatcher = dispatcher.clone();

                                    tokio::spawn(async move {
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
                                    info!(tag = handler.tag(), "inbound shutting down");
                                    break;
                                }
                            }
                        }
                    });

                    handles.push(handle);
                }
                InboundEntry::Tun { handler } => {
                    let handler = handler.clone();
                    let dispatcher = self.dispatcher.clone();
                    let cancel = self.cancel_token.clone();
                    let handle = tokio::spawn(async move {
                        if let Err(e) = handler.run(dispatcher, cancel).await {
                            error!(tag = handler.tag(), error = %e, "tun inbound failed");
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
