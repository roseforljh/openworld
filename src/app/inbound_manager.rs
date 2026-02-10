use std::sync::Arc;

use anyhow::Result;
use tokio::net::TcpListener;
use tracing::{error, info};

use crate::config::types::InboundConfig;
use crate::proxy::inbound::http::HttpInbound;
use crate::proxy::inbound::socks5::Socks5Inbound;
use crate::proxy::InboundHandler;

use super::dispatcher::Dispatcher;

struct InboundEntry {
    handler: Arc<dyn InboundHandler>,
    listen: String,
    port: u16,
}

pub struct InboundManager {
    entries: Vec<InboundEntry>,
    dispatcher: Arc<Dispatcher>,
}

impl InboundManager {
    pub fn new(configs: &[InboundConfig], dispatcher: Arc<Dispatcher>) -> Result<Self> {
        let mut entries = Vec::new();

        for config in configs {
            let handler: Arc<dyn InboundHandler> = match config.protocol.as_str() {
                "socks5" => Arc::new(Socks5Inbound::new(config.tag.clone())),
                "http" => Arc::new(HttpInbound::new(config.tag.clone())),
                other => anyhow::bail!("unsupported inbound protocol: {}", other),
            };
            entries.push(InboundEntry {
                handler,
                listen: config.listen.clone(),
                port: config.port,
            });
        }

        Ok(Self {
            entries,
            dispatcher,
        })
    }

    pub async fn run(self) -> Result<()> {
        let mut handles = Vec::new();

        for entry in self.entries {
            let dispatcher = self.dispatcher.clone();
            let handler = entry.handler.clone();
            let bind_addr = format!("{}:{}", entry.listen, entry.port);

            let handle = tokio::spawn(async move {
                let listener = match TcpListener::bind(&bind_addr).await {
                    Ok(l) => l,
                    Err(e) => {
                        error!(addr = bind_addr, error = %e, "failed to bind");
                        return;
                    }
                };

                info!(
                    tag = handler.tag(),
                    addr = bind_addr,
                    "inbound listening"
                );

                loop {
                    let (tcp_stream, source) = match listener.accept().await {
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
                            Ok(result) => {
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
            });

            handles.push(handle);
        }

        // 等待所有监听器（正常情况下不会返回）
        for handle in handles {
            let _ = handle.await;
        }

        Ok(())
    }
}
