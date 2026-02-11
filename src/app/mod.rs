pub mod dispatcher;
pub mod inbound_manager;
pub mod outbound_manager;
pub mod tracker;

use anyhow::Result;
use std::sync::Arc;
use tokio_util::sync::CancellationToken;
use tracing::info;

use crate::config::Config;
use crate::config::types::ApiConfig;
use crate::router::Router;

use dispatcher::Dispatcher;
use inbound_manager::InboundManager;
use outbound_manager::OutboundManager;
use tracker::ConnectionTracker;

pub struct App {
    inbound_manager: InboundManager,
    dispatcher: Arc<Dispatcher>,
    cancel_token: CancellationToken,
    api_config: Option<ApiConfig>,
    config_path: Option<String>,
    log_broadcaster: Option<crate::api::log_broadcast::LogBroadcaster>,
}

impl App {
    pub fn new(
        config: Config,
        config_path: Option<String>,
        log_broadcaster: Option<crate::api::log_broadcast::LogBroadcaster>,
    ) -> Result<Self> {
        let cancel_token = CancellationToken::new();
        let router = Arc::new(Router::new(&config.router)?);
        let outbound_manager = Arc::new(OutboundManager::new(
            &config.outbounds,
            &config.proxy_groups,
        )?);
        let tracker = Arc::new(ConnectionTracker::new());
        let dispatcher = Arc::new(Dispatcher::new(
            router,
            outbound_manager,
            tracker,
        ));
        let inbound_manager = InboundManager::new(
            &config.inbounds,
            dispatcher.clone(),
            cancel_token.clone(),
        )?;

        Ok(Self {
            inbound_manager,
            dispatcher,
            cancel_token,
            api_config: config.api,
            config_path,
            log_broadcaster,
        })
    }

    pub async fn run(self) -> Result<()> {
        info!("OpenWorld started");

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
}
