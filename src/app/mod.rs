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
    router: Arc<Router>,
    outbound_manager: Arc<OutboundManager>,
    #[allow(dead_code)]
    dispatcher: Arc<Dispatcher>,
    tracker: Arc<ConnectionTracker>,
    cancel_token: CancellationToken,
    api_config: Option<ApiConfig>,
}

impl App {
    pub fn new(config: Config) -> Result<Self> {
        let cancel_token = CancellationToken::new();
        let router = Arc::new(Router::new(&config.router)?);
        let outbound_manager = Arc::new(OutboundManager::new(&config.outbounds)?);
        let tracker = Arc::new(ConnectionTracker::new());
        let dispatcher = Arc::new(Dispatcher::new(
            router.clone(),
            outbound_manager.clone(),
            tracker.clone(),
        ));
        let inbound_manager = InboundManager::new(
            &config.inbounds,
            dispatcher.clone(),
            cancel_token.clone(),
        )?;

        Ok(Self {
            inbound_manager,
            router,
            outbound_manager,
            dispatcher,
            tracker,
            cancel_token,
            api_config: config.api,
        })
    }

    pub async fn run(self) -> Result<()> {
        info!("OpenWorld started");

        // 启动 API 服务器（如果配置了）
        let _api_handle = if let Some(ref api_config) = self.api_config {
            Some(crate::api::start(
                api_config,
                self.router.clone(),
                self.outbound_manager.clone(),
                self.tracker.clone(),
            )?)
        } else {
            None
        };

        let cancel_token = self.cancel_token.clone();
        let tracker = self.tracker.clone();

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
        let closed = self.tracker.close_all().await;
        info!(connections = closed, "all connections closed");
    }

    pub fn router(&self) -> &Arc<Router> {
        &self.router
    }

    pub fn outbound_manager(&self) -> &Arc<OutboundManager> {
        &self.outbound_manager
    }

    pub fn tracker(&self) -> &Arc<ConnectionTracker> {
        &self.tracker
    }

    pub fn cancel_token(&self) -> &CancellationToken {
        &self.cancel_token
    }
}
