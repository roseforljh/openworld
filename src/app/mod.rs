pub mod dispatcher;
pub mod inbound_manager;
pub mod outbound_manager;

use anyhow::Result;
use std::sync::Arc;
use tracing::info;

use crate::config::Config;
use crate::router::Router;

use dispatcher::Dispatcher;
use inbound_manager::InboundManager;
use outbound_manager::OutboundManager;

pub struct App {
    inbound_manager: InboundManager,
}

impl App {
    pub fn new(config: Config) -> Result<Self> {
        let router = Arc::new(Router::new(&config.router)?);
        let outbound_manager = Arc::new(OutboundManager::new(&config.outbounds)?);
        let dispatcher = Arc::new(Dispatcher::new(router, outbound_manager));
        let inbound_manager = InboundManager::new(&config.inbounds, dispatcher)?;

        Ok(Self { inbound_manager })
    }

    pub async fn run(self) -> Result<()> {
        info!("OpenWorld started");
        self.inbound_manager.run().await
    }
}
