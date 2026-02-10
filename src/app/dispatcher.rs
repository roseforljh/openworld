use std::sync::Arc;

use anyhow::Result;
use tracing::info;

use crate::proxy::relay::relay;
use crate::proxy::InboundResult;
use crate::router::Router;

use super::outbound_manager::OutboundManager;

pub struct Dispatcher {
    router: Arc<Router>,
    outbound_manager: Arc<OutboundManager>,
}

impl Dispatcher {
    pub fn new(router: Arc<Router>, outbound_manager: Arc<OutboundManager>) -> Self {
        Self {
            router,
            outbound_manager,
        }
    }

    pub async fn dispatch(&self, result: InboundResult) -> Result<()> {
        let InboundResult { session, stream: inbound_stream } = result;

        // 路由匹配
        let outbound_tag = self.router.route(&session);

        let outbound = self
            .outbound_manager
            .get(outbound_tag)
            .ok_or_else(|| anyhow::anyhow!("outbound '{}' not found", outbound_tag))?;

        info!(
            dest = %session.target,
            inbound = session.inbound_tag,
            outbound = outbound.tag(),
            "dispatching"
        );

        // 出站连接
        let outbound_stream = outbound.connect(&session).await?;

        // 双向转发
        relay(inbound_stream, outbound_stream).await?;

        Ok(())
    }
}
