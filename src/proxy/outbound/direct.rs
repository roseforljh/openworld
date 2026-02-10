use anyhow::Result;
use async_trait::async_trait;
use tokio::net::TcpStream;
use tracing::debug;

use crate::common::ProxyStream;
use crate::proxy::{OutboundHandler, Session};

pub struct DirectOutbound {
    tag: String,
}

impl DirectOutbound {
    pub fn new(tag: String) -> Self {
        Self { tag }
    }
}

#[async_trait]
impl OutboundHandler for DirectOutbound {
    fn tag(&self) -> &str {
        &self.tag
    }

    async fn connect(&self, session: &Session) -> Result<ProxyStream> {
        let addr = session.target.resolve().await?;
        debug!(target = %session.target, resolved = %addr, "direct connect");
        let stream = TcpStream::connect(addr).await?;
        Ok(Box::new(stream))
    }
}
