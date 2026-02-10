pub mod inbound;
pub mod outbound;
pub mod relay;

use std::net::SocketAddr;

use anyhow::Result;
use async_trait::async_trait;

use crate::common::{Address, ProxyStream};

/// 网络类型
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Network {
    Tcp,
    Udp,
}

/// 连接会话元数据
#[derive(Debug, Clone)]
pub struct Session {
    pub target: Address,
    pub source: Option<SocketAddr>,
    pub inbound_tag: String,
    pub network: Network,
}

/// 入站处理结果
pub struct InboundResult {
    pub session: Session,
    pub stream: ProxyStream,
}

/// 入站处理器 trait
#[async_trait]
pub trait InboundHandler: Send + Sync {
    fn tag(&self) -> &str;
    async fn handle(&self, stream: ProxyStream, source: SocketAddr) -> Result<InboundResult>;
}

/// 出站处理器 trait
#[async_trait]
pub trait OutboundHandler: Send + Sync {
    fn tag(&self) -> &str;
    async fn connect(&self, session: &Session) -> Result<ProxyStream>;
}
