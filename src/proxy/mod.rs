pub mod group;
pub mod inbound;
pub mod mux;
pub mod nat;
pub mod outbound;
pub mod relay;
pub mod sniff;
pub mod transport;

use std::net::SocketAddr;

use anyhow::Result;
use async_trait::async_trait;

use crate::common::{Address, BoxUdpTransport, ProxyStream};

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
    /// 是否启用协议嗅探
    #[allow(dead_code)]
    pub sniff: bool,
    /// 嗅探检测到的协议类型（tls, http, bittorrent, ssh, stun, dtls 等）
    pub detected_protocol: Option<String>,
}

/// 入站处理结果
pub struct InboundResult {
    pub session: Session,
    pub stream: ProxyStream,
    pub udp_transport: Option<BoxUdpTransport>,
}

/// 入站处理器 trait
#[async_trait]
pub trait InboundHandler: Send + Sync {
    fn tag(&self) -> &str;
    async fn handle(&self, stream: ProxyStream, source: SocketAddr) -> Result<InboundResult>;
}

/// 出站处理器 trait
#[async_trait]
pub trait OutboundHandler: Send + Sync + 'static {
    fn tag(&self) -> &str;
    async fn connect(&self, session: &Session) -> Result<ProxyStream>;
    async fn connect_udp(&self, _session: &Session) -> Result<BoxUdpTransport> {
        anyhow::bail!("UDP not supported by outbound '{}'", self.tag())
    }
    /// 用于 downcasting 到具体类型
    fn as_any(&self) -> &dyn std::any::Any;
}
