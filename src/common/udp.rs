use anyhow::Result;
use async_trait::async_trait;
use bytes::Bytes;

use super::Address;

/// UDP 数据包
pub struct UdpPacket {
    /// 目标(发送)或来源(接收)地址
    pub addr: Address,
    /// 载荷
    pub data: Bytes,
}

/// UDP 传输抽象 trait
#[async_trait]
pub trait UdpTransport: Send + Sync {
    async fn send(&self, packet: UdpPacket) -> Result<()>;
    async fn recv(&self) -> Result<UdpPacket>;
}

/// 类型擦除的 UDP 传输
pub type BoxUdpTransport = Box<dyn UdpTransport>;
