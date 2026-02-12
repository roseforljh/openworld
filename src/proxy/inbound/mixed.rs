use std::net::SocketAddr;

use anyhow::Result;
use async_trait::async_trait;
use tokio::io::AsyncReadExt;

use crate::common::{PrefixedStream, ProxyStream};
use crate::proxy::{InboundHandler, InboundResult};

use super::http::HttpInbound;
use super::socks5::Socks5Inbound;

pub struct MixedInbound {
    tag: String,
    socks5: Socks5Inbound,
    http: HttpInbound,
}

impl MixedInbound {
    pub fn new(tag: String, listen: String) -> Self {
        Self {
            tag: tag.clone(),
            socks5: Socks5Inbound::new(tag.clone(), listen),
            http: HttpInbound::new(tag),
        }
    }

    pub fn with_auth(mut self, users: Vec<(String, String)>) -> Self {
        self.socks5 = self.socks5.with_auth(users.clone());
        self.http = self.http.with_auth(users);
        self
    }
}

#[async_trait]
impl InboundHandler for MixedInbound {
    fn tag(&self) -> &str {
        &self.tag
    }

    async fn handle(&self, mut stream: ProxyStream, source: SocketAddr) -> Result<InboundResult> {
        // Peek 第一个字节判断协议
        let mut peek = [0u8; 1];
        stream.read_exact(&mut peek).await?;

        // 将读取的字节放回流中
        let stream: ProxyStream = Box::new(PrefixedStream::new(peek.to_vec(), stream));

        if peek[0] == 0x05 {
            // SOCKS5 版本号
            self.socks5.handle(stream, source).await
        } else {
            // 假定 HTTP
            self.http.handle(stream, source).await
        }
    }
}
