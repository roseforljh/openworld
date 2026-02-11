pub mod cache;
pub mod fakeip;
pub mod hosts;
pub mod resolver;

use std::net::IpAddr;

use anyhow::Result;
use async_trait::async_trait;

pub use resolver::{build_resolver, SystemResolver};

/// DNS 解析器 trait
#[async_trait]
pub trait DnsResolver: Send + Sync {
    /// 将域名解析为 IP 地址列表
    async fn resolve(&self, host: &str) -> Result<Vec<IpAddr>>;
}
