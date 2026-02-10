use serde::Serialize;
use std::collections::HashMap;

/// GET /version 响应
#[derive(Serialize)]
pub struct VersionResponse {
    pub version: String,
    pub premium: bool,
}

/// GET /proxies 响应
#[derive(Serialize)]
pub struct ProxiesResponse {
    pub proxies: HashMap<String, ProxyInfo>,
}

/// 单个代理信息
#[derive(Serialize, Clone)]
pub struct ProxyInfo {
    pub name: String,
    #[serde(rename = "type")]
    pub proxy_type: String,
    pub udp: bool,
    pub history: Vec<serde_json::Value>,
    /// 代理组专有：包含的代理列表
    #[serde(skip_serializing_if = "Option::is_none")]
    pub all: Option<Vec<String>>,
    /// 代理组专有：当前选中的代理
    #[serde(skip_serializing_if = "Option::is_none")]
    pub now: Option<String>,
}

/// GET /connections 响应
#[derive(Serialize)]
pub struct ConnectionsResponse {
    #[serde(rename = "downloadTotal")]
    pub download_total: u64,
    #[serde(rename = "uploadTotal")]
    pub upload_total: u64,
    pub connections: Vec<ConnectionItem>,
}

/// 单个连接信息
#[derive(Serialize)]
pub struct ConnectionItem {
    pub id: String,
    pub metadata: ConnectionMetadata,
    pub upload: u64,
    pub download: u64,
    pub start: String,
    pub chains: Vec<String>,
    pub rule: String,
}

/// 连接元数据
#[derive(Serialize)]
pub struct ConnectionMetadata {
    pub network: String,
    #[serde(rename = "type")]
    pub conn_type: String,
    #[serde(rename = "sourceIP")]
    pub source_ip: String,
    #[serde(rename = "sourcePort")]
    pub source_port: String,
    #[serde(rename = "destinationIP")]
    pub destination_ip: String,
    #[serde(rename = "destinationPort")]
    pub destination_port: String,
    pub host: String,
    #[serde(rename = "dnsMode")]
    pub dns_mode: String,
}

/// GET /rules 响应
#[derive(Serialize)]
pub struct RulesResponse {
    pub rules: Vec<RuleItem>,
}

/// 单个规则
#[derive(Serialize)]
pub struct RuleItem {
    #[serde(rename = "type")]
    pub rule_type: String,
    pub payload: String,
    pub proxy: String,
}

/// WebSocket /traffic 推送项
#[derive(Serialize)]
pub struct TrafficItem {
    pub up: u64,
    pub down: u64,
}

/// PUT /proxies/{name} 请求体
#[derive(serde::Deserialize)]
pub struct SelectProxyRequest {
    pub name: String,
}

/// GET /proxies/{name}/delay 响应
#[derive(Serialize)]
pub struct DelayResponse {
    pub delay: u64,
}
