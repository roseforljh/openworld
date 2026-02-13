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
    #[serde(rename = "routeTag")]
    pub route_tag: String,
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

/// GET /stats 响应
#[derive(Serialize)]
pub struct StatsResponse {
    #[serde(rename = "routeStats")]
    pub route_stats: HashMap<String, u64>,
    #[serde(rename = "errorStats")]
    pub error_stats: HashMap<String, u64>,
    #[serde(rename = "dnsStats")]
    pub dns_stats: DnsStats,
    pub latency: LatencyStats,
}

#[derive(Serialize)]
pub struct DnsStats {
    #[serde(rename = "cacheHit")]
    pub cache_hit: u64,
    #[serde(rename = "cacheMiss")]
    pub cache_miss: u64,
    #[serde(rename = "negativeHit")]
    pub negative_hit: u64,
}

#[derive(Serialize)]
pub struct LatencyStats {
    #[serde(rename = "p50")]
    pub p50_ms: Option<u64>,
    #[serde(rename = "p95")]
    pub p95_ms: Option<u64>,
    #[serde(rename = "p99")]
    pub p99_ms: Option<u64>,
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
    pub memory: u64,
    #[serde(rename = "connActive")]
    pub conn_active: usize,
}

/// PUT /proxies/{name} 请求体
#[derive(serde::Deserialize)]
pub struct SelectProxyRequest {
    pub name: String,
}

/// PATCH /configs 请求体
#[derive(serde::Deserialize)]
pub struct ReloadConfigRequest {
    pub path: Option<String>,
    /// Clash 模式: "rule", "global", "direct"
    pub mode: Option<String>,
}

/// GET /proxies/{name}/delay 响应
#[derive(Serialize)]
pub struct DelayResponse {
    pub delay: u64,
}

/// GET /memory 响应
#[derive(Serialize)]
pub struct MemoryResponse {
    #[serde(rename = "inuse")]
    pub in_use: u64,
    #[serde(rename = "oslimit")]
    pub os_limit: u64,
}

/// GET /uptime 响应
#[derive(Serialize)]
pub struct UptimeResponse {
    pub uptime_secs: u64,
    pub version: String,
    pub active_connections: usize,
}

/// GET /providers/rules 响应
#[derive(Serialize)]
pub struct RuleProvidersResponse {
    pub providers: HashMap<String, RuleProviderInfo>,
}

/// Rule provider info
#[derive(Serialize)]
pub struct RuleProviderInfo {
    pub name: String,
    #[serde(rename = "type")]
    pub provider_type: String,
    #[serde(rename = "ruleCount")]
    pub rule_count: usize,
    #[serde(rename = "updatedAt")]
    pub updated_at: String,
    pub behavior: String,
}

/// GET /providers/proxies 响应
#[derive(Serialize)]
pub struct ProxyProvidersResponse {
    pub providers: HashMap<String, ProxyProviderInfo>,
}

/// Proxy provider info
#[derive(Serialize)]
pub struct ProxyProviderInfo {
    pub name: String,
    #[serde(rename = "type")]
    pub provider_type: String,
    pub proxies: Vec<ProxyInfo>,
    #[serde(rename = "vehicleType")]
    pub vehicle_type: String,
}

/// GET /configs 响应
#[derive(Serialize)]
pub struct ConfigsResponse {
    pub port: u16,
    #[serde(rename = "socks-port")]
    pub socks_port: u16,
    #[serde(rename = "mixed-port")]
    pub mixed_port: u16,
    pub mode: String,
    #[serde(rename = "log-level")]
    pub log_level: String,
    #[serde(rename = "allow-lan")]
    pub allow_lan: bool,
    #[serde(rename = "outboundCount")]
    pub outbound_count: usize,
    #[serde(rename = "ruleCount")]
    pub rule_count: usize,
    #[serde(rename = "providerCount")]
    pub provider_count: usize,
}
