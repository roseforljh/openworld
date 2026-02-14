use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// 校验模式
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ValidationMode {
    #[default]
    Strict,
    Compat,
    Loose,
}

impl<'de> Deserialize<'de> for ValidationMode {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        match s.as_str() {
            "strict" => Ok(ValidationMode::Strict),
            "compat" => Ok(ValidationMode::Compat),
            "loose" => Ok(ValidationMode::Loose),
            _ => Err(serde::de::Error::custom(format!(
                "unknown validation mode: {}",
                s
            ))),
        }
    }
}

impl Serialize for ValidationMode {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match self {
            ValidationMode::Strict => serializer.serialize_str("strict"),
            ValidationMode::Compat => serializer.serialize_str("compat"),
            ValidationMode::Loose => serializer.serialize_str("loose"),
        }
    }
}

/// ZenOne 顶层文档
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZenOneDoc {
    #[serde(rename = "zen-version")]
    pub zen_version: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata: Option<ZenMetadata>,
    pub nodes: Vec<ZenNode>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub groups: Vec<ZenGroup>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub router: Option<ZenRouter>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dns: Option<ZenDns>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub inbounds: Vec<ZenInbound>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub settings: Option<ZenSettings>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature: Option<ZenSignature>,
}

/// 订阅元数据
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ZenMetadata {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "source-url")]
    pub source_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "update-interval")]
    pub update_interval: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "expire-at")]
    pub expire_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upload: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub download: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub total: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub homepage: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revision: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "generated-by")]
    pub generated_by: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "migrated-from")]
    pub migrated_from: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "migrated-at")]
    pub migrated_at: Option<String>,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub extra: HashMap<String, serde_json::Value>,
}

/// 节点定义
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZenNode {
    pub name: String,
    #[serde(rename = "type")]
    pub node_type: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    // 协议通用字段
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub uuid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub flow: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "alter-id")]
    pub alter_id: Option<u16>,
    // Shadowsocks 扩展
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub plugin: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "plugin-opts")]
    pub plugin_opts: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "identity-key")]
    pub identity_key: Option<String>,
    // Hysteria
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "up-mbps")]
    pub up_mbps: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "down-mbps")]
    pub down_mbps: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub obfs: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "obfs-password")]
    pub obfs_password: Option<String>,
    // TUIC
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "congestion-control")]
    pub congestion_control: Option<String>,
    // WireGuard
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "private-key")]
    pub private_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "peer-public-key")]
    pub peer_public_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "preshared-key")]
    pub preshared_key: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "local-address")]
    pub local_address: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mtu: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keepalive: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub peers: Option<Vec<ZenWireGuardPeer>>,
    // SSH
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "private-key-passphrase")]
    pub private_key_passphrase: Option<String>,
    // Chain
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub chain: Option<Vec<String>>,
    // 嵌套配置块
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls: Option<ZenTls>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transport: Option<ZenTransport>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mux: Option<ZenMux>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dialer: Option<ZenDialer>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "health-check")]
    pub health_check: Option<ZenHealthCheck>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZenWireGuardPeer {
    #[serde(rename = "public-key")]
    pub public_key: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty", rename = "allowed-ips")]
    pub allowed_ips: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZenTls {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sni: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alpn: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub insecure: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reality: Option<ZenReality>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ech: Option<ZenEch>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fragment: Option<ZenTlsFragment>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZenReality {
    #[serde(rename = "public-key")]
    pub public_key: String,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "short-id")]
    pub short_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZenEch {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub config: Option<String>,
    #[serde(default)]
    pub grease: bool,
    #[serde(default)]
    pub auto: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZenTlsFragment {
    #[serde(default = "default_frag_min", rename = "min-length")]
    pub min_length: usize,
    #[serde(default = "default_frag_max", rename = "max-length")]
    pub max_length: usize,
    #[serde(default = "default_frag_delay_min", rename = "min-delay-ms")]
    pub min_delay_ms: u64,
    #[serde(default = "default_frag_delay_max", rename = "max-delay-ms")]
    pub max_delay_ms: u64,
}

fn default_frag_min() -> usize { 10 }
fn default_frag_max() -> usize { 100 }
fn default_frag_delay_min() -> u64 { 10 }
fn default_frag_delay_max() -> u64 { 50 }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZenTransport {
    #[serde(rename = "type")]
    pub transport_type: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub headers: Option<HashMap<String, String>>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "service-name")]
    pub service_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "shadow-tls-password")]
    pub shadow_tls_password: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "shadow-tls-sni")]
    pub shadow_tls_sni: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZenMux {
    #[serde(default = "default_mux_proto")]
    pub protocol: String,
    #[serde(default = "default_mux_conns", rename = "max-connections")]
    pub max_connections: usize,
    #[serde(default = "default_mux_streams", rename = "max-streams")]
    pub max_streams: usize,
    #[serde(default)]
    pub padding: bool,
}

fn default_mux_proto() -> String { "sing-mux".into() }
fn default_mux_conns() -> usize { 4 }
fn default_mux_streams() -> usize { 128 }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZenDialer {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub interface: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fwmark: Option<u32>,
    #[serde(default, rename = "tcp-fast-open")]
    pub tcp_fast_open: bool,
    #[serde(default)]
    pub mptcp: bool,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "domain-resolver")]
    pub domain_resolver: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZenHealthCheck {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub interval: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "timeout-ms")]
    pub timeout_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retries: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "failure-threshold")]
    pub failure_threshold: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "recovery-threshold")]
    pub recovery_threshold: Option<u32>,
}

/// 代理组
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZenGroup {
    pub name: String,
    #[serde(rename = "type")]
    pub group_type: String,
    pub nodes: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub interval: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tolerance: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub strategy: Option<String>,
}

/// 路由
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZenRouter {
    #[serde(default = "default_direct")]
    pub default: String,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "geoip-db")]
    pub geoip_db: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "geosite-db")]
    pub geosite_db: Option<String>,
    #[serde(default, rename = "geo-auto-update")]
    pub geo_auto_update: bool,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "geoip-url")]
    pub geoip_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "geosite-url")]
    pub geosite_url: Option<String>,
    #[serde(default, skip_serializing_if = "HashMap::is_empty", rename = "rule-providers")]
    pub rule_providers: HashMap<String, ZenRuleProvider>,
    #[serde(default)]
    pub rules: Vec<ZenRule>,
}

fn default_direct() -> String { "direct".into() }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZenRuleProvider {
    #[serde(rename = "type")]
    pub provider_type: String,
    pub behavior: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub interval: Option<u64>,
    #[serde(default)]
    pub lazy: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZenRule {
    #[serde(rename = "type")]
    pub rule_type: String,
    #[serde(default)]
    pub values: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outbound: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub action: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sniff: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "override-address")]
    pub override_address: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "override-port")]
    pub override_port: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "sub-rules")]
    pub sub_rules: Option<Vec<ZenRule>>,
}

/// DNS
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZenDns {
    #[serde(default = "default_dns_mode")]
    pub mode: String,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "cache-size")]
    pub cache_size: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "cache-ttl")]
    pub cache_ttl: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "negative-cache-ttl")]
    pub negative_cache_ttl: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "prefer-ip")]
    pub prefer_ip: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "edns-client-subnet")]
    pub edns_client_subnet: Option<String>,
    #[serde(default)]
    pub servers: Vec<ZenDnsServer>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub fallback: Vec<ZenDnsServer>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "fallback-filter")]
    pub fallback_filter: Option<ZenFallbackFilter>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "fake-ip")]
    pub fake_ip: Option<ZenFakeIp>,
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub hosts: HashMap<String, String>,
}

fn default_dns_mode() -> String { "split".into() }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZenDnsServer {
    pub address: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub domains: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZenFallbackFilter {
    #[serde(default, skip_serializing_if = "Vec::is_empty", rename = "ip-cidr")]
    pub ip_cidr: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub domain: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZenFakeIp {
    #[serde(default = "default_fakeip_v4", rename = "ipv4-range")]
    pub ipv4_range: String,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "ipv6-range")]
    pub ipv6_range: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub exclude: Vec<String>,
}

fn default_fakeip_v4() -> String { "198.18.0.0/15".into() }

/// 入站
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZenInbound {
    pub tag: String,
    #[serde(rename = "type")]
    pub inbound_type: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub listen: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "max-connections")]
    pub max_connections: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sniffing: Option<ZenSniffing>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth: Option<Vec<ZenAuth>>,
    #[serde(default, rename = "set-system-proxy")]
    pub set_system_proxy: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty", rename = "system-proxy-bypass")]
    pub system_proxy_bypass: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZenSniffing {
    #[serde(default)]
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZenAuth {
    pub username: String,
    pub password: String,
}

/// 全局设置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZenSettings {
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "log-level")]
    pub log_level: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "max-connections")]
    pub max_connections: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "validation-mode")]
    pub validation_mode: Option<ValidationMode>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub api: Option<ZenApi>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub derp: Option<ZenDerp>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secrets: Option<ZenSecrets>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub performance: Option<ZenPerformance>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub extensions: Option<ZenExtensions>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZenApi {
    #[serde(default = "default_api_listen")]
    pub listen: String,
    #[serde(default = "default_api_port")]
    pub port: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "external-ui")]
    pub external_ui: Option<String>,
}

fn default_api_listen() -> String { "127.0.0.1".into() }
fn default_api_port() -> u16 { 9090 }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZenDerp {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZenSecrets {
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "key-file")]
    pub key_file: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZenPerformance {
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "parse-concurrency")]
    pub parse_concurrency: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "healthcheck-concurrency")]
    pub healthcheck_concurrency: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "max-nodes")]
    pub max_nodes: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZenExtensions {
    #[serde(default, skip_serializing_if = "Vec::is_empty", rename = "allowed-prefixes")]
    pub allowed_prefixes: Vec<String>,
}

/// 签名
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZenSignature {
    pub algorithm: String,
    #[serde(rename = "key-id")]
    pub key_id: String,
    #[serde(rename = "created-at")]
    pub created_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none", rename = "expires-at")]
    pub expires_at: Option<String>,
    pub value: String,
}
