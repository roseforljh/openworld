use std::collections::HashMap;

use anyhow::Result;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub log: LogConfig,
    #[serde(default)]
    pub profile: Option<String>,
    pub inbounds: Vec<InboundConfig>,
    pub outbounds: Vec<OutboundConfig>,
    #[serde(default, rename = "proxy-groups")]
    pub proxy_groups: Vec<ProxyGroupConfig>,
    #[serde(default)]
    pub router: RouterConfig,
    #[serde(default)]
    pub subscriptions: Vec<SubscriptionConfig>,
    pub api: Option<ApiConfig>,
    pub dns: Option<DnsConfig>,
    /// 全局最大连接数限制
    #[serde(default = "default_max_connections", rename = "max-connections")]
    pub max_connections: u32,
}

#[derive(Debug, Deserialize, Clone)]
pub struct SubscriptionConfig {
    pub name: String,
    pub url: String,
    #[serde(default = "default_subscription_interval")]
    pub interval_secs: u64,
    #[serde(default = "default_subscription_enabled")]
    pub enabled: bool,
}

fn default_subscription_interval() -> u64 {
    3600
}

fn default_subscription_enabled() -> bool {
    true
}

impl Config {
    pub fn validate(&self) -> Result<()> {
        if self.inbounds.is_empty() {
            anyhow::bail!("at least one inbound is required");
        }
        if self.outbounds.is_empty() {
            anyhow::bail!("at least one outbound is required");
        }
        // 收集所有可用的出站 tag（outbound + proxy-group）
        let mut all_tags: Vec<&str> = self.outbounds.iter().map(|o| o.tag.as_str()).collect();
        for group in &self.proxy_groups {
            all_tags.push(group.name.as_str());
        }
        // 验证 router default 指向存在的 outbound/group
        if !all_tags.contains(&self.router.default.as_str()) {
            anyhow::bail!(
                "router default '{}' does not match any outbound or proxy-group",
                self.router.default
            );
        }
        for rule in &self.router.rules {
            if matches!(rule.rule_type.as_str(), "ip-asn" | "uid") {
                anyhow::bail!(
                    "router rule type '{}' is declared but not implemented in matcher yet",
                    rule.rule_type
                );
            }
            if !all_tags.contains(&rule.outbound.as_str()) {
                anyhow::bail!(
                    "rule outbound '{}' does not match any outbound or proxy-group",
                    rule.outbound
                );
            }
        }
        // 验证 proxy-group 引用的 proxies 存在
        for group in &self.proxy_groups {
            for proxy_name in &group.proxies {
                if !all_tags.contains(&proxy_name.as_str()) {
                    anyhow::bail!(
                        "proxy-group '{}' references unknown proxy '{}'",
                        group.name,
                        proxy_name
                    );
                }
            }
        }

        let outbound_tags: Vec<&str> = self.outbounds.iter().map(|o| o.tag.as_str()).collect();
        for outbound in &self.outbounds {
            if outbound.protocol != "chain" {
                continue;
            }

            let hops = outbound.settings.chain.as_ref().ok_or_else(|| {
                anyhow::anyhow!("chain outbound '{}' requires settings.chain", outbound.tag)
            })?;
            if hops.is_empty() {
                anyhow::bail!(
                    "chain outbound '{}' requires non-empty settings.chain",
                    outbound.tag
                );
            }

            for hop in hops {
                if hop == &outbound.tag {
                    anyhow::bail!("chain outbound '{}' cannot contain itself", outbound.tag);
                }
                if !outbound_tags.contains(&hop.as_str()) {
                    anyhow::bail!(
                        "chain outbound '{}' references unknown hop '{}'",
                        outbound.tag,
                        hop
                    );
                }
            }
        }
        Ok(())
    }
}

#[derive(Debug, Deserialize)]
pub struct LogConfig {
    #[serde(default = "default_log_level")]
    pub level: String,
}

impl Default for LogConfig {
    fn default() -> Self {
        Self {
            level: "info".to_string(),
        }
    }
}

fn default_log_level() -> String {
    "info".to_string()
}

fn default_max_connections() -> u32 {
    10000
}

fn default_true() -> bool {
    true
}

fn default_tproxy_mark() -> u32 {
    1
}

fn default_tproxy_table() -> u32 {
    100
}

#[derive(Debug, Deserialize, Clone)]
pub struct InboundConfig {
    pub tag: String,
    pub protocol: String,
    pub listen: String,
    pub port: u16,
    #[serde(default)]
    pub sniffing: SniffingConfig,
    #[serde(default)]
    pub settings: InboundSettings,
    /// 此入站的最大连接数限制（可选，不设则仅受全局限制）
    #[serde(default, rename = "max-connections", alias = "max_connections")]
    pub max_connections: Option<u32>,
}

#[derive(Debug, Default, Deserialize, Clone)]
pub struct InboundSettings {
    pub method: Option<String>,
    pub password: Option<String>,
    #[serde(default)]
    pub users: Option<Vec<ShadowsocksUserConfig>>,
    pub uuid: Option<String>,
    pub flow: Option<String>,
    #[serde(default)]
    pub clients: Option<Vec<VlessClientConfig>>,
    /// 网络类型 (tcp/udp)，用于 TProxy 等入站
    pub network: Option<String>,
    /// 认证用户列表（SOCKS5/HTTP/Mixed 入站）
    #[serde(default)]
    pub auth: Option<Vec<AuthUserConfig>>,
    /// 自动设置系统代理（主要用于 Windows）
    #[serde(default, rename = "set-system-proxy")]
    pub set_system_proxy: bool,
    /// 系统代理绕过列表
    #[serde(default, rename = "system-proxy-bypass")]
    pub system_proxy_bypass: Vec<String>,
    /// 系统代理 SOCKS 端口（可选）
    #[serde(default, rename = "system-proxy-socks-port")]
    pub system_proxy_socks_port: Option<u16>,
    /// Linux 透明代理规则自动应用（redirect/tproxy 入站）
    #[serde(default = "default_true", rename = "auto-route")]
    pub auto_route: bool,
    /// Linux 透明代理后端：iptables | nftables
    #[serde(default, rename = "route-backend")]
    pub route_backend: Option<String>,
    /// Linux cgroup 路径（可选）
    #[serde(default, rename = "cgroup-path")]
    pub cgroup_path: Option<String>,
    /// TPROXY fwmark（默认 1）
    #[serde(default = "default_tproxy_mark", rename = "tproxy-mark")]
    pub tproxy_mark: u32,
    /// TPROXY 路由表号（默认 100）
    #[serde(default = "default_tproxy_table", rename = "tproxy-table")]
    pub tproxy_table: u32,
    /// TUN DNS 劫持规则（如 ["udp://any:53", "tcp://any:53"]）
    #[serde(default, rename = "dns-hijack")]
    pub dns_hijack: Vec<String>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct AuthUserConfig {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Deserialize, Clone)]
pub struct ShadowsocksUserConfig {
    pub password: String,
    pub method: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct VlessClientConfig {
    pub uuid: String,
    pub flow: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct OutboundConfig {
    pub tag: String,
    pub protocol: String,
    #[serde(default)]
    pub settings: OutboundSettings,
}

#[derive(Debug, Default, Deserialize, Clone)]
pub struct OutboundSettings {
    pub address: Option<String>,
    pub port: Option<u16>,
    pub uuid: Option<String>,
    pub password: Option<String>,
    pub method: Option<String>,
    pub security: Option<String>,
    pub sni: Option<String>,
    #[serde(default)]
    pub allow_insecure: bool,
    pub flow: Option<String>,
    pub public_key: Option<String>,
    pub short_id: Option<String>,
    pub server_name: Option<String>,
    pub fingerprint: Option<String>,
    /// SIP003 插件名（如 obfs-local / v2ray-plugin）
    pub plugin: Option<String>,
    /// SIP003 插件参数
    pub plugin_opts: Option<String>,
    /// Shadowsocks 2022 iPSK (identity PSK) for multi-user
    pub identity_key: Option<String>,
    /// WireGuard private key (base64)
    pub private_key: Option<String>,
    /// WireGuard peer public key (base64)
    pub peer_public_key: Option<String>,
    /// WireGuard preshared key (base64)
    pub preshared_key: Option<String>,
    /// WireGuard local address
    pub local_address: Option<String>,
    /// WireGuard MTU
    pub mtu: Option<u16>,
    /// WireGuard keepalive interval (seconds)
    pub keepalive: Option<u16>,
    /// SSH/认证用户名
    pub username: Option<String>,
    /// SSH 私钥密码
    pub private_key_passphrase: Option<String>,
    /// 拥塞控制算法 (cubic/bbr/new_reno)
    pub congestion_control: Option<String>,
    /// Hysteria2 上行带宽提示 (Mbps)
    pub up_mbps: Option<u64>,
    /// Hysteria2 下行带宽提示 (Mbps)
    pub down_mbps: Option<u64>,
    /// VMess AlterID (0 = AEAD, >0 = legacy MD5+Timestamp)
    pub alter_id: Option<u16>,
    /// WireGuard 多 Peer 配置
    pub peers: Option<Vec<WireGuardPeerConfig>>,
    /// Tor SOCKS5 端口
    pub socks_port: Option<u16>,
    /// 传输层配置（新格式）
    pub transport: Option<TransportConfig>,
    /// TLS 配置（新格式）
    pub tls: Option<TlsConfig>,
    pub mux: Option<MuxConfig>,
    /// Hysteria v1 混淆方式
    pub obfs: Option<String>,
    /// Hysteria v1 混淆密码
    #[serde(rename = "obfs-password")]
    pub obfs_password: Option<String>,
    pub chain: Option<Vec<String>>,
    /// 统一 Dialer 配置（接口绑定、路由标记、TFO、MPTCP 等）
    pub dialer: Option<crate::common::DialerConfig>,
    /// Per-outbound domain resolver — references a named DNS server.
    /// Resolves the outbound server's domain name independently.
    #[serde(rename = "domain-resolver")]
    pub domain_resolver: Option<String>,
}

impl OutboundSettings {
    /// 获取有效的传输层配置（新格式优先，回退到默认 TCP）
    pub fn effective_transport(&self) -> TransportConfig {
        self.transport.clone().unwrap_or_default()
    }

    /// 获取有效的 TLS 配置（新格式优先，回退到旧字段）
    pub fn effective_tls(&self) -> TlsConfig {
        if let Some(ref tls) = self.tls {
            return tls.clone();
        }
        // 从旧字段构建
        let security = self.security.clone().unwrap_or_default();
        let enabled = !security.is_empty() && security != "none";
        TlsConfig {
            enabled,
            security: if security.is_empty() {
                "tls".to_string()
            } else {
                security
            },
            sni: self.sni.clone(),
            allow_insecure: self.allow_insecure,
            alpn: None,
            public_key: self.public_key.clone(),
            short_id: self.short_id.clone(),
            server_name: self.server_name.clone(),
            fingerprint: self.fingerprint.clone(),
            ech_config: None,
            ech_grease: false,
            ech_outer_sni: None,
            ech_auto: false,
            fragment: None,
        }
    }
}

fn default_tcp() -> String {
    "tcp".to_string()
}

fn default_tls_security() -> String {
    "tls".to_string()
}

fn default_mux_protocol() -> String {
    "sing-mux".to_string()
}

fn default_mux_max_connections() -> usize {
    4
}

fn default_mux_max_streams_per_connection() -> usize {
    128
}

#[derive(Debug, Deserialize, Clone)]
pub struct MuxConfig {
    #[serde(default = "default_mux_protocol")]
    pub protocol: String,
    #[serde(default = "default_mux_max_connections")]
    pub max_connections: usize,
    #[serde(default = "default_mux_max_streams_per_connection")]
    pub max_streams_per_connection: usize,
    #[serde(default)]
    pub padding: bool,
}

impl Default for MuxConfig {
    fn default() -> Self {
        Self {
            protocol: default_mux_protocol(),
            max_connections: default_mux_max_connections(),
            max_streams_per_connection: default_mux_max_streams_per_connection(),
            padding: false,
        }
    }
}

/// 传输层配置
#[derive(Debug, Default, Deserialize, Clone)]
pub struct TransportConfig {
    #[serde(rename = "type", default = "default_tcp")]
    pub transport_type: String,
    pub path: Option<String>,
    pub host: Option<String>,
    pub headers: Option<HashMap<String, String>>,
    /// gRPC 服务名（仅 grpc 传输使用）
    pub service_name: Option<String>,
    /// ShadowTLS v3 密码
    #[serde(rename = "shadow-tls-password")]
    pub shadow_tls_password: Option<String>,
    /// ShadowTLS v3 握手 SNI
    #[serde(rename = "shadow-tls-sni")]
    pub shadow_tls_sni: Option<String>,
}

/// TLS 配置
#[derive(Debug, Deserialize, Clone)]
pub struct TlsConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_tls_security")]
    pub security: String,
    pub sni: Option<String>,
    #[serde(default)]
    pub allow_insecure: bool,
    pub alpn: Option<Vec<String>>,
    pub public_key: Option<String>,
    pub short_id: Option<String>,
    pub server_name: Option<String>,
    pub fingerprint: Option<String>,
    /// ECHConfigList(base64)
    #[serde(default, rename = "ech-config")]
    pub ech_config: Option<String>,
    /// 启用 ECH GREASE（无配置时发送占位扩展）
    #[serde(default, rename = "ech-grease")]
    pub ech_grease: bool,
    /// ECH outer SNI（保留）
    #[serde(default, rename = "ech-outer-sni")]
    pub ech_outer_sni: Option<String>,
    /// 自动从 DNS HTTPS 记录获取 ECH 配置
    #[serde(default, rename = "ech-auto")]
    pub ech_auto: bool,

    /// TLS 分片: 将 ClientHello 拆分成多个小 TCP 段发送（绕过 DPI）
    #[serde(default, rename = "fragment")]
    pub fragment: Option<TlsFragmentConfig>,
}

impl Default for TlsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            security: "tls".to_string(),
            sni: None,
            allow_insecure: false,
            alpn: None,
            public_key: None,
            short_id: None,
            server_name: None,
            fingerprint: None,
            ech_config: None,
            ech_grease: false,
            ech_outer_sni: None,
            ech_auto: false,
            fragment: None,
        }
    }
}

/// TLS 分片配置
#[derive(Debug, Deserialize, Clone)]
pub struct TlsFragmentConfig {
    /// 分片大小范围下限（字节），默认 10
    #[serde(default = "default_fragment_min")]
    pub min_length: usize,
    /// 分片大小范围上限（字节），默认 100
    #[serde(default = "default_fragment_max")]
    pub max_length: usize,
    /// 分片间延迟下限（毫秒），默认 10
    #[serde(default = "default_fragment_delay_min")]
    pub min_delay_ms: u64,
    /// 分片间延迟上限（毫秒），默认 50
    #[serde(default = "default_fragment_delay_max")]
    pub max_delay_ms: u64,
}

fn default_fragment_min() -> usize { 10 }
fn default_fragment_max() -> usize { 100 }
fn default_fragment_delay_min() -> u64 { 10 }
fn default_fragment_delay_max() -> u64 { 50 }

/// API 配置（Clash 兼容）
#[derive(Debug, Deserialize, Clone)]
pub struct ApiConfig {
    #[serde(default = "default_api_listen")]
    pub listen: String,
    #[serde(default = "default_api_port")]
    pub port: u16,
    pub secret: Option<String>,
    #[serde(default, rename = "external-ui")]
    pub external_ui: Option<String>,
}

fn default_api_listen() -> String {
    "127.0.0.1".to_string()
}

fn default_api_port() -> u16 {
    9090
}

/// DNS 配置
#[derive(Debug, Deserialize, Clone)]
pub struct DnsConfig {
    pub servers: Vec<DnsServerConfig>,
    #[serde(default = "default_cache_size")]
    pub cache_size: usize,
    #[serde(default = "default_cache_ttl")]
    pub cache_ttl: u64,
    #[serde(default = "default_negative_cache_ttl")]
    pub negative_cache_ttl: u64,
    /// HOSTS 静态映射 (域名 → IP)
    #[serde(default)]
    pub hosts: HashMap<String, String>,
    /// FakeIP 配置
    #[serde(default)]
    pub fake_ip: Option<FakeIpConfig>,
    /// 并发查询模式: "split"(域名分流,默认) | "race"(竞速) | "fallback"(主备)
    #[serde(default = "default_dns_mode")]
    pub mode: String,
    /// fallback 模式的备用 DNS 服务器
    #[serde(default)]
    pub fallback: Vec<DnsServerConfig>,
    /// fallback 过滤: 当 nameserver 返回这些 IP 段时使用 fallback
    #[serde(default)]
    pub fallback_filter: Option<FallbackFilterConfig>,
    /// EDNS Client Subnet (如 "1.2.3.0/24")
    #[serde(default, rename = "edns-client-subnet")]
    pub edns_client_subnet: Option<String>,
    /// IP 地址偏好策略: "ipv4" | "ipv6" | "" (默认不偏好)
    #[serde(default, rename = "prefer-ip")]
    pub prefer_ip: Option<String>,
}

fn default_dns_mode() -> String {
    "split".to_string()
}

/// FakeIP 配置
#[derive(Debug, Deserialize, Clone)]
pub struct FakeIpConfig {
    #[serde(default = "default_fakeip_range")]
    pub ipv4_range: String,
    #[serde(default)]
    pub ipv6_range: Option<String>,
    #[serde(default)]
    pub exclude: Vec<String>,
}

fn default_fakeip_range() -> String {
    "198.18.0.0/15".to_string()
}

/// Fallback 过滤配置
#[derive(Debug, Deserialize, Clone)]
pub struct FallbackFilterConfig {
    /// 当 nameserver 返回这些 CIDR 范围内的 IP 时，使用 fallback
    #[serde(default)]
    pub ip_cidr: Vec<String>,
    /// 当查询这些域名时，使用 fallback
    #[serde(default)]
    pub domain: Vec<String>,
}

fn default_cache_size() -> usize {
    1024
}

fn default_cache_ttl() -> u64 {
    300
}

fn default_negative_cache_ttl() -> u64 {
    30
}

/// DNS 服务器配置
#[derive(Debug, Deserialize, Clone)]
pub struct DnsServerConfig {
    pub address: String,
    #[serde(default)]
    pub domains: Vec<String>,
}

/// 协议嗅探配置
#[derive(Debug, Deserialize, Clone, Default)]
pub struct SniffingConfig {
    #[serde(default)]
    pub enabled: bool,
}

/// 代理组配置
#[derive(Debug, Deserialize, Clone)]
pub struct ProxyGroupConfig {
    pub name: String,
    #[serde(rename = "type")]
    pub group_type: String,
    pub proxies: Vec<String>,
    /// url-test/fallback 健康检查 URL
    pub url: Option<String>,
    /// 健康检查间隔（秒）
    #[serde(default = "default_health_interval")]
    pub interval: u64,
    /// url-test 容差（毫秒），延迟差在此范围内不切换
    #[serde(default = "default_tolerance")]
    pub tolerance: u64,
    /// load-balance 策略: round-robin | random | consistent-hash | sticky
    #[serde(default)]
    pub strategy: Option<String>,
}

fn default_health_interval() -> u64 {
    300
}

fn default_tolerance() -> u64 {
    150
}

#[derive(Debug, Deserialize)]
pub struct RouterConfig {
    #[serde(default)]
    pub rules: Vec<RuleConfig>,
    #[serde(default = "default_outbound")]
    pub default: String,
    pub geoip_db: Option<String>,
    pub geosite_db: Option<String>,
    #[serde(default, rename = "rule-providers")]
    pub rule_providers: HashMap<String, RuleProviderConfig>,
    /// GeoIP 自动更新 URL
    #[serde(default, rename = "geoip-url")]
    pub geoip_url: Option<String>,
    /// GeoSite 自动更新 URL
    #[serde(default, rename = "geosite-url")]
    pub geosite_url: Option<String>,
    /// Geo 数据库自动更新间隔（秒），默认 7 天
    #[serde(
        default = "default_geo_update_interval",
        rename = "geo-update-interval"
    )]
    pub geo_update_interval: u64,
    /// 是否启用 Geo 数据库自动更新
    #[serde(default, rename = "geo-auto-update")]
    pub geo_auto_update: bool,
}

impl Default for RouterConfig {
    fn default() -> Self {
        Self {
            rules: Vec::new(),
            default: "direct".to_string(),
            geoip_db: None,
            geosite_db: None,
            rule_providers: HashMap::new(),
            geoip_url: None,
            geosite_url: None,
            geo_update_interval: default_geo_update_interval(),
            geo_auto_update: false,
        }
    }
}

fn default_outbound() -> String {
    "direct".to_string()
}

fn default_geo_update_interval() -> u64 {
    7 * 24 * 3600
}

#[derive(Debug, Deserialize, Clone)]
pub struct RuleConfig {
    #[serde(rename = "type")]
    pub rule_type: String,
    pub values: Vec<String>,
    #[serde(default)]
    pub outbound: String,
    /// Rule Action: route(默认) / reject / reject-drop / bypass / hijack-dns
    #[serde(default = "default_rule_action")]
    pub action: String,
    /// 覆盖目标地址
    #[serde(default, rename = "override-address")]
    pub override_address: Option<String>,
    /// 覆盖目标端口
    #[serde(default, rename = "override-port")]
    pub override_port: Option<u16>,
    /// 启用协议嗅探
    #[serde(default)]
    pub sniff: bool,
    /// DNS 解析策略
    #[serde(default, rename = "resolve-strategy")]
    pub resolve_strategy: Option<String>,
}

impl Default for RuleConfig {
    fn default() -> Self {
        Self {
            rule_type: String::new(),
            values: Vec::new(),
            outbound: String::new(),
            action: "route".to_string(),
            override_address: None,
            override_port: None,
            sniff: false,
            resolve_strategy: None,
        }
    }
}

fn default_rule_action() -> String { "route".to_string() }

/// 规则提供者配置（Clash 兼容）
#[derive(Debug, Deserialize, Clone)]
pub struct RuleProviderConfig {
    /// 提供者类型: "file" | "http"
    #[serde(rename = "type")]
    pub provider_type: String,
    /// 行为类型: "domain" | "ipcidr" | "classical"
    pub behavior: String,
    /// 本地文件路径（file 类型）或缓存路径（http 类型）
    pub path: String,
    /// 远程 URL（仅 http 类型）
    pub url: Option<String>,
    /// 更新间隔，秒（仅 http 类型）
    #[serde(default = "default_provider_interval")]
    pub interval: u64,
    /// 惰性加载：首次匹配时才触发加载
    #[serde(default)]
    pub lazy: bool,
}

fn default_provider_interval() -> u64 {
    86400
}

/// WireGuard Peer 配置
#[derive(Debug, Deserialize, Clone)]
pub struct WireGuardPeerConfig {
    pub public_key: String,
    pub endpoint: Option<String>,
    #[serde(default)]
    pub allowed_ips: Vec<String>,
    pub keepalive: Option<u16>,
    pub preshared_key: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn minimal_config() -> Config {
        Config {
            log: LogConfig::default(),
            profile: None,
            inbounds: vec![InboundConfig {
                tag: "socks-in".to_string(),
                protocol: "socks5".to_string(),
                listen: "127.0.0.1".to_string(),
                port: 1080,
                sniffing: SniffingConfig::default(),
                settings: InboundSettings::default(),
                max_connections: None,
            }],
            outbounds: vec![OutboundConfig {
                tag: "direct".to_string(),
                protocol: "direct".to_string(),
                settings: OutboundSettings::default(),
            }],
            router: RouterConfig {
                rules: Vec::new(),
                default: "direct".to_string(),
                geoip_db: None,
                geosite_db: None,
                rule_providers: Default::default(),
                geoip_url: None,
                geosite_url: None,
                geo_update_interval: 7 * 24 * 3600,
                geo_auto_update: false,
            },
            subscriptions: vec![],
            api: None,
            dns: None,
            proxy_groups: vec![],
            max_connections: 10000,
        }
    }

    #[test]
    fn validate_ok() {
        assert!(minimal_config().validate().is_ok());
    }

    #[test]
    fn validate_no_inbounds() {
        let mut config = minimal_config();
        config.inbounds.clear();
        assert!(config.validate().is_err());
    }

    #[test]
    fn validate_no_outbounds() {
        let mut config = minimal_config();
        config.outbounds.clear();
        assert!(config.validate().is_err());
    }

    #[test]
    fn validate_router_default_missing() {
        let mut config = minimal_config();
        config.router.default = "nonexistent".to_string();
        assert!(config.validate().is_err());
    }

    #[test]
    fn validate_rule_outbound_missing() {
        let mut config = minimal_config();
        config.router.rules.push(RuleConfig {
            rule_type: "domain-suffix".to_string(),
            values: vec!["example.com".to_string()],
            outbound: "nonexistent".to_string(),
        ..Default::default()
        });
        assert!(config.validate().is_err());
    }

    #[test]
    fn validate_rule_outbound_ok() {
        let mut config = minimal_config();
        config.router.rules.push(RuleConfig {
            rule_type: "domain-suffix".to_string(),
            values: vec!["example.com".to_string()],
            outbound: "direct".to_string(),
        ..Default::default()
        });
        assert!(config.validate().is_ok());
    }

    #[test]
    fn deserialize_full_config() {
        let yaml = r#"
log:
  level: debug
inbounds:
  - tag: socks-in
    protocol: socks5
    listen: "127.0.0.1"
    port: 1080
    settings: {}
outbounds:
  - tag: direct
    protocol: direct
router:
  rules: []
  default: direct
"#;
        let config: Config = serde_yml::from_str(yaml).unwrap();
        assert_eq!(config.log.level, "debug");
        assert_eq!(config.inbounds.len(), 1);
        assert_eq!(config.inbounds[0].tag, "socks-in");
        assert!(config.validate().is_ok());
    }

    #[test]
    fn deserialize_default_log_level() {
        let yaml = r#"
inbounds:
  - tag: socks-in
    protocol: socks5
    listen: "127.0.0.1"
    port: 1080
    settings: {}
outbounds:
  - tag: direct
    protocol: direct
router:
  default: direct
"#;
        let config: Config = serde_yml::from_str(yaml).unwrap();
        assert_eq!(config.log.level, "info");
    }

    #[test]
    fn deserialize_outbound_settings() {
        let yaml = r#"
inbounds:
  - tag: socks-in
    protocol: socks5
    listen: "127.0.0.1"
    port: 1080
    settings: {}
outbounds:
  - tag: my-vless
    protocol: vless
    settings:
      address: "1.2.3.4"
      port: 443
      uuid: "550e8400-e29b-41d4-a716-446655440000"
      security: tls
      sni: "example.com"
      allow_insecure: true
  - tag: direct
    protocol: direct
router:
  default: direct
"#;
        let config: Config = serde_yml::from_str(yaml).unwrap();
        let vless = &config.outbounds[0].settings;
        assert_eq!(vless.address.as_deref(), Some("1.2.3.4"));
        assert_eq!(vless.port, Some(443));
        assert!(vless.allow_insecure);
        assert_eq!(vless.sni.as_deref(), Some("example.com"));
    }

    #[test]
    fn validate_chain_outbound_ok() {
        let mut config = minimal_config();
        config.outbounds.push(OutboundConfig {
            tag: "chain-out".to_string(),
            protocol: "chain".to_string(),
            settings: OutboundSettings {
                chain: Some(vec!["direct".to_string()]),
                ..Default::default()
            },
        });
        assert!(config.validate().is_ok());
    }

    #[test]
    fn validate_chain_outbound_unknown_hop() {
        let mut config = minimal_config();
        config.outbounds.push(OutboundConfig {
            tag: "chain-out".to_string(),
            protocol: "chain".to_string(),
            settings: OutboundSettings {
                chain: Some(vec!["missing".to_string()]),
                ..Default::default()
            },
        });
        assert!(config.validate().is_err());
    }

    #[test]
    fn validate_rejects_ip_asn_rule() {
        let mut config = minimal_config();
        config.router.rules.push(RuleConfig {
            rule_type: "ip-asn".to_string(),
            values: vec!["13335".to_string()],
            outbound: "direct".to_string(),
        ..Default::default()
        });
        assert!(config.validate().is_err());
    }

    #[test]
    fn validate_rejects_uid_rule() {
        let mut config = minimal_config();
        config.router.rules.push(RuleConfig {
            rule_type: "uid".to_string(),
            values: vec!["1000".to_string()],
            outbound: "direct".to_string(),
        ..Default::default()
        });
        assert!(config.validate().is_err());
    }
}
