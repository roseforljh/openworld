use std::collections::HashMap;

use anyhow::Result;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub log: LogConfig,
    pub inbounds: Vec<InboundConfig>,
    pub outbounds: Vec<OutboundConfig>,
    #[serde(default, rename = "proxy-groups")]
    pub proxy_groups: Vec<ProxyGroupConfig>,
    #[serde(default)]
    pub router: RouterConfig,
    pub api: Option<ApiConfig>,
    pub dns: Option<DnsConfig>,
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

#[derive(Debug, Deserialize)]
pub struct InboundConfig {
    pub tag: String,
    pub protocol: String,
    pub listen: String,
    pub port: u16,
    #[serde(default)]
    pub sniffing: SniffingConfig,
}

#[derive(Debug, Deserialize)]
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
    pub security: Option<String>,
    pub sni: Option<String>,
    #[serde(default)]
    pub allow_insecure: bool,
    pub flow: Option<String>,
    pub public_key: Option<String>,
    pub short_id: Option<String>,
    pub server_name: Option<String>,
    pub fingerprint: Option<String>,
    /// 传输层配置（新格式）
    pub transport: Option<TransportConfig>,
    /// TLS 配置（新格式）
    pub tls: Option<TlsConfig>,
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
            security: if security.is_empty() { "tls".to_string() } else { security },
            sni: self.sni.clone(),
            allow_insecure: self.allow_insecure,
            alpn: None,
            public_key: self.public_key.clone(),
            short_id: self.short_id.clone(),
            server_name: self.server_name.clone(),
            fingerprint: self.fingerprint.clone(),
        }
    }
}

fn default_tcp() -> String {
    "tcp".to_string()
}

fn default_tls_security() -> String {
    "tls".to_string()
}

/// 传输层配置
#[derive(Debug, Default, Deserialize, Clone)]
pub struct TransportConfig {
    #[serde(rename = "type", default = "default_tcp")]
    pub transport_type: String,
    pub path: Option<String>,
    pub host: Option<String>,
    pub headers: Option<HashMap<String, String>>,
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
        }
    }
}

/// API 配置（Clash 兼容）
#[derive(Debug, Deserialize, Clone)]
pub struct ApiConfig {
    #[serde(default = "default_api_listen")]
    pub listen: String,
    #[serde(default = "default_api_port")]
    pub port: u16,
    pub secret: Option<String>,
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
}

/// DNS 服务器配置
#[derive(Debug, Deserialize, Clone)]
pub struct DnsServerConfig {
    pub address: String,
    #[serde(default)]
    pub domains: Vec<String>,
}

/// 协议嗅探配置
#[derive(Debug, Deserialize, Clone)]
pub struct SniffingConfig {
    #[serde(default)]
    pub enabled: bool,
}

impl Default for SniffingConfig {
    fn default() -> Self {
        Self { enabled: false }
    }
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
}

impl Default for RouterConfig {
    fn default() -> Self {
        Self {
            rules: Vec::new(),
            default: "direct".to_string(),
            geoip_db: None,
            geosite_db: None,
        }
    }
}

fn default_outbound() -> String {
    "direct".to_string()
}

#[derive(Debug, Deserialize)]
pub struct RuleConfig {
    #[serde(rename = "type")]
    pub rule_type: String,
    pub values: Vec<String>,
    pub outbound: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn minimal_config() -> Config {
        Config {
            log: LogConfig::default(),
            inbounds: vec![InboundConfig {
                tag: "socks-in".to_string(),
                protocol: "socks5".to_string(),
                listen: "127.0.0.1".to_string(),
                port: 1080,
                sniffing: SniffingConfig::default(),
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
            },
            api: None,
            dns: None,
            proxy_groups: vec![],
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
}
