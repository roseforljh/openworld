use std::collections::HashMap;

use anyhow::Result;
use serde::Deserialize;
use tracing::info;

use super::types::*;

#[derive(Debug, Deserialize)]
pub struct ClashConfig {
    #[serde(default)]
    pub port: Option<u16>,
    #[serde(rename = "socks-port", default)]
    pub socks_port: Option<u16>,
    #[serde(rename = "mixed-port", default)]
    pub mixed_port: Option<u16>,
    #[serde(rename = "bind-address", default)]
    pub bind_address: Option<String>,
    #[serde(rename = "allow-lan", default)]
    pub allow_lan: bool,
    #[serde(rename = "log-level", default = "default_clash_log")]
    pub log_level: String,
    #[serde(rename = "external-controller", default)]
    pub external_controller: Option<String>,
    #[serde(default)]
    pub secret: Option<String>,
    #[serde(rename = "external-ui", default)]
    pub external_ui: Option<String>,
    #[serde(default)]
    pub proxies: Vec<serde_json::Value>,
    #[serde(rename = "proxy-groups", default)]
    pub proxy_groups: Vec<serde_json::Value>,
    #[serde(default)]
    pub rules: Vec<String>,
    #[serde(default)]
    pub dns: Option<serde_json::Value>,
    #[serde(rename = "rule-providers", default)]
    pub rule_providers: HashMap<String, serde_json::Value>,
}

fn default_clash_log() -> String {
    "info".to_string()
}

#[derive(Debug, Clone, PartialEq)]
pub enum CompatLevel {
    Full,
    Degraded(Vec<String>),
    Incompatible(Vec<String>),
}

pub struct CompatResult {
    pub config: Config,
    pub level: CompatLevel,
    pub warnings: Vec<String>,
}

pub fn parse_clash_config(content: &str) -> Result<CompatResult> {
    let clash: ClashConfig = serde_yml::from_str(content)?;
    let mut warnings = Vec::new();
    let mut degraded = Vec::new();

    let bind = if clash.allow_lan {
        clash
            .bind_address
            .clone()
            .unwrap_or_else(|| "0.0.0.0".to_string())
    } else {
        "127.0.0.1".to_string()
    };

    let mut inbounds = Vec::new();

    if let Some(port) = clash.mixed_port {
        inbounds.push(InboundConfig {
            tag: "mixed-in".to_string(),
            protocol: "mixed".to_string(),
            listen: bind.clone(),
            port,
            sniffing: SniffingConfig::default(),
            settings: InboundSettings::default(),
            max_connections: None,
        });
    }
    if let Some(port) = clash.socks_port {
        inbounds.push(InboundConfig {
            tag: "socks-in".to_string(),
            protocol: "socks5".to_string(),
            listen: bind.clone(),
            port,
            sniffing: SniffingConfig::default(),
            settings: InboundSettings::default(),
            max_connections: None,
        });
    }
    if let Some(port) = clash.port {
        inbounds.push(InboundConfig {
            tag: "http-in".to_string(),
            protocol: "http".to_string(),
            listen: bind.clone(),
            port,
            sniffing: SniffingConfig::default(),
            settings: InboundSettings::default(),
            max_connections: None,
        });
    }

    if inbounds.is_empty() {
        inbounds.push(InboundConfig {
            tag: "mixed-in".to_string(),
            protocol: "mixed".to_string(),
            listen: bind.clone(),
            port: 7890,
            sniffing: SniffingConfig::default(),
            settings: InboundSettings::default(),
            max_connections: None,
        });
        warnings.push("no port configured, defaulting to mixed-port 7890".to_string());
    }

    let mut outbounds = vec![OutboundConfig {
        tag: "direct".to_string(),
        protocol: "direct".to_string(),
        settings: OutboundSettings::default(),
    }];

    for proxy_value in &clash.proxies {
        match convert_clash_proxy(proxy_value) {
            Ok(ob) => outbounds.push(ob),
            Err(e) => {
                let name = proxy_value
                    .get("name")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown");
                degraded.push(format!("proxy '{}': {}", name, e));
            }
        }
    }

    let mut proxy_groups = Vec::new();
    for group_value in &clash.proxy_groups {
        match convert_clash_proxy_group(group_value) {
            Ok(g) => proxy_groups.push(g),
            Err(e) => {
                let name = group_value
                    .get("name")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown");
                degraded.push(format!("proxy-group '{}': {}", name, e));
            }
        }
    }

    let (rules, default_outbound) = convert_clash_rules(&clash.rules);

    let api = clash.external_controller.as_ref().map(|ec| {
        let (listen, port) = parse_listen_addr(ec);
        ApiConfig {
            listen,
            port,
            secret: clash.secret.clone(),
            external_ui: clash.external_ui.clone(),
        }
    });

    let config = Config {
        log: LogConfig {
            level: clash.log_level.clone(),
        },
        profile: None,
        inbounds,
        outbounds,
        proxy_groups,
        router: RouterConfig {
            rules,
            default: default_outbound,
            geoip_db: None,
            geosite_db: None,
            rule_providers: HashMap::new(),
            geoip_url: None,
            geosite_url: None,
            geo_update_interval: 7 * 24 * 3600,
            geo_auto_update: false,
        },
        api,
        dns: None,
        subscriptions: vec![],
        max_connections: 10000,
    };

    let level = if degraded.is_empty() {
        CompatLevel::Full
    } else {
        CompatLevel::Degraded(degraded.clone())
    };

    warnings.extend(degraded);

    info!(level = ?level, "clash config converted");

    Ok(CompatResult {
        config,
        level,
        warnings,
    })
}

fn convert_clash_proxy(value: &serde_json::Value) -> Result<OutboundConfig> {
    let name = value
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let proxy_type = value.get("type").and_then(|v| v.as_str()).unwrap_or("");
    let server = value
        .get("server")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let port = value.get("port").and_then(|v| v.as_u64()).map(|p| p as u16);

    let (protocol, settings) = match proxy_type {
        "ss" | "shadowsocks" => {
            let method = value
                .get("cipher")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            let password = value
                .get("password")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            let plugin = value
                .get("plugin")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            let plugin_opts = value
                .get("plugin-opts")
                .or(value.get("plugin_opts"))
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            (
                "shadowsocks".to_string(),
                OutboundSettings {
                    address: server,
                    port,
                    method,
                    password,
                    plugin,
                    plugin_opts,
                    ..Default::default()
                },
            )
        }
        "vless" => {
            let uuid = value
                .get("uuid")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            let sni = value
                .get("servername")
                .or(value.get("sni"))
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            let flow = value
                .get("flow")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            (
                "vless".to_string(),
                OutboundSettings {
                    address: server,
                    port,
                    uuid,
                    sni,
                    flow,
                    security: Some("tls".to_string()),
                    ..Default::default()
                },
            )
        }
        "vmess" => {
            let uuid = value
                .get("uuid")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            let sni = value
                .get("servername")
                .or(value.get("sni"))
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            let method = value
                .get("cipher")
                .or(value.get("security"))
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            let tls_enabled = value.get("tls").and_then(|v| v.as_bool()).unwrap_or(false);
            (
                "vmess".to_string(),
                OutboundSettings {
                    address: server,
                    port,
                    uuid,
                    method,
                    sni,
                    security: Some(if tls_enabled { "tls" } else { "none" }.to_string()),
                    ..Default::default()
                },
            )
        }
        "trojan" => {
            let password = value
                .get("password")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            let sni = value
                .get("sni")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            (
                "trojan".to_string(),
                OutboundSettings {
                    address: server,
                    port,
                    password,
                    sni,
                    security: Some("tls".to_string()),
                    ..Default::default()
                },
            )
        }
        "hysteria2" | "hy2" => {
            let password = value
                .get("password")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            let sni = value
                .get("sni")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());
            (
                "hysteria2".to_string(),
                OutboundSettings {
                    address: server,
                    port,
                    password,
                    sni,
                    ..Default::default()
                },
            )
        }
        "direct" => ("direct".to_string(), OutboundSettings::default()),
        other => anyhow::bail!("unsupported clash proxy type: {}", other),
    };

    Ok(OutboundConfig {
        tag: name,
        protocol,
        settings,
    })
}

fn convert_clash_proxy_group(value: &serde_json::Value) -> Result<ProxyGroupConfig> {
    let name = value
        .get("name")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let group_type = value.get("type").and_then(|v| v.as_str()).unwrap_or("");
    let proxies: Vec<String> = value
        .get("proxies")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default();
    let url = value
        .get("url")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());
    let interval = value
        .get("interval")
        .and_then(|v| v.as_u64())
        .unwrap_or(300);
    let tolerance = value
        .get("tolerance")
        .and_then(|v| v.as_u64())
        .unwrap_or(150);

    let mapped_type = match group_type {
        "select" => "selector",
        "url-test" => "url-test",
        "fallback" => "fallback",
        "load-balance" => "load-balance",
        other => anyhow::bail!("unsupported clash group type: {}", other),
    };

    Ok(ProxyGroupConfig {
        name,
        group_type: mapped_type.to_string(),
        proxies,
        url,
        interval,
        tolerance,
        strategy: None,
    })
}

fn convert_clash_rules(rules: &[String]) -> (Vec<RuleConfig>, String) {
    let mut rule_configs = Vec::new();
    let mut default_outbound = "direct".to_string();

    for rule_str in rules {
        let parts: Vec<&str> = rule_str.splitn(3, ',').collect();
        if parts.len() < 2 {
            continue;
        }

        let rule_type = parts[0].trim();
        if rule_type == "MATCH" {
            default_outbound = parts[1].trim().to_string();
            continue;
        }

        if parts.len() < 3 {
            continue;
        }

        let value = parts[1].trim().to_string();
        let outbound = parts[2].trim().to_string();

        let mapped_type = match rule_type {
            "DOMAIN-SUFFIX" => "domain-suffix",
            "DOMAIN-KEYWORD" => "domain-keyword",
            "DOMAIN" => "domain-full",
            "IP-CIDR" | "IP-CIDR6" => "ip-cidr",
            "GEOIP" => "geoip",
            "GEOSITE" => "geosite",
            "RULE-SET" => "rule-set",
            "DST-PORT" => "dst-port",
            "SRC-PORT" => "src-port",
            "NETWORK" => "network",
            "IN-TAG" => "in-tag",
            _ => continue,
        };

        rule_configs.push(RuleConfig {
            rule_type: mapped_type.to_string(),
            values: vec![value],
            outbound,
        });
    }

    (rule_configs, default_outbound)
}

fn parse_listen_addr(addr: &str) -> (String, u16) {
    if let Some((host, port_str)) = addr.rsplit_once(':') {
        if let Ok(port) = port_str.parse::<u16>() {
            return (host.to_string(), port);
        }
    }
    ("127.0.0.1".to_string(), 9090)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_minimal_clash_config() {
        let yaml = r#"
mixed-port: 7890
proxies:
  - name: my-ss
    type: ss
    server: 1.2.3.4
    port: 8388
    cipher: aes-256-gcm
    password: "secret"
rules:
  - MATCH,my-ss
"#;
        let result = parse_clash_config(yaml).unwrap();
        assert_eq!(result.config.inbounds.len(), 1);
        assert_eq!(result.config.inbounds[0].protocol, "mixed");
        assert_eq!(result.config.inbounds[0].port, 7890);
        assert_eq!(result.config.outbounds.len(), 2); // direct + my-ss
        assert_eq!(result.config.router.default, "my-ss");
    }

    #[test]
    fn parse_clash_proxy_groups() {
        let yaml = r#"
mixed-port: 7890
proxies:
  - name: ss1
    type: ss
    server: 1.2.3.4
    port: 443
    cipher: aes-256-gcm
    password: "p"
  - name: ss2
    type: ss
    server: 5.6.7.8
    port: 443
    cipher: aes-256-gcm
    password: "p"
proxy-groups:
  - name: auto
    type: url-test
    proxies: [ss1, ss2]
    url: "http://www.gstatic.com/generate_204"
    interval: 300
  - name: select
    type: select
    proxies: [auto, ss1, ss2]
rules:
  - DOMAIN-SUFFIX,google.com,auto
  - MATCH,select
"#;
        let result = parse_clash_config(yaml).unwrap();
        assert_eq!(result.config.proxy_groups.len(), 2);
        assert_eq!(result.config.proxy_groups[0].group_type, "url-test");
        assert_eq!(result.config.proxy_groups[1].group_type, "selector");
        assert_eq!(result.config.router.rules.len(), 1);
        assert_eq!(result.config.router.default, "select");
    }

    #[test]
    fn parse_clash_external_controller() {
        let yaml = r#"
mixed-port: 7890
external-controller: "0.0.0.0:9090"
secret: "my-secret"
proxies: []
rules:
  - MATCH,direct
"#;
        let result = parse_clash_config(yaml).unwrap();
        let api = result.config.api.unwrap();
        assert_eq!(api.listen, "0.0.0.0");
        assert_eq!(api.port, 9090);
        assert_eq!(api.secret, Some("my-secret".to_string()));
    }

    #[test]
    fn convert_clash_rules_all_types() {
        let rules = vec![
            "DOMAIN-SUFFIX,google.com,proxy".to_string(),
            "DOMAIN-KEYWORD,facebook,proxy".to_string(),
            "DOMAIN,exact.com,proxy".to_string(),
            "IP-CIDR,10.0.0.0/8,direct".to_string(),
            "GEOIP,CN,direct".to_string(),
            "DST-PORT,443,proxy".to_string(),
            "SRC-PORT,12345,direct".to_string(),
            "NETWORK,UDP,proxy".to_string(),
            "IN-TAG,mixed-in,proxy".to_string(),
            "MATCH,fallback".to_string(),
        ];
        let (configs, default) = convert_clash_rules(&rules);
        assert_eq!(configs.len(), 9);
        assert_eq!(default, "fallback");
        assert_eq!(configs[0].rule_type, "domain-suffix");
        assert_eq!(configs[1].rule_type, "domain-keyword");
        assert_eq!(configs[2].rule_type, "domain-full");
        assert_eq!(configs[3].rule_type, "ip-cidr");
        assert_eq!(configs[4].rule_type, "geoip");
        assert_eq!(configs[5].rule_type, "dst-port");
        assert_eq!(configs[6].rule_type, "src-port");
        assert_eq!(configs[7].rule_type, "network");
        assert_eq!(configs[8].rule_type, "in-tag");
    }

    #[test]
    fn parse_vmess_proxy() {
        let yaml = r#"
mixed-port: 7890
proxies:
  - name: vmess-node
    type: vmess
    server: 1.2.3.4
    port: 443
    uuid: "550e8400-e29b-41d4-a716-446655440000"
    cipher: aes-128-gcm
    tls: true
    servername: "example.com"
rules:
  - MATCH,vmess-node
"#;
        let result = parse_clash_config(yaml).unwrap();
        assert_eq!(result.config.outbounds.len(), 2); // direct + vmess-node
        let vmess = result
            .config
            .outbounds
            .iter()
            .find(|o| o.tag == "vmess-node")
            .unwrap();
        assert_eq!(vmess.protocol, "vmess");
        assert_eq!(vmess.settings.method.as_deref(), Some("aes-128-gcm"));
        assert_eq!(vmess.settings.security.as_deref(), Some("tls"));
        assert_eq!(vmess.settings.sni.as_deref(), Some("example.com"));
    }

    #[test]
    fn unsupported_proxy_type_is_degraded() {
        let yaml = r#"
mixed-port: 7890
proxies:
  - name: unknown-proxy
    type: wireguard
    server: 1.2.3.4
    port: 443
rules:
  - MATCH,direct
"#;
        let result = parse_clash_config(yaml).unwrap();
        assert!(matches!(result.level, CompatLevel::Degraded(_)));
    }

    #[test]
    fn compat_level_full_when_all_supported() {
        let yaml = r#"
mixed-port: 7890
proxies: []
rules:
  - MATCH,direct
"#;
        let result = parse_clash_config(yaml).unwrap();
        assert_eq!(result.level, CompatLevel::Full);
    }
}
