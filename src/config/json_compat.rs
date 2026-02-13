//! sing-box JSON 配置兼容层
//!
//! 将 sing-box 格式的 JSON 配置转换为 OpenWorld 内部 Config 结构。
//! 支持 KunBox 生成的 JSON 配置直接传入。

use serde::Deserialize;

use crate::config::types::{
    Config, DnsConfig, DnsServerConfig, InboundConfig, InboundSettings,
    LogConfig, OutboundConfig, OutboundSettings, ProxyGroupConfig,
    RouterConfig, RuleConfig, SniffingConfig,
};

/// 顶层 sing-box 配置
#[derive(Debug, Deserialize)]
struct SingBoxConfig {
    #[serde(default)]
    log: Option<SingBoxLog>,
    #[serde(default)]
    dns: Option<SingBoxDns>,
    #[serde(default)]
    inbounds: Vec<SingBoxInbound>,
    #[serde(default)]
    outbounds: Vec<SingBoxOutbound>,
    #[serde(default)]
    route: Option<SingBoxRoute>,
}

#[derive(Debug, Deserialize)]
struct SingBoxLog {
    #[serde(default = "default_log_level")]
    level: String,
}

fn default_log_level() -> String { "info".into() }

#[derive(Debug, Deserialize)]
struct SingBoxDns {
    #[serde(default)]
    servers: Vec<SingBoxDnsServer>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct SingBoxDnsServer {
    #[serde(default)]
    tag: String,
    address: String,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct SingBoxInbound {
    #[serde(rename = "type")]
    inbound_type: String,
    #[serde(default)]
    tag: String,
    #[serde(default)]
    listen: Option<String>,
    #[serde(default)]
    listen_port: Option<u16>,
    #[serde(default)]
    interface_name: Option<String>,
    #[serde(default)]
    auto_route: Option<bool>,
    #[serde(default)]
    inet4_address: Option<String>,
    #[serde(default)]
    mtu: Option<u32>,
    #[serde(default)]
    stack: Option<String>,
    #[serde(default)]
    sniff: Option<bool>,
}

#[derive(Debug, Deserialize)]
struct SingBoxOutbound {
    #[serde(rename = "type")]
    outbound_type: String,
    #[serde(default)]
    tag: String,
    #[serde(default)]
    server: Option<String>,
    #[serde(default)]
    server_port: Option<u16>,
    #[serde(default)]
    uuid: Option<String>,
    #[serde(default)]
    password: Option<String>,
    #[serde(default)]
    method: Option<String>,
    #[serde(default)]
    flow: Option<String>,
    #[serde(default)]
    tls: Option<SingBoxTls>,
    // proxy-group fields
    #[serde(default)]
    outbounds: Option<Vec<String>>,
    #[serde(default)]
    url: Option<String>,
    #[serde(default)]
    interval: Option<String>,
    #[serde(default)]
    tolerance: Option<u32>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct SingBoxTls {
    #[serde(default)]
    enabled: Option<bool>,
    #[serde(default)]
    server_name: Option<String>,
    #[serde(default)]
    insecure: Option<bool>,
}

#[derive(Debug, Deserialize)]
struct SingBoxRoute {
    #[serde(default)]
    rules: Vec<SingBoxRouteRule>,
    #[serde(rename = "final", default)]
    final_outbound: Option<String>,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
struct SingBoxRouteRule {
    #[serde(default)]
    domain_suffix: Option<Vec<String>>,
    #[serde(default)]
    domain_keyword: Option<Vec<String>>,
    #[serde(default)]
    domain: Option<Vec<String>>,
    #[serde(default)]
    ip_cidr: Option<Vec<String>>,
    #[serde(default)]
    outbound: String,
    #[serde(default)]
    protocol: Option<Vec<String>>,
    #[serde(default)]
    geoip: Option<Vec<String>>,
    #[serde(default)]
    geosite: Option<Vec<String>>,
}

/// 解析 sing-box 格式的 JSON 配置
pub fn parse_singbox_json(json_str: &str) -> anyhow::Result<Config> {
    let sb: SingBoxConfig = serde_json::from_str(json_str)?;
    convert_singbox_to_config(sb)
}

fn convert_singbox_to_config(sb: SingBoxConfig) -> anyhow::Result<Config> {
    let log_level = sb.log.map(|l| l.level).unwrap_or_else(|| "info".into());

    // DNS
    let dns = sb.dns.map(|d| {
        let servers: Vec<DnsServerConfig> = d.servers.iter().map(|s| {
            DnsServerConfig {
                address: s.address.clone(),
                domains: Vec::new(),
            }
        }).collect();
        DnsConfig {
            servers,
            cache_size: 1024,
            cache_ttl: 300,
            negative_cache_ttl: 30,
            hosts: Default::default(),
            fake_ip: None,
            mode: "split".into(),
            fallback: Vec::new(),
            fallback_filter: None,
            edns_client_subnet: None,
            prefer_ip: None,
        }
    });

    // Inbounds
    let inbounds: Vec<InboundConfig> = sb.inbounds.iter().map(|ib| {
        let protocol = match ib.inbound_type.as_str() {
            "mixed" => "socks5".to_string(),
            "tun" => "tun".to_string(),
            other => other.to_string(),
        };
        let tag = if ib.tag.is_empty() { format!("{}-in", protocol) } else { ib.tag.clone() };
        let listen = ib.listen.clone().unwrap_or_else(|| "127.0.0.1".into());
        let port = ib.listen_port.unwrap_or(1080);

        InboundConfig {
            tag,
            protocol,
            listen,
            port,
            sniffing: SniffingConfig {
                enabled: ib.sniff.unwrap_or(false),
                ..Default::default()
            },
            settings: InboundSettings {
                auto_route: ib.auto_route.unwrap_or(false),
                ..Default::default()
            },
            max_connections: None,
        }
    }).collect();

    // Outbounds + proxy groups
    let mut outbounds: Vec<OutboundConfig> = Vec::new();
    let mut proxy_groups: Vec<ProxyGroupConfig> = Vec::new();

    for ob in &sb.outbounds {
        match ob.outbound_type.as_str() {
            "direct" | "block" | "dns" => {
                outbounds.push(OutboundConfig {
                    tag: if ob.tag.is_empty() { ob.outbound_type.clone() } else { ob.tag.clone() },
                    protocol: ob.outbound_type.clone(),
                    settings: OutboundSettings::default(),
                });
            }
            "selector" | "urltest" | "url-test" => {
                let group_type = if ob.outbound_type == "selector" { "selector" } else { "url-test" };
                proxy_groups.push(ProxyGroupConfig {
                    name: ob.tag.clone(),
                    group_type: group_type.to_string(),
                    proxies: ob.outbounds.clone().unwrap_or_default(),
                    url: ob.url.clone(),
                    interval: parse_interval(ob.interval.as_deref()),
                    tolerance: ob.tolerance.unwrap_or(150) as u64,
                    strategy: None,
                });
            }
            _ => {
                let tls = ob.tls.as_ref();
                let sni = tls.and_then(|t| t.server_name.clone());
                let security = if tls.map(|t| t.enabled.unwrap_or(false)).unwrap_or(false) {
                    Some("tls".to_string())
                } else {
                    None
                };

                outbounds.push(OutboundConfig {
                    tag: ob.tag.clone(),
                    protocol: map_outbound_type(&ob.outbound_type),
                    settings: OutboundSettings {
                        address: ob.server.clone(),
                        port: ob.server_port,
                        uuid: ob.uuid.clone(),
                        password: ob.password.clone(),
                        method: ob.method.clone(),
                        flow: ob.flow.clone(),
                        sni,
                        security,
                        ..Default::default()
                    },
                });
            }
        }
    }

    // Router
    let mut rules = Vec::new();
    if let Some(route) = &sb.route {
        for r in &route.rules {
            if let Some(domains) = &r.domain_suffix {
                rules.push(RuleConfig {
                    rule_type: "domain-suffix".into(),
                    values: domains.clone(),
                    outbound: r.outbound.clone(),
                ..Default::default()
                });
            }
            if let Some(domains) = &r.domain_keyword {
                rules.push(RuleConfig {
                    rule_type: "domain-keyword".into(),
                    values: domains.clone(),
                    outbound: r.outbound.clone(),
                ..Default::default()
                });
            }
            if let Some(cidrs) = &r.ip_cidr {
                rules.push(RuleConfig {
                    rule_type: "ip-cidr".into(),
                    values: cidrs.clone(),
                    outbound: r.outbound.clone(),
                ..Default::default()
                });
            }
            if let Some(geoips) = &r.geoip {
                rules.push(RuleConfig {
                    rule_type: "geoip".into(),
                    values: geoips.clone(),
                    outbound: r.outbound.clone(),
                ..Default::default()
                });
            }
            if let Some(geosites) = &r.geosite {
                rules.push(RuleConfig {
                    rule_type: "geosite".into(),
                    values: geosites.clone(),
                    outbound: r.outbound.clone(),
                ..Default::default()
                });
            }
        }
    }

    let default_outbound = sb.route
        .as_ref()
        .and_then(|r| r.final_outbound.clone())
        .unwrap_or_else(|| "direct".into());

    let router = RouterConfig {
        rules,
        default: default_outbound,
        geoip_db: None,
        geosite_db: None,
        rule_providers: Default::default(),
        geoip_url: None,
        geosite_url: None,
        geo_update_interval: 7 * 24 * 3600,
        geo_auto_update: false,
    };

    Ok(Config {
        log: LogConfig { level: log_level },
        profile: None,
        inbounds,
        outbounds,
        proxy_groups,
        router,
        subscriptions: Vec::new(),
        api: None,
        dns,
        derp: None,
        max_connections: 65536,
    })
}

fn map_outbound_type(t: &str) -> String {
    match t {
        "vmess" => "vmess".into(),
        "vless" => "vless".into(),
        "trojan" => "trojan".into(),
        "shadowsocks" | "ss" => "shadowsocks".into(),
        "hysteria2" | "hy2" => "hysteria2".into(),
        "wireguard" | "wg" => "wireguard".into(),
        "tuic" => "tuic".into(),
        "ssh" => "ssh".into(),
        other => other.into(),
    }
}

fn parse_interval(s: Option<&str>) -> u64 {
    match s {
        Some(s) => {
            if let Some(rest) = s.strip_suffix('m') {
                rest.parse::<u64>().unwrap_or(5) * 60
            } else if let Some(rest) = s.strip_suffix('s') {
                rest.parse::<u64>().unwrap_or(300)
            } else {
                s.parse::<u64>().unwrap_or(300)
            }
        }
        None => 300,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_minimal_singbox() {
        let json = r#"{
            "outbounds": [
                {"type": "direct", "tag": "direct"}
            ]
        }"#;
        let config = parse_singbox_json(json).unwrap();
        assert_eq!(config.outbounds.len(), 1);
        assert_eq!(config.outbounds[0].tag, "direct");
    }

    #[test]
    fn parse_singbox_with_inbound() {
        let json = r#"{
            "inbounds": [
                {"type": "mixed", "tag": "mixed-in", "listen": "127.0.0.1", "listen_port": 2080}
            ],
            "outbounds": [
                {"type": "direct", "tag": "direct"}
            ]
        }"#;
        let config = parse_singbox_json(json).unwrap();
        assert_eq!(config.inbounds.len(), 1);
        assert_eq!(config.inbounds[0].port, 2080);
        assert_eq!(config.inbounds[0].protocol, "socks5");
    }

    #[test]
    fn parse_singbox_with_vless() {
        let json = r#"{
            "outbounds": [
                {
                    "type": "vless",
                    "tag": "proxy",
                    "server": "example.com",
                    "server_port": 443,
                    "uuid": "test-uuid",
                    "tls": {"enabled": true, "server_name": "example.com"}
                },
                {"type": "direct", "tag": "direct"}
            ]
        }"#;
        let config = parse_singbox_json(json).unwrap();
        assert_eq!(config.outbounds.len(), 2);
        assert_eq!(config.outbounds[0].protocol, "vless");
        assert_eq!(config.outbounds[0].settings.uuid.as_deref(), Some("test-uuid"));
        assert_eq!(config.outbounds[0].settings.sni.as_deref(), Some("example.com"));
    }

    #[test]
    fn parse_singbox_with_selector() {
        let json = r#"{
            "outbounds": [
                {"type": "selector", "tag": "proxy", "outbounds": ["node-a", "node-b"]},
                {"type": "direct", "tag": "node-a"},
                {"type": "direct", "tag": "node-b"}
            ]
        }"#;
        let config = parse_singbox_json(json).unwrap();
        assert_eq!(config.proxy_groups.len(), 1);
        assert_eq!(config.proxy_groups[0].name, "proxy");
        assert_eq!(config.proxy_groups[0].group_type, "selector");
        assert_eq!(config.proxy_groups[0].proxies, vec!["node-a", "node-b"]);
    }

    #[test]
    fn parse_singbox_with_route() {
        let json = r#"{
            "outbounds": [{"type": "direct", "tag": "direct"}, {"type": "direct", "tag": "proxy"}],
            "route": {
                "rules": [
                    {"domain_suffix": [".cn"], "outbound": "direct"},
                    {"ip_cidr": ["10.0.0.0/8"], "outbound": "direct"}
                ],
                "final": "proxy"
            }
        }"#;
        let config = parse_singbox_json(json).unwrap();
        assert_eq!(config.router.default, "proxy");
        assert!(config.router.rules.len() >= 2);
    }

    #[test]
    fn parse_interval_minutes() {
        assert_eq!(parse_interval(Some("5m")), 300);
        assert_eq!(parse_interval(Some("1m")), 60);
    }

    #[test]
    fn parse_interval_seconds() {
        assert_eq!(parse_interval(Some("300s")), 300);
    }

    #[test]
    fn parse_interval_raw() {
        assert_eq!(parse_interval(Some("600")), 600);
        assert_eq!(parse_interval(None), 300);
    }

    #[test]
    fn map_outbound_types() {
        assert_eq!(map_outbound_type("vmess"), "vmess");
        assert_eq!(map_outbound_type("ss"), "shadowsocks");
        assert_eq!(map_outbound_type("hy2"), "hysteria2");
    }

    #[test]
    fn parse_invalid_json() {
        assert!(parse_singbox_json("not json").is_err());
    }
}
