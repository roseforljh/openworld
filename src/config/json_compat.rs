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
    #[serde(default)]
    transport: Option<SingBoxTransport>,
    // proxy-group fields
    #[serde(default)]
    outbounds: Option<Vec<String>>,
    #[serde(default)]
    url: Option<String>,
    #[serde(default)]
    interval: Option<String>,
    #[serde(default)]
    tolerance: Option<u32>,
    // WireGuard fields
    #[serde(default)]
    private_key: Option<String>,
    #[serde(default)]
    local_address: Option<Vec<String>>,
    #[serde(default)]
    peers: Option<Vec<SingBoxWgPeer>>,
    #[serde(default)]
    mtu: Option<u16>,
    // TUIC fields
    #[serde(default)]
    congestion_control: Option<String>,
    // SSH fields
    #[serde(default)]
    user: Option<String>,
    #[serde(default)]
    #[allow(dead_code)]
    private_key_path: Option<String>,
    #[serde(default)]
    private_key_passphrase: Option<String>,
    // Hysteria fields
    #[serde(default)]
    obfs: Option<SingBoxObfs>,
    #[serde(default)]
    up_mbps: Option<u64>,
    #[serde(default)]
    down_mbps: Option<u64>,
    #[serde(default)]
    auth_str: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
#[allow(dead_code)]
struct SingBoxWgPeer {
    #[serde(default)]
    public_key: Option<String>,
    #[serde(default)]
    pre_shared_key: Option<String>,
    #[serde(default)]
    allowed_ips: Option<Vec<String>>,
    #[serde(default)]
    server: Option<String>,
    #[serde(default)]
    server_port: Option<u16>,
}

#[derive(Debug, Deserialize, Default)]
struct SingBoxObfs {
    #[serde(default, rename = "type")]
    obfs_type: Option<String>,
    #[serde(default)]
    password: Option<String>,
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
    #[serde(default)]
    alpn: Option<Vec<String>>,
    #[serde(default)]
    reality: Option<SingBoxReality>,
    #[serde(default)]
    utls: Option<SingBoxUtls>,
}

#[derive(Debug, Deserialize)]
struct SingBoxTransport {
    #[serde(rename = "type", default)]
    transport_type: String,
    #[serde(default)]
    path: Option<String>,
    #[serde(default)]
    host: Option<String>,
    #[serde(default)]
    service_name: Option<String>,
    #[serde(default)]
    headers: Option<std::collections::HashMap<String, String>>,
}

#[derive(Debug, Deserialize)]
struct SingBoxReality {
    #[serde(default)]
    enabled: Option<bool>,
    #[serde(default)]
    public_key: Option<String>,
    #[serde(default)]
    short_id: Option<String>,
}

#[derive(Debug, Deserialize)]
struct SingBoxUtls {
    #[serde(default)]
    fingerprint: Option<String>,
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
    #[serde(default)]
    process_name: Option<Vec<String>>,
    #[serde(default)]
    rule_set: Option<Vec<String>>,
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
                let tls_ref = ob.tls.as_ref();
                let sni = tls_ref.and_then(|t| t.server_name.clone());
                let tls_enabled = tls_ref.map(|t| t.enabled.unwrap_or(false)).unwrap_or(false);
                let security = if tls_enabled { Some("tls".to_string()) } else { None };

                // 构建 TlsConfig
                let tls_config = if tls_enabled {
                    tls_ref.map(|t| {
                        let reality = t.reality.as_ref();
                        let is_reality = reality.and_then(|r| r.enabled).unwrap_or(false);
                        crate::config::types::TlsConfig {
                            enabled: true,
                            security: if is_reality { "reality".to_string() } else { "tls".to_string() },
                            sni: t.server_name.clone(),
                            allow_insecure: t.insecure.unwrap_or(false),
                            alpn: t.alpn.clone(),
                            fingerprint: t.utls.as_ref().and_then(|u| u.fingerprint.clone()),
                            public_key: reality.and_then(|r| r.public_key.clone()),
                            short_id: reality.and_then(|r| r.short_id.clone()),
                            ..Default::default()
                        }
                    })
                } else { None };

                // 构建 TransportConfig
                let transport_config = ob.transport.as_ref().and_then(|t| {
                    let tt = t.transport_type.as_str();
                    if tt.is_empty() || tt == "tcp" { return None; }
                    Some(crate::config::types::TransportConfig {
                        transport_type: tt.to_string(),
                        path: t.path.clone(),
                        host: t.host.clone(),
                        service_name: t.service_name.clone(),
                        headers: t.headers.clone(),
                        ..Default::default()
                    })
                });

                outbounds.push(OutboundConfig {
                    tag: ob.tag.clone(),
                    protocol: map_outbound_type(&ob.outbound_type),
                    settings: OutboundSettings {
                        address: ob.server.clone(),
                        port: ob.server_port,
                        uuid: ob.uuid.clone(),
                        password: ob.password.clone().or_else(|| ob.auth_str.clone()),
                        method: ob.method.clone(),
                        flow: ob.flow.clone(),
                        sni,
                        security,
                        tls: tls_config,
                        transport: transport_config,
                        // WireGuard
                        private_key: ob.private_key.clone(),
                        peer_public_key: ob.peers.as_ref()
                            .and_then(|p| p.first())
                            .and_then(|p| p.public_key.clone()),
                        preshared_key: ob.peers.as_ref()
                            .and_then(|p| p.first())
                            .and_then(|p| p.pre_shared_key.clone()),
                        local_address: ob.local_address.as_ref()
                            .and_then(|a| a.first()).cloned(),
                        mtu: ob.mtu,
                        // TUIC
                        congestion_control: ob.congestion_control.clone(),
                        // SSH
                        username: ob.user.clone(),
                        private_key_passphrase: ob.private_key_passphrase.clone(),
                        // Hysteria
                        obfs: ob.obfs.as_ref().and_then(|o| o.obfs_type.clone()),
                        obfs_password: ob.obfs.as_ref().and_then(|o| o.password.clone()),
                        up_mbps: ob.up_mbps,
                        down_mbps: ob.down_mbps,
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
            if let Some(domains) = &r.domain {
                rules.push(RuleConfig {
                    rule_type: "domain-full".into(),
                    values: domains.clone(),
                    outbound: r.outbound.clone(),
                ..Default::default()
                });
            }
            if let Some(procs) = &r.process_name {
                rules.push(RuleConfig {
                    rule_type: "process-name".into(),
                    values: procs.clone(),
                    outbound: r.outbound.clone(),
                ..Default::default()
                });
            }
            if let Some(sets) = &r.rule_set {
                for set_name in sets {
                    rules.push(RuleConfig {
                        rule_type: "rule-set".into(),
                        values: vec![set_name.clone()],
                        outbound: r.outbound.clone(),
                    ..Default::default()
                    });
                }
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

    #[test]
    fn parse_singbox_wireguard() {
        let json = r#"{
            "outbounds": [{
                "type": "wireguard",
                "tag": "wg-node",
                "server": "162.159.192.1",
                "server_port": 2408,
                "private_key": "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=",
                "local_address": ["172.16.0.2/32"],
                "peers": [{
                    "public_key": "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=",
                    "pre_shared_key": "psk123"
                }],
                "mtu": 1280
            }]
        }"#;
        let config = parse_singbox_json(json).unwrap();
        let wg = config.outbounds.iter().find(|o| o.tag == "wg-node").unwrap();
        assert_eq!(wg.protocol, "wireguard");
        assert_eq!(wg.settings.private_key.as_deref(), Some("yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk="));
        assert_eq!(wg.settings.peer_public_key.as_deref(), Some("bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo="));
        assert_eq!(wg.settings.preshared_key.as_deref(), Some("psk123"));
        assert_eq!(wg.settings.local_address.as_deref(), Some("172.16.0.2/32"));
        assert_eq!(wg.settings.mtu, Some(1280));
    }

    #[test]
    fn parse_singbox_vmess_ws_transport() {
        let json = r#"{
            "outbounds": [{
                "type": "vmess",
                "tag": "vmess-ws",
                "server": "1.2.3.4",
                "server_port": 443,
                "uuid": "550e8400-e29b-41d4-a716-446655440000",
                "tls": {
                    "enabled": true,
                    "server_name": "cdn.example.com"
                },
                "transport": {
                    "type": "ws",
                    "path": "/ws-path",
                    "host": "cdn.example.com"
                }
            }]
        }"#;
        let config = parse_singbox_json(json).unwrap();
        let vmess = config.outbounds.iter().find(|o| o.tag == "vmess-ws").unwrap();
        assert_eq!(vmess.protocol, "vmess");
        let transport = vmess.settings.transport.as_ref().unwrap();
        assert_eq!(transport.transport_type, "ws");
        assert_eq!(transport.path.as_deref(), Some("/ws-path"));
        let tls = vmess.settings.tls.as_ref().unwrap();
        assert!(tls.enabled);
        assert_eq!(tls.sni.as_deref(), Some("cdn.example.com"));
    }

    #[test]
    fn parse_singbox_domain_and_process_rules() {
        let json = r#"{
            "outbounds": [{"type": "direct", "tag": "direct"}, {"type": "direct", "tag": "proxy"}],
            "route": {
                "rules": [
                    {"domain": ["example.com", "test.com"], "outbound": "direct"},
                    {"process_name": ["chrome.exe", "firefox.exe"], "outbound": "proxy"},
                    {"rule_set": ["geosite-cn"], "outbound": "direct"}
                ],
                "final": "proxy"
            }
        }"#;
        let config = parse_singbox_json(json).unwrap();
        let domain_rule = config.router.rules.iter().find(|r| r.rule_type == "domain-full").unwrap();
        assert_eq!(domain_rule.values, vec!["example.com", "test.com"]);
        let proc_rule = config.router.rules.iter().find(|r| r.rule_type == "process-name").unwrap();
        assert_eq!(proc_rule.values, vec!["chrome.exe", "firefox.exe"]);
        let set_rule = config.router.rules.iter().find(|r| r.rule_type == "rule-set").unwrap();
        assert_eq!(set_rule.values, vec!["geosite-cn"]);
    }
}
