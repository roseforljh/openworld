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

    // DNS 深度解析
    let dns_config = clash
        .dns
        .as_ref()
        .and_then(|dns_val| convert_clash_dns(dns_val));

    // rule-providers 映射
    let mut rule_provider_map = HashMap::new();
    for (name, rp_val) in &clash.rule_providers {
        if let Some(rpc) = convert_clash_rule_provider(rp_val) {
            rule_provider_map.insert(name.clone(), rpc);
        }
    }

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
            rule_providers: rule_provider_map,
            geoip_url: None,
            geosite_url: None,
            geo_update_interval: 7 * 24 * 3600,
            geo_auto_update: false,
        },
        api,
        dns: dns_config,
        derp: None,
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

    // 提取传输层配置（所有协议通用）
    let network = value
        .get("network")
        .and_then(|v| v.as_str())
        .unwrap_or("tcp");
    let transport = if network != "tcp" {
        let mut path = None;
        let mut host = None;
        let mut service_name = None;
        let mut headers = None;
        match network {
            "ws" | "httpupgrade" => {
                if let Some(opts) = value.get("ws-opts").or(value.get("ws-opt")) {
                    path = opts.get("path").and_then(|v| v.as_str()).map(String::from);
                    if let Some(h) = opts.get("headers").and_then(|v| v.as_object()) {
                        let mut hm = HashMap::new();
                        for (k, v) in h {
                            if let Some(s) = v.as_str() {
                                hm.insert(k.clone(), s.to_string());
                            }
                        }
                        host = hm.get("Host").cloned();
                        if !hm.is_empty() {
                            headers = Some(hm);
                        }
                    }
                }
            }
            "grpc" => {
                if let Some(opts) = value.get("grpc-opts").or(value.get("grpc-opt")) {
                    service_name = opts
                        .get("grpc-service-name")
                        .and_then(|v| v.as_str())
                        .map(String::from);
                }
            }
            "h2" => {
                if let Some(opts) = value.get("h2-opts").or(value.get("h2-opt")) {
                    path = opts.get("path").and_then(|v| v.as_str()).map(String::from);
                    host = opts
                        .get("host")
                        .and_then(|v| v.as_array())
                        .and_then(|a| a.first())
                        .and_then(|v| v.as_str())
                        .map(String::from);
                }
            }
            "http" => {
                if let Some(opts) = value.get("http-opts") {
                    path = opts
                        .get("path")
                        .and_then(|v| v.as_array())
                        .and_then(|a| a.first())
                        .and_then(|v| v.as_str())
                        .map(String::from);
                }
            }
            _ => {}
        }
        Some(TransportConfig {
            transport_type: network.to_string(),
            path,
            host,
            service_name,
            headers,
            ..Default::default()
        })
    } else {
        None
    };

    // 提取 TLS 配置
    let tls_bool = value.get("tls").and_then(|v| v.as_bool()).unwrap_or(false);
    let skip_cert = value
        .get("skip-cert-verify")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let fp = value
        .get("client-fingerprint")
        .and_then(|v| v.as_str())
        .map(String::from);
    let alpn_vec = value.get("alpn").and_then(|v| v.as_array()).map(|a| {
        a.iter()
            .filter_map(|v| v.as_str().map(String::from))
            .collect::<Vec<_>>()
    });

    let (protocol, mut settings) = match proxy_type {
        "ss" | "shadowsocks" => {
            let method = value
                .get("cipher")
                .and_then(|v| v.as_str())
                .map(String::from);
            let password = value
                .get("password")
                .and_then(|v| v.as_str())
                .map(String::from);
            let plugin = value
                .get("plugin")
                .and_then(|v| v.as_str())
                .map(String::from);
            let plugin_opts = value
                .get("plugin-opts")
                .or(value.get("plugin_opts"))
                .and_then(|v| v.as_str())
                .map(String::from);
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
            let uuid = value.get("uuid").and_then(|v| v.as_str()).map(String::from);
            let sni = value
                .get("servername")
                .or(value.get("sni"))
                .and_then(|v| v.as_str())
                .map(String::from);
            let flow = value.get("flow").and_then(|v| v.as_str()).map(String::from);
            let reality_opts = value.get("reality-opts");
            let (public_key, short_id, security) = if let Some(ro) = reality_opts {
                (
                    ro.get("public-key")
                        .and_then(|v| v.as_str())
                        .map(String::from),
                    ro.get("short-id")
                        .and_then(|v| v.as_str())
                        .map(String::from),
                    Some("reality".to_string()),
                )
            } else {
                (None, None, Some("tls".to_string()))
            };
            (
                "vless".to_string(),
                OutboundSettings {
                    address: server,
                    port,
                    uuid,
                    sni,
                    flow,
                    security,
                    public_key,
                    short_id,
                    ..Default::default()
                },
            )
        }
        "vmess" => {
            let uuid = value.get("uuid").and_then(|v| v.as_str()).map(String::from);
            let sni = value
                .get("servername")
                .or(value.get("sni"))
                .and_then(|v| v.as_str())
                .map(String::from);
            let method = value
                .get("cipher")
                .or(value.get("security"))
                .and_then(|v| v.as_str())
                .map(String::from);
            let alter_id = value
                .get("alterId")
                .and_then(|v| v.as_u64())
                .map(|v| v as u16);
            let tls_enabled = value.get("tls").and_then(|v| v.as_bool()).unwrap_or(false);
            (
                "vmess".to_string(),
                OutboundSettings {
                    address: server,
                    port,
                    uuid,
                    method,
                    sni,
                    alter_id,
                    security: Some(if tls_enabled { "tls" } else { "none" }.to_string()),
                    ..Default::default()
                },
            )
        }
        "trojan" => {
            let password = value
                .get("password")
                .and_then(|v| v.as_str())
                .map(String::from);
            let sni = value.get("sni").and_then(|v| v.as_str()).map(String::from);
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
                .map(String::from);
            let sni = value.get("sni").and_then(|v| v.as_str()).map(String::from);
            let up_mbps = value.get("up").and_then(|v| v.as_u64());
            let down_mbps = value.get("down").and_then(|v| v.as_u64());
            (
                "hysteria2".to_string(),
                OutboundSettings {
                    address: server,
                    port,
                    password,
                    sni,
                    up_mbps,
                    down_mbps,
                    ..Default::default()
                },
            )
        }
        "hysteria" => {
            let password = value
                .get("auth-str")
                .or(value.get("auth_str"))
                .and_then(|v| v.as_str())
                .map(String::from);
            let sni = value.get("sni").and_then(|v| v.as_str()).map(String::from);
            let up_mbps = value.get("up").and_then(|v| v.as_u64());
            let down_mbps = value.get("down").and_then(|v| v.as_u64());
            let obfs = value.get("obfs").and_then(|v| v.as_str()).map(String::from);
            (
                "hysteria".to_string(),
                OutboundSettings {
                    address: server,
                    port,
                    password,
                    sni,
                    up_mbps,
                    down_mbps,
                    obfs,
                    ..Default::default()
                },
            )
        }
        "tuic" => {
            let uuid = value.get("uuid").and_then(|v| v.as_str()).map(String::from);
            let password = value
                .get("password")
                .and_then(|v| v.as_str())
                .map(String::from);
            let sni = value.get("sni").and_then(|v| v.as_str()).map(String::from);
            let congestion_control = value
                .get("congestion-controller")
                .and_then(|v| v.as_str())
                .map(String::from);
            (
                "tuic".to_string(),
                OutboundSettings {
                    address: server,
                    port,
                    uuid,
                    password,
                    sni,
                    congestion_control,
                    ..Default::default()
                },
            )
        }
        "wireguard" | "wg" => {
            let private_key = value
                .get("private-key")
                .and_then(|v| v.as_str())
                .map(String::from);
            let peer_public_key = value
                .get("public-key")
                .and_then(|v| v.as_str())
                .map(String::from);
            let preshared_key = value
                .get("pre-shared-key")
                .and_then(|v| v.as_str())
                .map(String::from);
            let local_address = value.get("ip").and_then(|v| v.as_str()).map(String::from);
            let mtu = value.get("mtu").and_then(|v| v.as_u64()).map(|v| v as u16);
            (
                "wireguard".to_string(),
                OutboundSettings {
                    address: server,
                    port,
                    private_key,
                    peer_public_key,
                    preshared_key,
                    local_address,
                    mtu,
                    ..Default::default()
                },
            )
        }
        "ssh" => {
            let username = value
                .get("username")
                .and_then(|v| v.as_str())
                .map(String::from);
            let password = value
                .get("password")
                .and_then(|v| v.as_str())
                .map(String::from);
            (
                "ssh".to_string(),
                OutboundSettings {
                    address: server,
                    port,
                    username,
                    password,
                    ..Default::default()
                },
            )
        }
        "direct" => ("direct".to_string(), OutboundSettings::default()),
        other => anyhow::bail!("unsupported clash proxy type: {}", other),
    };

    // 注入传输层
    settings.transport = transport;

    // 注入 TLS（对需要 TLS 的协议或显式开启 TLS 时）
    let needs_tls = tls_bool
        || matches!(protocol.as_str(), "vless" | "trojan" | "tuic")
        || settings.security.as_deref() == Some("tls")
        || settings.security.as_deref() == Some("reality");
    if needs_tls {
        settings.tls = Some(TlsConfig {
            enabled: true,
            security: settings
                .security
                .clone()
                .unwrap_or_else(|| "tls".to_string()),
            sni: settings.sni.clone(),
            allow_insecure: skip_cert,
            fingerprint: fp,
            alpn: alpn_vec,
            public_key: settings.public_key.clone(),
            short_id: settings.short_id.clone(),
            ..Default::default()
        });
    }

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
        "select" | "selector" => "selector",
        "url-test" => "url-test",
        "fallback" => "fallback",
        "load-balance" => "load-balance",
        "relay" => "relay",
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
            "PROCESS-NAME" => "process-name",
            "PROCESS-PATH" => "process-path",
            _ => continue,
        };

        rule_configs.push(RuleConfig {
            rule_type: mapped_type.to_string(),
            values: vec![value],
            outbound,
            ..Default::default()
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

/// 将 Clash DNS 配置 JSON 转换为 DnsConfig
fn convert_clash_dns(dns_val: &serde_json::Value) -> Option<DnsConfig> {
    if !dns_val
        .get("enable")
        .and_then(|v| v.as_bool())
        .unwrap_or(true)
    {
        return None;
    }

    let parse_servers = |key: &str| -> Vec<DnsServerConfig> {
        dns_val
            .get(key)
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|item| {
                        if let Some(s) = item.as_str() {
                            Some(DnsServerConfig {
                                address: s.to_string(),
                                domains: vec![],
                            })
                        } else if let Some(obj) = item.as_object() {
                            // 高级格式: { "address": "...", "domains": [...] }
                            let address = obj
                                .get("address")
                                .or(obj.get("addr"))
                                .and_then(|v| v.as_str())?
                                .to_string();
                            let domains = obj
                                .get("domains")
                                .and_then(|v| v.as_array())
                                .map(|a| {
                                    a.iter()
                                        .filter_map(|d| d.as_str().map(String::from))
                                        .collect()
                                })
                                .unwrap_or_default();
                            Some(DnsServerConfig { address, domains })
                        } else {
                            None
                        }
                    })
                    .collect()
            })
            .unwrap_or_default()
    };

    let servers = parse_servers("nameserver");
    let fallback = parse_servers("fallback");

    // nameserver-policy: { "+.cn": "114.114.114.114" } → 转为带 domains 的 server
    let mut policy_servers: Vec<DnsServerConfig> = Vec::new();
    if let Some(policy) = dns_val.get("nameserver-policy").and_then(|v| v.as_object()) {
        for (domain_pattern, server_val) in policy {
            if let Some(addr) = server_val.as_str() {
                policy_servers.push(DnsServerConfig {
                    address: addr.to_string(),
                    domains: vec![domain_pattern.clone()],
                });
            }
        }
    }

    let mut all_servers = servers;
    all_servers.extend(policy_servers);

    // fake-ip
    let fake_ip = dns_val
        .get("enhanced-mode")
        .and_then(|v| v.as_str())
        .filter(|m| *m == "fake-ip")
        .map(|_| {
            let range = dns_val
                .get("fake-ip-range")
                .and_then(|v| v.as_str())
                .unwrap_or("198.18.0.1/16")
                .to_string();
            let exclude = dns_val
                .get("fake-ip-filter")
                .and_then(|v| v.as_array())
                .map(|a| {
                    a.iter()
                        .filter_map(|d| d.as_str().map(String::from))
                        .collect()
                })
                .unwrap_or_default();
            FakeIpConfig {
                ipv4_range: range,
                ipv6_range: None,
                exclude,
            }
        });

    // hosts
    let hosts = dns_val
        .get("hosts")
        .and_then(|v| v.as_object())
        .map(|obj| {
            obj.iter()
                .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
                .collect::<HashMap<String, String>>()
        })
        .unwrap_or_default();

    // fallback-filter
    let fallback_filter = dns_val.get("fallback-filter").and_then(|ff| {
        let ip_cidr: Vec<String> = ff
            .get("ipcidr")
            .and_then(|v| v.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|s| s.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();
        let domain: Vec<String> = ff
            .get("domain")
            .and_then(|v| v.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|s| s.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();
        if ip_cidr.is_empty() && domain.is_empty() {
            None
        } else {
            Some(FallbackFilterConfig { ip_cidr, domain })
        }
    });

    // 模式
    let mode = match dns_val.get("enhanced-mode").and_then(|v| v.as_str()) {
        Some("fake-ip") => "split".to_string(), // fake-ip 模式使用 split
        _ => {
            if !fallback.is_empty() {
                "fallback".to_string()
            } else {
                "split".to_string()
            }
        }
    };

    Some(DnsConfig {
        servers: all_servers,
        cache_size: 4096,
        cache_ttl: 600,
        negative_cache_ttl: 30,
        hosts,
        fake_ip,
        mode,
        fallback,
        fallback_filter,
        edns_client_subnet: None,
        prefer_ip: dns_val.get("prefer-h3").and_then(|_| None), // Clash 无此字段
    })
}

/// 将 Clash rule-provider 转换为 RuleProviderConfig
fn convert_clash_rule_provider(rp: &serde_json::Value) -> Option<RuleProviderConfig> {
    let provider_type = rp
        .get("type")
        .and_then(|v| v.as_str())
        .unwrap_or("http")
        .to_string();
    let behavior = rp
        .get("behavior")
        .and_then(|v| v.as_str())
        .unwrap_or("domain")
        .to_string();
    let path = rp
        .get("path")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let url = rp.get("url").and_then(|v| v.as_str()).map(String::from);
    let interval = rp.get("interval").and_then(|v| v.as_u64()).unwrap_or(86400);

    Some(RuleProviderConfig {
        provider_type,
        behavior,
        path,
        url,
        interval,
        lazy: false,
    })
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
    fn parse_clash_proxy_groups_selector_alias() {
        let yaml = r#"
mixed-port: 7890
proxies:
  - name: ss1
    type: ss
    server: 1.2.3.4
    port: 443
    cipher: aes-256-gcm
    password: "p"
proxy-groups:
  - name: main
    type: selector
    proxies: [ss1]
rules:
  - MATCH,main
"#;
        let result = parse_clash_config(yaml).unwrap();
        assert_eq!(result.config.proxy_groups.len(), 1);
        assert_eq!(result.config.proxy_groups[0].group_type, "selector");
        assert_eq!(result.config.router.default, "main");
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
    type: someunknownproto
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

    #[test]
    fn parse_clash_vmess_ws_transport() {
        let yaml = r#"
mixed-port: 7890
proxies:
  - name: vmess-ws
    type: vmess
    server: 1.2.3.4
    port: 443
    uuid: "550e8400-e29b-41d4-a716-446655440000"
    cipher: auto
    tls: true
    servername: "cdn.example.com"
    network: ws
    ws-opts:
      path: /ws-path
      headers:
        Host: cdn.example.com
rules:
  - MATCH,vmess-ws
"#;
        let result = parse_clash_config(yaml).unwrap();
        let vmess = result
            .config
            .outbounds
            .iter()
            .find(|o| o.tag == "vmess-ws")
            .unwrap();
        assert_eq!(vmess.protocol, "vmess");
        let transport = vmess.settings.transport.as_ref().unwrap();
        assert_eq!(transport.transport_type, "ws");
        assert_eq!(transport.path.as_deref(), Some("/ws-path"));
        assert_eq!(transport.host.as_deref(), Some("cdn.example.com"));
        let tls = vmess.settings.tls.as_ref().unwrap();
        assert!(tls.enabled);
        assert_eq!(tls.sni.as_deref(), Some("cdn.example.com"));
    }

    #[test]
    fn parse_clash_trojan_grpc_transport() {
        let yaml = r#"
mixed-port: 7890
proxies:
  - name: trojan-grpc
    type: trojan
    server: 1.2.3.4
    port: 443
    password: "testpass"
    network: grpc
    grpc-opts:
      grpc-service-name: my-service
    sni: "example.com"
rules:
  - MATCH,trojan-grpc
"#;
        let result = parse_clash_config(yaml).unwrap();
        let trojan = result
            .config
            .outbounds
            .iter()
            .find(|o| o.tag == "trojan-grpc")
            .unwrap();
        assert_eq!(trojan.protocol, "trojan");
        let transport = trojan.settings.transport.as_ref().unwrap();
        assert_eq!(transport.transport_type, "grpc");
        assert_eq!(transport.service_name.as_deref(), Some("my-service"));
    }

    #[test]
    fn parse_clash_wireguard() {
        let yaml = r#"
mixed-port: 7890
proxies:
  - name: wg-node
    type: wireguard
    server: 162.159.192.1
    port: 2408
    private-key: "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk="
    public-key: "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo="
    ip: "172.16.0.2/32"
    mtu: 1280
rules:
  - MATCH,wg-node
"#;
        let result = parse_clash_config(yaml).unwrap();
        let wg = result
            .config
            .outbounds
            .iter()
            .find(|o| o.tag == "wg-node")
            .unwrap();
        assert_eq!(wg.protocol, "wireguard");
        assert_eq!(
            wg.settings.private_key.as_deref(),
            Some("yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=")
        );
        assert_eq!(
            wg.settings.peer_public_key.as_deref(),
            Some("bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=")
        );
        assert_eq!(wg.settings.local_address.as_deref(), Some("172.16.0.2/32"));
        assert_eq!(wg.settings.mtu, Some(1280));
    }

    #[test]
    fn parse_clash_dns_full() {
        let yaml = r#"
mixed-port: 7890
proxies: []
rules:
  - MATCH,direct
dns:
  enable: true
  enhanced-mode: fake-ip
  fake-ip-range: 198.18.0.1/16
  fake-ip-filter:
    - "*.lan"
    - "localhost.ptlogin2.qq.com"
  nameserver:
    - 223.5.5.5
    - 114.114.114.114
  fallback:
    - tls://1.1.1.1:853
    - https://dns.google/dns-query
  fallback-filter:
    ipcidr:
      - 240.0.0.0/4
    domain:
      - "+.google.com"
  nameserver-policy:
    "+.cn": "114.114.114.114"
  hosts:
    "router.lan": "192.168.1.1"
"#;
        let result = parse_clash_config(yaml).unwrap();
        let dns = result.config.dns.unwrap();
        // nameserver + nameserver-policy
        assert!(dns.servers.len() >= 3);
        assert_eq!(dns.servers[0].address, "223.5.5.5");
        // fallback
        assert_eq!(dns.fallback.len(), 2);
        assert_eq!(dns.fallback[0].address, "tls://1.1.1.1:853");
        // fake-ip
        let fip = dns.fake_ip.unwrap();
        assert_eq!(fip.ipv4_range, "198.18.0.1/16");
        assert_eq!(fip.exclude.len(), 2);
        // hosts
        assert_eq!(dns.hosts.get("router.lan").unwrap(), "192.168.1.1");
        // fallback-filter
        let ff = dns.fallback_filter.unwrap();
        assert_eq!(ff.ip_cidr, vec!["240.0.0.0/4"]);
        assert_eq!(ff.domain, vec!["+.google.com"]);
    }

    #[test]
    fn parse_clash_dns_disabled() {
        let yaml = r#"
mixed-port: 7890
proxies: []
rules:
  - MATCH,direct
dns:
  enable: false
  nameserver:
    - 8.8.8.8
"#;
        let result = parse_clash_config(yaml).unwrap();
        assert!(result.config.dns.is_none());
    }

    #[test]
    fn parse_clash_rule_providers() {
        let yaml = r#"
mixed-port: 7890
proxies: []
rules:
  - RULE-SET,my-provider,direct
rule-providers:
  my-provider:
    type: http
    behavior: domain
    url: "https://example.com/rules.yaml"
    path: "./rules/my-provider.yaml"
    interval: 86400
"#;
        let result = parse_clash_config(yaml).unwrap();
        let rp = result
            .config
            .router
            .rule_providers
            .get("my-provider")
            .unwrap();
        assert_eq!(rp.provider_type, "http");
        assert_eq!(rp.behavior, "domain");
        assert_eq!(rp.url.as_deref(), Some("https://example.com/rules.yaml"));
        assert_eq!(rp.interval, 86400);
        // 规则中引用了
        let rule = result
            .config
            .router
            .rules
            .iter()
            .find(|r| r.rule_type == "rule-set")
            .unwrap();
        assert_eq!(rule.values, vec!["my-provider"]);
    }

    #[test]
    fn parse_clash_process_name_rule() {
        let yaml = r#"
mixed-port: 7890
proxies: []
rules:
  - PROCESS-NAME,chrome.exe,direct
  - PROCESS-PATH,/usr/bin/curl,direct
  - MATCH,direct
"#;
        let result = parse_clash_config(yaml).unwrap();
        let proc_rule = result
            .config
            .router
            .rules
            .iter()
            .find(|r| r.rule_type == "process-name")
            .unwrap();
        assert_eq!(proc_rule.values, vec!["chrome.exe"]);
        let path_rule = result
            .config
            .router
            .rules
            .iter()
            .find(|r| r.rule_type == "process-path")
            .unwrap();
        assert_eq!(path_rule.values, vec!["/usr/bin/curl"]);
    }

    #[test]
    fn parse_clash_relay_group() {
        let yaml = r#"
mixed-port: 7890
proxies:
  - name: node-a
    type: ss
    server: 1.2.3.4
    port: 8388
    cipher: aes-256-gcm
    password: pass
  - name: node-b
    type: ss
    server: 5.6.7.8
    port: 8389
    cipher: aes-256-gcm
    password: pass2
proxy-groups:
  - name: relay-chain
    type: relay
    proxies:
      - node-a
      - node-b
rules:
  - MATCH,relay-chain
"#;
        let result = parse_clash_config(yaml).unwrap();
        let relay = result
            .config
            .proxy_groups
            .iter()
            .find(|g| g.name == "relay-chain")
            .unwrap();
        assert_eq!(relay.group_type, "relay");
        assert_eq!(relay.proxies, vec!["node-a", "node-b"]);
    }
}
