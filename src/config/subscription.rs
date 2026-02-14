//! 订阅链接解析器
//!
//! 支持以下订阅格式：
//! - **ZenOne**: `zen-version:` 开头的 YAML/JSON（自研格式）
//! - **URI 列表** (Base64 编码): `vmess://`, `vless://`, `ss://`, `trojan://`, `hy2://`, `hysteria2://`
//! - **Clash / mihomo YAML** : `proxies:` 列表
//! - **sing-box JSON**: `outbounds:` 列表（转换为 OutboundConfig）
//! - **SIP008 JSON**: Shadowsocks 标准订阅格式

use anyhow::Result;
use base64::Engine;
use tracing::debug;

use crate::config::types::{OutboundConfig, OutboundSettings, TlsConfig, TransportConfig};
use crate::config::zenone::parser::is_zenone;
use crate::config::zenone::bridge::zenone_to_outbounds;

// ─── 公共接口 ───

/// 自动检测格式并解析订阅内容
pub fn parse_subscription(content: &str) -> Result<Vec<OutboundConfig>> {
    let content = content.trim();

    // 1. 尝试 ZenOne 格式（自研格式，优先级最高）
    if is_zenone(content) {
        if let Ok(configs) = parse_zenone_subscription(content) {
            if !configs.is_empty() {
                debug!(count = configs.len(), "parsed as ZenOne format");
                return Ok(configs);
            }
        }
    }

    // 2. 尝试 JSON
    if content.starts_with('{') || content.starts_with('[') {
        if let Ok(configs) = parse_sip008_json(content) {
            if !configs.is_empty() {
                debug!(count = configs.len(), "parsed as SIP008 JSON");
                return Ok(configs);
            }
        }
        if let Ok(configs) = parse_singbox_json(content) {
            debug!(count = configs.len(), "parsed as sing-box JSON");
            return Ok(configs);
        }
    }

    // 2. 尝试 YAML (以 proxies: 或 --- 开头)
    if content.contains("proxies:") || content.starts_with("---") {
        if let Ok(configs) = parse_clash_yaml(content) {
            debug!(count = configs.len(), "parsed as Clash YAML");
            return Ok(configs);
        }
    }

    // 3. 尝试 Base64 解码后的 URI 列表
    if let Ok(decoded) = decode_base64_content(content) {
        if let Ok(configs) = parse_uri_list(&decoded) {
            if !configs.is_empty() {
                debug!(count = configs.len(), "parsed as Base64 URI list");
                return Ok(configs);
            }
        }
    }

    // 4. 直接当作 URI 列表
    if content.contains("://") {
        if let Ok(configs) = parse_uri_list(content) {
            debug!(count = configs.len(), "parsed as plain URI list");
            return Ok(configs);
        }
    }

    anyhow::bail!("unable to detect subscription format")
}

/// 从 URL 异步获取并解析订阅
pub async fn fetch_subscription(url: &str) -> Result<Vec<OutboundConfig>> {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .user_agent("OpenWorld/1.0")
        .build()?;

    let resp = client.get(url).send().await?;
    let text = resp.text().await?;
    parse_subscription(&text)
}

// ─── Base64 解码 ───

fn decode_base64_content(content: &str) -> Result<String> {
    let clean: String = content.chars().filter(|c| !c.is_whitespace()).collect();
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(&clean)
        .or_else(|_| base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(&clean))
        .or_else(|_| base64::engine::general_purpose::STANDARD_NO_PAD.decode(&clean))?;
    Ok(String::from_utf8(bytes)?)
}

// ─── URI 列表 ───

fn parse_uri_list(content: &str) -> Result<Vec<OutboundConfig>> {
    let mut configs = Vec::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Ok(config) = parse_proxy_uri(line) {
            configs.push(config);
        }
    }
    if configs.is_empty() {
        anyhow::bail!("no valid proxy URIs found");
    }
    Ok(configs)
}

/// 解析单个代理 URI
pub fn parse_proxy_uri(uri: &str) -> Result<OutboundConfig> {
    let uri = uri.trim();
    if let Some(rest) = uri.strip_prefix("vmess://") {
        parse_vmess_uri(rest)
    } else if let Some(rest) = uri.strip_prefix("vless://") {
        parse_vless_uri(rest)
    } else if let Some(rest) = uri.strip_prefix("ss://") {
        parse_ss_uri(rest)
    } else if let Some(rest) = uri.strip_prefix("trojan://") {
        parse_trojan_uri(rest)
    } else if let Some(rest) = uri
        .strip_prefix("hysteria2://")
        .or_else(|| uri.strip_prefix("hy2://"))
    {
        parse_hy2_uri(rest)
    } else if let Some(rest) = uri.strip_prefix("tuic://") {
        parse_tuic_uri(rest)
    } else if let Some(rest) = uri
        .strip_prefix("wg://")
        .or_else(|| uri.strip_prefix("wireguard://"))
    {
        parse_wg_uri(rest)
    } else if let Some(rest) = uri.strip_prefix("ssh://") {
        parse_ssh_uri(rest)
    } else if let Some(rest) = uri.strip_prefix("hysteria://") {
        parse_hy1_uri(rest)
    } else {
        anyhow::bail!(
            "unsupported proxy URI scheme: {}",
            uri.split("://").next().unwrap_or("?")
        )
    }
}

// ─── VMess URI ───

fn parse_vmess_uri(encoded: &str) -> Result<OutboundConfig> {
    let json_bytes = base64::engine::general_purpose::STANDARD
        .decode(encoded.trim())
        .or_else(|_| base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(encoded.trim()))?;
    let json_str = String::from_utf8(json_bytes)?;
    let v: serde_json::Value = serde_json::from_str(&json_str)?;

    let tag = v["ps"].as_str().unwrap_or("vmess").to_string();
    let address = v["add"].as_str().unwrap_or("").to_string();
    let port = v["port"]
        .as_u64()
        .or_else(|| v["port"].as_str().and_then(|s| s.parse().ok()))
        .unwrap_or(443) as u16;
    let uuid = v["id"].as_str().unwrap_or("").to_string();
    let alter_id = v["aid"]
        .as_u64()
        .or_else(|| v["aid"].as_str().and_then(|s| s.parse().ok()))
        .unwrap_or(0) as u16;
    let sni = v["sni"]
        .as_str()
        .or_else(|| v["host"].as_str())
        .map(String::from);
    let security = if v["tls"].as_str() == Some("tls") {
        Some("tls".to_string())
    } else {
        None
    };

    // 传输层: net/path/host
    let net = v["net"].as_str().unwrap_or("tcp");
    let transport = if net != "tcp" {
        let ws_path = v["path"].as_str().map(String::from);
        let ws_host = v["host"].as_str().map(String::from);
        Some(TransportConfig {
            transport_type: net.to_string(),
            path: ws_path,
            host: ws_host,
            service_name: if net == "grpc" {
                v["path"].as_str().map(String::from)
            } else {
                None
            },
            ..Default::default()
        })
    } else {
        None
    };

    let tls = if security.as_deref() == Some("tls") {
        Some(TlsConfig {
            enabled: true,
            security: "tls".to_string(),
            sni: sni.clone(),
            ..Default::default()
        })
    } else {
        None
    };

    Ok(OutboundConfig {
        tag,
        protocol: "vmess".to_string(),
        settings: OutboundSettings {
            address: Some(address),
            port: Some(port),
            uuid: Some(uuid),
            alter_id: Some(alter_id),
            sni,
            security,
            transport,
            tls,
            ..Default::default()
        },
    })
}

// ─── VLESS URI ───

fn parse_vless_uri(rest: &str) -> Result<OutboundConfig> {
    // vless://uuid@host:port?params#tag
    let (main, tag) = rest.rsplit_once('#').unwrap_or((rest, "vless"));
    let tag = url_decode(tag).unwrap_or_else(|_| tag.into()).to_string();

    let (userinfo, host_params) = main
        .split_once('@')
        .ok_or_else(|| anyhow::anyhow!("vless: missing @"))?;
    let uuid = userinfo.to_string();

    let (host_port, params_str) = host_params.split_once('?').unwrap_or((host_params, ""));
    let (host, port_str) = parse_host_port(host_port)?;
    let port: u16 = port_str.parse()?;

    let params = parse_query_params(params_str);

    let security = params.get("security").cloned();
    let sni = params.get("sni").cloned();
    let flow = params.get("flow").cloned();
    let fingerprint = params.get("fp").cloned();
    let public_key = params.get("pbk").cloned();
    let short_id = params.get("sid").cloned();
    let server_name = params.get("serverName").or(params.get("sni")).cloned();

    let transport = extract_transport_from_params(&params);
    let tls = extract_tls_from_params(&params, sni.clone());

    Ok(OutboundConfig {
        tag,
        protocol: "vless".to_string(),
        settings: OutboundSettings {
            address: Some(host),
            port: Some(port),
            uuid: Some(uuid),
            sni,
            security,
            flow,
            fingerprint,
            public_key,
            short_id,
            server_name,
            transport,
            tls,
            ..Default::default()
        },
    })
}

// ─── SS URI ───

fn parse_ss_uri(rest: &str) -> Result<OutboundConfig> {
    let (main, tag) = rest.rsplit_once('#').unwrap_or((rest, "ss"));
    let tag = url_decode(tag).unwrap_or_else(|_| tag.into()).to_string();

    if main.contains('@') {
        // SIP002 format: base64(method:password)@host:port
        let (encoded_part, host_part) = main.split_once('@').unwrap();
        let decoded =
            decode_base64_content(encoded_part).unwrap_or_else(|_| encoded_part.to_string());

        let (method, password) = decoded
            .split_once(':')
            .ok_or_else(|| anyhow::anyhow!("ss: invalid method:password"))?;

        let (host, port_str) = parse_host_port(host_part)?;
        let port: u16 = port_str.parse()?;

        Ok(OutboundConfig {
            tag,
            protocol: "shadowsocks".to_string(),
            settings: OutboundSettings {
                address: Some(host),
                port: Some(port),
                method: Some(method.to_string()),
                password: Some(password.to_string()),
                ..Default::default()
            },
        })
    } else {
        // Legacy: base64(method:password@host:port)
        let decoded = decode_base64_content(main)?;
        let (method_pass, host_port) = decoded
            .rsplit_once('@')
            .ok_or_else(|| anyhow::anyhow!("ss: invalid format"))?;
        let (method, password) = method_pass
            .split_once(':')
            .ok_or_else(|| anyhow::anyhow!("ss: invalid method:password"))?;
        let (host, port_str) = parse_host_port(host_port)?;
        let port: u16 = port_str.parse()?;

        Ok(OutboundConfig {
            tag,
            protocol: "shadowsocks".to_string(),
            settings: OutboundSettings {
                address: Some(host),
                port: Some(port),
                method: Some(method.to_string()),
                password: Some(password.to_string()),
                ..Default::default()
            },
        })
    }
}

// ─── Trojan URI ───

fn parse_trojan_uri(rest: &str) -> Result<OutboundConfig> {
    let (main, tag) = rest.rsplit_once('#').unwrap_or((rest, "trojan"));
    let tag = url_decode(tag).unwrap_or_else(|_| tag.into()).to_string();

    let (password, host_params) = main
        .split_once('@')
        .ok_or_else(|| anyhow::anyhow!("trojan: missing @"))?;
    let password = url_decode(password)
        .unwrap_or_else(|_| password.into())
        .to_string();

    let (host_port, params_str) = host_params.split_once('?').unwrap_or((host_params, ""));
    let (host, port_str) = parse_host_port(host_port)?;
    let port: u16 = port_str.parse()?;

    let params = parse_query_params(params_str);
    let sni = params.get("sni").cloned().or_else(|| Some(host.clone()));
    let transport = extract_transport_from_params(&params);
    let tls = extract_tls_from_params(&params, sni.clone());

    Ok(OutboundConfig {
        tag,
        protocol: "trojan".to_string(),
        settings: OutboundSettings {
            address: Some(host),
            port: Some(port),
            password: Some(password),
            sni,
            security: Some("tls".to_string()),
            transport,
            tls,
            ..Default::default()
        },
    })
}

// ─── Hysteria2 URI ───

fn parse_hy2_uri(rest: &str) -> Result<OutboundConfig> {
    let (main, tag) = rest.rsplit_once('#').unwrap_or((rest, "hy2"));
    let tag = url_decode(tag).unwrap_or_else(|_| tag.into()).to_string();

    let (password, host_params) = main
        .split_once('@')
        .ok_or_else(|| anyhow::anyhow!("hy2: missing @"))?;
    let (host_port, params_str) = host_params.split_once('?').unwrap_or((host_params, ""));
    let (host, port_str) = parse_host_port(host_port)?;
    let port: u16 = port_str.parse()?;

    let params = parse_query_params(params_str);
    let sni = params.get("sni").cloned();
    let insecure = params.get("insecure").map(|v| v == "1").unwrap_or(false);

    Ok(OutboundConfig {
        tag,
        protocol: "hysteria2".to_string(),
        settings: OutboundSettings {
            address: Some(host),
            port: Some(port),
            password: Some(password.to_string()),
            sni,
            allow_insecure: insecure,
            ..Default::default()
        },
    })
}

// ─── TUIC URI ───

fn parse_tuic_uri(rest: &str) -> Result<OutboundConfig> {
    // tuic://uuid:password@host:port?congestion_control=bbr&alpn=h3#tag
    let (main, tag) = rest.rsplit_once('#').unwrap_or((rest, "tuic"));
    let tag = url_decode(tag).unwrap_or_else(|_| tag.into()).to_string();

    let (userinfo, host_params) = main
        .split_once('@')
        .ok_or_else(|| anyhow::anyhow!("tuic: missing @"))?;
    let (uuid, password) = userinfo
        .split_once(':')
        .ok_or_else(|| anyhow::anyhow!("tuic: missing password after uuid"))?;

    let (host_port, params_str) = host_params.split_once('?').unwrap_or((host_params, ""));
    let (host, port_str) = parse_host_port(host_port)?;
    let port: u16 = port_str.parse()?;

    let params = parse_query_params(params_str);
    let sni = params.get("sni").cloned();
    let congestion_control = params
        .get("congestion_control")
        .or(params.get("congestion-controller"))
        .cloned();
    let alpn = params
        .get("alpn")
        .map(|a| a.split(',').map(String::from).collect::<Vec<_>>());
    let allow_insecure = params
        .get("insecure")
        .or(params.get("allowInsecure"))
        .map(|v| v == "1" || v == "true")
        .unwrap_or(false);

    let tls = Some(TlsConfig {
        enabled: true,
        security: "tls".to_string(),
        sni: sni.clone(),
        alpn,
        allow_insecure,
        ..Default::default()
    });

    Ok(OutboundConfig {
        tag,
        protocol: "tuic".to_string(),
        settings: OutboundSettings {
            address: Some(host),
            port: Some(port),
            uuid: Some(uuid.to_string()),
            password: Some(password.to_string()),
            congestion_control,
            sni,
            security: Some("tls".to_string()),
            tls,
            ..Default::default()
        },
    })
}

// ─── WireGuard URI ───

fn parse_wg_uri(rest: &str) -> Result<OutboundConfig> {
    // wg://privkey@host:port?publickey=xxx&address=10.0.0.1/32&mtu=1280#tag
    let (main, tag) = rest.rsplit_once('#').unwrap_or((rest, "wireguard"));
    let tag = url_decode(tag).unwrap_or_else(|_| tag.into()).to_string();

    let (private_key, host_params) = main
        .split_once('@')
        .ok_or_else(|| anyhow::anyhow!("wg: missing @"))?;
    let private_key = url_decode(private_key)
        .unwrap_or_else(|_| private_key.into())
        .to_string();

    let (host_port, params_str) = host_params.split_once('?').unwrap_or((host_params, ""));
    let (host, port_str) = parse_host_port(host_port)?;
    let port: u16 = port_str.parse()?;

    let params = parse_query_params(params_str);
    let peer_public_key = params
        .get("publickey")
        .or(params.get("public-key"))
        .cloned();
    let preshared_key = params
        .get("presharedkey")
        .or(params.get("pre-shared-key"))
        .cloned();
    let local_address = params.get("address").or(params.get("ip")).cloned();
    let mtu = params.get("mtu").and_then(|v| v.parse().ok());
    let keepalive = params.get("keepalive").and_then(|v| v.parse().ok());

    Ok(OutboundConfig {
        tag,
        protocol: "wireguard".to_string(),
        settings: OutboundSettings {
            address: Some(host),
            port: Some(port),
            private_key: Some(private_key),
            peer_public_key,
            preshared_key,
            local_address,
            mtu,
            keepalive,
            ..Default::default()
        },
    })
}

// ─── SSH URI ───

fn parse_ssh_uri(rest: &str) -> Result<OutboundConfig> {
    // ssh://user:pass@host:port#tag
    let (main, tag) = rest.rsplit_once('#').unwrap_or((rest, "ssh"));
    let tag = url_decode(tag).unwrap_or_else(|_| tag.into()).to_string();

    let (userinfo, host_port) = main
        .split_once('@')
        .ok_or_else(|| anyhow::anyhow!("ssh: missing @"))?;
    let (username, password) = userinfo.split_once(':').unwrap_or((userinfo, ""));
    let username = url_decode(username)
        .unwrap_or_else(|_| username.into())
        .to_string();
    let password = url_decode(password)
        .unwrap_or_else(|_| password.into())
        .to_string();

    let (host, port_str) = parse_host_port(host_port)?;
    let port: u16 = port_str.parse()?;

    Ok(OutboundConfig {
        tag,
        protocol: "ssh".to_string(),
        settings: OutboundSettings {
            address: Some(host),
            port: Some(port),
            username: Some(username),
            password: if password.is_empty() {
                None
            } else {
                Some(password)
            },
            ..Default::default()
        },
    })
}

// ─── Hysteria v1 URI ───

fn parse_hy1_uri(rest: &str) -> Result<OutboundConfig> {
    // hysteria://host:port?auth=xxx&obfs=xplus&obfsParam=yyy&upmbps=100&downmbps=100&sni=xxx#tag
    let (main, tag) = rest.rsplit_once('#').unwrap_or((rest, "hysteria"));
    let tag = url_decode(tag).unwrap_or_else(|_| tag.into()).to_string();

    let (host_port, params_str) = main.split_once('?').unwrap_or((main, ""));
    let (host, port_str) = parse_host_port(host_port)?;
    let port: u16 = port_str.parse()?;

    let params = parse_query_params(params_str);
    let password = params.get("auth").or(params.get("auth_str")).cloned();
    let sni = params.get("sni").or(params.get("peer")).cloned();
    let obfs = params.get("obfs").cloned();
    let obfs_password = params
        .get("obfsParam")
        .or(params.get("obfs-password"))
        .cloned();
    let up_mbps = params
        .get("upmbps")
        .or(params.get("up"))
        .and_then(|v| v.parse().ok());
    let down_mbps = params
        .get("downmbps")
        .or(params.get("down"))
        .and_then(|v| v.parse().ok());
    let allow_insecure = params
        .get("insecure")
        .map(|v| v == "1" || v == "true")
        .unwrap_or(false);
    let alpn = params
        .get("alpn")
        .map(|a| a.split(',').map(String::from).collect::<Vec<_>>());

    let tls = Some(TlsConfig {
        enabled: true,
        security: "tls".to_string(),
        sni: sni.clone(),
        alpn,
        allow_insecure,
        ..Default::default()
    });

    Ok(OutboundConfig {
        tag,
        protocol: "hysteria".to_string(),
        settings: OutboundSettings {
            address: Some(host),
            port: Some(port),
            password,
            sni,
            obfs,
            obfs_password,
            up_mbps,
            down_mbps,
            tls,
            ..Default::default()
        },
    })
}

// ─── Clash YAML ───

fn parse_clash_yaml(content: &str) -> Result<Vec<OutboundConfig>> {
    let yaml: serde_yml::Value = serde_yml::from_str(content)?;
    let proxies = yaml["proxies"]
        .as_sequence()
        .ok_or_else(|| anyhow::anyhow!("clash YAML: missing proxies array"))?;

    let mut configs = Vec::new();
    for proxy in proxies {
        if let Some(config) = parse_clash_proxy(proxy) {
            configs.push(config);
        }
    }
    Ok(configs)
}

fn parse_clash_proxy(v: &serde_yml::Value) -> Option<OutboundConfig> {
    let name = v["name"].as_str()?.to_string();
    let proto = v["type"].as_str()?;
    let server = v["server"].as_str()?.to_string();
    let port = v["port"].as_u64()? as u16;

    let protocol = match proto {
        "vmess" => "vmess",
        "vless" => "vless",
        "ss" | "shadowsocks" => "shadowsocks",
        "trojan" => "trojan",
        "hysteria2" | "hy2" => "hysteria2",
        "hysteria" => "hysteria",
        "wireguard" | "wg" => "wireguard",
        "tuic" => "tuic",
        "ssh" => "ssh",
        _ => return None,
    };

    let uuid = v["uuid"].as_str().map(String::from);
    let password = v["password"].as_str().map(String::from);
    let method = v["cipher"]
        .as_str()
        .or(v["method"].as_str())
        .map(String::from);
    let sni = v["sni"]
        .as_str()
        .or(v["servername"].as_str())
        .map(String::from);
    let allow_insecure = v["skip-cert-verify"].as_bool().unwrap_or(false);
    let flow = v["flow"].as_str().map(String::from);
    let alter_id = v["alterId"].as_u64().map(|v| v as u16);
    let up_mbps = v["up"].as_u64().or(v["up_mbps"].as_u64());
    let down_mbps = v["down"].as_u64().or(v["down_mbps"].as_u64());

    // 传输层解析
    let network = v["network"].as_str().unwrap_or("tcp");
    let transport = if network != "tcp" {
        let mut path = None;
        let mut host = None;
        let mut service_name = None;
        match network {
            "ws" => {
                if let Some(opts) = v.get("ws-opts").or(v.get("ws-opt")) {
                    path = opts["path"].as_str().map(String::from);
                    host = opts["headers"]["Host"].as_str().map(String::from);
                }
            }
            "grpc" => {
                if let Some(opts) = v.get("grpc-opts").or(v.get("grpc-opt")) {
                    service_name = opts["grpc-service-name"].as_str().map(String::from);
                }
            }
            "h2" => {
                if let Some(opts) = v.get("h2-opts").or(v.get("h2-opt")) {
                    path = opts["path"].as_str().map(String::from);
                    host = opts["host"]
                        .as_sequence()
                        .and_then(|s| s.first())
                        .and_then(|v| v.as_str())
                        .map(String::from);
                }
            }
            "http" => {
                if let Some(opts) = v.get("http-opts") {
                    path = opts["path"]
                        .as_sequence()
                        .and_then(|s| s.first())
                        .and_then(|v| v.as_str())
                        .map(String::from);
                    host = opts["headers"]["Host"]
                        .as_sequence()
                        .and_then(|s| s.first())
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
            ..Default::default()
        })
    } else {
        None
    };

    // TLS 配置
    let tls_enabled =
        v["tls"].as_bool().unwrap_or(false) || protocol == "trojan" || protocol == "vless";
    let tls = if tls_enabled {
        Some(TlsConfig {
            enabled: true,
            security: "tls".to_string(),
            sni: sni.clone(),
            allow_insecure,
            fingerprint: v["client-fingerprint"].as_str().map(String::from),
            ..Default::default()
        })
    } else {
        None
    };

    // WireGuard 特殊字段
    let private_key = v["private-key"].as_str().map(String::from);
    let peer_public_key = v["public-key"].as_str().map(String::from);
    let local_address = v["ip"].as_str().map(String::from);
    let mtu = v["mtu"].as_u64().map(|v| v as u16);
    // TUIC 特殊字段
    let congestion_control = v["congestion-controller"].as_str().map(String::from);
    // SSH 特殊字段
    let username = v["username"].as_str().map(String::from);

    Some(OutboundConfig {
        tag: name,
        protocol: protocol.to_string(),
        settings: OutboundSettings {
            address: Some(server),
            port: Some(port),
            uuid,
            password,
            method,
            sni,
            allow_insecure,
            flow,
            alter_id,
            up_mbps,
            down_mbps,
            transport,
            tls,
            private_key,
            peer_public_key,
            local_address,
            mtu,
            congestion_control,
            username,
            ..Default::default()
        },
    })
}

// ─── sing-box JSON ───

fn parse_singbox_json(content: &str) -> Result<Vec<OutboundConfig>> {
    let v: serde_json::Value = serde_json::from_str(content)?;
    let outbounds = v["outbounds"]
        .as_array()
        .ok_or_else(|| anyhow::anyhow!("sing-box: missing outbounds"))?;

    let mut configs = Vec::new();
    for ob in outbounds {
        let ob_type = ob["type"].as_str().unwrap_or("");
        match ob_type {
            "direct" | "block" | "dns" | "selector" | "urltest" => continue,
            _ => {}
        }
        let tag = ob["tag"].as_str().unwrap_or("").to_string();
        let server = ob["server"].as_str().map(String::from);
        let server_port = ob["server_port"].as_u64().map(|p| p as u16);
        let uuid = ob["uuid"].as_str().map(String::from);
        let password = ob["password"].as_str().map(String::from);
        let method = ob["method"].as_str().map(String::from);
        let flow = ob["flow"].as_str().map(String::from);

        // TLS 配置
        let tls_obj = &ob["tls"];
        let sni = tls_obj["server_name"].as_str().map(String::from);
        let allow_insecure = tls_obj["insecure"].as_bool().unwrap_or(false);
        let tls_enabled = tls_obj["enabled"].as_bool().unwrap_or(false);
        let security = if tls_enabled {
            Some("tls".to_string())
        } else {
            None
        };
        let tls = if tls_enabled {
            let reality = &tls_obj["reality"];
            Some(TlsConfig {
                enabled: true,
                security: if reality["enabled"].as_bool().unwrap_or(false) {
                    "reality".to_string()
                } else {
                    "tls".to_string()
                },
                sni: sni.clone(),
                allow_insecure,
                fingerprint: tls_obj["utls"]["fingerprint"].as_str().map(String::from),
                alpn: tls_obj["alpn"].as_array().map(|a| {
                    a.iter()
                        .filter_map(|v| v.as_str().map(String::from))
                        .collect()
                }),
                public_key: reality["public_key"].as_str().map(String::from),
                short_id: reality["short_id"].as_str().map(String::from),
                ..Default::default()
            })
        } else {
            None
        };

        // 传输层配置
        let transport_obj = &ob["transport"];
        let transport = if transport_obj.is_object() {
            let t_type = transport_obj["type"].as_str().unwrap_or("tcp");
            if t_type != "tcp" {
                Some(TransportConfig {
                    transport_type: t_type.to_string(),
                    path: transport_obj["path"].as_str().map(String::from),
                    host: transport_obj["host"]
                        .as_str()
                        .or_else(|| transport_obj["headers"]["Host"].as_str())
                        .map(String::from),
                    service_name: transport_obj["service_name"].as_str().map(String::from),
                    ..Default::default()
                })
            } else {
                None
            }
        } else {
            None
        };

        let protocol = match ob_type {
            "vmess" => "vmess",
            "vless" => "vless",
            "trojan" => "trojan",
            "shadowsocks" | "ss" => "shadowsocks",
            "hysteria2" | "hy2" => "hysteria2",
            "wireguard" | "wg" => "wireguard",
            "tuic" => "tuic",
            "ssh" => "ssh",
            other => other,
        };

        configs.push(OutboundConfig {
            tag,
            protocol: protocol.to_string(),
            settings: OutboundSettings {
                address: server,
                port: server_port,
                uuid,
                password,
                method,
                sni,
                security,
                allow_insecure,
                flow,
                transport,
                tls,
                ..Default::default()
            },
        });
    }
    Ok(configs)
}

// ─── SIP008 JSON ───

fn parse_sip008_json(content: &str) -> Result<Vec<OutboundConfig>> {
    #[derive(serde::Deserialize)]
    struct Sip008 {
        servers: Vec<Sip008Server>,
    }
    #[derive(serde::Deserialize)]
    struct Sip008Server {
        server: String,
        server_port: u16,
        password: String,
        method: String,
        #[serde(default)]
        remarks: Option<String>,
    }

    let sip: Sip008 = serde_json::from_str(content)?;
    let configs = sip
        .servers
        .into_iter()
        .enumerate()
        .map(|(i, s)| OutboundConfig {
            tag: s.remarks.unwrap_or_else(|| format!("ss-{}", i)),
            protocol: "shadowsocks".to_string(),
            settings: OutboundSettings {
                address: Some(s.server),
                port: Some(s.server_port),
                password: Some(s.password),
                method: Some(s.method),
                ..Default::default()
            },
        })
        .collect();
    Ok(configs)
}

// ─── 传输层辅助函数 ───

/// 从 URI 查询参数提取传输层配置 (type/path/host/serviceName)
fn extract_transport_from_params(
    params: &std::collections::HashMap<String, String>,
) -> Option<TransportConfig> {
    let t = params.get("type").map(|s| s.as_str()).unwrap_or("tcp");
    if t == "tcp" || t == "none" || t.is_empty() {
        return None;
    }
    Some(TransportConfig {
        transport_type: t.to_string(),
        path: params.get("path").cloned(),
        host: params.get("host").cloned(),
        service_name: if t == "grpc" {
            params.get("serviceName").cloned()
        } else {
            None
        },
        ..Default::default()
    })
}

/// 从 URI 查询参数提取 TLS 配置 (security/sni/fp/pbk/sid/alpn)
fn extract_tls_from_params(
    params: &std::collections::HashMap<String, String>,
    sni: Option<String>,
) -> Option<TlsConfig> {
    let sec = params.get("security").map(|s| s.as_str()).unwrap_or("");
    if sec.is_empty() || sec == "none" {
        return None;
    }
    Some(TlsConfig {
        enabled: true,
        security: sec.to_string(),
        sni,
        fingerprint: params.get("fp").cloned(),
        public_key: params.get("pbk").cloned(),
        short_id: params.get("sid").cloned(),
        server_name: params.get("serverName").cloned(),
        ..Default::default()
    })
}

// ─── 辅助函数 ───

fn parse_host_port(s: &str) -> Result<(String, &str)> {
    if let Some(rest) = s.strip_prefix('[') {
        let (host, port_with_bracket) = rest
            .split_once(']')
            .ok_or_else(|| anyhow::anyhow!("invalid IPv6 address"))?;
        let port_str = port_with_bracket
            .strip_prefix(':')
            .ok_or_else(|| anyhow::anyhow!("missing port after IPv6"))?;
        Ok((host.to_string(), port_str))
    } else {
        let (host, port) = s
            .rsplit_once(':')
            .ok_or_else(|| anyhow::anyhow!("missing port in: {}", s))?;
        Ok((host.to_string(), port))
    }
}

/// Simple percent-decoding (URL decode)
fn url_decode(s: &str) -> Result<std::borrow::Cow<'_, str>> {
    if !s.contains('%') {
        return Ok(std::borrow::Cow::Borrowed(s));
    }
    let mut result = Vec::with_capacity(s.len());
    let mut chars = s.as_bytes().iter();
    while let Some(&b) = chars.next() {
        if b == b'%' {
            let hi = chars
                .next()
                .ok_or_else(|| anyhow::anyhow!("incomplete percent encoding"))?;
            let lo = chars
                .next()
                .ok_or_else(|| anyhow::anyhow!("incomplete percent encoding"))?;
            let byte = u8::from_str_radix(&format!("{}{}", *hi as char, *lo as char), 16)
                .map_err(|_| anyhow::anyhow!("invalid percent encoding"))?;
            result.push(byte);
        } else if b == b'+' {
            result.push(b' ');
        } else {
            result.push(b);
        }
    }
    Ok(std::borrow::Cow::Owned(String::from_utf8(result)?))
}

fn parse_query_params(s: &str) -> std::collections::HashMap<String, String> {
    let mut map = std::collections::HashMap::new();
    if s.is_empty() {
        return map;
    }
    for pair in s.split('&') {
        if let Some((k, v)) = pair.split_once('=') {
            let k = url_decode(k).unwrap_or_else(|_| k.into()).to_string();
            let v = url_decode(v).unwrap_or_else(|_| v.into()).to_string();
            map.insert(k, v);
        }
    }
    map
}

// ─── ZenOne 格式解析 ───

/// 解析 ZenOne 订阅内容为 OutboundConfig 列表
fn parse_zenone_subscription(content: &str) -> Result<Vec<OutboundConfig>> {
    use crate::config::zenone::parser::parse_and_validate;

    let (doc, diags) = parse_and_validate(content, None)?;

    if diags.has_errors() {
        anyhow::bail!("ZenOne 解析错误: {:?}", diags.errors());
    }

    let outbounds = zenone_to_outbounds(&doc, &mut Diagnostics::new());
    Ok(outbounds)
}

/// ZenOne 内部诊断类型别名（避免与本模块冲突）
type Diagnostics = crate::config::zenone::Diagnostics;

// ─── 兼容层 (proxy_provider.rs 使用) ───

/// 格式枚举（兼容旧 API）
#[derive(Debug, Clone, PartialEq)]
pub enum SubFormat {
    ClashYaml,
    SingBoxJson,
    Base64,
    UriList,
    Unknown,
}

/// 检测订阅内容格式
pub fn detect_format(content: &str) -> SubFormat {
    let content = content.trim();
    if content.starts_with('{') || content.starts_with('[') {
        if content.contains("\"outbounds\"") {
            return SubFormat::SingBoxJson;
        }
        return SubFormat::SingBoxJson; // also handles SIP008
    }
    if content.contains("proxies:") || content.starts_with("---") {
        return SubFormat::ClashYaml;
    }
    if content.contains("://") {
        return SubFormat::UriList;
    }
    // Possibly base64
    let clean: String = content.chars().filter(|c| !c.is_whitespace()).collect();
    if clean
        .chars()
        .all(|c| c.is_alphanumeric() || c == '+' || c == '/' || c == '=')
        && clean.len() > 20
    {
        return SubFormat::Base64;
    }
    SubFormat::Unknown
}

/// 代理节点（兼容旧 ProxyNode 类型）
#[derive(Debug, Clone)]
pub struct ProxyNode {
    pub name: String,
    pub protocol: String,
    pub address: String,
    pub port: u16,
    pub settings: std::collections::HashMap<String, String>,
}

impl ProxyNode {
    pub fn to_outbound_tag(&self) -> String {
        self.name.clone()
    }

    /// 从 OutboundConfig 转换
    fn from_outbound_config(config: &OutboundConfig) -> Self {
        let mut settings = std::collections::HashMap::new();
        let s = &config.settings;
        if let Some(v) = &s.uuid {
            settings.insert("uuid".to_string(), v.clone());
        }
        if let Some(v) = &s.password {
            settings.insert("password".to_string(), v.clone());
        }
        if let Some(v) = &s.method {
            settings.insert("method".to_string(), v.clone());
            settings.insert("cipher".to_string(), v.clone());
        }
        if let Some(v) = &s.sni {
            settings.insert("sni".to_string(), v.clone());
        }
        if let Some(v) = &s.security {
            settings.insert("security".to_string(), v.clone());
        }
        if let Some(v) = &s.flow {
            settings.insert("flow".to_string(), v.clone());
        }
        if let Some(v) = s.alter_id {
            settings.insert("alter_id".to_string(), v.to_string());
        }
        if let Some(v) = &s.plugin {
            settings.insert("plugin".to_string(), v.clone());
        }
        if let Some(v) = &s.plugin_opts {
            settings.insert("plugin_opts".to_string(), v.clone());
        }

        ProxyNode {
            name: config.tag.clone(),
            protocol: config.protocol.clone(),
            address: s.address.clone().unwrap_or_default(),
            port: s.port.unwrap_or(0),
            settings,
        }
    }
}

/// 解析 Clash YAML 为 ProxyNode 列表（pub 兼容）
pub fn parse_clash_yaml_nodes(content: &str) -> Result<Vec<ProxyNode>> {
    let configs = parse_clash_yaml(content)?;
    Ok(configs
        .iter()
        .map(ProxyNode::from_outbound_config)
        .collect())
}

/// 解析 sing-box JSON 为 ProxyNode 列表（pub 兼容）
pub fn parse_singbox_json_nodes(content: &str) -> Result<Vec<ProxyNode>> {
    let configs = parse_singbox_json(content)?;
    Ok(configs
        .iter()
        .map(ProxyNode::from_outbound_config)
        .collect())
}

/// 解析 Base64 编码的 URI 列表为 ProxyNode
pub fn parse_base64(content: &str) -> Result<Vec<ProxyNode>> {
    let decoded = decode_base64_content(content)?;
    let configs = parse_uri_list(&decoded)?;
    Ok(configs
        .iter()
        .map(ProxyNode::from_outbound_config)
        .collect())
}

/// 解析单个代理链接为 ProxyNode
pub fn parse_proxy_link(line: &str) -> Option<ProxyNode> {
    parse_proxy_uri(line)
        .ok()
        .map(|c| ProxyNode::from_outbound_config(&c))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_vless_uri_basic() {
        let uri = "vless://uuid-1234@server.com:443?security=tls&sni=server.com&flow=xtls-rprx-vision#MyNode";
        let config = parse_proxy_uri(uri).unwrap();
        assert_eq!(config.tag, "MyNode");
        assert_eq!(config.protocol, "vless");
        assert_eq!(config.settings.uuid.as_deref(), Some("uuid-1234"));
        assert_eq!(config.settings.address.as_deref(), Some("server.com"));
        assert_eq!(config.settings.port, Some(443));
        assert_eq!(config.settings.flow.as_deref(), Some("xtls-rprx-vision"));
    }

    #[test]
    fn parse_ss_sip002() {
        let method_pass =
            base64::engine::general_purpose::STANDARD.encode("aes-256-gcm:mypassword");
        let uri = format!("ss://{}@server.com:8388#MySSNode", method_pass);
        let config = parse_proxy_uri(&uri).unwrap();
        assert_eq!(config.tag, "MySSNode");
        assert_eq!(config.protocol, "shadowsocks");
        assert_eq!(config.settings.method.as_deref(), Some("aes-256-gcm"));
        assert_eq!(config.settings.password.as_deref(), Some("mypassword"));
    }

    #[test]
    fn parse_trojan_uri_basic() {
        let uri = "trojan://password123@server.com:443?sni=server.com#MyTrojan";
        let config = parse_proxy_uri(uri).unwrap();
        assert_eq!(config.tag, "MyTrojan");
        assert_eq!(config.protocol, "trojan");
        assert_eq!(config.settings.password.as_deref(), Some("password123"));
    }

    #[test]
    fn parse_hy2_uri_basic() {
        let uri = "hy2://password@server.com:443?sni=server.com&insecure=1#MyHy2";
        let config = parse_proxy_uri(uri).unwrap();
        assert_eq!(config.tag, "MyHy2");
        assert_eq!(config.protocol, "hysteria2");
        assert!(config.settings.allow_insecure);
    }

    #[test]
    fn parse_vmess_uri_basic() {
        let vmess_json = serde_json::json!({
            "v": "2", "ps": "TestVMess", "add": "server.com",
            "port": 443, "id": "test-uuid", "aid": 0,
            "tls": "tls", "sni": "server.com"
        });
        let encoded = base64::engine::general_purpose::STANDARD.encode(vmess_json.to_string());
        let uri = format!("vmess://{}", encoded);
        let config = parse_proxy_uri(&uri).unwrap();
        assert_eq!(config.tag, "TestVMess");
        assert_eq!(config.settings.uuid.as_deref(), Some("test-uuid"));
    }

    #[test]
    fn parse_clash_yaml_basic() {
        let yaml = r#"
proxies:
  - name: "node1"
    type: vless
    server: server.com
    port: 443
    uuid: "test-uuid"
    sni: "server.com"
  - name: "node2"
    type: ss
    server: ss.server.com
    port: 8388
    cipher: aes-256-gcm
    password: "pass"
"#;
        let configs = parse_subscription(yaml).unwrap();
        assert_eq!(configs.len(), 2);
        assert_eq!(configs[0].tag, "node1");
        assert_eq!(configs[1].protocol, "shadowsocks");
    }

    #[test]
    fn parse_sip008_basic() {
        let json = r#"{
            "servers": [
                {"server": "s1.com", "server_port": 8388, "password": "pass1", "method": "aes-128-gcm"},
                {"server": "s2.com", "server_port": 8389, "password": "pass2", "method": "chacha20-ietf-poly1305", "remarks": "Node2"}
            ]
        }"#;
        let configs = parse_subscription(json).unwrap();
        assert_eq!(configs.len(), 2);
        assert_eq!(configs[0].settings.address.as_deref(), Some("s1.com"));
        assert_eq!(configs[1].tag, "Node2");
    }

    #[test]
    fn parse_base64_uri_list() {
        let line1 = "trojan://pass@s1.com:443#N1";
        let line2 = "hy2://pass@s2.com:443#N2";
        let content = format!("{}\n{}", line1, line2);
        let encoded = base64::engine::general_purpose::STANDARD.encode(&content);
        let configs = parse_subscription(&encoded).unwrap();
        assert_eq!(configs.len(), 2);
    }

    #[test]
    fn unsupported_scheme() {
        assert!(parse_proxy_uri("unknown://test").is_err());
    }

    #[test]
    fn parse_host_port_ipv4() {
        let (host, port) = parse_host_port("1.2.3.4:443").unwrap();
        assert_eq!(host, "1.2.3.4");
        assert_eq!(port, "443");
    }

    #[test]
    fn parse_host_port_ipv6() {
        let (host, port) = parse_host_port("[::1]:443").unwrap();
        assert_eq!(host, "::1");
        assert_eq!(port, "443");
    }

    #[test]
    fn query_params_parsing() {
        let params = parse_query_params("security=tls&sni=test.com&fp=chrome");
        assert_eq!(params.get("security").unwrap(), "tls");
        assert_eq!(params.get("sni").unwrap(), "test.com");
        assert_eq!(params.get("fp").unwrap(), "chrome");
    }

    #[test]
    fn parse_tuic_uri_basic() {
        let uri = "tuic://uuid-1234:mypass@tuic.example.com:443?congestion_control=bbr&alpn=h3&sni=tuic.example.com#TUIC%20Node";
        let cfg = parse_proxy_uri(uri).unwrap();
        assert_eq!(cfg.protocol, "tuic");
        assert_eq!(cfg.tag, "TUIC Node");
        assert_eq!(cfg.settings.uuid.as_deref(), Some("uuid-1234"));
        assert_eq!(cfg.settings.password.as_deref(), Some("mypass"));
        assert_eq!(cfg.settings.address.as_deref(), Some("tuic.example.com"));
        assert_eq!(cfg.settings.port, Some(443));
        assert_eq!(cfg.settings.congestion_control.as_deref(), Some("bbr"));
        let tls = cfg.settings.tls.as_ref().unwrap();
        assert!(tls.enabled);
        assert_eq!(tls.sni.as_deref(), Some("tuic.example.com"));
        assert_eq!(tls.alpn.as_ref().unwrap(), &["h3"]);
    }

    #[test]
    fn parse_wg_uri_basic() {
        let uri = "wg://cHJpdmtleQ%3D%3D@wg.example.com:51820?publickey=pubkey123&address=10.0.0.2/32&mtu=1280#WG%20Node";
        let cfg = parse_proxy_uri(uri).unwrap();
        assert_eq!(cfg.protocol, "wireguard");
        assert_eq!(cfg.tag, "WG Node");
        assert_eq!(cfg.settings.address.as_deref(), Some("wg.example.com"));
        assert_eq!(cfg.settings.port, Some(51820));
        assert_eq!(cfg.settings.peer_public_key.as_deref(), Some("pubkey123"));
        assert_eq!(cfg.settings.local_address.as_deref(), Some("10.0.0.2/32"));
        assert_eq!(cfg.settings.mtu, Some(1280));
    }

    #[test]
    fn parse_wg_uri_wireguard_scheme() {
        let uri = "wireguard://privkey@1.2.3.4:51820?publickey=pk#wg";
        let cfg = parse_proxy_uri(uri).unwrap();
        assert_eq!(cfg.protocol, "wireguard");
        assert_eq!(cfg.settings.private_key.as_deref(), Some("privkey"));
    }

    #[test]
    fn parse_ssh_uri_basic() {
        let uri = "ssh://admin:s3cret@ssh.example.com:22#SSH%20Server";
        let cfg = parse_proxy_uri(uri).unwrap();
        assert_eq!(cfg.protocol, "ssh");
        assert_eq!(cfg.tag, "SSH Server");
        assert_eq!(cfg.settings.username.as_deref(), Some("admin"));
        assert_eq!(cfg.settings.password.as_deref(), Some("s3cret"));
        assert_eq!(cfg.settings.address.as_deref(), Some("ssh.example.com"));
        assert_eq!(cfg.settings.port, Some(22));
    }

    #[test]
    fn parse_ssh_uri_no_password() {
        let uri = "ssh://user@host.com:2222#ssh";
        let cfg = parse_proxy_uri(uri).unwrap();
        assert_eq!(cfg.settings.username.as_deref(), Some("user"));
        assert!(cfg.settings.password.is_none());
    }

    #[test]
    fn parse_hy1_uri_basic() {
        let uri = "hysteria://hy1.example.com:443?auth=mytoken&obfs=xplus&obfsParam=obfs_secret&upmbps=100&downmbps=200&sni=hy1.example.com&insecure=1#Hy1%20Node";
        let cfg = parse_proxy_uri(uri).unwrap();
        assert_eq!(cfg.protocol, "hysteria");
        assert_eq!(cfg.tag, "Hy1 Node");
        assert_eq!(cfg.settings.password.as_deref(), Some("mytoken"));
        assert_eq!(cfg.settings.obfs.as_deref(), Some("xplus"));
        assert_eq!(cfg.settings.obfs_password.as_deref(), Some("obfs_secret"));
        assert_eq!(cfg.settings.up_mbps, Some(100));
        assert_eq!(cfg.settings.down_mbps, Some(200));
        let tls = cfg.settings.tls.as_ref().unwrap();
        assert!(tls.allow_insecure);
        assert_eq!(tls.sni.as_deref(), Some("hy1.example.com"));
    }

    #[test]
    fn parse_vless_ws_transport() {
        let uri = "vless://uuid@example.com:443?type=ws&path=%2Fws&host=cdn.example.com&security=tls&sni=cdn.example.com#VLESS+WS";
        let cfg = parse_proxy_uri(uri).unwrap();
        assert_eq!(cfg.protocol, "vless");
        let transport = cfg.settings.transport.as_ref().unwrap();
        assert_eq!(transport.transport_type, "ws");
        assert_eq!(transport.path.as_deref(), Some("/ws"));
        assert_eq!(transport.host.as_deref(), Some("cdn.example.com"));
        let tls = cfg.settings.tls.as_ref().unwrap();
        assert!(tls.enabled);
    }

    #[test]
    fn parse_trojan_grpc_transport() {
        let uri = "trojan://password@example.com:443?type=grpc&serviceName=grpc_svc&sni=example.com#Trojan+gRPC";
        let cfg = parse_proxy_uri(uri).unwrap();
        assert_eq!(cfg.protocol, "trojan");
        let transport = cfg.settings.transport.as_ref().unwrap();
        assert_eq!(transport.transport_type, "grpc");
        assert_eq!(transport.service_name.as_deref(), Some("grpc_svc"));
    }

    #[test]
    fn parse_zenone_yaml_subscription() {
        let zenone_yaml = r#"
zen-version: 1
metadata:
  name: "Test ZenOne Sub"
nodes:
  - name: "HK-VLESS"
    type: vless
    address: hk.example.com
    port: 443
    uuid: "550e8400-e29b-41d4-a716-446655440000"
    flow: xtls-rprx-vision
    tls:
      fingerprint: chrome
      reality:
        public-key: abc123
        short-id: def456
  - name: "US-HY2"
    type: hysteria2
    address: us.example.com
    port: 443
    password: my-pass
    up-mbps: 100
    down-mbps: 200
"#;
        let configs = parse_subscription(zenone_yaml).unwrap();
        assert_eq!(configs.len(), 2);
        assert_eq!(configs[0].tag, "HK-VLESS");
        assert_eq!(configs[0].protocol, "vless");
        assert_eq!(configs[1].tag, "US-HY2");
        assert_eq!(configs[1].protocol, "hysteria2");
    }

    #[test]
    fn parse_zenone_json_subscription() {
        let zenone_json = r#"{
            "zen-version": 1,
            "nodes": [
                {
                    "name": "SG-VLESS",
                    "type": "vless",
                    "address": "sg.example.com",
                    "port": 443,
                    "uuid": "test-uuid"
                }
            ]
        }"#;
        let configs = parse_subscription(zenone_json).unwrap();
        assert_eq!(configs.len(), 1);
        assert_eq!(configs[0].tag, "SG-VLESS");
        assert_eq!(configs[0].protocol, "vless");
    }

    #[test]
    fn parse_subscription_zenone_priority() {
        // ZenOne格式应该被优先检测
        let content = r#"
zen-version: 1
nodes:
  - name: zenone-node
    type: direct
"#;
        let configs = parse_subscription(content).unwrap();
        assert_eq!(configs.len(), 1);
        assert_eq!(configs[0].tag, "zenone-node");
    }
}
