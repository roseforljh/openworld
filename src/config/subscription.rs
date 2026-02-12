//! 订阅链接解析器
//!
//! 支持以下订阅格式：
//! - **URI 列表** (Base64 编码): `vmess://`, `vless://`, `ss://`, `trojan://`, `hy2://`, `hysteria2://`
//! - **Clash / mihomo YAML** : `proxies:` 列表
//! - **sing-box JSON**: `outbounds:` 列表（转换为 OutboundConfig）
//! - **SIP008 JSON**: Shadowsocks 标准订阅格式

use anyhow::Result;
use base64::Engine;
use tracing::debug;

use crate::config::types::OutboundConfig;
use crate::config::types::OutboundSettings;

// ─── 公共接口 ───

/// 自动检测格式并解析订阅内容
pub fn parse_subscription(content: &str) -> Result<Vec<OutboundConfig>> {
    let content = content.trim();

    // 1. 尝试 JSON
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
    } else if let Some(rest) = uri.strip_prefix("hysteria2://").or_else(|| uri.strip_prefix("hy2://")) {
        parse_hy2_uri(rest)
    } else {
        anyhow::bail!("unsupported proxy URI scheme: {}", uri.split("://").next().unwrap_or("?"))
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
    let port = v["port"].as_u64().or_else(|| v["port"].as_str().and_then(|s| s.parse().ok())).unwrap_or(443) as u16;
    let uuid = v["id"].as_str().unwrap_or("").to_string();
    let alter_id = v["aid"].as_u64().or_else(|| v["aid"].as_str().and_then(|s| s.parse().ok())).unwrap_or(0) as u16;
    let sni = v["sni"].as_str().or_else(|| v["host"].as_str()).map(String::from);
    let security = if v["tls"].as_str() == Some("tls") {
        Some("tls".to_string())
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
            ..Default::default()
        },
    })
}

// ─── VLESS URI ───

fn parse_vless_uri(rest: &str) -> Result<OutboundConfig> {
    // vless://uuid@host:port?params#tag
    let (main, tag) = rest.rsplit_once('#').unwrap_or((rest, "vless"));
    let tag = url_decode(tag).unwrap_or_else(|_| tag.into()).to_string();

    let (userinfo, host_params) = main.split_once('@').ok_or_else(|| anyhow::anyhow!("vless: missing @"))?;
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
        let decoded = decode_base64_content(encoded_part)
            .unwrap_or_else(|_| encoded_part.to_string());

        let (method, password) = decoded.split_once(':')
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
        let (method_pass, host_port) = decoded.rsplit_once('@')
            .ok_or_else(|| anyhow::anyhow!("ss: invalid format"))?;
        let (method, password) = method_pass.split_once(':')
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

    let (password, host_params) = main.split_once('@').ok_or_else(|| anyhow::anyhow!("trojan: missing @"))?;
    let password = url_decode(password).unwrap_or_else(|_| password.into()).to_string();

    let (host_port, params_str) = host_params.split_once('?').unwrap_or((host_params, ""));
    let (host, port_str) = parse_host_port(host_port)?;
    let port: u16 = port_str.parse()?;

    let params = parse_query_params(params_str);
    let sni = params.get("sni").cloned().or_else(|| Some(host.clone()));

    Ok(OutboundConfig {
        tag,
        protocol: "trojan".to_string(),
        settings: OutboundSettings {
            address: Some(host),
            port: Some(port),
            password: Some(password),
            sni,
            security: Some("tls".to_string()),
            ..Default::default()
        },
    })
}

// ─── Hysteria2 URI ───

fn parse_hy2_uri(rest: &str) -> Result<OutboundConfig> {
    let (main, tag) = rest.rsplit_once('#').unwrap_or((rest, "hy2"));
    let tag = url_decode(tag).unwrap_or_else(|_| tag.into()).to_string();

    let (password, host_params) = main.split_once('@').ok_or_else(|| anyhow::anyhow!("hy2: missing @"))?;
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

// ─── Clash YAML ───

fn parse_clash_yaml(content: &str) -> Result<Vec<OutboundConfig>> {
    let yaml: serde_yml::Value = serde_yml::from_str(content)?;
    let proxies = yaml["proxies"].as_sequence()
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
        _ => return None,
    };

    let uuid = v["uuid"].as_str().map(String::from);
    let password = v["password"].as_str().map(String::from);
    let method = v["cipher"].as_str().or(v["method"].as_str()).map(String::from);
    let sni = v["sni"].as_str().or(v["servername"].as_str()).map(String::from);
    let allow_insecure = v["skip-cert-verify"].as_bool().unwrap_or(false);
    let flow = v["flow"].as_str().map(String::from);
    let alter_id = v["alterId"].as_u64().map(|v| v as u16);
    let up_mbps = v["up"].as_u64().or(v["up_mbps"].as_u64());
    let down_mbps = v["down"].as_u64().or(v["down_mbps"].as_u64());

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
            ..Default::default()
        },
    })
}

// ─── sing-box JSON ───

fn parse_singbox_json(content: &str) -> Result<Vec<OutboundConfig>> {
    let v: serde_json::Value = serde_json::from_str(content)?;
    let outbounds = v["outbounds"].as_array()
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

        let tls = &ob["tls"];
        let sni = tls["server_name"].as_str().map(String::from);
        let allow_insecure = tls["insecure"].as_bool().unwrap_or(false);
        let security = if tls["enabled"].as_bool().unwrap_or(false) {
            Some("tls".to_string())
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
    let configs = sip.servers.into_iter().enumerate().map(|(i, s)| {
        OutboundConfig {
            tag: s.remarks.unwrap_or_else(|| format!("ss-{}", i)),
            protocol: "shadowsocks".to_string(),
            settings: OutboundSettings {
                address: Some(s.server),
                port: Some(s.server_port),
                password: Some(s.password),
                method: Some(s.method),
                ..Default::default()
            },
        }
    }).collect();
    Ok(configs)
}

// ─── 辅助函数 ───

fn parse_host_port(s: &str) -> Result<(String, &str)> {
    if let Some(rest) = s.strip_prefix('[') {
        let (host, port_with_bracket) = rest.split_once(']')
            .ok_or_else(|| anyhow::anyhow!("invalid IPv6 address"))?;
        let port_str = port_with_bracket.strip_prefix(':')
            .ok_or_else(|| anyhow::anyhow!("missing port after IPv6"))?;
        Ok((host.to_string(), port_str))
    } else {
        let (host, port) = s.rsplit_once(':')
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
            let hi = chars.next().ok_or_else(|| anyhow::anyhow!("incomplete percent encoding"))?;
            let lo = chars.next().ok_or_else(|| anyhow::anyhow!("incomplete percent encoding"))?;
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
    if clean.chars().all(|c| c.is_alphanumeric() || c == '+' || c == '/' || c == '=') && clean.len() > 20 {
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
        if let Some(v) = &s.uuid { settings.insert("uuid".to_string(), v.clone()); }
        if let Some(v) = &s.password { settings.insert("password".to_string(), v.clone()); }
        if let Some(v) = &s.method { settings.insert("method".to_string(), v.clone()); settings.insert("cipher".to_string(), v.clone()); }
        if let Some(v) = &s.sni { settings.insert("sni".to_string(), v.clone()); }
        if let Some(v) = &s.security { settings.insert("security".to_string(), v.clone()); }
        if let Some(v) = &s.flow { settings.insert("flow".to_string(), v.clone()); }
        if let Some(v) = s.alter_id { settings.insert("alter_id".to_string(), v.to_string()); }
        if let Some(v) = &s.plugin { settings.insert("plugin".to_string(), v.clone()); }
        if let Some(v) = &s.plugin_opts { settings.insert("plugin_opts".to_string(), v.clone()); }

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
    Ok(configs.iter().map(ProxyNode::from_outbound_config).collect())
}

/// 解析 sing-box JSON 为 ProxyNode 列表（pub 兼容）
pub fn parse_singbox_json_nodes(content: &str) -> Result<Vec<ProxyNode>> {
    let configs = parse_singbox_json(content)?;
    Ok(configs.iter().map(ProxyNode::from_outbound_config).collect())
}

/// 解析 Base64 编码的 URI 列表为 ProxyNode
pub fn parse_base64(content: &str) -> Result<Vec<ProxyNode>> {
    let decoded = decode_base64_content(content)?;
    let configs = parse_uri_list(&decoded)?;
    Ok(configs.iter().map(ProxyNode::from_outbound_config).collect())
}

/// 解析单个代理链接为 ProxyNode
pub fn parse_proxy_link(line: &str) -> Option<ProxyNode> {
    parse_proxy_uri(line).ok().map(|c| ProxyNode::from_outbound_config(&c))
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
        let method_pass = base64::engine::general_purpose::STANDARD.encode("aes-256-gcm:mypassword");
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
}
