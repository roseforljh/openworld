use std::collections::HashMap;

use anyhow::Result;
use serde::Deserialize;

/// 订阅解析器 trait
///
/// 内置解析器和自定义解析器都实现此 trait。
/// 支持通过 `SubscriptionRegistry::register_parser()` 注册自定义 parser。
pub trait SubscriptionParser: Send + Sync {
    /// 解析订阅内容为代理节点列表
    fn parse(&self, content: &str) -> Result<Vec<ProxyNode>>;

    /// 解析器名称
    fn name(&self) -> &str;
}

/// 内置 Base64 解析器
pub struct Base64Parser;

impl SubscriptionParser for Base64Parser {
    fn parse(&self, content: &str) -> Result<Vec<ProxyNode>> {
        parse_base64(content)
    }
    fn name(&self) -> &str {
        "base64"
    }
}

/// 内置 Clash YAML 解析器
pub struct ClashYamlParser;

impl SubscriptionParser for ClashYamlParser {
    fn parse(&self, content: &str) -> Result<Vec<ProxyNode>> {
        parse_clash_yaml(content)
    }
    fn name(&self) -> &str {
        "clash-yaml"
    }
}

/// 内置 sing-box JSON 解析器
pub struct SingBoxParser;

impl SubscriptionParser for SingBoxParser {
    fn parse(&self, content: &str) -> Result<Vec<ProxyNode>> {
        parse_singbox_json(content)
    }
    fn name(&self) -> &str {
        "singbox"
    }
}

/// 内置 SIP008 解析器
pub struct Sip008ParserImpl;

impl SubscriptionParser for Sip008ParserImpl {
    fn parse(&self, content: &str) -> Result<Vec<ProxyNode>> {
        parse_sip008(content)
    }
    fn name(&self) -> &str {
        "sip008"
    }
}

/// 订阅解析器注册表
///
/// 管理内置和自定义解析器，支持运行时注册。
pub struct SubscriptionRegistry {
    parsers: HashMap<String, Box<dyn SubscriptionParser>>,
}

impl SubscriptionRegistry {
    pub fn new() -> Self {
        let mut registry = Self {
            parsers: HashMap::new(),
        };
        // 注册内置解析器
        registry.register(Box::new(Base64Parser));
        registry.register(Box::new(ClashYamlParser));
        registry.register(Box::new(SingBoxParser));
        registry.register(Box::new(Sip008ParserImpl));
        registry
    }

    /// 注册自定义解析器
    pub fn register_parser(&mut self, name: &str, parser: Box<dyn SubscriptionParser>) {
        self.parsers.insert(name.to_string(), parser);
    }

    /// 内部注册（按解析器自身名称）
    fn register(&mut self, parser: Box<dyn SubscriptionParser>) {
        let name = parser.name().to_string();
        self.parsers.insert(name, parser);
    }

    /// 使用指定解析器解析内容
    pub fn parse_with(&self, parser_name: &str, content: &str) -> Result<Vec<ProxyNode>> {
        let parser = self
            .parsers
            .get(parser_name)
            .ok_or_else(|| anyhow::anyhow!("unknown subscription parser: {}", parser_name))?;
        parser.parse(content)
    }

    /// 列出所有已注册的解析器名称
    pub fn parser_names(&self) -> Vec<&str> {
        self.parsers.keys().map(|k| k.as_str()).collect()
    }

    /// 检查解析器是否已注册
    pub fn has_parser(&self, name: &str) -> bool {
        self.parsers.contains_key(name)
    }

    /// 已注册解析器数量
    pub fn len(&self) -> usize {
        self.parsers.len()
    }
}

/// Subscription format types
#[derive(Debug, Clone, PartialEq)]
pub enum SubFormat {
    Base64,
    ClashYaml,
    SingBoxJson,
    Sip008,
    Unknown,
}

/// A parsed proxy node from a subscription
#[derive(Debug, Clone)]
pub struct ProxyNode {
    pub name: String,
    pub protocol: String,
    pub address: String,
    pub port: u16,
    pub settings: HashMap<String, String>,
}

impl ProxyNode {
    pub fn to_outbound_tag(&self) -> String {
        self.name.clone()
    }
}

/// Detect the format of subscription content
pub fn detect_format(content: &str) -> SubFormat {
    let trimmed = content.trim();

    // Try JSON (sing-box / SIP008)
    if trimmed.starts_with('{') || trimmed.starts_with('[') {
        if trimmed.contains("\"outbounds\"") {
            return SubFormat::SingBoxJson;
        }
        if trimmed.contains("\"servers\"") || trimmed.contains("\"server\"") {
            return SubFormat::Sip008;
        }
        return SubFormat::SingBoxJson;
    }

    // Try YAML (Clash)
    if trimmed.contains("proxies:") || trimmed.contains("Proxy:") {
        return SubFormat::ClashYaml;
    }

    // Try Base64
    if is_base64(trimmed) {
        return SubFormat::Base64;
    }

    SubFormat::Unknown
}

fn is_base64(s: &str) -> bool {
    let s = s.trim();
    if s.is_empty() {
        return false;
    }
    // Base64 can contain A-Z, a-z, 0-9, +, /, = and newlines
    s.chars().all(|c| {
        c.is_ascii_alphanumeric() || c == '+' || c == '/' || c == '=' || c == '\n' || c == '\r'
    })
}

/// Parse Base64 subscription content (SS/VMess/Trojan links)
pub fn parse_base64(content: &str) -> Result<Vec<ProxyNode>> {
    let decoded = match base64_decode(content.trim()) {
        Some(d) => d,
        None => anyhow::bail!("invalid base64 subscription content"),
    };

    let mut nodes = Vec::new();
    for line in decoded.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if let Some(node) = parse_proxy_link(line) {
            nodes.push(node);
        }
    }
    Ok(nodes)
}

fn base64_decode(s: &str) -> Option<String> {
    use base64::Engine;
    let s = s.replace('\n', "").replace('\r', "");
    // Try standard and URL-safe
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(&s)
        .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(&s))
        .or_else(|_| base64::engine::general_purpose::STANDARD_NO_PAD.decode(&s))
        .ok()?;
    String::from_utf8(bytes).ok()
}

/// Parse a single proxy link (ss://, vmess://, trojan://, vless://)
pub fn parse_proxy_link(link: &str) -> Option<ProxyNode> {
    if link.starts_with("ss://") {
        return parse_ss_link(link);
    }
    if link.starts_with("vmess://") {
        return parse_vmess_link(link);
    }
    if link.starts_with("trojan://") {
        return parse_trojan_link(link);
    }
    if link.starts_with("vless://") {
        return parse_vless_link(link);
    }
    None
}

fn parse_ss_link(link: &str) -> Option<ProxyNode> {
    // ss://base64(method:password)@server:port#name
    let rest = link.strip_prefix("ss://")?;
    let (encoded_part, name) = if let Some(idx) = rest.rfind('#') {
        (&rest[..idx], urlencoding_decode(&rest[idx + 1..]))
    } else {
        (rest, "ss-node".to_string())
    };

    let (user_info, server_part) = if let Some(idx) = encoded_part.rfind('@') {
        (&encoded_part[..idx], &encoded_part[idx + 1..])
    } else {
        // Entire part might be base64 encoded
        let decoded = base64_decode(encoded_part)?;
        let parts: Vec<&str> = decoded.rsplitn(2, '@').collect();
        if parts.len() < 2 {
            return None;
        }
        // Can't reference decoded after this scope, return early
        let server = parts[0].to_string();
        let user = parts[1].to_string();
        let (addr, port) = parse_host_port(&server)?;
        let (method, password) = user.split_once(':')?;
        let mut settings = HashMap::new();
        settings.insert("method".to_string(), method.to_string());
        settings.insert("password".to_string(), password.to_string());
        return Some(ProxyNode {
            name,
            protocol: "ss".to_string(),
            address: addr,
            port,
            settings,
        });
    };

    let decoded_user = base64_decode(user_info).unwrap_or_else(|| user_info.to_string());
    let (method, password) = decoded_user.split_once(':')?;
    let (addr, port) = parse_host_port(server_part)?;

    let mut settings = HashMap::new();
    settings.insert("method".to_string(), method.to_string());
    settings.insert("password".to_string(), password.to_string());

    Some(ProxyNode {
        name,
        protocol: "ss".to_string(),
        address: addr,
        port,
        settings,
    })
}

fn parse_vmess_link(link: &str) -> Option<ProxyNode> {
    // vmess://base64(json)
    let rest = link.strip_prefix("vmess://")?;
    let decoded = base64_decode(rest)?;
    let json: serde_json::Value = serde_json::from_str(&decoded).ok()?;

    let address = json.get("add")?.as_str()?.to_string();
    let port = json
        .get("port")?
        .as_str()
        .and_then(|s| s.parse().ok())
        .or_else(|| json.get("port")?.as_u64().map(|p| p as u16))?;
    let name = json
        .get("ps")
        .and_then(|v| v.as_str())
        .unwrap_or("vmess-node")
        .to_string();

    let mut settings = HashMap::new();
    if let Some(uuid) = json.get("id").and_then(|v| v.as_str()) {
        settings.insert("uuid".to_string(), uuid.to_string());
    }
    if let Some(aid) = json.get("aid").and_then(|v| v.as_str()) {
        settings.insert("alter_id".to_string(), aid.to_string());
    }
    if let Some(net) = json.get("net").and_then(|v| v.as_str()) {
        settings.insert("network".to_string(), net.to_string());
    }
    if let Some(tls) = json.get("tls").and_then(|v| v.as_str()) {
        settings.insert("tls".to_string(), tls.to_string());
    }
    if let Some(sni) = json.get("sni").and_then(|v| v.as_str()) {
        settings.insert("sni".to_string(), sni.to_string());
    }

    Some(ProxyNode {
        name,
        protocol: "vmess".to_string(),
        address,
        port,
        settings,
    })
}

fn parse_trojan_link(link: &str) -> Option<ProxyNode> {
    // trojan://password@server:port?params#name
    let rest = link.strip_prefix("trojan://")?;
    let (main_part, name) = if let Some(idx) = rest.rfind('#') {
        (&rest[..idx], urlencoding_decode(&rest[idx + 1..]))
    } else {
        (rest, "trojan-node".to_string())
    };

    let (password, server_part) = main_part.split_once('@')?;
    let (server_and_port, params) = if let Some(idx) = server_part.find('?') {
        (&server_part[..idx], Some(&server_part[idx + 1..]))
    } else {
        (server_part, None)
    };

    let (addr, port) = parse_host_port(server_and_port)?;

    let mut settings = HashMap::new();
    settings.insert("password".to_string(), password.to_string());
    if let Some(p) = params {
        for pair in p.split('&') {
            if let Some((k, v)) = pair.split_once('=') {
                settings.insert(k.to_string(), urlencoding_decode(v));
            }
        }
    }

    Some(ProxyNode {
        name,
        protocol: "trojan".to_string(),
        address: addr,
        port,
        settings,
    })
}

fn parse_vless_link(link: &str) -> Option<ProxyNode> {
    // vless://uuid@server:port?params#name
    let rest = link.strip_prefix("vless://")?;
    let (main_part, name) = if let Some(idx) = rest.rfind('#') {
        (&rest[..idx], urlencoding_decode(&rest[idx + 1..]))
    } else {
        (rest, "vless-node".to_string())
    };

    let (uuid, server_part) = main_part.split_once('@')?;
    let (server_and_port, params) = if let Some(idx) = server_part.find('?') {
        (&server_part[..idx], Some(&server_part[idx + 1..]))
    } else {
        (server_part, None)
    };

    let (addr, port) = parse_host_port(server_and_port)?;

    let mut settings = HashMap::new();
    settings.insert("uuid".to_string(), uuid.to_string());
    if let Some(p) = params {
        for pair in p.split('&') {
            if let Some((k, v)) = pair.split_once('=') {
                settings.insert(k.to_string(), urlencoding_decode(v));
            }
        }
    }

    Some(ProxyNode {
        name,
        protocol: "vless".to_string(),
        address: addr,
        port,
        settings,
    })
}

/// Parse Clash YAML subscription
pub fn parse_clash_yaml(content: &str) -> Result<Vec<ProxyNode>> {
    #[derive(Deserialize)]
    struct ClashConfig {
        proxies: Option<Vec<ClashProxy>>,
        #[serde(rename = "Proxy")]
        proxy_legacy: Option<Vec<ClashProxy>>,
    }

    #[derive(Deserialize)]
    struct ClashProxy {
        name: String,
        #[serde(rename = "type")]
        proxy_type: String,
        server: String,
        port: u16,
        #[serde(flatten)]
        extra: HashMap<String, serde_json::Value>,
    }

    let config: ClashConfig = serde_yml::from_str(content)?;
    let proxies = config.proxies.or(config.proxy_legacy).unwrap_or_default();

    let mut nodes = Vec::new();
    for proxy in proxies {
        let mut settings = HashMap::new();
        for (k, v) in &proxy.extra {
            match v {
                serde_json::Value::String(s) => {
                    settings.insert(k.clone(), s.clone());
                }
                serde_json::Value::Number(n) => {
                    settings.insert(k.clone(), n.to_string());
                }
                serde_json::Value::Bool(b) => {
                    settings.insert(k.clone(), b.to_string());
                }
                _ => {}
            }
        }
        nodes.push(ProxyNode {
            name: proxy.name,
            protocol: proxy.proxy_type,
            address: proxy.server,
            port: proxy.port,
            settings,
        });
    }
    Ok(nodes)
}

/// Parse sing-box JSON subscription
pub fn parse_singbox_json(content: &str) -> Result<Vec<ProxyNode>> {
    #[derive(Deserialize)]
    struct SingBoxConfig {
        outbounds: Option<Vec<SingBoxOutbound>>,
    }

    #[derive(Deserialize)]
    struct SingBoxOutbound {
        tag: Option<String>,
        #[serde(rename = "type")]
        outbound_type: String,
        server: Option<String>,
        server_port: Option<u16>,
        #[serde(flatten)]
        extra: HashMap<String, serde_json::Value>,
    }

    let config: SingBoxConfig = serde_json::from_str(content)?;
    let outbounds = config.outbounds.unwrap_or_default();

    let mut nodes = Vec::new();
    for ob in outbounds {
        // Skip non-proxy types
        if matches!(
            ob.outbound_type.as_str(),
            "direct" | "block" | "dns" | "selector" | "urltest"
        ) {
            continue;
        }
        let server = match ob.server {
            Some(s) => s,
            None => continue,
        };
        let port = ob.server_port.unwrap_or(443);

        let mut settings = HashMap::new();
        for (k, v) in &ob.extra {
            match v {
                serde_json::Value::String(s) => {
                    settings.insert(k.clone(), s.clone());
                }
                serde_json::Value::Number(n) => {
                    settings.insert(k.clone(), n.to_string());
                }
                serde_json::Value::Bool(b) => {
                    settings.insert(k.clone(), b.to_string());
                }
                _ => {}
            }
        }

        nodes.push(ProxyNode {
            name: ob
                .tag
                .unwrap_or_else(|| format!("{}-{}", ob.outbound_type, server)),
            protocol: ob.outbound_type,
            address: server,
            port,
            settings,
        });
    }
    Ok(nodes)
}

/// Parse SIP008 (Shadowsocks) JSON subscription
///
/// Format: {"version": 1, "servers": [{"server": "...", "server_port": 8388, ...}]}
pub fn parse_sip008(content: &str) -> Result<Vec<ProxyNode>> {
    #[derive(Deserialize)]
    #[allow(dead_code)]
    struct Sip008Config {
        version: Option<u32>,
        servers: Option<Vec<Sip008Server>>,
    }

    #[derive(Deserialize)]
    struct Sip008Server {
        id: Option<String>,
        remarks: Option<String>,
        server: String,
        server_port: u16,
        password: String,
        method: String,
        plugin: Option<String>,
        plugin_opts: Option<String>,
    }

    let config: Sip008Config = serde_json::from_str(content)?;
    let servers = config.servers.unwrap_or_default();

    let mut nodes = Vec::new();
    for (idx, srv) in servers.iter().enumerate() {
        let name = srv
            .remarks
            .clone()
            .or_else(|| srv.id.clone())
            .unwrap_or_else(|| format!("ss-{}", idx));

        let mut settings = HashMap::new();
        settings.insert("method".to_string(), srv.method.clone());
        settings.insert("password".to_string(), srv.password.clone());
        if let Some(ref plugin) = srv.plugin {
            settings.insert("plugin".to_string(), plugin.clone());
        }
        if let Some(ref opts) = srv.plugin_opts {
            settings.insert("plugin_opts".to_string(), opts.clone());
        }

        nodes.push(ProxyNode {
            name,
            protocol: "ss".to_string(),
            address: srv.server.clone(),
            port: srv.server_port,
            settings,
        });
    }
    Ok(nodes)
}

/// 订阅更新回滚支持
#[derive(Debug, Clone)]
pub struct SubscriptionSnapshot {
    pub source: String,
    pub nodes: Vec<ProxyNode>,
    pub timestamp: u64,
    pub etag: Option<String>,
}

impl SubscriptionSnapshot {
    pub fn new(source: String, nodes: Vec<ProxyNode>) -> Self {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        Self {
            source,
            nodes,
            timestamp,
            etag: None,
        }
    }

    pub fn with_etag(mut self, etag: String) -> Self {
        self.etag = Some(etag);
        self
    }

    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }
}

pub struct SubscriptionRollback {
    snapshots: std::collections::HashMap<String, Vec<SubscriptionSnapshot>>,
    max_history: usize,
}

impl SubscriptionRollback {
    pub fn new(max_history: usize) -> Self {
        Self {
            snapshots: std::collections::HashMap::new(),
            max_history,
        }
    }

    pub fn save(&mut self, name: &str, snapshot: SubscriptionSnapshot) {
        let history = self
            .snapshots
            .entry(name.to_string())
            .or_insert_with(Vec::new);
        history.push(snapshot);
        while history.len() > self.max_history {
            history.remove(0);
        }
    }

    pub fn rollback(&self, name: &str) -> Option<&SubscriptionSnapshot> {
        let history = self.snapshots.get(name)?;
        if history.len() >= 2 {
            // Return the second-to-last (previous working version)
            Some(&history[history.len() - 2])
        } else {
            history.last()
        }
    }

    pub fn latest(&self, name: &str) -> Option<&SubscriptionSnapshot> {
        self.snapshots.get(name)?.last()
    }

    pub fn history_count(&self, name: &str) -> usize {
        self.snapshots.get(name).map_or(0, |h| h.len())
    }

    pub fn clear(&mut self, name: &str) {
        self.snapshots.remove(name);
    }
}

/// 根据格式自动解析订阅内容
pub fn parse_subscription(content: &str) -> Result<Vec<ProxyNode>> {
    match detect_format(content) {
        SubFormat::Base64 => parse_base64(content),
        SubFormat::ClashYaml => parse_clash_yaml(content),
        SubFormat::SingBoxJson => parse_singbox_json(content),
        SubFormat::Sip008 => parse_sip008(content),
        SubFormat::Unknown => anyhow::bail!("unknown subscription format"),
    }
}
pub fn dedup_nodes(mut nodes: Vec<ProxyNode>) -> Vec<ProxyNode> {
    let mut seen = std::collections::HashSet::new();
    nodes.retain(|n| {
        let key = format!("{}:{}:{}", n.protocol, n.address, n.port);
        seen.insert(key)
    });
    nodes
}

fn parse_host_port(s: &str) -> Option<(String, u16)> {
    // Handle IPv6: [::1]:port
    if s.starts_with('[') {
        let end = s.find(']')?;
        let host = &s[1..end];
        let port_str = s.get(end + 2..)?; // skip ]:
        let port = port_str.parse().ok()?;
        return Some((host.to_string(), port));
    }
    let (host, port_str) = s.rsplit_once(':')?;
    let port = port_str.parse().ok()?;
    Some((host.to_string(), port))
}

fn urlencoding_decode(s: &str) -> String {
    let mut result = String::new();
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c == '%' {
            let hex: String = chars.by_ref().take(2).collect();
            if let Ok(byte) = u8::from_str_radix(&hex, 16) {
                result.push(byte as char);
            } else {
                result.push('%');
                result.push_str(&hex);
            }
        } else if c == '+' {
            result.push(' ');
        } else {
            result.push(c);
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_base64_format() {
        // "ss://test" base64 encoded
        use base64::Engine;
        let encoded = base64::engine::general_purpose::STANDARD
            .encode("ss://test@1.2.3.4:8388\nvmess://test");
        assert_eq!(detect_format(&encoded), SubFormat::Base64);
    }

    #[test]
    fn detect_clash_yaml_format() {
        let yaml = "proxies:\n  - name: test\n    type: ss\n    server: 1.2.3.4\n    port: 8388";
        assert_eq!(detect_format(yaml), SubFormat::ClashYaml);
    }

    #[test]
    fn detect_singbox_json_format() {
        let json = r#"{"outbounds": [{"type": "vless", "server": "1.2.3.4"}]}"#;
        assert_eq!(detect_format(json), SubFormat::SingBoxJson);
    }

    #[test]
    fn parse_ss_link_basic() {
        use base64::Engine;
        let user_info = base64::engine::general_purpose::STANDARD.encode("aes-256-gcm:password123");
        let link = format!("ss://{}@1.2.3.4:8388#My%20SS", user_info);
        let node = parse_proxy_link(&link).unwrap();
        assert_eq!(node.protocol, "ss");
        assert_eq!(node.address, "1.2.3.4");
        assert_eq!(node.port, 8388);
        assert_eq!(node.name, "My SS");
        assert_eq!(node.settings.get("method").unwrap(), "aes-256-gcm");
        assert_eq!(node.settings.get("password").unwrap(), "password123");
    }

    #[test]
    fn parse_vmess_link_basic() {
        use base64::Engine;
        let json = serde_json::json!({
            "v": "2",
            "ps": "test-vmess",
            "add": "example.com",
            "port": "443",
            "id": "550e8400-e29b-41d4-a716-446655440000",
            "aid": "0",
            "net": "ws",
            "tls": "tls"
        });
        let encoded = base64::engine::general_purpose::STANDARD.encode(json.to_string());
        let link = format!("vmess://{}", encoded);
        let node = parse_proxy_link(&link).unwrap();
        assert_eq!(node.protocol, "vmess");
        assert_eq!(node.address, "example.com");
        assert_eq!(node.port, 443);
        assert_eq!(node.name, "test-vmess");
        assert_eq!(
            node.settings.get("uuid").unwrap(),
            "550e8400-e29b-41d4-a716-446655440000"
        );
    }

    #[test]
    fn parse_trojan_link_basic() {
        let link = "trojan://mypassword@server.com:443?sni=server.com&type=tcp#My%20Trojan";
        let node = parse_proxy_link(link).unwrap();
        assert_eq!(node.protocol, "trojan");
        assert_eq!(node.address, "server.com");
        assert_eq!(node.port, 443);
        assert_eq!(node.name, "My Trojan");
        assert_eq!(node.settings.get("password").unwrap(), "mypassword");
        assert_eq!(node.settings.get("sni").unwrap(), "server.com");
    }

    #[test]
    fn parse_vless_link_basic() {
        let link = "vless://550e8400-e29b-41d4-a716-446655440000@server.com:443?security=tls&flow=xtls-rprx-vision#VLESS%20Node";
        let node = parse_proxy_link(link).unwrap();
        assert_eq!(node.protocol, "vless");
        assert_eq!(node.address, "server.com");
        assert_eq!(node.port, 443);
        assert_eq!(node.name, "VLESS Node");
        assert_eq!(
            node.settings.get("uuid").unwrap(),
            "550e8400-e29b-41d4-a716-446655440000"
        );
        assert_eq!(node.settings.get("security").unwrap(), "tls");
        assert_eq!(node.settings.get("flow").unwrap(), "xtls-rprx-vision");
    }

    #[test]
    fn parse_clash_yaml_basic() {
        let yaml = r#"
proxies:
  - name: "ss-node"
    type: ss
    server: 1.2.3.4
    port: 8388
    cipher: aes-256-gcm
    password: "test123"
  - name: "trojan-node"
    type: trojan
    server: 5.6.7.8
    port: 443
    password: "pass"
"#;
        let nodes = parse_clash_yaml(yaml).unwrap();
        assert_eq!(nodes.len(), 2);
        assert_eq!(nodes[0].name, "ss-node");
        assert_eq!(nodes[0].protocol, "ss");
        assert_eq!(nodes[0].port, 8388);
        assert_eq!(nodes[1].name, "trojan-node");
        assert_eq!(nodes[1].protocol, "trojan");
    }

    #[test]
    fn parse_singbox_json_basic() {
        let json = r#"{
            "outbounds": [
                {"type": "direct", "tag": "direct"},
                {"type": "vless", "tag": "my-vless", "server": "example.com", "server_port": 443, "uuid": "test-uuid"},
                {"type": "trojan", "tag": "my-trojan", "server": "trojan.com", "server_port": 443, "password": "pass"}
            ]
        }"#;
        let nodes = parse_singbox_json(json).unwrap();
        assert_eq!(nodes.len(), 2); // direct is skipped
        assert_eq!(nodes[0].name, "my-vless");
        assert_eq!(nodes[0].protocol, "vless");
        assert_eq!(nodes[1].name, "my-trojan");
    }

    #[test]
    fn dedup_nodes_removes_duplicates() {
        let nodes = vec![
            ProxyNode {
                name: "node1".to_string(),
                protocol: "ss".to_string(),
                address: "1.2.3.4".to_string(),
                port: 8388,
                settings: HashMap::new(),
            },
            ProxyNode {
                name: "node2".to_string(),
                protocol: "ss".to_string(),
                address: "1.2.3.4".to_string(),
                port: 8388,
                settings: HashMap::new(),
            },
            ProxyNode {
                name: "node3".to_string(),
                protocol: "trojan".to_string(),
                address: "1.2.3.4".to_string(),
                port: 443,
                settings: HashMap::new(),
            },
        ];
        let deduped = dedup_nodes(nodes);
        assert_eq!(deduped.len(), 2); // same protocol+addr+port = 1 + different protocol = 1
    }

    #[test]
    fn parse_host_port_ipv4() {
        let (host, port) = parse_host_port("1.2.3.4:443").unwrap();
        assert_eq!(host, "1.2.3.4");
        assert_eq!(port, 443);
    }

    #[test]
    fn parse_host_port_domain() {
        let (host, port) = parse_host_port("example.com:8080").unwrap();
        assert_eq!(host, "example.com");
        assert_eq!(port, 8080);
    }

    #[test]
    fn parse_host_port_ipv6() {
        let (host, port) = parse_host_port("[::1]:53").unwrap();
        assert_eq!(host, "::1");
        assert_eq!(port, 53);
    }

    #[test]
    fn url_decode() {
        assert_eq!(urlencoding_decode("Hello%20World"), "Hello World");
        assert_eq!(urlencoding_decode("test+space"), "test space");
        assert_eq!(urlencoding_decode("no%2Fslash"), "no/slash");
    }

    // --- SIP008 tests ---

    #[test]
    fn detect_sip008_format() {
        let json = r#"{"version": 1, "servers": [{"server": "1.2.3.4", "server_port": 8388}]}"#;
        assert_eq!(detect_format(json), SubFormat::Sip008);
    }

    #[test]
    fn parse_sip008_basic() {
        let json = r#"{
            "version": 1,
            "servers": [
                {
                    "id": "id1",
                    "remarks": "US Node",
                    "server": "1.2.3.4",
                    "server_port": 8388,
                    "password": "pass123",
                    "method": "aes-256-gcm"
                },
                {
                    "server": "5.6.7.8",
                    "server_port": 8389,
                    "password": "pass456",
                    "method": "chacha20-ietf-poly1305",
                    "plugin": "obfs-local",
                    "plugin_opts": "obfs=http;obfs-host=example.com"
                }
            ]
        }"#;
        let nodes = parse_sip008(json).unwrap();
        assert_eq!(nodes.len(), 2);
        assert_eq!(nodes[0].name, "US Node");
        assert_eq!(nodes[0].address, "1.2.3.4");
        assert_eq!(nodes[0].port, 8388);
        assert_eq!(nodes[0].settings.get("method").unwrap(), "aes-256-gcm");
        assert_eq!(nodes[1].settings.get("plugin").unwrap(), "obfs-local");
    }

    #[test]
    fn parse_sip008_empty_servers() {
        let json = r#"{"version": 1, "servers": []}"#;
        let nodes = parse_sip008(json).unwrap();
        assert!(nodes.is_empty());
    }

    #[test]
    fn parse_sip008_no_remarks_uses_index() {
        let json = r#"{"version": 1, "servers": [{"server": "1.2.3.4", "server_port": 8388, "password": "pw", "method": "aes-256-gcm"}]}"#;
        let nodes = parse_sip008(json).unwrap();
        assert_eq!(nodes[0].name, "ss-0");
    }

    #[test]
    fn parse_subscription_auto_detect_sip008() {
        let json = r#"{"version": 1, "servers": [{"server": "1.2.3.4", "server_port": 8388, "password": "pw", "method": "aes-256-gcm"}]}"#;
        let nodes = parse_subscription(json).unwrap();
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].protocol, "ss");
    }

    #[test]
    fn parse_subscription_unknown_format() {
        assert!(parse_subscription("not valid anything").is_err());
    }

    // --- Subscription Rollback tests ---

    #[test]
    fn rollback_save_and_latest() {
        let mut rb = SubscriptionRollback::new(5);
        let snap = SubscriptionSnapshot::new("http://sub.example.com".to_string(), vec![]);
        rb.save("sub1", snap);
        assert_eq!(rb.history_count("sub1"), 1);
        assert!(rb.latest("sub1").is_some());
    }

    #[test]
    fn rollback_returns_previous_version() {
        let mut rb = SubscriptionRollback::new(5);
        let snap1 = SubscriptionSnapshot::new(
            "v1".to_string(),
            vec![ProxyNode {
                name: "node1".to_string(),
                protocol: "ss".to_string(),
                address: "1.1.1.1".to_string(),
                port: 8388,
                settings: HashMap::new(),
            }],
        );
        let snap2 = SubscriptionSnapshot::new("v2".to_string(), vec![]);
        rb.save("sub1", snap1);
        rb.save("sub1", snap2);
        let rolled_back = rb.rollback("sub1").unwrap();
        assert_eq!(rolled_back.source, "v1");
        assert_eq!(rolled_back.node_count(), 1);
    }

    #[test]
    fn rollback_max_history() {
        let mut rb = SubscriptionRollback::new(3);
        for i in 0..5 {
            rb.save("sub1", SubscriptionSnapshot::new(format!("v{}", i), vec![]));
        }
        assert_eq!(rb.history_count("sub1"), 3);
        assert_eq!(rb.latest("sub1").unwrap().source, "v4");
    }

    #[test]
    fn rollback_clear() {
        let mut rb = SubscriptionRollback::new(5);
        rb.save("sub1", SubscriptionSnapshot::new("v1".to_string(), vec![]));
        rb.clear("sub1");
        assert_eq!(rb.history_count("sub1"), 0);
        assert!(rb.latest("sub1").is_none());
    }

    #[test]
    fn rollback_nonexistent_subscription() {
        let rb = SubscriptionRollback::new(5);
        assert!(rb.rollback("nonexistent").is_none());
        assert!(rb.latest("nonexistent").is_none());
    }

    #[test]
    fn snapshot_with_etag() {
        let snap =
            SubscriptionSnapshot::new("url".to_string(), vec![]).with_etag("W/\"abc\"".to_string());
        assert_eq!(snap.etag, Some("W/\"abc\"".to_string()));
    }

    // --- SubscriptionParser trait tests ---

    #[test]
    fn registry_has_builtin_parsers() {
        let registry = SubscriptionRegistry::new();
        assert!(registry.has_parser("base64"));
        assert!(registry.has_parser("clash-yaml"));
        assert!(registry.has_parser("singbox"));
        assert!(registry.has_parser("sip008"));
        assert_eq!(registry.len(), 4);
    }

    #[test]
    fn registry_parse_with_builtin() {
        let registry = SubscriptionRegistry::new();
        let json = r#"{"version": 1, "servers": [{"server": "1.2.3.4", "server_port": 8388, "password": "pw", "method": "aes-256-gcm"}]}"#;
        let nodes = registry.parse_with("sip008", json).unwrap();
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].protocol, "ss");
    }

    #[test]
    fn registry_parse_with_unknown_fails() {
        let registry = SubscriptionRegistry::new();
        let result = registry.parse_with("nonexistent", "data");
        assert!(result.is_err());
    }

    struct MockParser;
    impl SubscriptionParser for MockParser {
        fn parse(&self, _content: &str) -> Result<Vec<ProxyNode>> {
            Ok(vec![ProxyNode {
                name: "mock-node".to_string(),
                protocol: "mock".to_string(),
                address: "127.0.0.1".to_string(),
                port: 1234,
                settings: HashMap::new(),
            }])
        }
        fn name(&self) -> &str {
            "mock"
        }
    }

    #[test]
    fn registry_register_custom_parser() {
        let mut registry = SubscriptionRegistry::new();
        registry.register_parser("custom", Box::new(MockParser));
        assert!(registry.has_parser("custom"));
        let nodes = registry.parse_with("custom", "anything").unwrap();
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].name, "mock-node");
        assert_eq!(nodes[0].protocol, "mock");
    }

    #[test]
    fn registry_parser_names() {
        let registry = SubscriptionRegistry::new();
        let names = registry.parser_names();
        assert!(names.contains(&"base64"));
        assert!(names.contains(&"clash-yaml"));
        assert!(names.contains(&"singbox"));
        assert!(names.contains(&"sip008"));
    }
}
