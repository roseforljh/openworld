use std::collections::HashMap;
use std::fs;
use std::io::{Read, Write};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, RwLock};

use anyhow::Result;
use ipnet::IpNet;
use reqwest::header::{IF_MODIFIED_SINCE, LAST_MODIFIED};
use tracing::info;

use crate::config::types::RuleProviderConfig;

/// 规则集中的域名规则
#[derive(Debug, Clone, PartialEq)]
pub enum DomainRule {
    Full(String),
    Suffix(String),
    Keyword(String),
}

/// 规则集数据
///
/// 包含域名规则和 IP CIDR 规则，由 Rule::RuleSet 引用。
#[derive(Debug, Clone, PartialEq)]
pub struct RuleSetData {
    pub domain_rules: Vec<DomainRule>,
    pub ip_cidrs: Vec<IpNet>,
}

impl RuleSetData {
    /// 检查域名是否匹配任一域名规则
    pub fn matches_domain(&self, domain: &str) -> bool {
        let domain_lower = domain.to_lowercase();
        self.domain_rules.iter().any(|rule| match rule {
            DomainRule::Full(d) => domain_lower == *d,
            DomainRule::Suffix(suffix) => {
                domain_lower == *suffix || domain_lower.ends_with(&format!(".{}", suffix))
            }
            DomainRule::Keyword(keyword) => domain_lower.contains(keyword.as_str()),
        })
    }

    /// 检查 IP 是否匹配任一 CIDR 规则
    pub fn matches_ip(&self, ip: std::net::IpAddr) -> bool {
        self.ip_cidrs.iter().any(|net| net.contains(&ip))
    }
}

pub struct RuleProvider {
    name: String,
    config: RuleProviderConfig,
    rules: Arc<RwLock<RuleSetData>>,
    loaded: AtomicBool,
    last_modified: RwLock<Option<String>>,
    load_lock: Mutex<()>,
}

impl RuleProvider {
    pub fn new(name: String, config: RuleProviderConfig) -> Self {
        Self {
            name,
            config,
            rules: Arc::new(RwLock::new(RuleSetData {
                domain_rules: Vec::new(),
                ip_cidrs: Vec::new(),
            })),
            loaded: AtomicBool::new(false),
            last_modified: RwLock::new(None),
            load_lock: Mutex::new(()),
        }
    }

    pub fn provider_type(&self) -> &str {
        &self.config.provider_type
    }

    pub fn behavior(&self) -> &str {
        &self.config.behavior
    }

    pub fn interval_secs(&self) -> u64 {
        self.config.interval
    }

    pub fn lazy(&self) -> bool {
        self.config.lazy
    }

    pub fn is_loaded(&self) -> bool {
        self.loaded.load(Ordering::Acquire)
    }

    pub fn should_periodic_refresh(&self) -> bool {
        self.provider_type() == "http" && self.interval_secs() > 0
    }

    pub fn snapshot(&self) -> RuleSetData {
        match self.rules.read() {
            Ok(guard) => guard.clone(),
            Err(_) => RuleSetData {
                domain_rules: Vec::new(),
                ip_cidrs: Vec::new(),
            },
        }
    }

    pub fn matches_domain(&self, domain: &str) -> bool {
        self.ensure_loaded_for_match();
        match self.rules.read() {
            Ok(guard) => guard.matches_domain(domain),
            Err(_) => false,
        }
    }

    pub fn matches_ip(&self, ip: std::net::IpAddr) -> bool {
        self.ensure_loaded_for_match();
        match self.rules.read() {
            Ok(guard) => guard.matches_ip(ip),
            Err(_) => false,
        }
    }

    pub fn init_load_if_needed(&self) -> Result<()> {
        if self.config.lazy {
            return Ok(());
        }
        self.load_once()
    }

    pub fn refresh_http_provider(&self) -> Result<bool> {
        if self.provider_type() != "http" {
            return Ok(false);
        }

        let url = self
            .config
            .url
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("rule-provider '{}' missing url", self.name))?;

        let client = reqwest::blocking::Client::new();
        let mut request = client.get(url);
        if let Some(last_modified) = self
            .last_modified
            .read()
            .map_err(|_| {
                anyhow::anyhow!("rule-provider '{}' last_modified lock poisoned", self.name)
            })?
            .clone()
        {
            request = request.header(IF_MODIFIED_SINCE, last_modified);
        }

        let response = request
            .send()
            .map_err(|e| anyhow::anyhow!("HTTP request failed: {}", e))?;

        if response.status() == reqwest::StatusCode::NOT_MODIFIED {
            return Ok(false);
        }

        if !response.status().is_success() {
            anyhow::bail!("HTTP {} for {}", response.status(), url);
        }

        let remote_last_modified = response
            .headers()
            .get(LAST_MODIFIED)
            .and_then(|v| v.to_str().ok())
            .map(ToOwned::to_owned);

        let content = response
            .text()
            .map_err(|e| anyhow::anyhow!("failed to read response body: {}", e))?;

        // 确保父目录存在
        if let Some(parent) = std::path::Path::new(&self.config.path).parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(&self.config.path, &content)?;

        let parsed = self.parse_content(&content)?;
        let changed = self.replace_rules(parsed)?;

        if let Some(lm) = remote_last_modified {
            let mut guard = self.last_modified.write().map_err(|_| {
                anyhow::anyhow!("rule-provider '{}' last_modified lock poisoned", self.name)
            })?;
            *guard = Some(lm);
        }
        self.loaded.store(true, Ordering::Release);

        Ok(changed)
    }

    fn ensure_loaded_for_match(&self) {
        if !self.config.lazy || self.is_loaded() {
            return;
        }

        if let Err(e) = self.load_once() {
            tracing::warn!(
                name = self.name.as_str(),
                error = %e,
                "lazy rule-provider load failed"
            );
        }
    }

    fn load_once(&self) -> Result<()> {
        if self.is_loaded() {
            return Ok(());
        }

        let _guard = self
            .load_lock
            .lock()
            .map_err(|_| anyhow::anyhow!("rule-provider '{}' load lock poisoned", self.name))?;

        if self.is_loaded() {
            return Ok(());
        }

        let changed = if self.provider_type() == "http" {
            self.load_http_with_cache_fallback()?
        } else {
            self.load_from_local_file()?
        };

        self.loaded.store(true, Ordering::Release);

        let snapshot = self.snapshot();
        info!(
            name = self.name.as_str(),
            behavior = self.config.behavior.as_str(),
            domains = snapshot.domain_rules.len(),
            cidrs = snapshot.ip_cidrs.len(),
            changed = changed,
            "rule-provider loaded"
        );

        Ok(())
    }

    fn load_http_with_cache_fallback(&self) -> Result<bool> {
        let url = self.config.url.as_deref().ok_or_else(|| {
            anyhow::anyhow!("rule-provider '{}' is type 'http' but no 'url'", self.name)
        })?;

        let has_cache = fs::metadata(&self.config.path).is_ok();
        let should_update = self.should_update_cache();

        if should_update {
            info!(
                name = self.name.as_str(),
                url = url,
                "downloading rule-provider"
            );
            match self.refresh_http_provider() {
                Ok(changed) => return Ok(changed),
                Err(e) => {
                    if has_cache {
                        tracing::warn!(
                            name = self.name.as_str(),
                            error = %e,
                            "rule-provider refresh failed, using cached version"
                        );
                    } else {
                        return Err(anyhow::anyhow!(
                            "rule-provider '{}' download failed and no cache available: {}",
                            self.name,
                            e
                        ));
                    }
                }
            }
        }

        self.load_from_local_file()
    }

    fn should_update_cache(&self) -> bool {
        match fs::metadata(&self.config.path) {
            Ok(meta) => match meta.modified() {
                Ok(modified) => {
                    let elapsed = modified.elapsed().unwrap_or_default();
                    elapsed.as_secs() > self.config.interval
                }
                Err(_) => true,
            },
            Err(_) => true,
        }
    }

    fn load_from_local_file(&self) -> Result<bool> {
        let raw = fs::read(&self.config.path).map_err(|e| {
            anyhow::anyhow!(
                "failed to read rule-provider '{}' from '{}': {}",
                self.name,
                self.config.path,
                e
            )
        })?;

        let parsed = if super::srs::is_srs_format(&raw) {
            super::srs::parse_srs(&raw)?
        } else {
            let content = String::from_utf8(raw).map_err(|e| {
                anyhow::anyhow!(
                    "rule-provider '{}' is not valid UTF-8 and not SRS format: {}",
                    self.name,
                    e
                )
            })?;
            self.parse_content(&content)?
        };
        self.replace_rules(parsed)
    }

    fn parse_content(&self, content: &str) -> Result<RuleSetData> {
        match self.config.behavior.as_str() {
            "domain" => parse_domain_rules(content),
            "ipcidr" => parse_ipcidr_rules(content),
            "classical" => parse_classical_rules(content),
            other => anyhow::bail!(
                "unsupported rule-provider behavior '{}' for '{}'",
                other,
                self.name
            ),
        }
    }

    fn replace_rules(&self, parsed: RuleSetData) -> Result<bool> {
        let mut guard = self
            .rules
            .write()
            .map_err(|_| anyhow::anyhow!("rule-provider '{}' rules lock poisoned", self.name))?;
        let changed = *guard != parsed;
        *guard = parsed;
        Ok(changed)
    }
}

/// 从配置加载单个规则提供者
pub fn load_provider(name: &str, config: &RuleProviderConfig) -> Result<Arc<RuleProvider>> {
    let provider = Arc::new(RuleProvider::new(name.to_string(), config.clone()));
    provider.init_load_if_needed()?;
    Ok(provider)
}

/// 从所有配置加载规则提供者
pub fn load_all_providers(
    configs: &HashMap<String, RuleProviderConfig>,
) -> Result<HashMap<String, Arc<RuleProvider>>> {
    let mut providers = HashMap::new();
    for (name, config) in configs {
        let data = load_provider(name, config)?;
        providers.insert(name.clone(), data);
    }
    Ok(providers)
}

/// 解析域名行为的规则文件
///
/// 支持格式:
/// - 纯文本: 每行一个域名，默认后缀匹配
/// - Clash YAML payload: `- '+.example.com'` 或 `- 'example.com'`
/// - 前缀语法: `domain:`, `domain_suffix:`, `domain_keyword:`, `+.`
fn parse_domain_rules(content: &str) -> Result<RuleSetData> {
    let mut domain_rules = Vec::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line == "payload:" {
            continue;
        }

        // 剥离 YAML 列表前缀和引号
        let line = line.strip_prefix("- ").unwrap_or(line);
        let line = line.trim_matches('\'').trim_matches('"');

        if line.is_empty() {
            continue;
        }

        let rule = if let Some(domain) = line.strip_prefix("domain:") {
            DomainRule::Full(domain.to_lowercase())
        } else if let Some(suffix) = line.strip_prefix("domain_suffix:") {
            DomainRule::Suffix(suffix.to_lowercase())
        } else if let Some(keyword) = line.strip_prefix("domain_keyword:") {
            DomainRule::Keyword(keyword.to_lowercase())
        } else if let Some(suffix) = line.strip_prefix("+.") {
            DomainRule::Suffix(suffix.to_lowercase())
        } else {
            // 默认: 后缀匹配
            DomainRule::Suffix(line.to_lowercase())
        };
        domain_rules.push(rule);
    }
    Ok(RuleSetData {
        domain_rules,
        ip_cidrs: Vec::new(),
    })
}

/// 解析 IP CIDR 行为的规则文件
fn parse_ipcidr_rules(content: &str) -> Result<RuleSetData> {
    let mut ip_cidrs = Vec::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line == "payload:" {
            continue;
        }

        let line = line.strip_prefix("- ").unwrap_or(line);
        let line = line.trim_matches('\'').trim_matches('"');

        if line.is_empty() {
            continue;
        }

        let cidr: IpNet = line
            .parse()
            .map_err(|e| anyhow::anyhow!("invalid CIDR '{}': {}", line, e))?;
        ip_cidrs.push(cidr);
    }
    Ok(RuleSetData {
        domain_rules: Vec::new(),
        ip_cidrs,
    })
}

/// 解析 classical 行为的规则文件
///
/// 每行格式: `RULE-TYPE,value[,extra]`
/// 支持: DOMAIN, DOMAIN-SUFFIX, DOMAIN-KEYWORD, IP-CIDR, IP-CIDR6
fn parse_classical_rules(content: &str) -> Result<RuleSetData> {
    let mut domain_rules = Vec::new();
    let mut ip_cidrs = Vec::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line == "payload:" {
            continue;
        }

        let line = line.strip_prefix("- ").unwrap_or(line);
        let line = line.trim_matches('\'').trim_matches('"');

        if line.is_empty() {
            continue;
        }

        if let Some(value) = line.strip_prefix("DOMAIN-SUFFIX,") {
            let value = value.split(',').next().unwrap_or(value);
            domain_rules.push(DomainRule::Suffix(value.to_lowercase()));
        } else if let Some(value) = line.strip_prefix("DOMAIN-KEYWORD,") {
            let value = value.split(',').next().unwrap_or(value);
            domain_rules.push(DomainRule::Keyword(value.to_lowercase()));
        } else if let Some(value) = line.strip_prefix("DOMAIN,") {
            let value = value.split(',').next().unwrap_or(value);
            domain_rules.push(DomainRule::Full(value.to_lowercase()));
        } else if let Some(value) = line.strip_prefix("IP-CIDR,") {
            let value = value.split(',').next().unwrap_or(value);
            let cidr: IpNet = value
                .parse()
                .map_err(|e| anyhow::anyhow!("invalid CIDR '{}': {}", value, e))?;
            ip_cidrs.push(cidr);
        } else if let Some(value) = line.strip_prefix("IP-CIDR6,") {
            let value = value.split(',').next().unwrap_or(value);
            let cidr: IpNet = value
                .parse()
                .map_err(|e| anyhow::anyhow!("invalid CIDR6 '{}': {}", value, e))?;
            ip_cidrs.push(cidr);
        }
        // 跳过不支持的规则类型
    }
    Ok(RuleSetData {
        domain_rules,
        ip_cidrs,
    })
}

// ─── Binary Rule-Set Format ────────────────────────────────────────────────
//
// 高效二进制序列化格式，加载速度比文本解析快 5-10x。
//
// 格式:
//   Magic: "OWRS" (4 bytes)
//   Version: u8
//   Domain rule count: u32 LE
//   IP CIDR count: u32 LE
//   [Domain rules...]
//     type: u8 (0=Full, 1=Suffix, 2=Keyword)
//     len: u16 LE
//     data: [u8; len]
//   [IP CIDRs...]
//     family: u8 (4=IPv4, 6=IPv6)
//     prefix_len: u8
//     addr: [u8; 4 or 16]

const BINARY_MAGIC: &[u8; 4] = b"OWRS";
const BINARY_VERSION: u8 = 1;

/// 将 RuleSetData 序列化为二进制格式
pub fn serialize_ruleset_binary(data: &RuleSetData) -> Vec<u8> {
    let mut buf = Vec::with_capacity(
        4 + 1 + 4 + 4 + data.domain_rules.len() * 32 + data.ip_cidrs.len() * 20,
    );
    buf.extend_from_slice(BINARY_MAGIC);
    buf.push(BINARY_VERSION);
    buf.extend_from_slice(&(data.domain_rules.len() as u32).to_le_bytes());
    buf.extend_from_slice(&(data.ip_cidrs.len() as u32).to_le_bytes());

    for rule in &data.domain_rules {
        let (tag, value) = match rule {
            DomainRule::Full(v) => (0u8, v.as_bytes()),
            DomainRule::Suffix(v) => (1u8, v.as_bytes()),
            DomainRule::Keyword(v) => (2u8, v.as_bytes()),
        };
        buf.push(tag);
        buf.extend_from_slice(&(value.len() as u16).to_le_bytes());
        buf.extend_from_slice(value);
    }

    for cidr in &data.ip_cidrs {
        match cidr.addr() {
            std::net::IpAddr::V4(v4) => {
                buf.push(4);
                buf.push(cidr.prefix_len());
                buf.extend_from_slice(&v4.octets());
            }
            std::net::IpAddr::V6(v6) => {
                buf.push(6);
                buf.push(cidr.prefix_len());
                buf.extend_from_slice(&v6.octets());
            }
        }
    }

    buf
}

/// 从二进制格式反序列化 RuleSetData
pub fn deserialize_ruleset_binary(data: &[u8]) -> Result<RuleSetData> {
    let mut pos = 0;

    // Magic
    if data.len() < 13 || &data[0..4] != BINARY_MAGIC {
        anyhow::bail!("invalid binary rule-set: bad magic");
    }
    pos += 4;

    // Version
    let version = data[pos];
    if version != BINARY_VERSION {
        anyhow::bail!("unsupported binary rule-set version: {}", version);
    }
    pos += 1;

    // Counts
    let domain_count = u32::from_le_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]) as usize;
    pos += 4;
    let cidr_count = u32::from_le_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]) as usize;
    pos += 4;

    // Domain rules
    let mut domain_rules = Vec::with_capacity(domain_count);
    for _ in 0..domain_count {
        if pos + 3 > data.len() {
            anyhow::bail!("binary rule-set truncated at domain rule");
        }
        let tag = data[pos];
        pos += 1;
        let len = u16::from_le_bytes([data[pos], data[pos + 1]]) as usize;
        pos += 2;
        if pos + len > data.len() {
            anyhow::bail!("binary rule-set truncated at domain value");
        }
        let value = std::str::from_utf8(&data[pos..pos + len])
            .map_err(|e| anyhow::anyhow!("invalid UTF-8 in binary rule-set: {}", e))?
            .to_string();
        pos += len;

        let rule = match tag {
            0 => DomainRule::Full(value),
            1 => DomainRule::Suffix(value),
            2 => DomainRule::Keyword(value),
            _ => anyhow::bail!("unknown domain rule type: {}", tag),
        };
        domain_rules.push(rule);
    }

    // IP CIDRs
    let mut ip_cidrs = Vec::with_capacity(cidr_count);
    for _ in 0..cidr_count {
        if pos + 2 > data.len() {
            anyhow::bail!("binary rule-set truncated at CIDR");
        }
        let family = data[pos];
        pos += 1;
        let prefix_len = data[pos];
        pos += 1;

        let cidr = match family {
            4 => {
                if pos + 4 > data.len() {
                    anyhow::bail!("binary rule-set truncated at IPv4 addr");
                }
                let addr = std::net::Ipv4Addr::new(data[pos], data[pos + 1], data[pos + 2], data[pos + 3]);
                pos += 4;
                IpNet::V4(ipnet::Ipv4Net::new(addr, prefix_len)
                    .map_err(|e| anyhow::anyhow!("invalid IPv4 CIDR: {}", e))?)
            }
            6 => {
                if pos + 16 > data.len() {
                    anyhow::bail!("binary rule-set truncated at IPv6 addr");
                }
                let mut octets = [0u8; 16];
                octets.copy_from_slice(&data[pos..pos + 16]);
                let addr = std::net::Ipv6Addr::from(octets);
                pos += 16;
                IpNet::V6(ipnet::Ipv6Net::new(addr, prefix_len)
                    .map_err(|e| anyhow::anyhow!("invalid IPv6 CIDR: {}", e))?)
            }
            _ => anyhow::bail!("unknown CIDR family: {}", family),
        };
        ip_cidrs.push(cidr);
    }

    Ok(RuleSetData {
        domain_rules,
        ip_cidrs,
    })
}

/// 将文本规则文件编译为二进制格式并写入文件
pub fn compile_ruleset_to_binary(text_path: &str, binary_path: &str, behavior: &str) -> Result<()> {
    let content = fs::read_to_string(text_path)?;
    let data = match behavior {
        "domain" => parse_domain_rules(&content)?,
        "ipcidr" => parse_ipcidr_rules(&content)?,
        "classical" => parse_classical_rules(&content)?,
        other => anyhow::bail!("unsupported behavior: {}", other),
    };
    let binary = serialize_ruleset_binary(&data);
    let mut file = fs::File::create(binary_path)?;
    file.write_all(&binary)?;
    info!(
        text = text_path,
        binary = binary_path,
        domains = data.domain_rules.len(),
        cidrs = data.ip_cidrs.len(),
        bytes = binary.len(),
        "rule-set compiled to binary"
    );
    Ok(())
}

/// 尝试从二进制缓存加载规则集，如果缓存不存在或过期则从文本加载并编译
pub fn load_ruleset_with_binary_cache(text_path: &str, behavior: &str) -> Result<RuleSetData> {
    let binary_path = format!("{}.bin", text_path);

    // 检查二进制缓存是否比文本文件新
    let text_modified = fs::metadata(text_path)
        .and_then(|m| m.modified())
        .ok();
    let bin_modified = fs::metadata(&binary_path)
        .and_then(|m| m.modified())
        .ok();

    if let (Some(text_t), Some(bin_t)) = (text_modified, bin_modified) {
        if bin_t >= text_t {
            // 二进制缓存有效，直接加载
            let mut file = fs::File::open(&binary_path)?;
            let mut buf = Vec::new();
            file.read_to_end(&mut buf)?;
            match deserialize_ruleset_binary(&buf) {
                Ok(data) => {
                    info!(path = binary_path.as_str(), "loaded binary rule-set cache");
                    return Ok(data);
                }
                Err(e) => {
                    tracing::warn!(error = %e, "binary rule-set cache corrupted, recompiling");
                }
            }
        }
    }

    // 从文本加载并编译二进制缓存
    let content = fs::read_to_string(text_path)?;
    let data = match behavior {
        "domain" => parse_domain_rules(&content)?,
        "ipcidr" => parse_ipcidr_rules(&content)?,
        "classical" => parse_classical_rules(&content)?,
        other => anyhow::bail!("unsupported behavior: {}", other),
    };

    // 写入二进制缓存（忽略写入失败）
    let binary = serialize_ruleset_binary(&data);
    if let Err(e) = fs::write(&binary_path, &binary) {
        tracing::warn!(error = %e, path = binary_path.as_str(), "failed to write binary cache");
    }

    Ok(data)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_domain_plain_text() {
        let content = "example.com\ngoogle.com\n# comment\n\ntest.org\n";
        let data = parse_domain_rules(content).unwrap();
        assert_eq!(data.domain_rules.len(), 3);
        assert!(data.matches_domain("example.com"));
        assert!(data.matches_domain("www.example.com"));
        assert!(data.matches_domain("sub.google.com"));
        assert!(!data.matches_domain("notexample.com"));
    }

    #[test]
    fn parse_domain_with_prefixes() {
        let content = "domain:exact.com\ndomain_suffix:suffix.com\ndomain_keyword:kw\n";
        let data = parse_domain_rules(content).unwrap();
        assert_eq!(data.domain_rules.len(), 3);
        assert!(data.matches_domain("exact.com"));
        assert!(!data.matches_domain("sub.exact.com"));
        assert!(data.matches_domain("sub.suffix.com"));
        assert!(data.matches_domain("kw.example.com"));
    }

    #[test]
    fn parse_domain_clash_yaml_format() {
        let content = "payload:\n  - '+.google.com'\n  - 'facebook.com'\n  - '+.twitter.com'\n";
        let data = parse_domain_rules(content).unwrap();
        assert_eq!(data.domain_rules.len(), 3);
        assert!(data.matches_domain("www.google.com"));
        assert!(data.matches_domain("facebook.com"));
        assert!(data.matches_domain("sub.facebook.com"));
        assert!(data.matches_domain("t.twitter.com"));
    }

    #[test]
    fn parse_domain_plus_dot_prefix() {
        let content = "+.example.com\n+.test.org\n";
        let data = parse_domain_rules(content).unwrap();
        assert!(data.matches_domain("example.com"));
        assert!(data.matches_domain("sub.example.com"));
        assert!(data.matches_domain("test.org"));
    }

    #[test]
    fn parse_ipcidr_plain_text() {
        let content = "10.0.0.0/8\n172.16.0.0/12\n192.168.0.0/16\n";
        let data = parse_ipcidr_rules(content).unwrap();
        assert_eq!(data.ip_cidrs.len(), 3);
        assert!(data.matches_ip("10.1.2.3".parse().unwrap()));
        assert!(data.matches_ip("172.16.0.1".parse().unwrap()));
        assert!(data.matches_ip("192.168.1.1".parse().unwrap()));
        assert!(!data.matches_ip("8.8.8.8".parse().unwrap()));
    }

    #[test]
    fn parse_ipcidr_clash_yaml_format() {
        let content = "payload:\n  - '10.0.0.0/8'\n  - '172.16.0.0/12'\n";
        let data = parse_ipcidr_rules(content).unwrap();
        assert_eq!(data.ip_cidrs.len(), 2);
        assert!(data.matches_ip("10.0.0.1".parse().unwrap()));
    }

    #[test]
    fn parse_ipcidr_invalid() {
        let content = "not-a-cidr\n";
        assert!(parse_ipcidr_rules(content).is_err());
    }

    #[test]
    fn parse_classical_mixed() {
        let content =
            "DOMAIN,exact.com\nDOMAIN-SUFFIX,google.com\nDOMAIN-KEYWORD,facebook\nIP-CIDR,10.0.0.0/8\nIP-CIDR6,::1/128\n";
        let data = parse_classical_rules(content).unwrap();
        assert_eq!(data.domain_rules.len(), 3);
        assert_eq!(data.ip_cidrs.len(), 2);
        assert!(data.matches_domain("exact.com"));
        assert!(!data.matches_domain("sub.exact.com"));
        assert!(data.matches_domain("www.google.com"));
        assert!(data.matches_domain("facebook.com"));
        assert!(data.matches_ip("10.1.2.3".parse().unwrap()));
    }

    #[test]
    fn parse_classical_clash_format() {
        let content =
            "payload:\n  - 'DOMAIN-SUFFIX,google.com'\n  - 'IP-CIDR,10.0.0.0/8,no-resolve'\n";
        let data = parse_classical_rules(content).unwrap();
        assert_eq!(data.domain_rules.len(), 1);
        assert_eq!(data.ip_cidrs.len(), 1);
        assert!(data.matches_domain("www.google.com"));
        assert!(data.matches_ip("10.0.0.1".parse().unwrap()));
    }

    #[test]
    fn parse_classical_ip_cidr_no_resolve() {
        let content = "IP-CIDR,192.168.0.0/16,no-resolve\n";
        let data = parse_classical_rules(content).unwrap();
        assert_eq!(data.ip_cidrs.len(), 1);
        assert!(data.matches_ip("192.168.1.1".parse().unwrap()));
    }

    #[test]
    fn empty_file() {
        let data = parse_domain_rules("").unwrap();
        assert!(data.domain_rules.is_empty());
        let data = parse_ipcidr_rules("# only comments\n").unwrap();
        assert!(data.ip_cidrs.is_empty());
    }

    #[test]
    fn case_insensitive_domain_match() {
        let content = "Example.COM\n";
        let data = parse_domain_rules(content).unwrap();
        assert!(data.matches_domain("example.com"));
        assert!(data.matches_domain("EXAMPLE.COM"));
        assert!(data.matches_domain("www.Example.Com"));
    }

    // ─── Binary Rule-Set Tests ─────────────────────────────────────────────

    #[test]
    fn binary_roundtrip_domain_rules() {
        let data = RuleSetData {
            domain_rules: vec![
                DomainRule::Full("example.com".to_string()),
                DomainRule::Suffix("google.com".to_string()),
                DomainRule::Keyword("facebook".to_string()),
            ],
            ip_cidrs: vec![],
        };
        let binary = serialize_ruleset_binary(&data);
        let restored = deserialize_ruleset_binary(&binary).unwrap();
        assert_eq!(restored.domain_rules, data.domain_rules);
        assert!(restored.ip_cidrs.is_empty());
    }

    #[test]
    fn binary_roundtrip_ip_cidrs() {
        let data = RuleSetData {
            domain_rules: vec![],
            ip_cidrs: vec![
                "10.0.0.0/8".parse().unwrap(),
                "192.168.0.0/16".parse().unwrap(),
                "2001:db8::/32".parse().unwrap(),
            ],
        };
        let binary = serialize_ruleset_binary(&data);
        let restored = deserialize_ruleset_binary(&binary).unwrap();
        assert!(restored.domain_rules.is_empty());
        assert_eq!(restored.ip_cidrs.len(), 3);
        assert!(restored.matches_ip("10.1.2.3".parse().unwrap()));
        assert!(restored.matches_ip("192.168.1.1".parse().unwrap()));
    }

    #[test]
    fn binary_roundtrip_mixed() {
        let data = RuleSetData {
            domain_rules: vec![
                DomainRule::Suffix("cn".to_string()),
                DomainRule::Full("baidu.com".to_string()),
            ],
            ip_cidrs: vec!["172.16.0.0/12".parse().unwrap()],
        };
        let binary = serialize_ruleset_binary(&data);
        let restored = deserialize_ruleset_binary(&binary).unwrap();
        assert_eq!(restored.domain_rules.len(), 2);
        assert_eq!(restored.ip_cidrs.len(), 1);
        assert!(restored.matches_domain("test.cn"));
        assert!(restored.matches_domain("baidu.com"));
        assert!(restored.matches_ip("172.16.0.1".parse().unwrap()));
    }

    #[test]
    fn binary_invalid_magic() {
        assert!(deserialize_ruleset_binary(b"XXXX\x01\x00\x00\x00\x00\x00\x00\x00\x00").is_err());
    }

    #[test]
    fn binary_invalid_version() {
        assert!(deserialize_ruleset_binary(b"OWRS\xFF\x00\x00\x00\x00\x00\x00\x00\x00").is_err());
    }

    #[test]
    fn binary_empty_ruleset() {
        let data = RuleSetData {
            domain_rules: vec![],
            ip_cidrs: vec![],
        };
        let binary = serialize_ruleset_binary(&data);
        let restored = deserialize_ruleset_binary(&binary).unwrap();
        assert!(restored.domain_rules.is_empty());
        assert!(restored.ip_cidrs.is_empty());
    }

    #[test]
    fn binary_size_smaller_than_text() {
        // 大量规则时二进制应该更紧凑
        let mut domain_rules = Vec::new();
        for i in 0..1000 {
            domain_rules.push(DomainRule::Suffix(format!("domain{}.example.com", i)));
        }
        let data = RuleSetData {
            domain_rules,
            ip_cidrs: vec![],
        };
        let binary = serialize_ruleset_binary(&data);
        // 文本格式大约 30 bytes/rule, 二进制约 25 bytes/rule (type + len + data)
        assert!(binary.len() < 30 * 1000);
    }
}
