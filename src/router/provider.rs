use std::collections::HashMap;
use std::fs;
use std::sync::Arc;

use anyhow::Result;
use ipnet::IpNet;
use tracing::info;

use crate::config::types::RuleProviderConfig;

/// 规则集中的域名规则
#[derive(Debug, Clone)]
pub enum DomainRule {
    Full(String),
    Suffix(String),
    Keyword(String),
}

/// 规则集数据
///
/// 包含域名规则和 IP CIDR 规则，由 Rule::RuleSet 引用。
#[derive(Debug)]
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

/// 下载规则提供者到本地文件
fn download_provider(url: &str, path: &str) -> Result<()> {
    let response = reqwest::blocking::get(url)
        .map_err(|e| anyhow::anyhow!("HTTP request failed: {}", e))?;

    if !response.status().is_success() {
        anyhow::bail!("HTTP {} for {}", response.status(), url);
    }

    let content = response
        .text()
        .map_err(|e| anyhow::anyhow!("failed to read response body: {}", e))?;

    // 确保父目录存在
    if let Some(parent) = std::path::Path::new(path).parent() {
        fs::create_dir_all(parent)?;
    }

    fs::write(path, &content)?;
    Ok(())
}

/// 从配置加载单个规则提供者
pub fn load_provider(name: &str, config: &RuleProviderConfig) -> Result<Arc<RuleSetData>> {
    // 如果是 http 类型，尝试下载
    if config.provider_type == "http" {
        if let Some(ref url) = config.url {
            // 检查本地缓存是否过期
            let needs_update = match fs::metadata(&config.path) {
                Ok(meta) => match meta.modified() {
                    Ok(modified) => {
                        let elapsed = modified.elapsed().unwrap_or_default();
                        elapsed.as_secs() > config.interval
                    }
                    Err(_) => true,
                },
                Err(_) => true, // 文件不存在
            };

            if needs_update {
                info!(name = name, url = url.as_str(), "downloading rule-provider");
                match download_provider(url, &config.path) {
                    Ok(_) => {
                        info!(
                            name = name,
                            path = config.path.as_str(),
                            "rule-provider downloaded and cached"
                        );
                    }
                    Err(e) => {
                        // 下载失败，检查是否有本地缓存
                        if fs::metadata(&config.path).is_ok() {
                            tracing::warn!(
                                name = name,
                                error = %e,
                                "rule-provider download failed, using cached version"
                            );
                        } else {
                            return Err(anyhow::anyhow!(
                                "rule-provider '{}' download failed and no cache available: {}",
                                name,
                                e
                            ));
                        }
                    }
                }
            }
        } else {
            anyhow::bail!(
                "rule-provider '{}' is type 'http' but no 'url' is configured",
                name
            );
        }
    }

    // 从本地文件读取
    let content = fs::read_to_string(&config.path).map_err(|e| {
        anyhow::anyhow!(
            "failed to read rule-provider '{}' from '{}': {}",
            name,
            config.path,
            e
        )
    })?;

    let data = match config.behavior.as_str() {
        "domain" => parse_domain_rules(&content)?,
        "ipcidr" => parse_ipcidr_rules(&content)?,
        "classical" => parse_classical_rules(&content)?,
        other => anyhow::bail!(
            "unsupported rule-provider behavior '{}' for '{}'",
            other,
            name
        ),
    };

    info!(
        name = name,
        behavior = config.behavior.as_str(),
        domains = data.domain_rules.len(),
        cidrs = data.ip_cidrs.len(),
        "rule-provider loaded"
    );
    Ok(Arc::new(data))
}

/// 从所有配置加载规则提供者
pub fn load_all_providers(
    configs: &HashMap<String, RuleProviderConfig>,
) -> Result<HashMap<String, Arc<RuleSetData>>> {
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
}
