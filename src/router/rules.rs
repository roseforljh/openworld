use std::fmt;

use anyhow::Result;
use ipnet::IpNet;

use crate::common::Address;
use crate::config::types::RuleConfig;

/// 路由规则
pub enum Rule {
    /// 域名后缀匹配
    DomainSuffix(Vec<String>),
    /// 域名关键字匹配
    DomainKeyword(Vec<String>),
    /// 域名完全匹配
    DomainFull(Vec<String>),
    /// IP CIDR 匹配
    IpCidr(Vec<IpNet>),
}

impl Rule {
    pub fn from_config(config: &RuleConfig) -> Result<Self> {
        match config.rule_type.as_str() {
            "domain-suffix" => Ok(Rule::DomainSuffix(config.values.clone())),
            "domain-keyword" => Ok(Rule::DomainKeyword(config.values.clone())),
            "domain-full" => Ok(Rule::DomainFull(config.values.clone())),
            "ip-cidr" => {
                let nets: Result<Vec<IpNet>, _> = config
                    .values
                    .iter()
                    .map(|s| s.parse::<IpNet>())
                    .collect();
                Ok(Rule::IpCidr(nets?))
            }
            other => anyhow::bail!("unsupported rule type: {}", other),
        }
    }

    pub fn matches(&self, addr: &Address) -> bool {
        match self {
            Rule::DomainSuffix(suffixes) => {
                if let Address::Domain(domain, _) = addr {
                    let domain_lower = domain.to_lowercase();
                    suffixes.iter().any(|suffix| {
                        let suffix_lower = suffix.to_lowercase();
                        domain_lower == suffix_lower
                            || domain_lower.ends_with(&format!(".{}", suffix_lower))
                    })
                } else {
                    false
                }
            }
            Rule::DomainKeyword(keywords) => {
                if let Address::Domain(domain, _) = addr {
                    let domain_lower = domain.to_lowercase();
                    keywords
                        .iter()
                        .any(|kw| domain_lower.contains(&kw.to_lowercase()))
                } else {
                    false
                }
            }
            Rule::DomainFull(domains) => {
                if let Address::Domain(domain, _) = addr {
                    let domain_lower = domain.to_lowercase();
                    domains
                        .iter()
                        .any(|d| d.to_lowercase() == domain_lower)
                } else {
                    false
                }
            }
            Rule::IpCidr(nets) => {
                if let Address::Ip(sock_addr) = addr {
                    let ip = sock_addr.ip();
                    nets.iter().any(|net| net.contains(&ip))
                } else {
                    false
                }
            }
        }
    }
}

impl fmt::Display for Rule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Rule::DomainSuffix(v) => write!(f, "domain-suffix({})", v.join(",")),
            Rule::DomainKeyword(v) => write!(f, "domain-keyword({})", v.join(",")),
            Rule::DomainFull(v) => write!(f, "domain-full({})", v.join(",")),
            Rule::IpCidr(v) => {
                let strs: Vec<String> = v.iter().map(|n| n.to_string()).collect();
                write!(f, "ip-cidr({})", strs.join(","))
            }
        }
    }
}
