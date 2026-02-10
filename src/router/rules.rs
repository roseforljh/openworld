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

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;

    fn domain(s: &str, port: u16) -> Address {
        Address::Domain(s.to_string(), port)
    }

    fn ip(s: &str) -> Address {
        Address::Ip(s.parse::<SocketAddr>().unwrap())
    }

    // DomainSuffix
    #[test]
    fn domain_suffix_match() {
        let rule = Rule::DomainSuffix(vec!["example.com".to_string()]);
        assert!(rule.matches(&domain("www.example.com", 443)));
        assert!(rule.matches(&domain("example.com", 443)));
        assert!(!rule.matches(&domain("notexample.com", 443)));
        assert!(!rule.matches(&domain("example.org", 443)));
    }

    #[test]
    fn domain_suffix_case_insensitive() {
        let rule = Rule::DomainSuffix(vec!["Example.COM".to_string()]);
        assert!(rule.matches(&domain("WWW.EXAMPLE.COM", 443)));
        assert!(rule.matches(&domain("www.example.com", 443)));
    }

    #[test]
    fn domain_suffix_no_match_ip() {
        let rule = Rule::DomainSuffix(vec!["example.com".to_string()]);
        assert!(!rule.matches(&ip("1.2.3.4:443")));
    }

    #[test]
    fn domain_suffix_cn() {
        let rule = Rule::DomainSuffix(vec!["cn".to_string()]);
        assert!(rule.matches(&domain("baidu.cn", 80)));
        assert!(rule.matches(&domain("www.gov.cn", 443)));
        assert!(!rule.matches(&domain("cnn.com", 443)));
    }

    // DomainKeyword
    #[test]
    fn domain_keyword_match() {
        let rule = Rule::DomainKeyword(vec!["google".to_string()]);
        assert!(rule.matches(&domain("www.google.com", 443)));
        assert!(rule.matches(&domain("google.co.jp", 443)));
        assert!(!rule.matches(&domain("example.com", 443)));
    }

    #[test]
    fn domain_keyword_no_match_ip() {
        let rule = Rule::DomainKeyword(vec!["google".to_string()]);
        assert!(!rule.matches(&ip("8.8.8.8:53")));
    }

    // DomainFull
    #[test]
    fn domain_full_match() {
        let rule = Rule::DomainFull(vec!["example.com".to_string()]);
        assert!(rule.matches(&domain("example.com", 443)));
        assert!(!rule.matches(&domain("www.example.com", 443)));
        assert!(!rule.matches(&domain("example.com.cn", 443)));
    }

    #[test]
    fn domain_full_case_insensitive() {
        let rule = Rule::DomainFull(vec!["Example.COM".to_string()]);
        assert!(rule.matches(&domain("example.com", 443)));
    }

    // IpCidr
    #[test]
    fn ip_cidr_match() {
        let rule = Rule::IpCidr(vec!["192.168.0.0/16".parse().unwrap()]);
        assert!(rule.matches(&ip("192.168.1.1:80")));
        assert!(rule.matches(&ip("192.168.255.255:443")));
        assert!(!rule.matches(&ip("10.0.0.1:80")));
    }

    #[test]
    fn ip_cidr_no_match_domain() {
        let rule = Rule::IpCidr(vec!["10.0.0.0/8".parse().unwrap()]);
        assert!(!rule.matches(&domain("example.com", 80)));
    }

    #[test]
    fn ip_cidr_multiple() {
        let rule = Rule::IpCidr(vec![
            "10.0.0.0/8".parse().unwrap(),
            "172.16.0.0/12".parse().unwrap(),
            "192.168.0.0/16".parse().unwrap(),
        ]);
        assert!(rule.matches(&ip("10.1.2.3:80")));
        assert!(rule.matches(&ip("172.16.0.1:80")));
        assert!(rule.matches(&ip("192.168.0.1:80")));
        assert!(!rule.matches(&ip("8.8.8.8:53")));
    }

    // from_config
    #[test]
    fn from_config_domain_suffix() {
        let config = RuleConfig {
            rule_type: "domain-suffix".to_string(),
            values: vec!["cn".to_string(), "baidu.com".to_string()],
            outbound: "direct".to_string(),
        };
        let rule = Rule::from_config(&config).unwrap();
        assert!(rule.matches(&domain("www.baidu.com", 443)));
        assert!(rule.matches(&domain("test.cn", 80)));
    }

    #[test]
    fn from_config_invalid_type() {
        let config = RuleConfig {
            rule_type: "unknown-type".to_string(),
            values: vec![],
            outbound: "direct".to_string(),
        };
        assert!(Rule::from_config(&config).is_err());
    }

    #[test]
    fn from_config_invalid_cidr() {
        let config = RuleConfig {
            rule_type: "ip-cidr".to_string(),
            values: vec!["not-a-cidr".to_string()],
            outbound: "direct".to_string(),
        };
        assert!(Rule::from_config(&config).is_err());
    }

    // Display
    #[test]
    fn display_format() {
        let rule = Rule::DomainSuffix(vec!["cn".to_string(), "com".to_string()]);
        assert_eq!(format!("{}", rule), "domain-suffix(cn,com)");
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
