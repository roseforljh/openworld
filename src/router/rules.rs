use std::fmt;
use std::sync::{Arc, OnceLock};

use anyhow::Result;
use ipnet::IpNet;

use crate::common::Address;
use crate::config::types::RuleConfig;

use super::process::{extract_process_name, ProcessDetector};
use super::provider::RuleProvider;

/// 获取当前连接的 WIFI SSID（跨平台）。
///
/// - Windows: `netsh wlan show interfaces`
/// - macOS: `/System/Library/PrivateFrameworks/Apple80211.framework/...`
/// - Linux: `iwgetid -r` 或 `nmcli -t -f active,ssid dev wifi`
/// - Android/iOS: 通过 FFI 回调获取（由宿主 app 设置）
///
/// 返回 `None` 表示未连接 WIFI 或无法检测。
fn get_current_wifi_ssid() -> Option<String> {
    // 优先检查 FFI 设置的 SSID（Android/iOS）
    {
        let guard = CURRENT_WIFI_SSID.lock().ok()?;
        if let Some(ref ssid) = *guard {
            return Some(ssid.clone());
        }
    }

    // 平台原生检测
    #[cfg(target_os = "windows")]
    {
        detect_wifi_ssid_windows()
    }
    #[cfg(target_os = "macos")]
    {
        detect_wifi_ssid_macos()
    }
    #[cfg(target_os = "linux")]
    {
        detect_wifi_ssid_linux()
    }
    #[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
    {
        None
    }
}

/// FFI: 由宿主 app 设置当前 WIFI SSID（Android/iOS）
static CURRENT_WIFI_SSID: std::sync::Mutex<Option<String>> = std::sync::Mutex::new(None);

/// 由 FFI 层调用，设置当前 WIFI SSID
pub fn set_current_wifi_ssid(ssid: Option<String>) {
    if let Ok(mut guard) = CURRENT_WIFI_SSID.lock() {
        *guard = ssid;
    }
}

#[cfg(target_os = "windows")]
fn detect_wifi_ssid_windows() -> Option<String> {
    let output = std::process::Command::new("netsh")
        .args(["wlan", "show", "interfaces"])
        .output()
        .ok()?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    for line in stdout.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("SSID")
            && !trimmed.starts_with("SSID ")
            && !trimmed.contains("BSSID")
        {
            // "SSID                   : MyWifi" 或 "SSID : MyWifi"
            if let Some(pos) = trimmed.find(':') {
                let ssid = trimmed[pos + 1..].trim();
                if !ssid.is_empty() {
                    return Some(ssid.to_string());
                }
            }
        }
    }
    None
}

#[cfg(target_os = "macos")]
fn detect_wifi_ssid_macos() -> Option<String> {
    // macOS 14.4+: 使用 system_profiler
    let output = std::process::Command::new("/usr/sbin/networksetup")
        .args(["-getairportnetwork", "en0"])
        .output()
        .ok()?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    // "Current Wi-Fi Network: MyWifi"
    if let Some(pos) = stdout.find(": ") {
        let ssid = stdout[pos + 2..].trim();
        if !ssid.is_empty() {
            return Some(ssid.to_string());
        }
    }
    None
}

#[cfg(target_os = "linux")]
fn detect_wifi_ssid_linux() -> Option<String> {
    // 方法1: iwgetid
    if let Ok(output) = std::process::Command::new("iwgetid").arg("-r").output() {
        let ssid = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if !ssid.is_empty() {
            return Some(ssid);
        }
    }
    // 方法2: nmcli
    if let Ok(output) = std::process::Command::new("nmcli")
        .args(["-t", "-f", "active,ssid", "dev", "wifi"])
        .output()
    {
        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines() {
            if line.starts_with("yes:") {
                return Some(line[4..].to_string());
            }
        }
    }
    None
}

/// 路由规则
pub enum Rule {
    /// 域名后缀匹配
    DomainSuffix(Vec<String>),
    /// 域名关键字匹配
    DomainKeyword(Vec<String>),
    /// 域名完全匹配
    DomainFull(Vec<String>),
    /// 域名正则匹配
    DomainRegex(Vec<regex::Regex>),
    /// IP CIDR 匹配
    IpCidr(Vec<IpNet>),
    /// GeoIP 国家代码匹配
    GeoIp(Vec<String>),
    /// GeoSite 分类匹配
    GeoSite(Vec<String>),
    /// 规则集匹配（引用规则提供者）
    RuleSet {
        name: String,
        data: Arc<RuleProvider>,
    },
    /// 目标端口匹配
    DstPort(Vec<u16>),
    /// 源端口匹配
    SrcPort(Vec<u16>),
    /// 网络类型匹配 (tcp/udp)
    Network(String),
    /// 入站标签匹配
    InTag(Vec<String>),
    /// 进程名匹配
    ProcessName(Vec<String>),
    /// 进程路径匹配
    ProcessPath(Vec<String>),
    /// IP ASN (自治系统号) 匹配
    IpAsn(Vec<u32>),
    /// UID 匹配 (Android/Linux 用户 ID)
    Uid(Vec<u32>),
    /// 嗅探协议类型匹配 (tls, http, quic, bittorrent, ssh, stun, dtls)
    Protocol(Vec<String>),
    /// 逻辑 AND: all sub-rules must match
    And(Vec<Rule>),
    /// 逻辑 OR: any sub-rule must match
    Or(Vec<Rule>),
    /// 逻辑 NOT: inner rule must NOT match
    Not(Box<Rule>),
    /// WIFI SSID 匹配
    WifiSsid(Vec<String>),
}

/// 路由规则动作 (sing-box Rule Action 系统)
#[derive(Debug, Clone)]
pub enum RuleAction {
    /// 路由到指定出站（Final）
    Route(String),
    /// 拒绝连接（Final）
    Reject,
    /// 丢弃连接（Final）
    RejectDrop,
    /// 绕过代理/直连（Final）
    Bypass,
    /// 劫持 DNS 请求（Final）
    HijackDns,
    /// 覆盖目标地址/端口（Non-final）
    RouteOptions {
        override_address: Option<String>,
        override_port: Option<u16>,
    },
    /// 触发协议嗅探（Non-final）
    Sniff,
    /// 触发 DNS 解析（Non-final）
    Resolve { strategy: Option<String> },
}

impl RuleAction {
    pub fn from_config(config: &crate::config::types::RuleConfig) -> Self {
        match config.action.as_str() {
            "reject" => RuleAction::Reject,
            "reject-drop" => RuleAction::RejectDrop,
            "bypass" | "direct" => RuleAction::Bypass,
            "hijack-dns" => RuleAction::HijackDns,
            "route-options" => RuleAction::RouteOptions {
                override_address: config.override_address.clone(),
                override_port: config.override_port,
            },
            "sniff" => RuleAction::Sniff,
            "resolve" => RuleAction::Resolve {
                strategy: config.resolve_strategy.clone(),
            },
            _ => RuleAction::Route(config.outbound.clone()),
        }
    }

    pub fn is_final(&self) -> bool {
        matches!(
            self,
            RuleAction::Route(_)
                | RuleAction::Reject
                | RuleAction::RejectDrop
                | RuleAction::Bypass
                | RuleAction::HijackDns
        )
    }

    pub fn outbound_tag(&self) -> Option<&str> {
        match self {
            RuleAction::Route(tag) => Some(tag),
            RuleAction::Bypass => Some("direct"),
            _ => None,
        }
    }
}

impl fmt::Display for RuleAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RuleAction::Route(tag) => write!(f, "route({})", tag),
            RuleAction::Reject => write!(f, "reject"),
            RuleAction::RejectDrop => write!(f, "reject-drop"),
            RuleAction::Bypass => write!(f, "bypass"),
            RuleAction::HijackDns => write!(f, "hijack-dns"),
            RuleAction::RouteOptions { .. } => write!(f, "route-options"),
            RuleAction::Sniff => write!(f, "sniff"),
            RuleAction::Resolve { .. } => write!(f, "resolve"),
        }
    }
}

impl Rule {
    pub fn from_config(config: &RuleConfig) -> Result<Self> {
        match config.rule_type.as_str() {
            "domain-suffix" => Ok(Rule::DomainSuffix(config.values.clone())),
            "domain-keyword" => Ok(Rule::DomainKeyword(config.values.clone())),
            "domain-full" => Ok(Rule::DomainFull(config.values.clone())),
            "domain-regex" => {
                let regexes: Result<Vec<regex::Regex>, _> =
                    config.values.iter().map(|s| regex::Regex::new(s)).collect();
                Ok(Rule::DomainRegex(regexes.map_err(|e| {
                    anyhow::anyhow!("invalid domain regex: {}", e)
                })?))
            }
            "ip-cidr" => {
                let nets: Result<Vec<IpNet>, _> =
                    config.values.iter().map(|s| s.parse::<IpNet>()).collect();
                Ok(Rule::IpCidr(nets?))
            }
            "geoip" => Ok(Rule::GeoIp(
                config.values.iter().map(|s| s.to_uppercase()).collect(),
            )),
            "geosite" => Ok(Rule::GeoSite(
                config.values.iter().map(|s| s.to_lowercase()).collect(),
            )),
            "dst-port" => {
                let ports: Result<Vec<u16>, _> =
                    config.values.iter().map(|s| s.parse::<u16>()).collect();
                Ok(Rule::DstPort(ports?))
            }
            "src-port" => {
                let ports: Result<Vec<u16>, _> =
                    config.values.iter().map(|s| s.parse::<u16>()).collect();
                Ok(Rule::SrcPort(ports?))
            }
            "network" => {
                let network = config
                    .values
                    .first()
                    .cloned()
                    .unwrap_or_default()
                    .to_lowercase();
                Ok(Rule::Network(network))
            }
            "in-tag" => Ok(Rule::InTag(config.values.clone())),
            "process-name" => Ok(Rule::ProcessName(config.values.clone())),
            "process-path" => Ok(Rule::ProcessPath(config.values.clone())),
            "ip-asn" => {
                let asns: Result<Vec<u32>, _> =
                    config.values.iter().map(|s| s.parse::<u32>()).collect();
                Ok(Rule::IpAsn(
                    asns.map_err(|e| anyhow::anyhow!("invalid ASN: {}", e))?,
                ))
            }
            "uid" => {
                let uids: Result<Vec<u32>, _> =
                    config.values.iter().map(|s| s.parse::<u32>()).collect();
                Ok(Rule::Uid(
                    uids.map_err(|e| anyhow::anyhow!("invalid UID: {}", e))?,
                ))
            }
            "protocol" => Ok(Rule::Protocol(
                config.values.iter().map(|s| s.to_lowercase()).collect(),
            )),
            "and" | "AND" => {
                let sub_rules: Result<Vec<Rule>> = config
                    .values
                    .iter()
                    .map(|v| {
                        let parts: Vec<&str> = v.splitn(2, ':').collect();
                        if parts.len() != 2 {
                            anyhow::bail!("AND sub-rule must be 'type:value', got '{}'", v);
                        }
                        let sub_config = RuleConfig {
                            rule_type: parts[0].to_string(),
                            values: vec![parts[1].to_string()],
                            outbound: config.outbound.clone(),
                            ..Default::default()
                        };
                        Rule::from_config(&sub_config)
                    })
                    .collect();
                Ok(Rule::And(sub_rules?))
            }
            "or" | "OR" => {
                let sub_rules: Result<Vec<Rule>> = config
                    .values
                    .iter()
                    .map(|v| {
                        let parts: Vec<&str> = v.splitn(2, ':').collect();
                        if parts.len() != 2 {
                            anyhow::bail!("OR sub-rule must be 'type:value', got '{}'", v);
                        }
                        let sub_config = RuleConfig {
                            rule_type: parts[0].to_string(),
                            values: vec![parts[1].to_string()],
                            outbound: config.outbound.clone(),
                            ..Default::default()
                        };
                        Rule::from_config(&sub_config)
                    })
                    .collect();
                Ok(Rule::Or(sub_rules?))
            }
            "not" | "NOT" => {
                let v = config
                    .values
                    .first()
                    .ok_or_else(|| anyhow::anyhow!("NOT rule requires exactly one sub-rule"))?;
                let parts: Vec<&str> = v.splitn(2, ':').collect();
                if parts.len() != 2 {
                    anyhow::bail!("NOT sub-rule must be 'type:value', got '{}'", v);
                }
                let sub_config = RuleConfig {
                    rule_type: parts[0].to_string(),
                    values: vec![parts[1].to_string()],
                    outbound: config.outbound.clone(),
                    ..Default::default()
                };
                Ok(Rule::Not(Box::new(Rule::from_config(&sub_config)?)))
            }
            "wifi-ssid" | "ssid" => Ok(Rule::WifiSsid(config.values.clone())),
            other => anyhow::bail!("unsupported rule type: {}", other),
        }
    }

    pub fn matches(
        &self,
        addr: &Address,
        geoip_db: Option<&super::geoip::GeoIpDb>,
        geosite_db: Option<&super::geosite::GeoSiteDb>,
    ) -> bool {
        self.matches_session(addr, geoip_db, geosite_db, None, None, None, None)
    }

    pub fn matches_session(
        &self,
        addr: &Address,
        geoip_db: Option<&super::geoip::GeoIpDb>,
        geosite_db: Option<&super::geosite::GeoSiteDb>,
        source: Option<std::net::SocketAddr>,
        network: Option<&str>,
        inbound_tag: Option<&str>,
        detected_protocol: Option<&str>,
    ) -> bool {
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
                    domains.iter().any(|d| d.to_lowercase() == domain_lower)
                } else {
                    false
                }
            }
            Rule::DomainRegex(regexes) => {
                if let Address::Domain(domain, _) = addr {
                    regexes.iter().any(|re| re.is_match(domain))
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
            Rule::GeoIp(codes) => {
                if let Address::Ip(sock_addr) = addr {
                    if let Some(db) = geoip_db {
                        if let Some(country) = db.lookup_country(sock_addr.ip()) {
                            let country_upper = country.to_uppercase();
                            return codes.iter().any(|c| c == &country_upper);
                        }
                    }
                }
                false
            }
            Rule::GeoSite(categories) => {
                if let Address::Domain(domain, _) = addr {
                    if let Some(db) = geosite_db {
                        return categories.iter().any(|cat| db.matches(domain, cat));
                    }
                }
                false
            }
            Rule::RuleSet { data, .. } => match addr {
                Address::Domain(domain, _) => data.matches_domain(domain),
                Address::Ip(sock_addr) => data.matches_ip(sock_addr.ip()),
            },
            Rule::DstPort(ports) => {
                let dst_port = match addr {
                    Address::Ip(sock_addr) => sock_addr.port(),
                    Address::Domain(_, port) => *port,
                };
                ports.contains(&dst_port)
            }
            Rule::SrcPort(ports) => {
                if let Some(src) = source {
                    ports.contains(&src.port())
                } else {
                    false
                }
            }
            Rule::Network(net) => {
                if let Some(n) = network {
                    n == net
                } else {
                    false
                }
            }
            Rule::InTag(tags) => {
                if let Some(tag) = inbound_tag {
                    tags.iter().any(|t| t == tag)
                } else {
                    false
                }
            }
            Rule::ProcessName(names) => {
                if let Some(src) = source {
                    if let Some(process_name) = process_detector().lookup(&src) {
                        return names.iter().any(|name| {
                            process_name.eq_ignore_ascii_case(name)
                                || process_name.eq_ignore_ascii_case(&extract_process_name(name))
                        });
                    }
                }
                false
            }
            Rule::ProcessPath(paths) => {
                if let Some(src) = source {
                    if let Some(process_path) = process_detector().lookup_path(&src) {
                        return paths
                            .iter()
                            .any(|path| process_path_matches(path, &process_path));
                    }
                }
                false
            }
            Rule::IpAsn(_asns) => {
                // IP ASN matching requires an ASN database (e.g., MaxMind GeoLite2-ASN).
                // Currently a stub — always returns false.
                false
            }
            Rule::Uid(_uids) => {
                // UID matching requires OS-specific APIs (Android/Linux).
                // Currently a stub — always returns false.
                false
            }
            Rule::Protocol(protocols) => {
                if let Some(proto) = detected_protocol {
                    protocols.iter().any(|p| p == proto)
                } else {
                    false
                }
            }
            Rule::And(sub_rules) => sub_rules.iter().all(|r| {
                r.matches_session(
                    addr,
                    geoip_db,
                    geosite_db,
                    source,
                    network,
                    inbound_tag,
                    detected_protocol,
                )
            }),
            Rule::Or(sub_rules) => sub_rules.iter().any(|r| {
                r.matches_session(
                    addr,
                    geoip_db,
                    geosite_db,
                    source,
                    network,
                    inbound_tag,
                    detected_protocol,
                )
            }),
            Rule::Not(inner) => !inner.matches_session(
                addr,
                geoip_db,
                geosite_db,
                source,
                network,
                inbound_tag,
                detected_protocol,
            ),
            Rule::WifiSsid(ssids) => {
                if let Some(current) = get_current_wifi_ssid() {
                    ssids.iter().any(|s| s.eq_ignore_ascii_case(&current))
                } else {
                    false
                }
            }
        }
    }
}

fn process_detector() -> &'static ProcessDetector {
    static DETECTOR: OnceLock<ProcessDetector> = OnceLock::new();
    DETECTOR.get_or_init(ProcessDetector::new)
}

fn process_path_matches(rule_path: &str, process_path: &str) -> bool {
    if cfg!(target_os = "windows") {
        rule_path.eq_ignore_ascii_case(process_path)
            || extract_process_name(rule_path)
                .eq_ignore_ascii_case(&extract_process_name(process_path))
    } else {
        rule_path == process_path
            || extract_process_name(rule_path) == extract_process_name(process_path)
    }
}

#[cfg(test)]
#[allow(clippy::items_after_test_module)]
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
        assert!(rule.matches(&domain("www.example.com", 443), None, None));
        assert!(rule.matches(&domain("example.com", 443), None, None));
        assert!(!rule.matches(&domain("notexample.com", 443), None, None));
        assert!(!rule.matches(&domain("example.org", 443), None, None));
    }

    #[test]
    fn domain_suffix_case_insensitive() {
        let rule = Rule::DomainSuffix(vec!["Example.COM".to_string()]);
        assert!(rule.matches(&domain("WWW.EXAMPLE.COM", 443), None, None));
        assert!(rule.matches(&domain("www.example.com", 443), None, None));
    }

    #[test]
    fn domain_suffix_no_match_ip() {
        let rule = Rule::DomainSuffix(vec!["example.com".to_string()]);
        assert!(!rule.matches(&ip("1.2.3.4:443"), None, None));
    }

    #[test]
    fn domain_suffix_cn() {
        let rule = Rule::DomainSuffix(vec!["cn".to_string()]);
        assert!(rule.matches(&domain("baidu.cn", 80), None, None));
        assert!(rule.matches(&domain("www.gov.cn", 443), None, None));
        assert!(!rule.matches(&domain("cnn.com", 443), None, None));
    }

    // DomainKeyword
    #[test]
    fn domain_keyword_match() {
        let rule = Rule::DomainKeyword(vec!["google".to_string()]);
        assert!(rule.matches(&domain("www.google.com", 443), None, None));
        assert!(rule.matches(&domain("google.co.jp", 443), None, None));
        assert!(!rule.matches(&domain("example.com", 443), None, None));
    }

    #[test]
    fn domain_keyword_no_match_ip() {
        let rule = Rule::DomainKeyword(vec!["google".to_string()]);
        assert!(!rule.matches(&ip("8.8.8.8:53"), None, None));
    }

    // DomainFull
    #[test]
    fn domain_full_match() {
        let rule = Rule::DomainFull(vec!["example.com".to_string()]);
        assert!(rule.matches(&domain("example.com", 443), None, None));
        assert!(!rule.matches(&domain("www.example.com", 443), None, None));
        assert!(!rule.matches(&domain("example.com.cn", 443), None, None));
    }

    #[test]
    fn domain_full_case_insensitive() {
        let rule = Rule::DomainFull(vec!["Example.COM".to_string()]);
        assert!(rule.matches(&domain("example.com", 443), None, None));
    }

    // IpCidr
    #[test]
    fn ip_cidr_match() {
        let rule = Rule::IpCidr(vec!["192.168.0.0/16".parse().unwrap()]);
        assert!(rule.matches(&ip("192.168.1.1:80"), None, None));
        assert!(rule.matches(&ip("192.168.255.255:443"), None, None));
        assert!(!rule.matches(&ip("10.0.0.1:80"), None, None));
    }

    #[test]
    fn ip_cidr_no_match_domain() {
        let rule = Rule::IpCidr(vec!["10.0.0.0/8".parse().unwrap()]);
        assert!(!rule.matches(&domain("example.com", 80), None, None));
    }

    #[test]
    fn ip_cidr_multiple() {
        let rule = Rule::IpCidr(vec![
            "10.0.0.0/8".parse().unwrap(),
            "172.16.0.0/12".parse().unwrap(),
            "192.168.0.0/16".parse().unwrap(),
        ]);
        assert!(rule.matches(&ip("10.1.2.3:80"), None, None));
        assert!(rule.matches(&ip("172.16.0.1:80"), None, None));
        assert!(rule.matches(&ip("192.168.0.1:80"), None, None));
        assert!(!rule.matches(&ip("8.8.8.8:53"), None, None));
    }

    // from_config
    #[test]
    fn from_config_domain_suffix() {
        let config = RuleConfig {
            rule_type: "domain-suffix".to_string(),
            values: vec!["cn".to_string(), "baidu.com".to_string()],
            outbound: "direct".to_string(),
            ..Default::default()
        };
        let rule = Rule::from_config(&config).unwrap();
        assert!(rule.matches(&domain("www.baidu.com", 443), None, None));
        assert!(rule.matches(&domain("test.cn", 80), None, None));
    }

    #[test]
    fn from_config_invalid_type() {
        let config = RuleConfig {
            rule_type: "unknown-type".to_string(),
            values: vec![],
            outbound: "direct".to_string(),
            ..Default::default()
        };
        assert!(Rule::from_config(&config).is_err());
    }

    #[test]
    fn from_config_invalid_cidr() {
        let config = RuleConfig {
            rule_type: "ip-cidr".to_string(),
            values: vec!["not-a-cidr".to_string()],
            outbound: "direct".to_string(),
            ..Default::default()
        };
        assert!(Rule::from_config(&config).is_err());
    }

    // Display
    #[test]
    fn display_format() {
        let rule = Rule::DomainSuffix(vec!["cn".to_string(), "com".to_string()]);
        assert_eq!(format!("{}", rule), "domain-suffix(cn,com)");
    }

    // AND rule
    #[test]
    fn and_rule_all_match() {
        let config = RuleConfig {
            rule_type: "and".to_string(),
            values: vec![
                "domain-suffix:example.com".to_string(),
                "dst-port:443".to_string(),
            ],
            outbound: "proxy".to_string(),
            ..Default::default()
        };
        let rule = Rule::from_config(&config).unwrap();
        assert!(rule.matches(&domain("www.example.com", 443), None, None));
        assert!(!rule.matches(&domain("www.example.com", 80), None, None));
        assert!(!rule.matches(&domain("other.org", 443), None, None));
    }

    #[test]
    fn and_rule_partial_match_fails() {
        let rule = Rule::And(vec![
            Rule::DomainSuffix(vec!["example.com".to_string()]),
            Rule::DstPort(vec![443]),
        ]);
        assert!(!rule.matches(&domain("www.example.com", 80), None, None));
    }

    // OR rule
    #[test]
    fn or_rule_any_match() {
        let config = RuleConfig {
            rule_type: "or".to_string(),
            values: vec![
                "domain-suffix:example.com".to_string(),
                "domain-suffix:google.com".to_string(),
            ],
            outbound: "proxy".to_string(),
            ..Default::default()
        };
        let rule = Rule::from_config(&config).unwrap();
        assert!(rule.matches(&domain("www.example.com", 443), None, None));
        assert!(rule.matches(&domain("www.google.com", 443), None, None));
        assert!(!rule.matches(&domain("www.other.org", 443), None, None));
    }

    // NOT rule
    #[test]
    fn not_rule_inverts() {
        let config = RuleConfig {
            rule_type: "not".to_string(),
            values: vec!["domain-suffix:cn".to_string()],
            outbound: "proxy".to_string(),
            ..Default::default()
        };
        let rule = Rule::from_config(&config).unwrap();
        assert!(!rule.matches(&domain("baidu.cn", 80), None, None));
        assert!(rule.matches(&domain("google.com", 443), None, None));
    }

    // PROCESS-NAME rule
    #[test]
    fn process_name_from_config() {
        let config = RuleConfig {
            rule_type: "process-name".to_string(),
            values: vec!["chrome.exe".to_string()],
            outbound: "direct".to_string(),
            ..Default::default()
        };
        let rule = Rule::from_config(&config).unwrap();
        // Process name matching is a stub, always returns false
        assert!(!rule.matches(&domain("example.com", 443), None, None));
    }

    // Display for new types
    #[test]
    fn display_and_rule() {
        let rule = Rule::And(vec![
            Rule::DomainSuffix(vec!["cn".to_string()]),
            Rule::DstPort(vec![443]),
        ]);
        let s = format!("{}", rule);
        assert!(s.starts_with("and("));
        assert!(s.contains("domain-suffix(cn)"));
        assert!(s.contains("dst-port(443)"));
    }

    #[test]
    fn display_or_rule() {
        let rule = Rule::Or(vec![
            Rule::Network("tcp".to_string()),
            Rule::Network("udp".to_string()),
        ]);
        let s = format!("{}", rule);
        assert!(s.starts_with("or("));
    }

    #[test]
    fn display_not_rule() {
        let rule = Rule::Not(Box::new(Rule::DomainKeyword(vec!["ad".to_string()])));
        assert_eq!(format!("{}", rule), "not(domain-keyword(ad))");
    }

    // DST-PORT and SRC-PORT
    #[test]
    fn dst_port_match() {
        let rule = Rule::DstPort(vec![80, 443]);
        assert!(rule.matches(&domain("example.com", 443), None, None));
        assert!(rule.matches(&ip("1.2.3.4:80"), None, None));
        assert!(!rule.matches(&domain("example.com", 8080), None, None));
    }

    #[test]
    fn src_port_match() {
        let rule = Rule::SrcPort(vec![12345]);
        let src: SocketAddr = "10.0.0.1:12345".parse().unwrap();
        assert!(rule.matches_session(
            &domain("example.com", 443),
            None,
            None,
            Some(src),
            None,
            None,
            None
        ));
        let other_src: SocketAddr = "10.0.0.1:54321".parse().unwrap();
        assert!(!rule.matches_session(
            &domain("example.com", 443),
            None,
            None,
            Some(other_src),
            None,
            None,
            None
        ));
    }

    // NETWORK rule
    #[test]
    fn network_rule_match() {
        let rule = Rule::Network("tcp".to_string());
        assert!(rule.matches_session(
            &domain("example.com", 443),
            None,
            None,
            None,
            Some("tcp"),
            None,
            None
        ));
        assert!(!rule.matches_session(
            &domain("example.com", 443),
            None,
            None,
            None,
            Some("udp"),
            None,
            None
        ));
    }

    // IN-TAG rule
    #[test]
    fn in_tag_rule_match() {
        let rule = Rule::InTag(vec!["socks-in".to_string()]);
        assert!(rule.matches_session(
            &domain("example.com", 443),
            None,
            None,
            None,
            None,
            Some("socks-in"),
            None
        ));
        assert!(!rule.matches_session(
            &domain("example.com", 443),
            None,
            None,
            None,
            None,
            Some("http-in"),
            None
        ));
    }

    // PROCESS-PATH rule
    #[test]
    fn process_path_from_config() {
        let config = RuleConfig {
            rule_type: "process-path".to_string(),
            values: vec!["/usr/bin/curl".to_string()],
            outbound: "direct".to_string(),
            ..Default::default()
        };
        let rule = Rule::from_config(&config).unwrap();
        // Stub — always false
        assert!(!rule.matches(&domain("example.com", 443), None, None));
    }

    #[test]
    fn process_path_display() {
        let rule = Rule::ProcessPath(vec!["/usr/bin/curl".to_string()]);
        assert_eq!(format!("{}", rule), "process-path(/usr/bin/curl)");
    }

    // IP-ASN rule
    #[test]
    fn ip_asn_from_config() {
        let config = RuleConfig {
            rule_type: "ip-asn".to_string(),
            values: vec!["13335".to_string(), "15169".to_string()],
            outbound: "proxy".to_string(),
            ..Default::default()
        };
        let rule = Rule::from_config(&config).unwrap();
        // Stub — always false
        assert!(!rule.matches(&ip("1.1.1.1:443"), None, None));
    }

    #[test]
    fn ip_asn_invalid_number() {
        let config = RuleConfig {
            rule_type: "ip-asn".to_string(),
            values: vec!["not-a-number".to_string()],
            outbound: "proxy".to_string(),
            ..Default::default()
        };
        assert!(Rule::from_config(&config).is_err());
    }

    #[test]
    fn ip_asn_display() {
        let rule = Rule::IpAsn(vec![13335, 15169]);
        assert_eq!(format!("{}", rule), "ip-asn(13335,15169)");
    }

    // Combined test: AND with new rule types
    #[test]
    fn and_with_dst_port_and_network() {
        let rule = Rule::And(vec![
            Rule::DstPort(vec![443]),
            Rule::Network("tcp".to_string()),
        ]);
        assert!(rule.matches_session(
            &domain("example.com", 443),
            None,
            None,
            None,
            Some("tcp"),
            None,
            None
        ));
        assert!(!rule.matches_session(
            &domain("example.com", 443),
            None,
            None,
            None,
            Some("udp"),
            None,
            None
        ));
        assert!(!rule.matches_session(
            &domain("example.com", 80),
            None,
            None,
            None,
            Some("tcp"),
            None,
            None
        ));
    }

    // UID rule
    #[test]
    fn uid_from_config() {
        let config = RuleConfig {
            rule_type: "uid".to_string(),
            values: vec!["1000".to_string(), "10086".to_string()],
            outbound: "direct".to_string(),
            ..Default::default()
        };
        let rule = Rule::from_config(&config).unwrap();
        // Stub — always false
        assert!(!rule.matches(&domain("example.com", 443), None, None));
    }

    #[test]
    fn uid_invalid_number() {
        let config = RuleConfig {
            rule_type: "uid".to_string(),
            values: vec!["not-a-uid".to_string()],
            outbound: "direct".to_string(),
            ..Default::default()
        };
        assert!(Rule::from_config(&config).is_err());
    }

    #[test]
    fn uid_display() {
        let rule = Rule::Uid(vec![1000, 10086]);
        assert_eq!(format!("{}", rule), "uid(1000,10086)");
    }

    // Domain Regex
    #[test]
    fn domain_regex_match() {
        let rule = Rule::DomainRegex(vec![regex::Regex::new(r"^(www\.)?google\.com$").unwrap()]);
        assert!(rule.matches(&domain("google.com", 443), None, None));
        assert!(rule.matches(&domain("www.google.com", 443), None, None));
        assert!(!rule.matches(&domain("notgoogle.com", 443), None, None));
        assert!(!rule.matches(&ip("8.8.8.8:53"), None, None));
    }

    #[test]
    fn domain_regex_from_config() {
        let config = RuleConfig {
            rule_type: "domain-regex".to_string(),
            values: vec![r".*\.ad\..*".to_string(), r"^tracker\.".to_string()],
            outbound: "reject".to_string(),
            ..Default::default()
        };
        let rule = Rule::from_config(&config).unwrap();
        assert!(rule.matches(&domain("cdn.ad.example.com", 80), None, None));
        assert!(rule.matches(&domain("tracker.example.com", 80), None, None));
        assert!(!rule.matches(&domain("example.com", 80), None, None));
    }

    #[test]
    fn domain_regex_invalid_pattern() {
        let config = RuleConfig {
            rule_type: "domain-regex".to_string(),
            values: vec![r"[invalid".to_string()],
            outbound: "reject".to_string(),
            ..Default::default()
        };
        assert!(Rule::from_config(&config).is_err());
    }

    #[test]
    fn domain_regex_display() {
        let rule = Rule::DomainRegex(vec![regex::Regex::new(r"^ad\.").unwrap()]);
        assert_eq!(format!("{}", rule), r"domain-regex(^ad\.)");
    }
}

impl fmt::Display for Rule {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Rule::DomainSuffix(v) => write!(f, "domain-suffix({})", v.join(",")),
            Rule::DomainKeyword(v) => write!(f, "domain-keyword({})", v.join(",")),
            Rule::DomainFull(v) => write!(f, "domain-full({})", v.join(",")),
            Rule::DomainRegex(v) => {
                let strs: Vec<String> = v.iter().map(|r| r.as_str().to_string()).collect();
                write!(f, "domain-regex({})", strs.join(","))
            }
            Rule::IpCidr(v) => {
                let strs: Vec<String> = v.iter().map(|n| n.to_string()).collect();
                write!(f, "ip-cidr({})", strs.join(","))
            }
            Rule::GeoIp(v) => write!(f, "geoip({})", v.join(",")),
            Rule::GeoSite(v) => write!(f, "geosite({})", v.join(",")),
            Rule::RuleSet { name, .. } => write!(f, "rule-set({})", name),
            Rule::DstPort(v) => {
                let strs: Vec<String> = v.iter().map(|p| p.to_string()).collect();
                write!(f, "dst-port({})", strs.join(","))
            }
            Rule::SrcPort(v) => {
                let strs: Vec<String> = v.iter().map(|p| p.to_string()).collect();
                write!(f, "src-port({})", strs.join(","))
            }
            Rule::Network(n) => write!(f, "network({})", n),
            Rule::InTag(v) => write!(f, "in-tag({})", v.join(",")),
            Rule::ProcessName(v) => write!(f, "process-name({})", v.join(",")),
            Rule::ProcessPath(v) => write!(f, "process-path({})", v.join(",")),
            Rule::IpAsn(v) => {
                let strs: Vec<String> = v.iter().map(|a| a.to_string()).collect();
                write!(f, "ip-asn({})", strs.join(","))
            }
            Rule::Uid(v) => {
                let strs: Vec<String> = v.iter().map(|u| u.to_string()).collect();
                write!(f, "uid({})", strs.join(","))
            }
            Rule::Protocol(v) => write!(f, "protocol({})", v.join(",")),
            Rule::And(rules) => {
                let strs: Vec<String> = rules.iter().map(|r| format!("{}", r)).collect();
                write!(f, "and({})", strs.join(","))
            }
            Rule::Or(rules) => {
                let strs: Vec<String> = rules.iter().map(|r| format!("{}", r)).collect();
                write!(f, "or({})", strs.join(","))
            }
            Rule::Not(inner) => write!(f, "not({})", inner),
            Rule::WifiSsid(v) => write!(f, "wifi-ssid({})", v.join(",")),
        }
    }
}
