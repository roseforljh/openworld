//! 轻量级脚本引擎
//!
//! 提供类 Lua 的规则表达式引擎，解析并执行路由决策脚本。
//! 脚本格式采用简洁的 DSL，例如：
//!
//! ```text
//! # 按域名匹配
//! when domain contains "google" => proxy
//! when domain suffix "cn" => direct
//! when ip cidr "10.0.0.0/8" => direct
//! when hour 0..6 => reject
//! when process "BitTorrent" => reject
//! default => proxy
//! ```

use std::fmt;
use std::net::IpAddr;

/// 脚本引擎错误
#[derive(Debug, Clone)]
pub enum ScriptError {
    ParseError { line: usize, message: String },
    RuntimeError(String),
    InvalidAction(String),
}

impl fmt::Display for ScriptError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ScriptError::ParseError { line, message } => {
                write!(f, "parse error at line {}: {}", line, message)
            }
            ScriptError::RuntimeError(msg) => write!(f, "runtime error: {}", msg),
            ScriptError::InvalidAction(msg) => write!(f, "invalid action: {}", msg),
        }
    }
}

impl std::error::Error for ScriptError {}

/// 编译后的脚本
#[derive(Debug, Clone)]
pub struct PluginScript {
    pub name: String,
    pub rules: Vec<ScriptRule>,
    pub default_action: String,
}

/// 单条规则
#[derive(Debug, Clone)]
pub struct ScriptRule {
    pub condition: Condition,
    pub action: String,
}

/// 匹配条件
#[derive(Debug, Clone)]
pub enum Condition {
    /// 域名包含子串
    DomainContains(String),
    /// 域名后缀匹配
    DomainSuffix(String),
    /// 域名完全匹配
    DomainFull(String),
    /// 域名关键词
    DomainKeyword(String),
    /// 域名正则
    DomainRegex(String),
    /// IP CIDR 匹配
    IpCidr { addr: IpAddr, prefix_len: u8 },
    /// 时间段匹配（小时范围）
    HourRange { start: u8, end: u8 },
    /// 进程名匹配
    ProcessName(String),
    /// 入站标签匹配
    InboundTag(String),
    /// 逻辑与
    And(Vec<Condition>),
    /// 逻辑或
    Or(Vec<Condition>),
    /// 逻辑非
    Not(Box<Condition>),
    /// 始终为真
    Always,
}

/// 脚本引擎
pub struct ScriptEngine;

impl ScriptEngine {
    /// 编译脚本文本 -> PluginScript
    pub fn compile(name: &str, source: &str) -> Result<PluginScript, ScriptError> {
        let mut rules = Vec::new();
        let mut default_action = String::from("direct");

        for (line_num, line) in source.lines().enumerate() {
            let line = line.trim();

            // 跳过空行和注释
            if line.is_empty() || line.starts_with('#') || line.starts_with("//") {
                continue;
            }

            if let Some(rest) = line.strip_prefix("default") {
                // default => action
                let rest = rest.trim();
                if let Some(action) = rest.strip_prefix("=>") {
                    default_action = action.trim().to_string();
                } else {
                    return Err(ScriptError::ParseError {
                        line: line_num + 1,
                        message: "expected '=>' after 'default'".into(),
                    });
                }
            } else if let Some(rest) = line.strip_prefix("when ") {
                // when <condition> => <action>
                let parts: Vec<&str> = rest.splitn(2, "=>").collect();
                if parts.len() != 2 {
                    return Err(ScriptError::ParseError {
                        line: line_num + 1,
                        message: "expected '=>' in when clause".into(),
                    });
                }

                let condition_str = parts[0].trim();
                let action = parts[1].trim().to_string();
                let condition = Self::parse_condition(condition_str, line_num + 1)?;

                rules.push(ScriptRule { condition, action });
            } else {
                return Err(ScriptError::ParseError {
                    line: line_num + 1,
                    message: format!("unexpected statement: '{}'", line),
                });
            }
        }

        Ok(PluginScript {
            name: name.to_string(),
            rules,
            default_action,
        })
    }

    /// 解析条件表达式
    fn parse_condition(s: &str, line: usize) -> Result<Condition, ScriptError> {
        let s = s.trim();

        // domain contains "xxx"
        if let Some(rest) = s.strip_prefix("domain contains ") {
            let val = Self::extract_quoted(rest, line)?;
            return Ok(Condition::DomainContains(val.to_lowercase()));
        }

        // domain suffix "xxx"
        if let Some(rest) = s.strip_prefix("domain suffix ") {
            let val = Self::extract_quoted(rest, line)?;
            return Ok(Condition::DomainSuffix(val.to_lowercase()));
        }

        // domain full "xxx"
        if let Some(rest) = s.strip_prefix("domain full ") {
            let val = Self::extract_quoted(rest, line)?;
            return Ok(Condition::DomainFull(val.to_lowercase()));
        }

        // domain keyword "xxx"
        if let Some(rest) = s.strip_prefix("domain keyword ") {
            let val = Self::extract_quoted(rest, line)?;
            return Ok(Condition::DomainKeyword(val.to_lowercase()));
        }

        // domain regex "xxx"
        if let Some(rest) = s.strip_prefix("domain regex ") {
            let val = Self::extract_quoted(rest, line)?;
            return Ok(Condition::DomainRegex(val));
        }

        // ip cidr "x.x.x.x/y"
        if let Some(rest) = s.strip_prefix("ip cidr ") {
            let val = Self::extract_quoted(rest, line)?;
            return Self::parse_cidr(&val, line);
        }

        // hour X..Y
        if let Some(rest) = s.strip_prefix("hour ") {
            let parts: Vec<&str> = rest.split("..").collect();
            if parts.len() != 2 {
                return Err(ScriptError::ParseError {
                    line,
                    message: "hour requires range like 0..6".into(),
                });
            }
            let start: u8 = parts[0]
                .trim()
                .parse()
                .map_err(|_| ScriptError::ParseError {
                    line,
                    message: "invalid hour start".into(),
                })?;
            let end: u8 = parts[1]
                .trim()
                .parse()
                .map_err(|_| ScriptError::ParseError {
                    line,
                    message: "invalid hour end".into(),
                })?;
            return Ok(Condition::HourRange { start, end });
        }

        // process "xxx"
        if let Some(rest) = s.strip_prefix("process ") {
            let val = Self::extract_quoted(rest, line)?;
            return Ok(Condition::ProcessName(val));
        }

        // inbound "xxx"
        if let Some(rest) = s.strip_prefix("inbound ") {
            let val = Self::extract_quoted(rest, line)?;
            return Ok(Condition::InboundTag(val));
        }

        // always
        if s == "always" {
            return Ok(Condition::Always);
        }

        Err(ScriptError::ParseError {
            line,
            message: format!("unknown condition: '{}'", s),
        })
    }

    /// 提取引号中的值
    fn extract_quoted(s: &str, line: usize) -> Result<String, ScriptError> {
        let s = s.trim();
        if s.starts_with('"') && s.ends_with('"') && s.len() >= 2 {
            Ok(s[1..s.len() - 1].to_string())
        } else {
            Err(ScriptError::ParseError {
                line,
                message: format!("expected quoted string, got: '{}'", s),
            })
        }
    }

    /// 解析 CIDR
    fn parse_cidr(s: &str, line: usize) -> Result<Condition, ScriptError> {
        let parts: Vec<&str> = s.split('/').collect();
        if parts.len() != 2 {
            return Err(ScriptError::ParseError {
                line,
                message: format!("invalid CIDR: '{}'", s),
            });
        }
        let addr: IpAddr = parts[0].parse().map_err(|_| ScriptError::ParseError {
            line,
            message: format!("invalid IP address: '{}'", parts[0]),
        })?;
        let prefix_len: u8 = parts[1].parse().map_err(|_| ScriptError::ParseError {
            line,
            message: format!("invalid prefix length: '{}'", parts[1]),
        })?;
        Ok(Condition::IpCidr { addr, prefix_len })
    }

    /// 评估条件
    pub fn evaluate(condition: &Condition, ctx: &super::host_api::HostContext) -> bool {
        match condition {
            Condition::DomainContains(s) => ctx
                .domain
                .as_ref()
                .map(|d| d.to_lowercase().contains(s))
                .unwrap_or(false),

            Condition::DomainSuffix(s) => ctx
                .domain
                .as_ref()
                .map(|d| {
                    let d = d.to_lowercase();
                    d == *s || d.ends_with(&format!(".{}", s))
                })
                .unwrap_or(false),

            Condition::DomainFull(s) => ctx
                .domain
                .as_ref()
                .map(|d| d.to_lowercase() == *s)
                .unwrap_or(false),

            Condition::DomainKeyword(s) => ctx
                .domain
                .as_ref()
                .map(|d| d.to_lowercase().contains(s))
                .unwrap_or(false),

            Condition::DomainRegex(pattern) => {
                if let Some(domain) = &ctx.domain {
                    regex::Regex::new(pattern)
                        .map(|re| re.is_match(domain))
                        .unwrap_or(false)
                } else {
                    false
                }
            }

            Condition::IpCidr { addr, prefix_len } => {
                if let Some(ip) = &ctx.dest_ip {
                    ip_in_cidr(ip, addr, *prefix_len)
                } else {
                    false
                }
            }

            Condition::HourRange { start, end } => {
                let hour = ctx.hour;
                if start <= end {
                    hour >= *start && hour < *end
                } else {
                    // 跨午夜，如 22..6
                    hour >= *start || hour < *end
                }
            }

            Condition::ProcessName(name) => ctx
                .process_name
                .as_ref()
                .map(|p| p.eq_ignore_ascii_case(name))
                .unwrap_or(false),

            Condition::InboundTag(tag) => ctx.inbound_tag == *tag,

            Condition::And(conditions) => conditions.iter().all(|c| Self::evaluate(c, ctx)),

            Condition::Or(conditions) => conditions.iter().any(|c| Self::evaluate(c, ctx)),

            Condition::Not(c) => !Self::evaluate(c, ctx),

            Condition::Always => true,
        }
    }

    /// 执行脚本，返回最终动作
    pub fn execute(script: &PluginScript, ctx: &super::host_api::HostContext) -> String {
        for rule in &script.rules {
            if Self::evaluate(&rule.condition, ctx) {
                return rule.action.clone();
            }
        }
        script.default_action.clone()
    }
}

/// 检查 IP 是否在 CIDR 范围内
fn ip_in_cidr(ip: &IpAddr, cidr_addr: &IpAddr, prefix_len: u8) -> bool {
    match (ip, cidr_addr) {
        (IpAddr::V4(ip), IpAddr::V4(cidr)) => {
            let ip_bits = u32::from(*ip);
            let cidr_bits = u32::from(*cidr);
            let mask = if prefix_len >= 32 {
                u32::MAX
            } else {
                u32::MAX << (32 - prefix_len)
            };
            (ip_bits & mask) == (cidr_bits & mask)
        }
        (IpAddr::V6(ip), IpAddr::V6(cidr)) => {
            let ip_bits = u128::from(*ip);
            let cidr_bits = u128::from(*cidr);
            let mask = if prefix_len >= 128 {
                u128::MAX
            } else {
                u128::MAX << (128 - prefix_len)
            };
            (ip_bits & mask) == (cidr_bits & mask)
        }
        _ => false,
    }
}

// ═══════════════════════════════════════════════════════════════════
// 测试
// ═══════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plugin::host_api::HostContext;

    fn default_ctx() -> HostContext {
        HostContext {
            domain: None,
            dest_ip: None,
            source_ip: None,
            dest_port: 443,
            inbound_tag: "socks-in".to_string(),
            process_name: None,
            hour: 12,
            detected_protocol: None,
        }
    }

    #[test]
    fn compile_basic_script() {
        let source = r#"
            # 路由规则
            when domain suffix "google.com" => proxy
            when domain contains "ads" => reject
            when ip cidr "10.0.0.0/8" => direct
            when hour 0..6 => reject
            default => direct
        "#;
        let script = ScriptEngine::compile("test", source).unwrap();
        assert_eq!(script.rules.len(), 4);
        assert_eq!(script.default_action, "direct");
    }

    #[test]
    fn compile_error_no_arrow() {
        let source = "when domain suffix google.com proxy";
        let result = ScriptEngine::compile("bad", source);
        assert!(result.is_err());
    }

    #[test]
    fn domain_suffix_match() {
        let script = ScriptEngine::compile("t", r#"when domain suffix "cn" => direct"#).unwrap();
        let mut ctx = default_ctx();
        ctx.domain = Some("baidu.cn".to_string());
        assert_eq!(ScriptEngine::execute(&script, &ctx), "direct");
    }

    #[test]
    fn domain_suffix_no_match() {
        let script = ScriptEngine::compile("t", r#"when domain suffix "cn" => direct"#).unwrap();
        let mut ctx = default_ctx();
        ctx.domain = Some("google.com".to_string());
        assert_eq!(ScriptEngine::execute(&script, &ctx), "direct"); // default
    }

    #[test]
    fn domain_contains_match() {
        let script =
            ScriptEngine::compile("t", r#"when domain contains "google" => proxy"#).unwrap();
        let mut ctx = default_ctx();
        ctx.domain = Some("www.google.com".to_string());
        assert_eq!(ScriptEngine::execute(&script, &ctx), "proxy");
    }

    #[test]
    fn ip_cidr_match() {
        let script =
            ScriptEngine::compile("t", r#"when ip cidr "192.168.0.0/16" => direct"#).unwrap();
        let mut ctx = default_ctx();
        ctx.dest_ip = Some("192.168.1.100".parse().unwrap());
        assert_eq!(ScriptEngine::execute(&script, &ctx), "direct");
    }

    #[test]
    fn ip_cidr_no_match() {
        let script =
            ScriptEngine::compile("t", r#"when ip cidr "192.168.0.0/16" => direct"#).unwrap();
        let mut ctx = default_ctx();
        ctx.dest_ip = Some("10.0.0.1".parse().unwrap());
        assert_eq!(ScriptEngine::execute(&script, &ctx), "direct"); // falls to default
    }

    #[test]
    fn hour_range_match() {
        let script =
            ScriptEngine::compile("t", "when hour 22..6 => reject\ndefault => proxy").unwrap();
        let mut ctx = default_ctx();

        // 午夜3点 = 在范围内
        ctx.hour = 3;
        assert_eq!(ScriptEngine::execute(&script, &ctx), "reject");

        // 中午12点 = 不在范围内
        ctx.hour = 12;
        assert_eq!(ScriptEngine::execute(&script, &ctx), "proxy");
    }

    #[test]
    fn process_name_match() {
        let script = ScriptEngine::compile("t", r#"when process "BitTorrent" => reject"#).unwrap();
        let mut ctx = default_ctx();
        ctx.process_name = Some("bittorrent".to_string());
        assert_eq!(ScriptEngine::execute(&script, &ctx), "reject");
    }

    #[test]
    fn inbound_tag_match() {
        let script = ScriptEngine::compile("t", r#"when inbound "tun-in" => proxy"#).unwrap();
        let mut ctx = default_ctx();

        // 不匹配
        assert_eq!(ScriptEngine::execute(&script, &ctx), "direct");

        // 匹配
        ctx.inbound_tag = "tun-in".to_string();
        assert_eq!(ScriptEngine::execute(&script, &ctx), "proxy");
    }

    #[test]
    fn domain_full_match() {
        let script =
            ScriptEngine::compile("t", r#"when domain full "example.com" => reject"#).unwrap();
        let mut ctx = default_ctx();
        ctx.domain = Some("example.com".to_string());
        assert_eq!(ScriptEngine::execute(&script, &ctx), "reject");

        ctx.domain = Some("sub.example.com".to_string());
        assert_eq!(ScriptEngine::execute(&script, &ctx), "direct");
    }

    #[test]
    fn multiple_rules_first_match_wins() {
        let source = r#"
            when domain contains "ads" => reject
            when domain suffix "google.com" => proxy
            default => direct
        "#;
        let script = ScriptEngine::compile("t", source).unwrap();
        let mut ctx = default_ctx();

        ctx.domain = Some("ads.google.com".to_string());
        // "ads" 先匹配
        assert_eq!(ScriptEngine::execute(&script, &ctx), "reject");
    }

    #[test]
    fn comments_and_blank_lines() {
        let source = r#"
            # This is a comment
            // Another comment

            when always => proxy

            # End
        "#;
        let script = ScriptEngine::compile("t", source).unwrap();
        let ctx = default_ctx();
        assert_eq!(ScriptEngine::execute(&script, &ctx), "proxy");
    }

    #[test]
    fn empty_script_uses_default() {
        let script = ScriptEngine::compile("t", "").unwrap();
        let ctx = default_ctx();
        assert_eq!(ScriptEngine::execute(&script, &ctx), "direct");
    }

    #[test]
    fn ip_in_cidr_v4() {
        let addr: IpAddr = "192.168.1.100".parse().unwrap();
        let cidr: IpAddr = "192.168.0.0".parse().unwrap();
        assert!(ip_in_cidr(&addr, &cidr, 16));
        assert!(!ip_in_cidr(&addr, &cidr, 24));
    }

    #[test]
    fn ip_in_cidr_v6() {
        let addr: IpAddr = "2001:db8::1".parse().unwrap();
        let cidr: IpAddr = "2001:db8::".parse().unwrap();
        assert!(ip_in_cidr(&addr, &cidr, 32));
        assert!(!ip_in_cidr(&"2001:db9::1".parse().unwrap(), &cidr, 32));
    }

    #[test]
    fn script_error_display() {
        let err = ScriptError::ParseError {
            line: 5,
            message: "oops".into(),
        };
        assert!(err.to_string().contains("line 5"));
    }

    #[test]
    fn domain_regex_match() {
        let script =
            ScriptEngine::compile("t", r#"when domain regex "^ads?\." => reject"#).unwrap();
        let mut ctx = default_ctx();
        ctx.domain = Some("ad.example.com".to_string());
        assert_eq!(ScriptEngine::execute(&script, &ctx), "reject");

        ctx.domain = Some("www.example.com".to_string());
        assert_eq!(ScriptEngine::execute(&script, &ctx), "direct");
    }
}
