use std::collections::HashMap;

use anyhow::Result;

use crate::config::types::{Config, InboundConfig, InboundSettings, RuleConfig, SniffingConfig};

/// Profile 系统
///
/// Profile = 一组预定义的 inbound/outbound/rule 组合。
/// 支持通过 `profile: gaming` / `profile: streaming` 快速切换。
/// 内置 profiles：default, minimal, full。
#[derive(Debug, Clone)]
pub struct Profile {
    pub name: String,
    pub description: String,
    pub inbounds: Vec<InboundConfig>,
    pub rules: Vec<RuleConfig>,
    pub log_level: String,
}

fn make_inbound(tag: &str, protocol: &str, listen: &str, port: u16) -> InboundConfig {
    InboundConfig {
        tag: tag.to_string(),
        protocol: protocol.to_string(),
        listen: listen.to_string(),
        port,
        sniffing: SniffingConfig::default(),
        settings: InboundSettings::default(),
        max_connections: None,
    }
}

impl Profile {
    pub fn new(name: &str, description: &str) -> Self {
        Self {
            name: name.to_string(),
            description: description.to_string(),
            inbounds: Vec::new(),
            rules: Vec::new(),
            log_level: "info".to_string(),
        }
    }

    pub fn with_inbound(mut self, inbound: InboundConfig) -> Self {
        self.inbounds.push(inbound);
        self
    }

    pub fn with_rule(mut self, rule: RuleConfig) -> Self {
        self.rules.push(rule);
        self
    }

    pub fn with_log_level(mut self, level: &str) -> Self {
        self.log_level = level.to_string();
        self
    }
}

/// Profile 管理器
pub struct ProfileManager {
    profiles: HashMap<String, Profile>,
}

impl ProfileManager {
    pub fn new() -> Self {
        let mut mgr = Self {
            profiles: HashMap::new(),
        };
        mgr.register_builtins();
        mgr
    }

    fn register_builtins(&mut self) {
        // default profile: SOCKS5 + HTTP inbound, basic routing
        let default = Profile::new("default", "Default profile with SOCKS5 and HTTP proxy")
            .with_inbound(make_inbound("socks-in", "socks5", "127.0.0.1", 1080))
            .with_inbound(make_inbound("http-in", "http", "127.0.0.1", 1081))
            .with_rule(RuleConfig {
                rule_type: "domain-suffix".to_string(),
                values: vec!["cn".to_string()],
                outbound: "direct".to_string(),
            })
            .with_rule(RuleConfig {
                rule_type: "ip-cidr".to_string(),
                values: vec![
                    "10.0.0.0/8".to_string(),
                    "172.16.0.0/12".to_string(),
                    "192.168.0.0/16".to_string(),
                ],
                outbound: "direct".to_string(),
            });
        self.profiles.insert("default".to_string(), default);

        // minimal profile: only SOCKS5, no routing rules
        let minimal = Profile::new("minimal", "Minimal profile with SOCKS5 only")
            .with_inbound(make_inbound("socks-in", "socks5", "127.0.0.1", 1080));
        self.profiles.insert("minimal".to_string(), minimal);

        // full profile: all inbound types, comprehensive routing
        let full = Profile::new("full", "Full-featured profile with all inbound types")
            .with_inbound(make_inbound("socks-in", "socks5", "127.0.0.1", 1080))
            .with_inbound(make_inbound("http-in", "http", "127.0.0.1", 1081))
            .with_rule(RuleConfig {
                rule_type: "domain-suffix".to_string(),
                values: vec!["cn".to_string(), "com.cn".to_string()],
                outbound: "direct".to_string(),
            })
            .with_rule(RuleConfig {
                rule_type: "ip-cidr".to_string(),
                values: vec![
                    "10.0.0.0/8".to_string(),
                    "172.16.0.0/12".to_string(),
                    "192.168.0.0/16".to_string(),
                    "127.0.0.0/8".to_string(),
                ],
                outbound: "direct".to_string(),
            })
            .with_rule(RuleConfig {
                rule_type: "domain-keyword".to_string(),
                values: vec![
                    "google".to_string(),
                    "youtube".to_string(),
                    "twitter".to_string(),
                ],
                outbound: "proxy".to_string(),
            })
            .with_log_level("debug");
        self.profiles.insert("full".to_string(), full);
    }

    /// 注册自定义 profile
    pub fn register(&mut self, profile: Profile) {
        self.profiles.insert(profile.name.clone(), profile);
    }

    /// 获取 profile
    pub fn get(&self, name: &str) -> Option<&Profile> {
        self.profiles.get(name)
    }

    /// 列出所有可用 profile 名称
    pub fn list(&self) -> Vec<&str> {
        self.profiles.keys().map(|k| k.as_str()).collect()
    }

    /// 检查 profile 是否存在
    pub fn has(&self, name: &str) -> bool {
        self.profiles.contains_key(name)
    }

    /// profile 数量
    pub fn len(&self) -> usize {
        self.profiles.len()
    }

    /// 将 profile 应用到配置，覆盖 inbound 和 router rules
    pub fn apply_to_config(&self, profile_name: &str, config: &mut Config) -> Result<()> {
        let profile = self
            .profiles
            .get(profile_name)
            .ok_or_else(|| anyhow::anyhow!("profile '{}' not found", profile_name))?;

        // 合并 inbounds（profile 的 inbounds 添加到 config 前面）
        if !profile.inbounds.is_empty() {
            let mut merged = profile.inbounds.clone();
            // 避免 tag 冲突：只添加 config 中没有的
            let profile_tags: Vec<String> = merged.iter().map(|i| i.tag.clone()).collect();
            for existing in &config.inbounds {
                if !profile_tags.iter().any(|t| t == &existing.tag) {
                    merged.push(existing.clone());
                }
            }
            config.inbounds = merged;
        }

        // 合并 rules（profile 的 rules 添加到 config 前面）
        if !profile.rules.is_empty() {
            let mut merged = profile.rules.clone();
            merged.extend(config.router.rules.drain(..));
            config.router.rules = merged;
        }

        // 应用 log level
        config.log.level = profile.log_level.clone();

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::types::{LogConfig, OutboundConfig, OutboundSettings, RouterConfig};

    #[test]
    fn profile_manager_has_builtins() {
        let mgr = ProfileManager::new();
        assert!(mgr.has("default"));
        assert!(mgr.has("minimal"));
        assert!(mgr.has("full"));
        assert_eq!(mgr.len(), 3);
    }

    #[test]
    fn profile_default_has_two_inbounds() {
        let mgr = ProfileManager::new();
        let default = mgr.get("default").unwrap();
        assert_eq!(default.inbounds.len(), 2);
        assert_eq!(default.name, "default");
    }

    #[test]
    fn profile_minimal_has_one_inbound() {
        let mgr = ProfileManager::new();
        let minimal = mgr.get("minimal").unwrap();
        assert_eq!(minimal.inbounds.len(), 1);
        assert_eq!(minimal.inbounds[0].protocol, "socks5");
    }

    #[test]
    fn profile_full_has_rules() {
        let mgr = ProfileManager::new();
        let full = mgr.get("full").unwrap();
        assert!(!full.rules.is_empty());
        assert_eq!(full.log_level, "debug");
    }

    #[test]
    fn profile_nonexistent_returns_none() {
        let mgr = ProfileManager::new();
        assert!(mgr.get("gaming").is_none());
        assert!(!mgr.has("gaming"));
    }

    #[test]
    fn profile_register_custom() {
        let mut mgr = ProfileManager::new();
        let gaming = Profile::new("gaming", "Optimized for low latency gaming")
            .with_inbound(make_inbound("socks-in", "socks5", "127.0.0.1", 1080))
            .with_log_level("warn");
        mgr.register(gaming);
        assert!(mgr.has("gaming"));
        let g = mgr.get("gaming").unwrap();
        assert_eq!(g.description, "Optimized for low latency gaming");
        assert_eq!(g.log_level, "warn");
    }

    #[test]
    fn profile_list_names() {
        let mgr = ProfileManager::new();
        let names = mgr.list();
        assert!(names.contains(&"default"));
        assert!(names.contains(&"minimal"));
        assert!(names.contains(&"full"));
    }

    #[test]
    fn profile_apply_to_config() {
        let mgr = ProfileManager::new();
        let mut config = Config {
            log: LogConfig {
                level: "info".to_string(),
            },
            profile: None,
            inbounds: vec![make_inbound("existing", "http", "0.0.0.0", 8080)],
            outbounds: vec![OutboundConfig {
                tag: "direct".to_string(),
                protocol: "direct".to_string(),
                settings: OutboundSettings::default(),
            }],
            proxy_groups: vec![],
            router: RouterConfig {
                rules: vec![],
                default: "direct".to_string(),
                geoip_db: None,
                geosite_db: None,
                rule_providers: Default::default(),
                geoip_url: None,
                geosite_url: None,
                geo_update_interval: 7 * 24 * 3600,
                geo_auto_update: false,
            },
            subscriptions: vec![],
            api: None,
            dns: None,
            max_connections: 10000,
        };

        mgr.apply_to_config("minimal", &mut config).unwrap();
        // Minimal has 1 inbound (socks-in) + existing "existing" = 2
        assert_eq!(config.inbounds.len(), 2);
        assert_eq!(config.inbounds[0].tag, "socks-in");
        assert_eq!(config.inbounds[1].tag, "existing");
    }

    #[test]
    fn profile_apply_nonexistent_fails() {
        let mgr = ProfileManager::new();
        let mut config = Config {
            log: LogConfig {
                level: "info".to_string(),
            },
            profile: None,
            inbounds: vec![make_inbound("in", "socks5", "127.0.0.1", 1080)],
            outbounds: vec![OutboundConfig {
                tag: "direct".to_string(),
                protocol: "direct".to_string(),
                settings: OutboundSettings::default(),
            }],
            proxy_groups: vec![],
            router: RouterConfig {
                rules: vec![],
                default: "direct".to_string(),
                geoip_db: None,
                geosite_db: None,
                rule_providers: Default::default(),
                geoip_url: None,
                geosite_url: None,
                geo_update_interval: 7 * 24 * 3600,
                geo_auto_update: false,
            },
            subscriptions: vec![],
            api: None,
            dns: None,
            max_connections: 10000,
        };

        let result = mgr.apply_to_config("nonexistent", &mut config);
        assert!(result.is_err());
    }
}
