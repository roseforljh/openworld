use anyhow::Result;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub log: LogConfig,
    pub inbounds: Vec<InboundConfig>,
    pub outbounds: Vec<OutboundConfig>,
    #[serde(default)]
    pub router: RouterConfig,
}

impl Config {
    pub fn validate(&self) -> Result<()> {
        if self.inbounds.is_empty() {
            anyhow::bail!("at least one inbound is required");
        }
        if self.outbounds.is_empty() {
            anyhow::bail!("at least one outbound is required");
        }
        // 验证 router default 指向存在的 outbound
        let outbound_tags: Vec<&str> = self.outbounds.iter().map(|o| o.tag.as_str()).collect();
        if !outbound_tags.contains(&self.router.default.as_str()) {
            anyhow::bail!(
                "router default '{}' does not match any outbound tag",
                self.router.default
            );
        }
        for rule in &self.router.rules {
            if !outbound_tags.contains(&rule.outbound.as_str()) {
                anyhow::bail!(
                    "rule outbound '{}' does not match any outbound tag",
                    rule.outbound
                );
            }
        }
        Ok(())
    }
}

#[derive(Debug, Deserialize)]
pub struct LogConfig {
    #[serde(default = "default_log_level")]
    pub level: String,
}

impl Default for LogConfig {
    fn default() -> Self {
        Self {
            level: "info".to_string(),
        }
    }
}

fn default_log_level() -> String {
    "info".to_string()
}

#[derive(Debug, Deserialize)]
pub struct InboundConfig {
    pub tag: String,
    pub protocol: String,
    pub listen: String,
    pub port: u16,
}

#[derive(Debug, Deserialize)]
pub struct OutboundConfig {
    pub tag: String,
    pub protocol: String,
    #[serde(default)]
    pub settings: OutboundSettings,
}

#[derive(Debug, Default, Deserialize)]
pub struct OutboundSettings {
    pub address: Option<String>,
    pub port: Option<u16>,
    pub uuid: Option<String>,
    pub password: Option<String>,
    pub security: Option<String>,
    pub sni: Option<String>,
    #[serde(default)]
    pub allow_insecure: bool,
    pub flow: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct RouterConfig {
    #[serde(default)]
    pub rules: Vec<RuleConfig>,
    #[serde(default = "default_outbound")]
    pub default: String,
}

impl Default for RouterConfig {
    fn default() -> Self {
        Self {
            rules: Vec::new(),
            default: "direct".to_string(),
        }
    }
}

fn default_outbound() -> String {
    "direct".to_string()
}

#[derive(Debug, Deserialize)]
pub struct RuleConfig {
    #[serde(rename = "type")]
    pub rule_type: String,
    pub values: Vec<String>,
    pub outbound: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn minimal_config() -> Config {
        Config {
            log: LogConfig::default(),
            inbounds: vec![InboundConfig {
                tag: "socks-in".to_string(),
                protocol: "socks5".to_string(),
                listen: "127.0.0.1".to_string(),
                port: 1080,
            }],
            outbounds: vec![OutboundConfig {
                tag: "direct".to_string(),
                protocol: "direct".to_string(),
                settings: OutboundSettings::default(),
            }],
            router: RouterConfig {
                rules: Vec::new(),
                default: "direct".to_string(),
            },
        }
    }

    #[test]
    fn validate_ok() {
        assert!(minimal_config().validate().is_ok());
    }

    #[test]
    fn validate_no_inbounds() {
        let mut config = minimal_config();
        config.inbounds.clear();
        assert!(config.validate().is_err());
    }

    #[test]
    fn validate_no_outbounds() {
        let mut config = minimal_config();
        config.outbounds.clear();
        assert!(config.validate().is_err());
    }

    #[test]
    fn validate_router_default_missing() {
        let mut config = minimal_config();
        config.router.default = "nonexistent".to_string();
        assert!(config.validate().is_err());
    }

    #[test]
    fn validate_rule_outbound_missing() {
        let mut config = minimal_config();
        config.router.rules.push(RuleConfig {
            rule_type: "domain-suffix".to_string(),
            values: vec!["example.com".to_string()],
            outbound: "nonexistent".to_string(),
        });
        assert!(config.validate().is_err());
    }

    #[test]
    fn validate_rule_outbound_ok() {
        let mut config = minimal_config();
        config.router.rules.push(RuleConfig {
            rule_type: "domain-suffix".to_string(),
            values: vec!["example.com".to_string()],
            outbound: "direct".to_string(),
        });
        assert!(config.validate().is_ok());
    }

    #[test]
    fn deserialize_full_config() {
        let yaml = r#"
log:
  level: debug
inbounds:
  - tag: socks-in
    protocol: socks5
    listen: "127.0.0.1"
    port: 1080
outbounds:
  - tag: direct
    protocol: direct
router:
  rules: []
  default: direct
"#;
        let config: Config = serde_yml::from_str(yaml).unwrap();
        assert_eq!(config.log.level, "debug");
        assert_eq!(config.inbounds.len(), 1);
        assert_eq!(config.inbounds[0].tag, "socks-in");
        assert!(config.validate().is_ok());
    }

    #[test]
    fn deserialize_default_log_level() {
        let yaml = r#"
inbounds:
  - tag: socks-in
    protocol: socks5
    listen: "127.0.0.1"
    port: 1080
outbounds:
  - tag: direct
    protocol: direct
router:
  default: direct
"#;
        let config: Config = serde_yml::from_str(yaml).unwrap();
        assert_eq!(config.log.level, "info");
    }

    #[test]
    fn deserialize_outbound_settings() {
        let yaml = r#"
inbounds:
  - tag: socks-in
    protocol: socks5
    listen: "127.0.0.1"
    port: 1080
outbounds:
  - tag: my-vless
    protocol: vless
    settings:
      address: "1.2.3.4"
      port: 443
      uuid: "550e8400-e29b-41d4-a716-446655440000"
      security: tls
      sni: "example.com"
      allow_insecure: true
  - tag: direct
    protocol: direct
router:
  default: direct
"#;
        let config: Config = serde_yml::from_str(yaml).unwrap();
        let vless = &config.outbounds[0].settings;
        assert_eq!(vless.address.as_deref(), Some("1.2.3.4"));
        assert_eq!(vless.port, Some(443));
        assert!(vless.allow_insecure);
        assert_eq!(vless.sni.as_deref(), Some("example.com"));
    }
}
