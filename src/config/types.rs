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
