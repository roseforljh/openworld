pub mod rules;

use tracing::debug;

use crate::config::types::RouterConfig;
use crate::proxy::Session;
use rules::Rule;

pub struct Router {
    rules: Vec<(Rule, String)>, // (规则, 出站 tag)
    default: String,
}

impl Router {
    pub fn new(config: &RouterConfig) -> anyhow::Result<Self> {
        let mut rules = Vec::new();
        for rule_config in &config.rules {
            let rule = Rule::from_config(rule_config)?;
            rules.push((rule, rule_config.outbound.clone()));
        }
        Ok(Self {
            rules,
            default: config.default.clone(),
        })
    }

    /// 根据 Session 匹配路由规则，返回出站 tag
    pub fn route(&self, session: &Session) -> &str {
        for (rule, outbound_tag) in &self.rules {
            if rule.matches(&session.target) {
                debug!(
                    dest = %session.target,
                    rule = %rule,
                    outbound = outbound_tag,
                    "route matched"
                );
                return outbound_tag;
            }
        }
        debug!(
            dest = %session.target,
            outbound = %self.default,
            "route default"
        );
        &self.default
    }
}
