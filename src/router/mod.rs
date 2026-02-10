pub mod geoip;
pub mod geosite;
pub mod provider;
pub mod rules;

use std::collections::HashMap;
use std::sync::Arc;

use tracing::{debug, info};

use crate::config::types::RouterConfig;
use crate::proxy::Session;
use geoip::GeoIpDb;
use geosite::GeoSiteDb;
use provider::RuleSetData;
use rules::Rule;

pub struct Router {
    rules: Vec<(Rule, String)>,
    default: String,
    geoip_db: Option<GeoIpDb>,
    geosite_db: Option<GeoSiteDb>,
    providers: HashMap<String, Arc<RuleSetData>>,
}

impl Router {
    pub fn new(config: &RouterConfig) -> anyhow::Result<Self> {
        let geoip_db = if let Some(ref path) = config.geoip_db {
            let db = GeoIpDb::load(path)?;
            info!(path = path, "GeoIP database loaded");
            Some(db)
        } else {
            None
        };

        let geosite_db = if let Some(ref path) = config.geosite_db {
            // 加载所有 geosite 规则引用的分类
            let categories: Vec<String> = config
                .rules
                .iter()
                .filter(|r| r.rule_type == "geosite")
                .flat_map(|r| r.values.clone())
                .collect();

            if categories.is_empty() {
                None
            } else {
                let db = GeoSiteDb::load(path, &categories.join(","))?;
                info!(path = path, "GeoSite database loaded");
                Some(db)
            }
        } else {
            None
        };

        // 加载规则提供者
        let providers = provider::load_all_providers(&config.rule_providers)?;

        let mut rules = Vec::new();
        for rule_config in &config.rules {
            if rule_config.rule_type == "rule-set" {
                // rule-set: values 中每个元素引用一个 provider
                for provider_name in &rule_config.values {
                    let data = providers.get(provider_name).ok_or_else(|| {
                        anyhow::anyhow!("unknown rule-provider: '{}'", provider_name)
                    })?;
                    let rule = Rule::RuleSet {
                        name: provider_name.clone(),
                        data: data.clone(),
                    };
                    rules.push((rule, rule_config.outbound.clone()));
                }
            } else {
                let rule = Rule::from_config(rule_config)?;
                rules.push((rule, rule_config.outbound.clone()));
            }
        }
        Ok(Self {
            rules,
            default: config.default.clone(),
            geoip_db,
            geosite_db,
            providers,
        })
    }

    pub fn geoip_db(&self) -> Option<&GeoIpDb> {
        self.geoip_db.as_ref()
    }

    pub fn geosite_db(&self) -> Option<&GeoSiteDb> {
        self.geosite_db.as_ref()
    }

    /// 根据 Session 匹配路由规则，返回出站 tag
    pub fn route(&self, session: &Session) -> &str {
        for (rule, outbound_tag) in &self.rules {
            if rule.matches(&session.target, self.geoip_db.as_ref(), self.geosite_db.as_ref()) {
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

    /// 获取所有规则（供 API 使用）
    pub fn rules(&self) -> &[(Rule, String)] {
        &self.rules
    }

    /// 获取默认出站 tag
    pub fn default_outbound(&self) -> &str {
        &self.default
    }

    /// 获取所有已加载的规则提供者
    pub fn providers(&self) -> &HashMap<String, Arc<RuleSetData>> {
        &self.providers
    }
}
