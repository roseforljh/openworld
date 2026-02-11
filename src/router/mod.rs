pub mod geoip;
pub mod geosite;
pub mod process;
pub mod provider;
pub mod rules;
pub mod trie;

use std::borrow::Cow;
use std::collections::HashMap;
use std::sync::Arc;

use tracing::{debug, info};

use crate::config::types::RouterConfig;
use crate::proxy::Session;
use geoip::GeoIpDb;
use geosite::GeoSiteDb;
use provider::RuleProvider;
use rules::Rule;

pub struct Router {
    rules: Vec<(Rule, String)>,
    default: String,
    domain_trie: trie::DomainTrie,
    ip_trie: trie::IpPrefixTrie,
    geoip_db: Option<GeoIpDb>,
    geosite_db: Option<GeoSiteDb>,
    providers: HashMap<String, Arc<RuleProvider>>,
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
        let mut domain_trie = trie::DomainTrie::new();
        let mut ip_trie = trie::IpPrefixTrie::new();
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
                let rule_idx = rules.len();
                match &rule {
                    Rule::DomainSuffix(suffixes) => {
                        for suffix in suffixes {
                            domain_trie.insert(suffix, rule_idx);
                        }
                    }
                    Rule::IpCidr(nets) => {
                        for net in nets {
                            ip_trie.insert(net, rule_idx);
                        }
                    }
                    _ => {}
                }
                rules.push((rule, rule_config.outbound.clone()));
            }
        }
        Ok(Self {
            rules,
            default: config.default.clone(),
            domain_trie,
            ip_trie,
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

    /// 根据 Session 匹配路由规则，返回 (出站 tag, 命中规则)
    pub fn route_with_rule<'a>(&'a self, session: &Session) -> (&'a str, Option<Cow<'a, str>>) {
        let network_str = match session.network {
            crate::proxy::Network::Tcp => "tcp",
            crate::proxy::Network::Udp => "udp",
        };
        let trie_match_idx = match &session.target {
            crate::common::Address::Domain(domain, _) => self.domain_trie.find_first_match(domain),
            crate::common::Address::Ip(sock_addr) => {
                self.ip_trie.first_prefix_match(sock_addr.ip())
            }
        };

        let mut fallback_match_idx = None;
        for (idx, (rule, _)) in self.rules.iter().enumerate() {
            if matches!(rule, Rule::DomainSuffix(_) | Rule::IpCidr(_)) {
                continue;
            }
            if rule.matches_session(
                &session.target,
                self.geoip_db.as_ref(),
                self.geosite_db.as_ref(),
                session.source,
                Some(network_str),
                Some(&session.inbound_tag),
            ) {
                fallback_match_idx = Some(idx);
                break;
            }
        }

        let selected_idx = match (trie_match_idx, fallback_match_idx) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (Some(a), None) => Some(a),
            (None, Some(b)) => Some(b),
            (None, None) => None,
        };

        if let Some(idx) = selected_idx {
            let (rule, outbound_tag) = &self.rules[idx];
            let rule_desc = rule.to_string();
            debug!(
                dest = %session.target,
                rule = %rule_desc,
                outbound = outbound_tag,
                "route matched"
            );
            return (outbound_tag, Some(Cow::Owned(rule_desc)));
        }

        debug!(
            dest = %session.target,
            outbound = %self.default,
            "route default"
        );
        (&self.default, None)
    }

    /// 根据 Session 匹配路由规则，返回出站 tag
    pub fn route(&self, session: &Session) -> &str {
        self.route_with_rule(session).0
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
    pub fn providers(&self) -> &HashMap<String, Arc<RuleProvider>> {
        &self.providers
    }
}
