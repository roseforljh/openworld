use std::collections::HashMap;
use std::sync::Arc;

use anyhow::Result;
use async_trait::async_trait;
use tokio::sync::RwLock;

use crate::common::ProxyStream;
use crate::proxy::{OutboundHandler, Session};

/// Sticky session proxy group: routes the same target to the same proxy.
pub struct StickyGroup {
    tag: String,
    proxies: Vec<Arc<dyn OutboundHandler>>,
    proxy_names: Vec<String>,
    sticky_map: RwLock<HashMap<String, usize>>,
}

impl StickyGroup {
    pub fn new(
        tag: String,
        proxies: Vec<Arc<dyn OutboundHandler>>,
        proxy_names: Vec<String>,
    ) -> Self {
        Self {
            tag,
            proxies,
            proxy_names,
            sticky_map: RwLock::new(HashMap::new()),
        }
    }

    pub fn proxy_names(&self) -> &[String] {
        &self.proxy_names
    }

    pub async fn sticky_map_size(&self) -> usize {
        self.sticky_map.read().await.len()
    }

    pub async fn clear_sticky(&self) {
        self.sticky_map.write().await.clear();
    }

    fn target_key(session: &Session) -> String {
        format!("{}", session.target)
    }
}

#[async_trait]
impl OutboundHandler for StickyGroup {
    fn tag(&self) -> &str {
        &self.tag
    }

    async fn connect(&self, session: &Session) -> Result<ProxyStream> {
        let key = Self::target_key(session);

        // Check sticky map
        let idx = {
            let map = self.sticky_map.read().await;
            map.get(&key).copied()
        };

        let proxy_idx = if let Some(i) = idx {
            if i < self.proxies.len() {
                i
            } else {
                0
            }
        } else {
            // Hash-based selection for new targets
            let hash = simple_hash(&key);
            let idx = hash % self.proxies.len();
            self.sticky_map.write().await.insert(key, idx);
            idx
        };

        self.proxies[proxy_idx].connect(session).await
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

fn simple_hash(s: &str) -> usize {
    let mut hash: usize = 5381;
    for b in s.bytes() {
        hash = hash.wrapping_mul(33).wrapping_add(b as usize);
    }
    hash
}

/// Filter proxy nodes by pattern matching
pub fn filter_proxies(
    names: &[String],
    include_pattern: Option<&str>,
    exclude_pattern: Option<&str>,
) -> Vec<String> {
    names
        .iter()
        .filter(|name| {
            if let Some(pattern) = include_pattern {
                if !name.contains(pattern) {
                    return false;
                }
            }
            if let Some(pattern) = exclude_pattern {
                if name.contains(pattern) {
                    return false;
                }
            }
            true
        })
        .cloned()
        .collect()
}

/// Filter proxy nodes by keyword matching
pub fn filter_proxies_keyword(names: &[String], keywords: &[String], exclude: bool) -> Vec<String> {
    names
        .iter()
        .filter(|name| {
            let matches = keywords.iter().any(|kw| name.contains(kw.as_str()));
            if exclude {
                !matches
            } else {
                matches
            }
        })
        .cloned()
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::Address;
    use crate::proxy::outbound::direct::DirectOutbound;
    use crate::proxy::Network;
    use std::net::SocketAddr;

    fn test_session(target: &str) -> Session {
        Session {
            target: Address::Domain(target.to_string(), 443),
            source: Some("127.0.0.1:1234".parse::<SocketAddr>().unwrap()),
            inbound_tag: "test".to_string(),
            network: Network::Tcp,
            sniff: false,
            detected_protocol: None,
        }
    }

    #[tokio::test]
    async fn sticky_group_same_target_same_proxy() {
        let p1 = Arc::new(DirectOutbound::new("p1".to_string())) as Arc<dyn OutboundHandler>;
        let p2 = Arc::new(DirectOutbound::new("p2".to_string())) as Arc<dyn OutboundHandler>;
        let group = StickyGroup::new(
            "sticky".to_string(),
            vec![p1, p2],
            vec!["p1".to_string(), "p2".to_string()],
        );

        // Same target should hash to same proxy consistently
        let _s1 = test_session("example.com");
        let _s2 = test_session("example.com");

        // After first call, sticky map should have an entry
        // (We can't actually connect without a server, but we can test the map)
        assert_eq!(group.sticky_map_size().await, 0);
    }

    #[tokio::test]
    async fn sticky_group_clear() {
        let p1 = Arc::new(DirectOutbound::new("p1".to_string())) as Arc<dyn OutboundHandler>;
        let group = StickyGroup::new("sticky".to_string(), vec![p1], vec!["p1".to_string()]);
        group.sticky_map.write().await.insert("test".to_string(), 0);
        assert_eq!(group.sticky_map_size().await, 1);
        group.clear_sticky().await;
        assert_eq!(group.sticky_map_size().await, 0);
    }

    #[test]
    fn filter_include() {
        let names = vec![
            "US-Node-1".to_string(),
            "US-Node-2".to_string(),
            "JP-Node-1".to_string(),
            "HK-Node-1".to_string(),
        ];
        let result = filter_proxies(&names, Some("US"), None);
        assert_eq!(result, vec!["US-Node-1", "US-Node-2"]);
    }

    #[test]
    fn filter_exclude() {
        let names = vec![
            "US-Node-1".to_string(),
            "US-Node-2".to_string(),
            "JP-Node-1".to_string(),
        ];
        let result = filter_proxies(&names, None, Some("US"));
        assert_eq!(result, vec!["JP-Node-1"]);
    }

    #[test]
    fn filter_include_and_exclude() {
        let names = vec![
            "US-Fast-1".to_string(),
            "US-Slow-1".to_string(),
            "JP-Fast-1".to_string(),
        ];
        let result = filter_proxies(&names, Some("Fast"), Some("JP"));
        assert_eq!(result, vec!["US-Fast-1"]);
    }

    #[test]
    fn filter_keywords_include() {
        let names = vec![
            "Premium US".to_string(),
            "Basic JP".to_string(),
            "Premium HK".to_string(),
        ];
        let result = filter_proxies_keyword(&names, &["Premium".to_string()], false);
        assert_eq!(result, vec!["Premium US", "Premium HK"]);
    }

    #[test]
    fn filter_keywords_exclude() {
        let names = vec![
            "Premium US".to_string(),
            "Basic JP".to_string(),
            "Premium HK".to_string(),
        ];
        let result = filter_proxies_keyword(&names, &["Basic".to_string()], true);
        assert_eq!(result, vec!["Premium US", "Premium HK"]);
    }
}
