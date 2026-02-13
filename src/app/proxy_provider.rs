use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::Result;
use reqwest::header::{ETAG, IF_MODIFIED_SINCE, IF_NONE_MATCH, LAST_MODIFIED};
use tokio::sync::RwLock;

use crate::config::subscription::{self, ProxyNode};
use crate::config::types::SubscriptionConfig;

/// Proxy provider source type
#[derive(Debug, Clone)]
pub enum ProviderSource {
    Http {
        url: String,
        interval: Duration,
        path: Option<String>,
    },
    File {
        path: String,
    },
}

/// Proxy provider state
#[derive(Debug, Clone)]
pub struct ProviderState {
    pub name: String,
    pub source: ProviderSource,
    pub nodes: Vec<ProxyNode>,
    pub last_updated: Option<u64>,
    pub etag: Option<String>,
    pub last_modified: Option<String>,
    pub error: Option<String>,
}

/// Proxy Provider manager: handles fetching, caching, and updating proxy lists
pub struct ProxyProviderManager {
    providers: RwLock<HashMap<String, ProviderState>>,
}

impl ProxyProviderManager {
    pub fn new() -> Self {
        Self {
            providers: RwLock::new(HashMap::new()),
        }
    }

    /// Add a provider
    pub async fn add_provider(&self, name: String, source: ProviderSource) {
        let state = ProviderState {
            name: name.clone(),
            source,
            nodes: Vec::new(),
            last_updated: None,
            etag: None,
            last_modified: None,
            error: None,
        };
        self.providers.write().await.insert(name, state);
    }

    /// Get nodes from a provider
    pub async fn get_nodes(&self, name: &str) -> Option<Vec<ProxyNode>> {
        self.providers.read().await.get(name).map(|s| s.nodes.clone())
    }

    /// Get provider state
    pub async fn get_state(&self, name: &str) -> Option<ProviderState> {
        self.providers.read().await.get(name).cloned()
    }

    /// List all provider names
    pub async fn list_providers(&self) -> Vec<String> {
        self.providers.read().await.keys().cloned().collect()
    }

    /// Update a file-based provider
    pub async fn update_file_provider(&self, name: &str) -> Result<usize> {
        let source = {
            let providers = self.providers.read().await;
            let state = providers.get(name).ok_or_else(|| anyhow::anyhow!("provider not found: {}", name))?;
            state.source.clone()
        };

        let path = match &source {
            ProviderSource::File { path } => path.clone(),
            _ => anyhow::bail!("provider '{}' is not a file provider", name),
        };

        let content = std::fs::read_to_string(&path)?;
        let nodes = parse_provider_content(&content)?;
        let node_count = nodes.len();

        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
        let mut providers = self.providers.write().await;
        if let Some(state) = providers.get_mut(name) {
            state.nodes = nodes;
            state.last_updated = Some(now);
            state.error = None;
        }

        Ok(node_count)
    }

    pub async fn update_http_provider(&self, name: &str) -> Result<usize> {
        let (url, etag, last_modified) = {
            let providers = self.providers.read().await;
            let state = providers
                .get(name)
                .ok_or_else(|| anyhow::anyhow!("provider not found: {}", name))?;
            match &state.source {
                ProviderSource::Http { url, .. } => {
                    (url.clone(), state.etag.clone(), state.last_modified.clone())
                }
                _ => anyhow::bail!("provider '{}' is not an http provider", name),
            }
        };

        let client = reqwest::Client::new();
        let mut req = client.get(&url);
        if let Some(etag_value) = etag {
            req = req.header(IF_NONE_MATCH, etag_value);
        }
        if let Some(last_modified_value) = last_modified {
            req = req.header(IF_MODIFIED_SINCE, last_modified_value);
        }

        let response = req.send().await?;
        let status = response.status();
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();

        if status == reqwest::StatusCode::NOT_MODIFIED {
            let mut providers = self.providers.write().await;
            if let Some(state) = providers.get_mut(name) {
                state.last_updated = Some(now);
                state.error = None;
                return Ok(state.nodes.len());
            }
            return Ok(0);
        }

        let response = response.error_for_status()?;
        let new_etag = response
            .headers()
            .get(ETAG)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());
        let new_last_modified = response
            .headers()
            .get(LAST_MODIFIED)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());
        let content = response.text().await?;
        let nodes = parse_provider_content(&content)?;
        let node_count = nodes.len();

        let mut providers = self.providers.write().await;
        if let Some(state) = providers.get_mut(name) {
            state.nodes = nodes;
            state.last_updated = Some(now);
            state.etag = new_etag;
            state.last_modified = new_last_modified;
            state.error = None;
        }

        Ok(node_count)
    }

    /// Get total node count across all providers
    pub async fn total_node_count(&self) -> usize {
        self.providers.read().await.values().map(|s| s.nodes.len()).sum()
    }

    pub async fn all_provider_nodes(&self) -> Vec<(String, ProxyNode)> {
        self.providers
            .read()
            .await
            .iter()
            .flat_map(|(provider, state)| {
                state
                    .nodes
                    .iter()
                    .cloned()
                    .map(|n| (provider.clone(), n))
                    .collect::<Vec<_>>()
            })
            .collect()
    }
}

/// Parse provider content (auto-detect format)
pub fn parse_provider_content(content: &str) -> Result<Vec<ProxyNode>> {
    let format = subscription::detect_format(content);
    match format {
        subscription::SubFormat::ClashYaml => subscription::parse_clash_yaml_nodes(content),
        subscription::SubFormat::SingBoxJson => subscription::parse_singbox_json_nodes(content),
        subscription::SubFormat::Base64 => subscription::parse_base64(content),
        _ => {
            // Try line-by-line link parsing
            let mut nodes = Vec::new();
            for line in content.lines() {
                let line = line.trim();
                if line.is_empty() || line.starts_with('#') {
                    continue;
                }
                if let Some(node) = subscription::parse_proxy_link(line) {
                    nodes.push(node);
                }
            }
            if nodes.is_empty() {
                anyhow::bail!("could not parse any proxy nodes from content");
            }
            Ok(nodes)
        }
    }
}

/// Subscription manager: handles multiple subscription sources
pub struct SubscriptionManager {
    subscriptions: RwLock<Vec<SubscriptionConfig>>,
    provider_manager: Arc<ProxyProviderManager>,
}

impl SubscriptionManager {
    pub fn new(provider_manager: Arc<ProxyProviderManager>) -> Self {
        Self {
            subscriptions: RwLock::new(Vec::new()),
            provider_manager,
        }
    }

    pub async fn add_subscription(&self, config: SubscriptionConfig) {
        let name = config.name.clone();
        let url = config.url.clone();
        let interval_secs = config.interval_secs;
        self.subscriptions.write().await.push(config);
        self.provider_manager
            .add_provider(
                name.clone(),
                ProviderSource::Http {
                    url,
                    interval: Duration::from_secs(interval_secs),
                    path: None,
                },
            )
            .await;
    }

    pub async fn list_subscriptions(&self) -> Vec<SubscriptionConfig> {
        self.subscriptions.read().await.clone()
    }

    pub async fn subscription_count(&self) -> usize {
        self.subscriptions.read().await.len()
    }

    pub fn provider_manager(&self) -> &Arc<ProxyProviderManager> {
        &self.provider_manager
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn provider_manager_add_and_list() {
        let mgr = ProxyProviderManager::new();
        mgr.add_provider("test".to_string(), ProviderSource::File { path: "test.yaml".to_string() }).await;
        let providers = mgr.list_providers().await;
        assert_eq!(providers.len(), 1);
        assert!(providers.contains(&"test".to_string()));
    }

    #[tokio::test]
    async fn provider_manager_get_state() {
        let mgr = ProxyProviderManager::new();
        mgr.add_provider("p1".to_string(), ProviderSource::File { path: "p1.yaml".to_string() }).await;
        let state = mgr.get_state("p1").await.unwrap();
        assert_eq!(state.name, "p1");
        assert!(state.nodes.is_empty());
        assert!(state.last_updated.is_none());
    }

    #[tokio::test]
    async fn provider_manager_file_update() {
        let mgr = ProxyProviderManager::new();
        let mut tmp = tempfile::NamedTempFile::new().unwrap();

        let yaml = r#"
proxies:
  - name: "node1"
    type: ss
    server: 1.2.3.4
    port: 8388
    cipher: aes-256-gcm
    password: "pass"
  - name: "node2"
    type: trojan
    server: 5.6.7.8
    port: 443
    password: "pass"
"#;
        use std::io::Write;
        write!(tmp, "{}", yaml).unwrap();

        mgr.add_provider(
            "sub1".to_string(),
            ProviderSource::File {
                path: tmp.path().to_string_lossy().to_string(),
            },
        )
        .await;

        let count = mgr.update_file_provider("sub1").await.unwrap();
        assert_eq!(count, 2);

        let nodes = mgr.get_nodes("sub1").await.unwrap();
        assert_eq!(nodes.len(), 2);
        assert_eq!(nodes[0].name, "node1");

        let state = mgr.get_state("sub1").await.unwrap();
        assert!(state.last_updated.is_some());
        assert!(state.error.is_none());
    }

    #[tokio::test]
    async fn provider_manager_total_count() {
        let mgr = ProxyProviderManager::new();
        let mut tmp_a = tempfile::NamedTempFile::new().unwrap();
        let mut tmp_b = tempfile::NamedTempFile::new().unwrap();

        let yaml_a = "proxies:\n  - name: n1\n    type: ss\n    server: 1.1.1.1\n    port: 1\n    cipher: aes-256-gcm\n    password: p";
        let yaml_b = "proxies:\n  - name: n2\n    type: ss\n    server: 2.2.2.2\n    port: 2\n    cipher: aes-256-gcm\n    password: p\n  - name: n3\n    type: ss\n    server: 3.3.3.3\n    port: 3\n    cipher: aes-256-gcm\n    password: p";
        use std::io::Write;
        write!(tmp_a, "{}", yaml_a).unwrap();
        write!(tmp_b, "{}", yaml_b).unwrap();

        mgr.add_provider(
            "a".to_string(),
            ProviderSource::File {
                path: tmp_a.path().to_string_lossy().to_string(),
            },
        )
        .await;
        mgr.add_provider(
            "b".to_string(),
            ProviderSource::File {
                path: tmp_b.path().to_string_lossy().to_string(),
            },
        )
        .await;

        mgr.update_file_provider("a").await.unwrap();
        mgr.update_file_provider("b").await.unwrap();

        assert_eq!(mgr.total_node_count().await, 3);
    }

    #[tokio::test]
    async fn subscription_manager_basic() {
        let pm = Arc::new(ProxyProviderManager::new());
        let sm = SubscriptionManager::new(pm.clone());

        sm.add_subscription(SubscriptionConfig {
            name: "sub1".to_string(),
            url: "https://example.com/sub".to_string(),
            interval_secs: 3600,
            enabled: true,
        }).await;

        assert_eq!(sm.subscription_count().await, 1);
        let subs = sm.list_subscriptions().await;
        assert_eq!(subs[0].name, "sub1");
        assert!(subs[0].enabled);
    }

    #[test]
    fn parse_provider_content_clash() {
        let yaml = "proxies:\n  - name: test\n    type: ss\n    server: 1.2.3.4\n    port: 8388\n    cipher: aes-256-gcm\n    password: pass";
        let nodes = parse_provider_content(yaml).unwrap();
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].name, "test");
    }

    #[test]
    fn parse_provider_content_links() {
        let content = "trojan://pass@server.com:443#Node1\nvless://uuid@server.com:443#Node2\n";
        let nodes = parse_provider_content(content).unwrap();
        assert_eq!(nodes.len(), 2);
    }

    #[test]
    fn parse_provider_content_empty_fails() {
        let result = parse_provider_content("");
        assert!(result.is_err());
    }
}
