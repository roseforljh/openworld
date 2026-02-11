use std::collections::HashMap;
use std::sync::Arc;

use anyhow::Result;
use async_trait::async_trait;
use tokio::sync::RwLock;

use crate::common::{BoxUdpTransport, ProxyStream};
use crate::proxy::{OutboundHandler, Session};

use super::health::HealthChecker;

/// Latency history weighted selection proxy group.
///
/// Selects proxies based on weighted probability derived from historical latency data.
/// Lower latency proxies get higher probability, providing a soft load-balancing
/// effect while still preferring faster nodes.
pub struct LatencyWeightedGroup {
    tag: String,
    proxies: Vec<Arc<dyn OutboundHandler>>,
    proxy_names: Vec<String>,
    health: Arc<HealthChecker>,
    /// Historical latency samples per proxy: name -> Vec<(timestamp_ms, latency_ms)>
    history: RwLock<HashMap<String, Vec<LatencySample>>>,
    /// Maximum number of history samples to keep per proxy
    max_history: usize,
    /// Weight exponent: higher = more aggressive preference for low latency
    weight_exponent: f64,
    /// Counter for deterministic round-robin fallback
    counter: std::sync::atomic::AtomicU64,
}

#[derive(Debug, Clone)]
pub struct LatencySample {
    pub timestamp_ms: u64,
    pub latency_ms: u64,
}

impl LatencyWeightedGroup {
    pub fn new(
        tag: String,
        proxies: Vec<Arc<dyn OutboundHandler>>,
        proxy_names: Vec<String>,
        url: String,
        interval: u64,
        max_history: usize,
        weight_exponent: f64,
    ) -> Self {
        let health = Arc::new(HealthChecker::new(
            proxies.clone(),
            proxy_names.clone(),
            url,
            interval,
        ));

        let health_clone = health.clone();
        let group_name = tag.clone();
        tokio::spawn(async move {
            health_clone.run_loop(group_name).await;
        });

        Self {
            tag,
            proxies,
            proxy_names,
            health,
            history: RwLock::new(HashMap::new()),
            max_history,
            weight_exponent,
            counter: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// Record a latency measurement for a proxy
    pub async fn record_latency(&self, name: &str, latency_ms: u64) {
        let mut history = self.history.write().await;
        let samples = history.entry(name.to_string()).or_insert_with(Vec::new);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        samples.push(LatencySample {
            timestamp_ms: now,
            latency_ms,
        });
        if samples.len() > self.max_history {
            samples.drain(0..samples.len() - self.max_history);
        }
    }

    /// Calculate average latency from history for each proxy
    pub async fn compute_weights(&self) -> Vec<(usize, f64)> {
        let latencies = self.health.latencies().await;
        let history = self.history.read().await;

        let mut weights = Vec::new();

        for (idx, name) in self.proxy_names.iter().enumerate() {
            // Combine health check latency with historical average
            let current = latencies.get(name).copied().flatten();
            let hist_avg = history.get(name).map(|samples| {
                if samples.is_empty() {
                    return None;
                }
                let sum: u64 = samples.iter().map(|s| s.latency_ms).sum();
                Some(sum / samples.len() as u64)
            }).flatten();

            let avg_latency = match (current, hist_avg) {
                (Some(c), Some(h)) => (c + h) / 2, // Blend current and historical
                (Some(c), None) => c,
                (None, Some(h)) => h,
                (None, None) => continue, // Skip unavailable proxies
            };

            if avg_latency == 0 {
                weights.push((idx, 1.0));
            } else {
                // Weight = 1 / latency^exponent (higher weight = more likely to be selected)
                let weight = 1.0 / (avg_latency as f64).powf(self.weight_exponent);
                weights.push((idx, weight));
            }
        }

        weights
    }

    /// Select a proxy index using weighted random selection
    pub async fn select_proxy(&self) -> usize {
        let weights = self.compute_weights().await;

        if weights.is_empty() {
            // Fallback to round-robin
            let cnt = self.counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            return (cnt as usize) % self.proxies.len();
        }

        let total_weight: f64 = weights.iter().map(|(_, w)| w).sum();
        if total_weight <= 0.0 {
            return weights[0].0;
        }

        // Deterministic weighted selection using counter (not random, for reproducibility)
        let cnt = self.counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let position = (cnt as f64 % (total_weight * 1000.0)) / 1000.0;

        let mut cumulative = 0.0;
        for (idx, weight) in &weights {
            cumulative += weight;
            if position < cumulative {
                return *idx;
            }
        }

        weights.last().map(|(idx, _)| *idx).unwrap_or(0)
    }

    pub fn proxy_names(&self) -> &[String] {
        &self.proxy_names
    }

    pub fn health(&self) -> &Arc<HealthChecker> {
        &self.health
    }

    pub async fn history_size(&self, name: &str) -> usize {
        self.history.read().await.get(name).map(|s| s.len()).unwrap_or(0)
    }
}

#[async_trait]
impl OutboundHandler for LatencyWeightedGroup {
    fn tag(&self) -> &str {
        &self.tag
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    async fn connect(&self, session: &Session) -> Result<ProxyStream> {
        let idx = self.select_proxy().await;
        self.proxies[idx].connect(session).await
    }

    async fn connect_udp(&self, session: &Session) -> Result<BoxUdpTransport> {
        let idx = self.select_proxy().await;
        self.proxies[idx].connect_udp(session).await
    }
}

/// Nested proxy group: a group that can reference other groups.
///
/// This is handled at build_proxy_groups level. The existing `build_proxy_groups`
/// already supports group nesting by searching `result` for already-built groups.
/// Here we provide a helper for validating nesting depth.
pub fn validate_group_nesting(
    configs: &[crate::config::types::ProxyGroupConfig],
    max_depth: usize,
) -> Result<()> {
    use std::collections::HashSet;

    let group_names: HashSet<&str> = configs.iter().map(|c| c.name.as_str()).collect();

    fn check_depth(
        name: &str,
        configs: &[crate::config::types::ProxyGroupConfig],
        group_names: &HashSet<&str>,
        visited: &mut HashSet<String>,
        depth: usize,
        max_depth: usize,
    ) -> Result<()> {
        if depth > max_depth {
            anyhow::bail!("proxy group nesting depth exceeds maximum ({}) at group '{}'", max_depth, name);
        }
        if visited.contains(name) {
            anyhow::bail!("circular reference detected in proxy group '{}'", name);
        }
        visited.insert(name.to_string());

        if let Some(config) = configs.iter().find(|c| c.name == name) {
            for proxy_name in &config.proxies {
                if group_names.contains(proxy_name.as_str()) {
                    check_depth(proxy_name, configs, group_names, visited, depth + 1, max_depth)?;
                }
            }
        }

        visited.remove(name);
        Ok(())
    }

    for config in configs {
        let mut visited = HashSet::new();
        check_depth(&config.name, configs, &group_names, &mut visited, 0, max_depth)?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::types::ProxyGroupConfig;

    #[test]
    fn validate_nesting_no_groups() {
        let configs: Vec<ProxyGroupConfig> = vec![];
        assert!(validate_group_nesting(&configs, 5).is_ok());
    }

    #[test]
    fn validate_nesting_flat() {
        let configs = vec![
            ProxyGroupConfig {
                name: "group-a".to_string(),
                group_type: "selector".to_string(),
                proxies: vec!["proxy-1".to_string(), "proxy-2".to_string()],
                url: None,
                interval: 300,
                tolerance: 150,
            },
        ];
        assert!(validate_group_nesting(&configs, 5).is_ok());
    }

    #[test]
    fn validate_nesting_one_level() {
        let configs = vec![
            ProxyGroupConfig {
                name: "inner".to_string(),
                group_type: "url-test".to_string(),
                proxies: vec!["proxy-1".to_string(), "proxy-2".to_string()],
                url: None,
                interval: 300,
                tolerance: 150,
            },
            ProxyGroupConfig {
                name: "outer".to_string(),
                group_type: "selector".to_string(),
                proxies: vec!["inner".to_string(), "proxy-3".to_string()],
                url: None,
                interval: 300,
                tolerance: 150,
            },
        ];
        assert!(validate_group_nesting(&configs, 5).is_ok());
    }

    #[test]
    fn validate_nesting_circular_reference() {
        let configs = vec![
            ProxyGroupConfig {
                name: "group-a".to_string(),
                group_type: "selector".to_string(),
                proxies: vec!["group-b".to_string()],
                url: None,
                interval: 300,
                tolerance: 150,
            },
            ProxyGroupConfig {
                name: "group-b".to_string(),
                group_type: "selector".to_string(),
                proxies: vec!["group-a".to_string()],
                url: None,
                interval: 300,
                tolerance: 150,
            },
        ];
        assert!(validate_group_nesting(&configs, 5).is_err());
    }

    #[test]
    fn validate_nesting_too_deep() {
        let configs = vec![
            ProxyGroupConfig {
                name: "g1".to_string(),
                group_type: "selector".to_string(),
                proxies: vec!["g2".to_string()],
                url: None,
                interval: 300,
                tolerance: 150,
            },
            ProxyGroupConfig {
                name: "g2".to_string(),
                group_type: "selector".to_string(),
                proxies: vec!["g3".to_string()],
                url: None,
                interval: 300,
                tolerance: 150,
            },
            ProxyGroupConfig {
                name: "g3".to_string(),
                group_type: "selector".to_string(),
                proxies: vec!["proxy-1".to_string()],
                url: None,
                interval: 300,
                tolerance: 150,
            },
        ];
        // max_depth=1 should fail (g1 -> g2 -> g3 is depth 2)
        assert!(validate_group_nesting(&configs, 1).is_err());
        // max_depth=3 should pass
        assert!(validate_group_nesting(&configs, 3).is_ok());
    }

    #[tokio::test]
    async fn latency_weighted_record_and_history() {
        // We can't fully test without real proxies, but we can test the history recording
        use crate::proxy::outbound::direct::DirectOutbound;

        let p1 = Arc::new(DirectOutbound::new("p1".to_string())) as Arc<dyn OutboundHandler>;
        let group = LatencyWeightedGroup::new(
            "weighted".to_string(),
            vec![p1],
            vec!["p1".to_string()],
            "http://example.com/generate_204".to_string(),
            300,
            10,
            2.0,
        );

        group.record_latency("p1", 100).await;
        group.record_latency("p1", 150).await;
        assert_eq!(group.history_size("p1").await, 2);
    }

    #[tokio::test]
    async fn latency_weighted_history_cap() {
        use crate::proxy::outbound::direct::DirectOutbound;

        let p1 = Arc::new(DirectOutbound::new("p1".to_string())) as Arc<dyn OutboundHandler>;
        let group = LatencyWeightedGroup::new(
            "weighted".to_string(),
            vec![p1],
            vec!["p1".to_string()],
            "http://example.com/generate_204".to_string(),
            300,
            3, // max_history = 3
            2.0,
        );

        for i in 0..5 {
            group.record_latency("p1", 100 + i * 10).await;
        }
        assert_eq!(group.history_size("p1").await, 3);
    }
}
