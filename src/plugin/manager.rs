//! 插件管理器
//!
//! 负责加载、管理、执行插件脚本，支持热重载。

use std::path::PathBuf;
use std::sync::Arc;

use tokio::sync::RwLock;
use tracing::{debug, info, warn};

use super::engine::{PluginScript, ScriptEngine, ScriptError};
use super::host_api::{HostContext, RoutingDecision};

/// 插件配置
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct PluginConfig {
    /// 插件名称
    pub name: String,
    /// 脚本文件路径
    pub path: String,
    /// 是否启用
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// 优先级（数字越小越先执行）
    #[serde(default)]
    pub priority: i32,
}

fn default_true() -> bool {
    true
}

/// 插件元数据
#[derive(Debug, Clone)]
pub struct PluginMeta {
    pub name: String,
    pub path: PathBuf,
    pub enabled: bool,
    pub priority: i32,
    pub rule_count: usize,
    pub default_action: String,
}

/// 已加载的插件
struct LoadedPlugin {
    meta: PluginMeta,
    script: PluginScript,
}

/// 插件管理器
pub struct PluginManager {
    plugins: Arc<RwLock<Vec<LoadedPlugin>>>,
}

impl Default for PluginManager {
    fn default() -> Self {
        Self::new()
    }
}

impl PluginManager {
    pub fn new() -> Self {
        Self {
            plugins: Arc::new(RwLock::new(Vec::new())),
        }
    }

    /// 从配置加载所有插件
    pub async fn load_from_configs(&self, configs: &[PluginConfig]) -> Vec<String> {
        let mut errors = Vec::new();
        let mut loaded = Vec::new();

        for config in configs {
            if !config.enabled {
                debug!(name = config.name, "plugin disabled, skipping");
                continue;
            }

            match self.load_plugin(config).await {
                Ok(_) => {
                    loaded.push(config.name.clone());
                }
                Err(e) => {
                    warn!(name = config.name, error = %e, "failed to load plugin");
                    errors.push(format!("{}: {}", config.name, e));
                }
            }
        }

        if !loaded.is_empty() {
            info!(count = loaded.len(), "plugins loaded");
        }

        errors
    }

    /// 加载单个插件
    pub async fn load_plugin(&self, config: &PluginConfig) -> Result<(), String> {
        let path = PathBuf::from(&config.path);
        let source = std::fs::read_to_string(&path)
            .map_err(|e| format!("failed to read {}: {}", config.path, e))?;

        let script = ScriptEngine::compile(&config.name, &source).map_err(|e| e.to_string())?;

        let meta = PluginMeta {
            name: config.name.clone(),
            path: path.clone(),
            enabled: config.enabled,
            priority: config.priority,
            rule_count: script.rules.len(),
            default_action: script.default_action.clone(),
        };

        let rule_count = script.rules.len();
        let mut plugins = self.plugins.write().await;

        // 如果同名插件已存在，替换（热重载）
        if let Some(pos) = plugins.iter().position(|p| p.meta.name == config.name) {
            plugins[pos] = LoadedPlugin { meta, script };
            info!(name = config.name, "plugin hot-reloaded");
        } else {
            plugins.push(LoadedPlugin { meta, script });
            // 按优先级排序
            plugins.sort_by_key(|p| p.meta.priority);
            info!(name = config.name, rules = rule_count, "plugin loaded");
        }

        Ok(())
    }

    /// 卸载插件
    pub async fn unload_plugin(&self, name: &str) -> bool {
        let mut plugins = self.plugins.write().await;
        if let Some(pos) = plugins.iter().position(|p| p.meta.name == name) {
            plugins.remove(pos);
            info!(name = name, "plugin unloaded");
            true
        } else {
            false
        }
    }

    /// 执行所有插件的路由决策
    /// 按优先级顺序执行，第一个返回 UseOutbound 的插件胜出
    pub async fn route(&self, ctx: &HostContext) -> RoutingDecision {
        let plugins = self.plugins.read().await;
        for plugin in plugins.iter() {
            if !plugin.meta.enabled {
                continue;
            }
            let action = ScriptEngine::execute(&plugin.script, ctx);
            // 如果插件返回了非默认动作，使用它
            if !action.is_empty() {
                return RoutingDecision::UseOutbound(action);
            }
        }
        RoutingDecision::Pass
    }

    /// 获取所有已加载插件的元数据
    pub async fn list_plugins(&self) -> Vec<PluginMeta> {
        let plugins = self.plugins.read().await;
        plugins.iter().map(|p| p.meta.clone()).collect()
    }

    /// 启用/禁用插件
    pub async fn set_plugin_enabled(&self, name: &str, enabled: bool) -> bool {
        let mut plugins = self.plugins.write().await;
        if let Some(plugin) = plugins.iter_mut().find(|p| p.meta.name == name) {
            plugin.meta.enabled = enabled;
            info!(name = name, enabled = enabled, "plugin state changed");
            true
        } else {
            false
        }
    }

    /// 热重载指定插件（从磁盘重新读取）
    pub async fn reload_plugin(&self, name: &str) -> Result<(), String> {
        let plugins = self.plugins.read().await;
        let path = plugins
            .iter()
            .find(|p| p.meta.name == name)
            .map(|p| p.meta.path.clone())
            .ok_or_else(|| format!("plugin '{}' not found", name))?;
        let priority = plugins
            .iter()
            .find(|p| p.meta.name == name)
            .map(|p| p.meta.priority)
            .unwrap_or(0);
        drop(plugins);

        let config = PluginConfig {
            name: name.to_string(),
            path: path.to_string_lossy().to_string(),
            enabled: true,
            priority,
        };

        self.load_plugin(&config).await
    }

    /// 从内联脚本文本加载（用于测试和 API）
    pub async fn load_inline(
        &self,
        name: &str,
        source: &str,
        priority: i32,
    ) -> Result<(), ScriptError> {
        let script = ScriptEngine::compile(name, source)?;
        let meta = PluginMeta {
            name: name.to_string(),
            path: PathBuf::new(),
            enabled: true,
            priority,
            rule_count: script.rules.len(),
            default_action: script.default_action.clone(),
        };

        let mut plugins = self.plugins.write().await;
        // 如果同名插件已存在，替换（热重载）
        if let Some(pos) = plugins.iter().position(|p| p.meta.name == name) {
            plugins[pos] = LoadedPlugin { meta, script };
        } else {
            plugins.push(LoadedPlugin { meta, script });
            plugins.sort_by_key(|p| p.meta.priority);
        }
        Ok(())
    }

    /// 已加载插件数量
    pub async fn count(&self) -> usize {
        self.plugins.read().await.len()
    }
}

// ═══════════════════════════════════════════════════════════════════
// 测试
// ═══════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plugin::host_api::HostContext;

    fn test_ctx(domain: &str) -> HostContext {
        HostContext {
            domain: Some(domain.to_string()),
            dest_ip: None,
            source_ip: None,
            dest_port: 443,
            inbound_tag: "socks-in".into(),
            process_name: None,
            hour: 12,
            detected_protocol: None,
        }
    }

    #[tokio::test]
    async fn load_inline_and_route() {
        let mgr = PluginManager::new();
        mgr.load_inline(
            "test-plugin",
            r#"
                when domain suffix "google.com" => proxy
                when domain contains "ads" => reject
                default => direct
            "#,
            0,
        )
        .await
        .unwrap();

        assert_eq!(mgr.count().await, 1);

        let decision = mgr.route(&test_ctx("www.google.com")).await;
        assert_eq!(decision, RoutingDecision::UseOutbound("proxy".into()));

        let decision = mgr.route(&test_ctx("ads.example.com")).await;
        assert_eq!(decision, RoutingDecision::UseOutbound("reject".into()));

        let decision = mgr.route(&test_ctx("example.org")).await;
        assert_eq!(decision, RoutingDecision::UseOutbound("direct".into()));
    }

    #[tokio::test]
    async fn priority_ordering() {
        let mgr = PluginManager::new();

        // 低优先级插件
        mgr.load_inline("low", r#"when domain suffix "example.com" => direct"#, 10)
            .await
            .unwrap();

        // 高优先级插件（先执行）
        mgr.load_inline("high", r#"when domain suffix "example.com" => proxy"#, 1)
            .await
            .unwrap();

        let decision = mgr.route(&test_ctx("example.com")).await;
        // 高优先级插件先执行
        assert_eq!(decision, RoutingDecision::UseOutbound("proxy".into()));
    }

    #[tokio::test]
    async fn unload_plugin() {
        let mgr = PluginManager::new();
        mgr.load_inline("removable", r#"when always => reject"#, 0)
            .await
            .unwrap();

        assert_eq!(mgr.count().await, 1);
        assert!(mgr.unload_plugin("removable").await);
        assert_eq!(mgr.count().await, 0);
        assert!(!mgr.unload_plugin("nonexistent").await);
    }

    #[tokio::test]
    async fn enable_disable() {
        let mgr = PluginManager::new();
        mgr.load_inline("toggleable", r#"when always => reject"#, 0)
            .await
            .unwrap();

        // 禁用后不应影响路由
        mgr.set_plugin_enabled("toggleable", false).await;
        let plugins = mgr.list_plugins().await;
        assert!(!plugins[0].enabled);
    }

    #[tokio::test]
    async fn list_plugins_metadata() {
        let mgr = PluginManager::new();
        mgr.load_inline(
            "test-meta",
            r#"
                when domain suffix "cn" => direct
                when domain suffix "com" => proxy
                default => reject
            "#,
            5,
        )
        .await
        .unwrap();

        let plugins = mgr.list_plugins().await;
        assert_eq!(plugins.len(), 1);
        assert_eq!(plugins[0].name, "test-meta");
        assert_eq!(plugins[0].priority, 5);
        assert_eq!(plugins[0].rule_count, 2);
        assert_eq!(plugins[0].default_action, "reject");
    }

    #[tokio::test]
    async fn hot_reload_inline() {
        let mgr = PluginManager::new();
        mgr.load_inline("mutable", r#"when always => proxy"#, 0)
            .await
            .unwrap();

        let decision = mgr.route(&test_ctx("anything")).await;
        assert_eq!(decision, RoutingDecision::UseOutbound("proxy".into()));

        // 热重载：更换规则
        mgr.load_inline("mutable", r#"when always => direct"#, 0)
            .await
            .unwrap();

        // 仍然只有1个插件
        assert_eq!(mgr.count().await, 1);

        let decision = mgr.route(&test_ctx("anything")).await;
        assert_eq!(decision, RoutingDecision::UseOutbound("direct".into()));
    }

    #[test]
    fn plugin_config_serde() {
        let json = r#"{"name":"test","path":"rules.ow","enabled":true,"priority":0}"#;
        let config: PluginConfig = serde_json::from_str(json).unwrap();
        assert_eq!(config.name, "test");
        assert!(config.enabled);
    }

    #[test]
    fn plugin_config_defaults() {
        // enabled 默认 true, priority 默认 0
        let json = r#"{"name":"test","path":"rules.ow"}"#;
        let config: PluginConfig = serde_json::from_str(json).unwrap();
        assert!(config.enabled);
        assert_eq!(config.priority, 0);
    }
}
