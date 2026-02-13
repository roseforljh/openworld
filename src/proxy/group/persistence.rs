use std::collections::HashMap;
use std::path::{Path, PathBuf};

use anyhow::Result;
use serde::{Deserialize, Serialize};
use tracing::{debug, warn};

/// 策略组选择结果持久化
///
/// 将 selector 当前选中节点、url-test 最优节点写入文件。
/// 启动时读取恢复，避免每次重启都重新测速。
/// 文件格式：JSON `{"selector-group": "node-name", ...}`
#[derive(Debug)]
pub struct GroupPersistence {
    path: PathBuf,
    state: HashMap<String, GroupState>,
}

/// 单个组的持久化状态
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GroupState {
    pub selected: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub best_latency_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_check_epoch: Option<u64>,
}

impl GroupPersistence {
    /// 创建新的持久化实例
    pub fn new(path: PathBuf) -> Self {
        Self {
            path,
            state: HashMap::new(),
        }
    }

    /// 从文件加载持久化状态
    pub fn load(&mut self) -> Result<()> {
        if !self.path.exists() {
            debug!(path = %self.path.display(), "persistence file not found, using defaults");
            return Ok(());
        }

        let content = std::fs::read_to_string(&self.path)?;
        let loaded: HashMap<String, GroupState> = serde_json::from_str(&content)?;
        debug!(
            path = %self.path.display(),
            groups = loaded.len(),
            "loaded group persistence state"
        );
        self.state = loaded;
        Ok(())
    }

    /// 保存当前状态到文件
    pub fn save(&self) -> Result<()> {
        let content = serde_json::to_string_pretty(&self.state)?;
        if let Some(parent) = self.path.parent() {
            if !parent.exists() {
                std::fs::create_dir_all(parent)?;
            }
        }
        std::fs::write(&self.path, content)?;
        debug!(path = %self.path.display(), "saved group persistence state");
        Ok(())
    }

    /// 更新某个组的选中节点
    pub fn set_selected(&mut self, group: &str, selected: &str) {
        let entry = self
            .state
            .entry(group.to_string())
            .or_insert_with(|| GroupState {
                selected: selected.to_string(),
                best_latency_ms: None,
                last_check_epoch: None,
            });
        entry.selected = selected.to_string();
    }

    /// 更新某个组的最优延迟
    pub fn set_best_latency(&mut self, group: &str, latency_ms: u64) {
        if let Some(state) = self.state.get_mut(group) {
            state.best_latency_ms = Some(latency_ms);
            state.last_check_epoch = Some(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs(),
            );
        }
    }

    /// 获取某个组的持久化状态
    pub fn get(&self, group: &str) -> Option<&GroupState> {
        self.state.get(group)
    }

    /// 获取某个组的选中节点名称
    pub fn get_selected(&self, group: &str) -> Option<&str> {
        self.state.get(group).map(|s| s.selected.as_str())
    }

    /// 移除某个组的状态
    pub fn remove(&mut self, group: &str) -> bool {
        self.state.remove(group).is_some()
    }

    /// 获取所有组名
    pub fn groups(&self) -> Vec<&str> {
        self.state.keys().map(|k| k.as_str()).collect()
    }

    /// 组数量
    pub fn len(&self) -> usize {
        self.state.len()
    }

    pub fn is_empty(&self) -> bool {
        self.state.is_empty()
    }

    /// 持久化文件路径
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// 尝试从文件加载，失败时使用默认空状态（降级行为）
    pub fn load_or_default(path: PathBuf) -> Self {
        let mut persistence = Self::new(path);
        if let Err(e) = persistence.load() {
            warn!(error = %e, "failed to load group persistence, using defaults");
        }
        persistence
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn persistence_new_is_empty() {
        let p = GroupPersistence::new(PathBuf::from("/tmp/test_openworld_persist.json"));
        assert!(p.is_empty());
        assert_eq!(p.len(), 0);
    }

    #[test]
    fn persistence_set_and_get() {
        let mut p = GroupPersistence::new(PathBuf::from("/tmp/test_persist.json"));
        p.set_selected("selector-group", "node-a");
        assert_eq!(p.get_selected("selector-group"), Some("node-a"));
        assert_eq!(p.len(), 1);
    }

    #[test]
    fn persistence_update_selected() {
        let mut p = GroupPersistence::new(PathBuf::from("/tmp/test_persist.json"));
        p.set_selected("group1", "node-a");
        p.set_selected("group1", "node-b");
        assert_eq!(p.get_selected("group1"), Some("node-b"));
        assert_eq!(p.len(), 1);
    }

    #[test]
    fn persistence_set_best_latency() {
        let mut p = GroupPersistence::new(PathBuf::from("/tmp/test_persist.json"));
        p.set_selected("urltest", "node-fast");
        p.set_best_latency("urltest", 42);
        let state = p.get("urltest").unwrap();
        assert_eq!(state.best_latency_ms, Some(42));
        assert!(state.last_check_epoch.is_some());
    }

    #[test]
    fn persistence_remove() {
        let mut p = GroupPersistence::new(PathBuf::from("/tmp/test_persist.json"));
        p.set_selected("group1", "node-a");
        assert!(p.remove("group1"));
        assert!(p.is_empty());
        assert!(!p.remove("group1"));
    }

    #[test]
    fn persistence_groups_list() {
        let mut p = GroupPersistence::new(PathBuf::from("/tmp/test_persist.json"));
        p.set_selected("group-a", "node1");
        p.set_selected("group-b", "node2");
        let groups = p.groups();
        assert_eq!(groups.len(), 2);
        assert!(groups.contains(&"group-a"));
        assert!(groups.contains(&"group-b"));
    }

    #[test]
    fn persistence_save_and_load() {
        let dir = std::env::temp_dir().join("openworld_test_persist");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("group_state.json");

        // Save
        {
            let mut p = GroupPersistence::new(path.clone());
            p.set_selected("selector-1", "proxy-hk");
            p.set_selected("urltest-1", "proxy-jp");
            p.set_best_latency("urltest-1", 120);
            p.save().unwrap();
        }

        // Load
        {
            let mut p = GroupPersistence::new(path.clone());
            p.load().unwrap();
            assert_eq!(p.get_selected("selector-1"), Some("proxy-hk"));
            assert_eq!(p.get_selected("urltest-1"), Some("proxy-jp"));
            assert_eq!(p.get("urltest-1").unwrap().best_latency_ms, Some(120));
        }

        // Cleanup
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_dir(&dir);
    }

    #[test]
    fn persistence_load_nonexistent_file() {
        let mut p = GroupPersistence::new(PathBuf::from("/tmp/does_not_exist_openworld.json"));
        // Should succeed with empty state
        assert!(p.load().is_ok());
        assert!(p.is_empty());
    }

    #[test]
    fn persistence_load_or_default_with_bad_file() {
        let dir = std::env::temp_dir().join("openworld_test_bad");
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("bad_state.json");
        // Write invalid JSON
        {
            let mut f = std::fs::File::create(&path).unwrap();
            f.write_all(b"not valid json!!!").unwrap();
        }
        let p = GroupPersistence::load_or_default(path.clone());
        assert!(p.is_empty()); // Falls back to defaults

        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_dir(&dir);
    }

    #[test]
    fn persistence_serialization_format() {
        let mut p = GroupPersistence::new(PathBuf::from("/tmp/test.json"));
        p.set_selected("my-group", "node-1");
        let state = p.get("my-group").unwrap();
        let json = serde_json::to_string(state).unwrap();
        assert!(json.contains("\"selected\":\"node-1\""));
        // best_latency_ms should be omitted when None
        assert!(!json.contains("best_latency_ms"));
    }
}
