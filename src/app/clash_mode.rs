//! Clash 模式切换
//!
//! 支持三种模式:
//! - Rule: 走规则路由（默认）
//! - Global: 所有流量走选中的代理出站
//! - Direct: 所有流量直连

use std::sync::atomic::{AtomicU8, Ordering};

/// Clash-compatible operation mode
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ClashMode {
    /// Route traffic based on rules (default)
    Rule = 0,
    /// Route all traffic through the selected proxy
    Global = 1,
    /// Route all traffic directly
    Direct = 2,
}

impl ClashMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Rule => "rule",
            Self::Global => "global",
            Self::Direct => "direct",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "rule" | "rules" => Some(Self::Rule),
            "global" => Some(Self::Global),
            "direct" => Some(Self::Direct),
            _ => None,
        }
    }
}

impl std::fmt::Display for ClashMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// 全局模式存储（lock-free）
static CLASH_MODE: AtomicU8 = AtomicU8::new(ClashMode::Rule as u8);

/// 获取当前模式
pub fn get_mode() -> ClashMode {
    match CLASH_MODE.load(Ordering::Relaxed) {
        1 => ClashMode::Global,
        2 => ClashMode::Direct,
        _ => ClashMode::Rule,
    }
}

/// 设置模式
pub fn set_mode(mode: ClashMode) {
    CLASH_MODE.store(mode as u8, Ordering::Relaxed);
    tracing::info!(mode = mode.as_str(), "clash mode changed");
}

/// 设置模式（字符串版）
pub fn set_mode_str(s: &str) -> bool {
    match ClashMode::from_str(s) {
        Some(m) => {
            set_mode(m);
            true
        }
        None => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mode_roundtrip() {
        for m in [ClashMode::Rule, ClashMode::Global, ClashMode::Direct] {
            assert_eq!(ClashMode::from_str(m.as_str()), Some(m));
        }
    }

    #[test]
    fn mode_set_get() {
        set_mode(ClashMode::Global);
        assert_eq!(get_mode(), ClashMode::Global);
        set_mode(ClashMode::Rule);
        assert_eq!(get_mode(), ClashMode::Rule);
    }

    #[test]
    fn mode_from_str_case_insensitive() {
        assert_eq!(ClashMode::from_str("GLOBAL"), Some(ClashMode::Global));
        assert_eq!(ClashMode::from_str("Direct"), Some(ClashMode::Direct));
        assert_eq!(ClashMode::from_str("Rules"), Some(ClashMode::Rule));
        assert_eq!(ClashMode::from_str("invalid"), None);
    }
}
