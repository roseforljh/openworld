//! 平台接口：存储和管理 Android/iOS 等平台推送的状态信息。
//!
//! Android 端在网络切换、低内存等事件发生时，通过 FFI 通知内核。
//! 内核可读取当前平台状态做决策（如：计量连接时降低预取等）。

use std::sync::{OnceLock, RwLock};
use std::time::Instant;

// ═══════════════════════════════════════════════════════════════════════════
// 数据类型
// ═══════════════════════════════════════════════════════════════════════════

/// 网络连接类型
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkType {
    /// 无网络
    None = 0,
    /// Wi-Fi
    WiFi = 1,
    /// 蜂窝数据
    Cellular = 2,
    /// 以太网
    Ethernet = 3,
    /// 其他
    Other = 4,
}

impl NetworkType {
    pub fn from_i32(v: i32) -> Self {
        match v {
            0 => Self::None,
            1 => Self::WiFi,
            2 => Self::Cellular,
            3 => Self::Ethernet,
            _ => Self::Other,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::None => "none",
            Self::WiFi => "wifi",
            Self::Cellular => "cellular",
            Self::Ethernet => "ethernet",
            Self::Other => "other",
        }
    }
}

/// 平台状态
pub struct PlatformState {
    /// 当前网络类型
    pub network_type: NetworkType,
    /// Wi-Fi SSID（仅 WiFi 时有值）
    pub wifi_ssid: Option<String>,
    /// 是否计量连接（蜂窝通常为 true）
    pub is_metered: bool,
    /// 上次网络变化时间
    pub last_network_change: Instant,
    /// 网络变化次数（用于判断是否频繁切换）
    pub change_count: u64,
}

impl Default for PlatformState {
    fn default() -> Self {
        Self {
            network_type: NetworkType::None,
            wifi_ssid: None,
            is_metered: false,
            last_network_change: Instant::now(),
            change_count: 0,
        }
    }
}

impl PlatformState {
    /// 序列化为 JSON
    pub fn to_json(&self) -> String {
        serde_json::json!({
            "network_type": self.network_type.as_str(),
            "wifi_ssid": self.wifi_ssid,
            "is_metered": self.is_metered,
            "last_change_secs_ago": self.last_network_change.elapsed().as_secs(),
            "change_count": self.change_count,
        })
        .to_string()
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// 全局状态
// ═══════════════════════════════════════════════════════════════════════════

static PLATFORM_STATE: OnceLock<RwLock<PlatformState>> = OnceLock::new();

fn state_lock() -> &'static RwLock<PlatformState> {
    PLATFORM_STATE.get_or_init(|| RwLock::new(PlatformState::default()))
}

/// 更新网络状态（由 FFI 层调用）
pub fn update_network(network_type: i32, ssid: Option<String>, is_metered: bool) {
    let mut state = state_lock().write().unwrap();
    let new_type = NetworkType::from_i32(network_type);

    // 仅在网络类型实际变化时增加计数
    if new_type != state.network_type {
        state.change_count += 1;
        tracing::info!(
            old = state.network_type.as_str(),
            new = new_type.as_str(),
            count = state.change_count,
            "网络类型变化"
        );
    }

    state.network_type = new_type;
    state.wifi_ssid = ssid;
    state.is_metered = is_metered;
    state.last_network_change = Instant::now();
}

/// 获取当前平台状态 JSON
pub fn get_state_json() -> String {
    let state = state_lock().read().unwrap();
    state.to_json()
}

/// 查询是否计量连接
pub fn is_metered() -> bool {
    let state = state_lock().read().unwrap();
    state.is_metered
}

/// 低内存通知：触发清理
pub fn notify_memory_low() {
    tracing::warn!("收到低内存通知，执行清理");
    // 目前仅记录日志，未来可触发 DNS 缓存清理、关闭空闲连接等
}

// ═══════════════════════════════════════════════════════════════════════════
// 测试
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn network_type_from_i32() {
        assert_eq!(NetworkType::from_i32(0), NetworkType::None);
        assert_eq!(NetworkType::from_i32(1), NetworkType::WiFi);
        assert_eq!(NetworkType::from_i32(2), NetworkType::Cellular);
        assert_eq!(NetworkType::from_i32(3), NetworkType::Ethernet);
        assert_eq!(NetworkType::from_i32(99), NetworkType::Other);
    }

    #[test]
    fn network_type_as_str() {
        assert_eq!(NetworkType::WiFi.as_str(), "wifi");
        assert_eq!(NetworkType::None.as_str(), "none");
    }

    #[test]
    fn platform_state_default() {
        let s = PlatformState::default();
        assert_eq!(s.network_type, NetworkType::None);
        assert!(s.wifi_ssid.is_none());
        assert!(!s.is_metered);
        assert_eq!(s.change_count, 0);
    }

    #[test]
    fn platform_state_to_json() {
        let s = PlatformState {
            network_type: NetworkType::WiFi,
            wifi_ssid: Some("MyWiFi".to_string()),
            is_metered: false,
            last_network_change: Instant::now(),
            change_count: 3,
        };
        let json = s.to_json();
        assert!(json.contains("\"network_type\":\"wifi\""));
        assert!(json.contains("\"wifi_ssid\":\"MyWiFi\""));
        assert!(json.contains("\"change_count\":3"));
    }
}
