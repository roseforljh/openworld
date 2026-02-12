//! FFI 层：将 OpenWorld 内核以 C ABI 接口导出，供 Android JNI 或其他 FFI 调用。
//!
//! 所有导出函数使用统一约定：
//! - 返回 i32: 0 = 成功, -1 = 未运行, -2 = 已运行, -3 = 参数错误, -4 = 内部错误
//! - 返回 *mut c_char: Rust 分配的字符串，调用方需通过 `openworld_free_string` 释放
//! - 返回 i64: 直接数值（流量字节等）

use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use crate::app::tracker::ConnectionTracker;
use crate::app::App;
use crate::config::Config;

/// 全局内核实例
static INSTANCE: OnceLock<Mutex<Option<OpenWorldInstance>>> = OnceLock::new();

fn instance_lock() -> &'static Mutex<Option<OpenWorldInstance>> {
    INSTANCE.get_or_init(|| Mutex::new(None))
}

/// 运行中的 OpenWorld 内核实例
struct OpenWorldInstance {
    runtime: tokio::runtime::Runtime,
    cancel_token: tokio_util::sync::CancellationToken,
    tracker: Arc<ConnectionTracker>,
    outbound_manager: Arc<crate::app::outbound_manager::OutboundManager>,
    paused: AtomicBool,
    tun_fd: AtomicI32,
}

// ─── Helper macros ──────────────────────────────────────────────────────────

/// 将 Rust String 转为堆分配的 C 字符串指针
fn to_c_string(s: &str) -> *mut c_char {
    match CString::new(s) {
        Ok(cs) => cs.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}

/// 安全地从 C 字符串指针读取 &str
unsafe fn from_c_str<'a>(ptr: *const c_char) -> Option<&'a str> {
    if ptr.is_null() {
        return None;
    }
    CStr::from_ptr(ptr).to_str().ok()
}

/// 对 instance 执行操作的宏: 锁定 -> 检查存在 -> 执行闭包
macro_rules! with_instance {
    ($f:expr) => {{
        let guard = match instance_lock().lock() {
            Ok(g) => g,
            Err(_) => return -4, // poisoned mutex
        };
        match guard.as_ref() {
            Some(inst) => $f(inst),
            None => -1, // not running
        }
    }};
}

// ═══════════════════════════════════════════════════════════════════════════
// 生命周期
// ═══════════════════════════════════════════════════════════════════════════

/// 启动代理内核
///
/// # Safety
/// `config_json` 必须是合法的 C 字符串指针，内容为 JSON 或 YAML 配置
#[no_mangle]
pub unsafe extern "C" fn openworld_start(config_json: *const c_char) -> i32 {
    let config_str = match from_c_str(config_json) {
        Some(s) => s.to_string(),
        None => return -3,
    };

    let mut guard = match instance_lock().lock() {
        Ok(g) => g,
        Err(_) => return -4,
    };

    if guard.is_some() {
        return -2; // already running
    }

    // 解析配置：先尝试 JSON, 再尝试 YAML
    let config: Config = match serde_json::from_str(&config_str) {
        Ok(c) => c,
        Err(_) => match serde_yml::from_str(&config_str) {
            Ok(c) => c,
            Err(_) => {
                // 尝试 sing-box JSON 兼容解析
                match crate::config::json_compat::parse_singbox_json(&config_str) {
                    Ok(c) => c,
                    Err(_) => return -3,
                }
            }
        },
    };

    // 创建 tokio runtime
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .thread_name("openworld-worker")
        .build()
    {
        Ok(rt) => rt,
        Err(_) => return -4,
    };

    let cancel_token = tokio_util::sync::CancellationToken::new();

    // 在 runtime 中构建 App 并运行
    let tracker = Arc::new(ConnectionTracker::new());
    let outbound_manager = match runtime.block_on(async {
        crate::app::outbound_manager::OutboundManager::new(
            &config.outbounds,
            &config.proxy_groups,
        )
    }) {
        Ok(om) => Arc::new(om),
        Err(_) => return -4,
    };

    let cancel = cancel_token.clone();
    let config_for_run = config;
    runtime.spawn(async move {
        match App::new(config_for_run, None, None).await {
            Ok(app) => {
                if let Err(e) = app.run().await {
                    tracing::error!(error = %e, "openworld run error");
                }
            }
            Err(e) => {
                tracing::error!(error = %e, "openworld init error");
            }
        }
        drop(cancel);
    });

    *guard = Some(OpenWorldInstance {
        runtime,
        cancel_token,
        tracker,
        outbound_manager,
        paused: AtomicBool::new(false),
        tun_fd: AtomicI32::new(-1),
    });

    0
}

/// 停止代理内核
#[no_mangle]
pub extern "C" fn openworld_stop() -> i32 {
    let mut guard = match instance_lock().lock() {
        Ok(g) => g,
        Err(_) => return -4,
    };

    match guard.take() {
        Some(instance) => {
            instance.cancel_token.cancel();
            // Runtime 在 drop 时会 shutdown
            drop(instance);
            0
        }
        None => -1,
    }
}

/// 检查是否运行中
#[no_mangle]
pub extern "C" fn openworld_is_running() -> i32 {
    let guard = match instance_lock().lock() {
        Ok(g) => g,
        Err(_) => return 0,
    };
    if guard.is_some() { 1 } else { 0 }
}

/// 获取版本号
#[no_mangle]
pub extern "C" fn openworld_version() -> *mut c_char {
    to_c_string(env!("CARGO_PKG_VERSION"))
}

// ═══════════════════════════════════════════════════════════════════════════
// 暂停/恢复
// ═══════════════════════════════════════════════════════════════════════════

/// 暂停内核（省电模式）
#[no_mangle]
pub extern "C" fn openworld_pause() -> i32 {
    with_instance!(|inst: &OpenWorldInstance| {
        inst.paused.store(true, Ordering::Release);
        0
    })
}

/// 恢复内核
#[no_mangle]
pub extern "C" fn openworld_resume() -> i32 {
    with_instance!(|inst: &OpenWorldInstance| {
        inst.paused.store(false, Ordering::Release);
        0
    })
}

/// 查询暂停状态
#[no_mangle]
pub extern "C" fn openworld_is_paused() -> i32 {
    with_instance!(|inst: &OpenWorldInstance| {
        if inst.paused.load(Ordering::Acquire) { 1 } else { 0 }
    })
}

// ═══════════════════════════════════════════════════════════════════════════
// 节点管理
// ═══════════════════════════════════════════════════════════════════════════

/// 切换出站节点
///
/// # Safety
/// `tag` 必须是合法的 C 字符串指针
#[no_mangle]
pub unsafe extern "C" fn openworld_select_outbound(tag: *const c_char) -> i32 {
    let tag_str = match from_c_str(tag) {
        Some(s) => s.to_string(),
        None => return -3,
    };

    let guard = match instance_lock().lock() {
        Ok(g) => g,
        Err(_) => return -4,
    };

    match guard.as_ref() {
        Some(inst) => {
            // 尝试在所有代理组中查找并切换
            let om = inst.outbound_manager.clone();
            let result = inst.runtime.block_on(async {
                // 遍历所有 handler, 尝试 selector 切换
                for (name, _handler) in om.list() {
                    if om.is_group(name) {
                        if om.select_proxy(name, &tag_str).await {
                            return true;
                        }
                    }
                }
                false
            });
            if result { 0 } else { -3 }
        }
        None => -1,
    }
}

/// 获取当前选中出站节点
#[no_mangle]
pub extern "C" fn openworld_get_selected_outbound() -> *mut c_char {
    let guard = match instance_lock().lock() {
        Ok(g) => g,
        Err(_) => return std::ptr::null_mut(),
    };

    match guard.as_ref() {
        Some(inst) => {
            let om = inst.outbound_manager.clone();
            let selected = inst.runtime.block_on(async {
                for (name, _handler) in om.list() {
                    if om.is_group(name) {
                        if let Some(sel) = om.group_selected(name).await {
                            return Some(sel);
                        }
                    }
                }
                None
            });
            match selected {
                Some(s) => to_c_string(&s),
                None => std::ptr::null_mut(),
            }
        }
        None => std::ptr::null_mut(),
    }
}

/// 获取出站列表（\n 分隔）
#[no_mangle]
pub extern "C" fn openworld_list_outbounds() -> *mut c_char {
    let guard = match instance_lock().lock() {
        Ok(g) => g,
        Err(_) => return std::ptr::null_mut(),
    };

    match guard.as_ref() {
        Some(inst) => {
            let tags: Vec<String> = inst.outbound_manager.list().keys().cloned().collect();
            to_c_string(&tags.join("\n"))
        }
        None => std::ptr::null_mut(),
    }
}

/// 是否有 selector 出站
#[no_mangle]
pub extern "C" fn openworld_has_selector() -> i32 {
    let guard = match instance_lock().lock() {
        Ok(g) => g,
        Err(_) => return 0,
    };

    match guard.as_ref() {
        Some(inst) => {
            let has = inst.outbound_manager.list().keys().any(|name| {
                inst.outbound_manager
                    .group_meta(name)
                    .map(|m| m.group_type == "selector")
                    .unwrap_or(false)
            });
            if has { 1 } else { 0 }
        }
        None => 0,
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// 流量统计
// ═══════════════════════════════════════════════════════════════════════════

/// 累计上传字节
#[no_mangle]
pub extern "C" fn openworld_get_upload_total() -> i64 {
    let guard = match instance_lock().lock() {
        Ok(g) => g,
        Err(_) => return 0,
    };
    match guard.as_ref() {
        Some(inst) => inst.tracker.snapshot().total_up as i64,
        None => 0,
    }
}

/// 累计下载字节
#[no_mangle]
pub extern "C" fn openworld_get_download_total() -> i64 {
    let guard = match instance_lock().lock() {
        Ok(g) => g,
        Err(_) => return 0,
    };
    match guard.as_ref() {
        Some(inst) => inst.tracker.snapshot().total_down as i64,
        None => 0,
    }
}

/// 重置流量统计
#[no_mangle]
pub extern "C" fn openworld_reset_traffic() -> i32 {
    with_instance!(|inst: &OpenWorldInstance| {
        inst.tracker.reset_traffic();
        0
    })
}

/// 活跃连接数
#[no_mangle]
pub extern "C" fn openworld_get_connection_count() -> i32 {
    let guard = match instance_lock().lock() {
        Ok(g) => g,
        Err(_) => return 0,
    };
    match guard.as_ref() {
        Some(inst) => inst.tracker.active_count_sync() as i32,
        None => 0,
    }
}

/// 按出站分组流量（JSON）
#[no_mangle]
pub extern "C" fn openworld_get_traffic_by_outbound() -> *mut c_char {
    let guard = match instance_lock().lock() {
        Ok(g) => g,
        Err(_) => return std::ptr::null_mut(),
    };
    match guard.as_ref() {
        Some(inst) => {
            let stats = inst.tracker.per_outbound_traffic();
            match serde_json::to_string(&stats) {
                Ok(json) => to_c_string(&json),
                Err(_) => to_c_string("{}"),
            }
        }
        None => std::ptr::null_mut(),
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// 连接管理
// ═══════════════════════════════════════════════════════════════════════════

/// 重置所有连接
#[no_mangle]
pub extern "C" fn openworld_reset_all_connections(system: i32) -> i32 {
    let guard = match instance_lock().lock() {
        Ok(g) => g,
        Err(_) => return -4,
    };
    match guard.as_ref() {
        Some(inst) => {
            let _ = system;
            let tracker = inst.tracker.clone();
            inst.runtime.block_on(async {
                tracker.close_all().await;
            });
            0
        }
        None => -1,
    }
}

/// 关闭所有追踪连接
#[no_mangle]
pub extern "C" fn openworld_close_all_tracked_connections() -> i32 {
    let guard = match instance_lock().lock() {
        Ok(g) => g,
        Err(_) => return -4,
    };
    match guard.as_ref() {
        Some(inst) => {
            let tracker = inst.tracker.clone();
            let count = inst.runtime.block_on(async {
                tracker.close_all().await
            });
            count as i32
        }
        None => -1,
    }
}

/// 关闭空闲连接
#[no_mangle]
pub extern "C" fn openworld_close_idle_connections(seconds: i64) -> i32 {
    let guard = match instance_lock().lock() {
        Ok(g) => g,
        Err(_) => return -4,
    };
    match guard.as_ref() {
        Some(inst) => {
            let duration = std::time::Duration::from_secs(seconds.max(0) as u64);
            let tracker = inst.tracker.clone();
            let count = inst.runtime.block_on(async {
                tracker.close_idle(duration).await
            });
            count as i32
        }
        None => -1,
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// 网络恢复
// ═══════════════════════════════════════════════════════════════════════════

/// 自动网络恢复
#[no_mangle]
pub extern "C" fn openworld_recover_network_auto() -> i32 {
    let guard = match instance_lock().lock() {
        Ok(g) => g,
        Err(_) => return -4,
    };
    match guard.as_ref() {
        Some(inst) => {
            let tracker = inst.tracker.clone();
            inst.runtime.block_on(async {
                tracker.close_all().await;
            });
            0
        }
        None => -1,
    }
}

/// 是否需要网络恢复
#[no_mangle]
pub extern "C" fn openworld_check_network_recovery_needed() -> i32 {
    // 此函数总是返回 0（不需要），实际的网络恢复逻辑由 Android 侧判断
    0
}

// ═══════════════════════════════════════════════════════════════════════════
// TUN
// ═══════════════════════════════════════════════════════════════════════════

/// 设置 TUN fd（Android VpnService 传入）
#[no_mangle]
pub extern "C" fn openworld_set_tun_fd(fd: i32) -> i32 {
    with_instance!(|inst: &OpenWorldInstance| {
        inst.tun_fd.store(fd, Ordering::Release);
        0
    })
}

// ═══════════════════════════════════════════════════════════════════════════
// 延迟测试
// ═══════════════════════════════════════════════════════════════════════════

/// URL 延迟测试
///
/// # Safety
/// `outbound_tag` 和 `url` 必须是合法的 C 字符串指针
#[no_mangle]
pub unsafe extern "C" fn openworld_url_test(
    outbound_tag: *const c_char,
    url: *const c_char,
    timeout_ms: i32,
) -> i32 {
    let tag = match from_c_str(outbound_tag) {
        Some(s) => s.to_string(),
        None => return -3,
    };
    let test_url = match from_c_str(url) {
        Some(s) => s.to_string(),
        None => return -3,
    };

    let guard = match instance_lock().lock() {
        Ok(g) => g,
        Err(_) => return -4,
    };

    match guard.as_ref() {
        Some(inst) => {
            let om = inst.outbound_manager.clone();
            let result = inst.runtime.block_on(async {
                om.test_delay(&tag, &test_url, timeout_ms as u64).await
            });
            match result {
                Some(ms) => ms as i32,
                None => -1,
            }
        }
        None => -1,
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// 内存管理
// ═══════════════════════════════════════════════════════════════════════════

/// 释放由 Rust 分配的 C 字符串
///
/// # Safety
/// `ptr` 必须是此库分配的字符串指针，且只能释放一次
#[no_mangle]
pub unsafe extern "C" fn openworld_free_string(ptr: *mut c_char) {
    if !ptr.is_null() {
        drop(CString::from_raw(ptr));
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// GUI 回调 (保留兼容)
// ═══════════════════════════════════════════════════════════════════════════

/// GUI 回调接口类型
pub type OnConnectionChanged = extern "C" fn(active: i32, total_up: u64, total_down: u64);
pub type OnLogMessage = extern "C" fn(level: i32, msg: *const c_char);
pub type OnConfigReloaded = extern "C" fn(success: i32);

/// GUI 回调注册表
pub struct CallbackRegistry {
    on_connection_changed: Option<OnConnectionChanged>,
    on_log_message: Option<OnLogMessage>,
    on_config_reloaded: Option<OnConfigReloaded>,
}

impl CallbackRegistry {
    pub fn new() -> Self {
        Self {
            on_connection_changed: None,
            on_log_message: None,
            on_config_reloaded: None,
        }
    }

    pub fn set_connection_changed(&mut self, cb: OnConnectionChanged) {
        self.on_connection_changed = Some(cb);
    }

    pub fn set_log_message(&mut self, cb: OnLogMessage) {
        self.on_log_message = Some(cb);
    }

    pub fn set_config_reloaded(&mut self, cb: OnConfigReloaded) {
        self.on_config_reloaded = Some(cb);
    }

    pub fn notify_connection_changed(&self, active: i32, total_up: u64, total_down: u64) {
        if let Some(cb) = self.on_connection_changed {
            cb(active, total_up, total_down);
        }
    }

    pub fn notify_log(&self, level: i32, msg: &str) {
        if let Some(cb) = self.on_log_message {
            if let Ok(c_msg) = CString::new(msg) {
                cb(level, c_msg.as_ptr());
            }
        }
    }

    pub fn notify_config_reloaded(&self, success: bool) {
        if let Some(cb) = self.on_config_reloaded {
            cb(if success { 1 } else { 0 });
        }
    }
}

/// 批量测速请求
pub struct SpeedTestRequest {
    pub proxy_names: Vec<String>,
    pub test_url: String,
    pub timeout_ms: u64,
}

/// 批量测速结果
#[derive(Debug, Clone)]
pub struct SpeedTestResult {
    pub proxy_name: String,
    pub latency_ms: Option<u64>,
    pub success: bool,
}

/// 系统托盘状态数据
#[derive(Debug, Clone)]
pub struct TrayStatus {
    pub running: bool,
    pub mode: String,
    pub active_connections: u32,
    pub upload_speed: u64,
    pub download_speed: u64,
    pub total_upload: u64,
    pub total_download: u64,
}

impl TrayStatus {
    pub fn new() -> Self {
        Self {
            running: false,
            mode: "rule".to_string(),
            active_connections: 0,
            upload_speed: 0,
            download_speed: 0,
            total_upload: 0,
            total_download: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ffi_version() {
        let ver = openworld_version();
        assert!(!ver.is_null());
        let s = unsafe { CStr::from_ptr(ver) }.to_str().unwrap();
        assert!(!s.is_empty());
        unsafe { openworld_free_string(ver) };
    }

    #[test]
    fn ffi_is_running_default() {
        assert_eq!(openworld_is_running(), 0);
    }

    #[test]
    fn ffi_stop_not_running() {
        assert_eq!(openworld_stop(), -1);
    }

    #[test]
    fn ffi_start_null_path() {
        let result = unsafe { openworld_start(std::ptr::null()) };
        assert_eq!(result, -3);
    }

    #[test]
    fn callback_registry_creation() {
        let reg = CallbackRegistry::new();
        assert!(reg.on_connection_changed.is_none());
        assert!(reg.on_log_message.is_none());
        assert!(reg.on_config_reloaded.is_none());
    }

    #[test]
    fn callback_notify_no_crash_when_none() {
        let reg = CallbackRegistry::new();
        reg.notify_connection_changed(0, 0, 0);
        reg.notify_log(0, "test");
        reg.notify_config_reloaded(true);
    }

    #[test]
    fn tray_status_default() {
        let status = TrayStatus::new();
        assert!(!status.running);
        assert_eq!(status.mode, "rule");
        assert_eq!(status.active_connections, 0);
    }

    #[test]
    fn speed_test_result_creation() {
        let result = SpeedTestResult {
            proxy_name: "test".to_string(),
            latency_ms: Some(50),
            success: true,
        };
        assert!(result.success);
        assert_eq!(result.latency_ms, Some(50));
    }

    #[test]
    fn free_string_null_safe() {
        unsafe { openworld_free_string(std::ptr::null_mut()) };
    }

    #[test]
    fn free_string_valid() {
        let ptr = to_c_string("hello");
        assert!(!ptr.is_null());
        unsafe { openworld_free_string(ptr) };
    }
}
