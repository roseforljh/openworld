use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::sync::atomic::{AtomicBool, Ordering};

static RUNNING: AtomicBool = AtomicBool::new(false);

/// FFI: 启动代理内核
///
/// # Safety
/// `config_path` 必须是合法的 C 字符串指针
#[no_mangle]
pub unsafe extern "C" fn openworld_start(config_path: *const c_char) -> i32 {
    if config_path.is_null() {
        return -1;
    }
    if RUNNING.load(Ordering::Relaxed) {
        return -2; // already running
    }

    let path = match CStr::from_ptr(config_path).to_str() {
        Ok(s) => s.to_string(),
        Err(_) => return -3,
    };

    RUNNING.store(true, Ordering::Relaxed);
    let _ = path; // TODO: 实际启动 App
    0
}

/// FFI: 停止代理内核
#[no_mangle]
pub extern "C" fn openworld_stop() -> i32 {
    if !RUNNING.load(Ordering::Relaxed) {
        return -1;
    }
    RUNNING.store(false, Ordering::Relaxed);
    0
}

/// FFI: 检查是否运行中
#[no_mangle]
pub extern "C" fn openworld_is_running() -> i32 {
    if RUNNING.load(Ordering::Relaxed) { 1 } else { 0 }
}

/// FFI: 获取版本号
#[no_mangle]
pub extern "C" fn openworld_version() -> *const c_char {
    static VERSION: &[u8] = b"0.1.0\0";
    VERSION.as_ptr() as *const c_char
}

/// FFI: 获取活跃连接数（需要 runtime 支持，当前返回 0）
#[no_mangle]
pub extern "C" fn openworld_active_connections() -> i32 {
    0
}

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
        let s = unsafe { CStr::from_ptr(ver) }.to_str().unwrap();
        assert_eq!(s, "0.1.0");
    }

    #[test]
    fn ffi_is_running_default() {
        RUNNING.store(false, Ordering::Relaxed);
        assert_eq!(openworld_is_running(), 0);
    }

    #[test]
    fn ffi_stop_not_running() {
        RUNNING.store(false, Ordering::Relaxed);
        assert_eq!(openworld_stop(), -1);
    }

    #[test]
    fn ffi_start_null_path() {
        let result = unsafe { openworld_start(std::ptr::null()) };
        assert_eq!(result, -1);
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
}
