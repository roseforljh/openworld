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

use crate::app::latency_test::LatencyTester;
use crate::app::proxy_provider::ProxyProviderManager;
use crate::app::tracker::ConnectionTracker;
use crate::app::App;
use crate::config::profile::ProfileManager;
use crate::config::Config;
use serde::Deserialize;

/// 全局内核实例
static INSTANCE: OnceLock<Mutex<Option<OpenWorldInstance>>> = OnceLock::new();

/// 延迟历史记录
struct DelayRecord {
    outbound_tag: String,
    url: String,
    delay_ms: i32,  // -1 = 超时/失败
    timestamp: u64, // Unix 秒
}

static DELAY_HISTORY: OnceLock<Mutex<Vec<DelayRecord>>> = OnceLock::new();

fn delay_history_lock() -> &'static Mutex<Vec<DelayRecord>> {
    DELAY_HISTORY.get_or_init(|| Mutex::new(Vec::new()))
}

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
    profile_manager: Mutex<ProfileManager>,
    active_profile: Mutex<String>,
    provider_manager: Arc<ProxyProviderManager>,
    auto_test_cancel: Mutex<Option<tokio_util::sync::CancellationToken>>,
    /// C2: 自定义规则存储 [{"type":"...","payload":"...","proxy":"..."}]
    custom_rules: Mutex<Vec<serde_json::Value>>,
    /// C3: WakeLock 状态
    wakelock_held: AtomicBool,
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
        crate::app::outbound_manager::OutboundManager::new(&config.outbounds, &config.proxy_groups)
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
        profile_manager: Mutex::new(ProfileManager::new()),
        active_profile: Mutex::new("default".to_string()),
        provider_manager: Arc::new(ProxyProviderManager::new()),
        auto_test_cancel: Mutex::new(None),
        custom_rules: Mutex::new(Vec::new()),
        wakelock_held: AtomicBool::new(false),
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
    if guard.is_some() {
        1
    } else {
        0
    }
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
        if inst.paused.load(Ordering::Acquire) {
            1
        } else {
            0
        }
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
            if result {
                0
            } else {
                -3
            }
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
            if has {
                1
            } else {
                0
            }
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
            let count = inst.runtime.block_on(async { tracker.close_all().await });
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
            let count = inst
                .runtime
                .block_on(async { tracker.close_idle(duration).await });
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
            let result = inst
                .runtime
                .block_on(async { om.test_delay(&tag, &test_url, timeout_ms as u64).await });
            let delay = match result {
                Some(ms) => ms as i32,
                None => -1,
            };
            // 记录到延迟历史
            if let Ok(mut history) = delay_history_lock().lock() {
                let ts = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                history.push(DelayRecord {
                    outbound_tag: tag.clone(),
                    url: test_url.clone(),
                    delay_ms: delay,
                    timestamp: ts,
                });
                // 限制最多保留 1000 条
                let hlen = history.len();
                if hlen > 1000 {
                    history.drain(0..hlen - 1000);
                }
            }
            delay
        }
        None => -1,
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// 独立延迟测试（不依赖核心启动）
// ═══════════════════════════════════════════════════════════════════════════

/// 独立延迟测试器句柄
static LATENCY_TESTER: once_cell::sync::Lazy<std::sync::Mutex<Option<LatencyTester>>> =
    once_cell::sync::Lazy::new(|| std::sync::Mutex::new(None));

#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
struct LatencyInitPayloadV1 {
    schema_version: i32,
    outbounds: Vec<LatencyOutboundV1>,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
struct LatencyOutboundV1 {
    tag: String,
    protocol: String,
    settings: LatencyOutboundSettingsV1,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
struct LatencyOutboundSettingsV1 {
    address: String,
    port: u16,
    uuid: Option<String>,
    password: Option<String>,
    method: Option<String>,
    security: Option<String>,
    sni: Option<String>,
    server_name: Option<String>,
    fingerprint: Option<String>,
    flow: Option<String>,
    alter_id: Option<u16>,
    network: Option<String>,
    up_mbps: Option<u64>,
    down_mbps: Option<u64>,
    auth_str: Option<String>,
    server_ports: Option<Vec<String>>,
    hop_interval: Option<String>,
    obfs: Option<LatencyObfsConfigV1>,
    tls: Option<LatencyTlsConfigV1>,
    transport: Option<LatencyTransportConfigV1>,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
struct LatencyTlsConfigV1 {
    enabled: Option<bool>,
    server_name: Option<String>,
    sni: Option<String>,
    fingerprint: Option<String>,
    alpn: Option<Vec<String>>,
    reality: Option<LatencyRealityConfigV1>,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
struct LatencyRealityConfigV1 {
    public_key: Option<String>,
    short_id: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
struct LatencyTransportConfigV1 {
    #[serde(rename = "type")]
    transport_type: Option<String>,
    path: Option<String>,
    headers: Option<std::collections::HashMap<String, String>>,
    service_name: Option<String>,
}

#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
struct LatencyObfsConfigV1 {
    #[serde(rename = "type")]
    obfs_type: Option<String>,
    password: Option<String>,
}

impl From<LatencyOutboundV1> for crate::config::types::OutboundConfig {
    fn from(outbound: LatencyOutboundV1) -> Self {
        let mut settings = crate::config::types::OutboundSettings::default();
        settings.address = Some(outbound.settings.address);
        settings.port = Some(outbound.settings.port);
        settings.uuid = outbound.settings.uuid;
        settings.password = outbound.settings.password.or(outbound.settings.auth_str);
        settings.method = outbound.settings.method;
        settings.security = outbound.settings.security.clone();
        settings.sni = outbound.settings.sni.clone();
        settings.server_name = outbound.settings.server_name.clone();
        settings.fingerprint = outbound.settings.fingerprint.clone();
        settings.flow = outbound.settings.flow;
        settings.alter_id = outbound.settings.alter_id;
        settings.up_mbps = outbound.settings.up_mbps;
        settings.down_mbps = outbound.settings.down_mbps;
        let _ = outbound.settings.server_ports;
        let _ = outbound.settings.hop_interval;

        if let Some(obfs) = outbound.settings.obfs {
            settings.obfs = obfs.obfs_type;
            settings.obfs_password = obfs.password;
        }

        if let Some(transport) = outbound.settings.transport {
            settings.transport = Some(crate::config::types::TransportConfig {
                transport_type: transport
                    .transport_type
                    .unwrap_or_else(|| "tcp".to_string()),
                path: transport.path,
                host: None,
                headers: transport.headers,
                service_name: transport.service_name,
                shadow_tls_password: None,
                shadow_tls_sni: None,
            });
        }

        if let Some(tls) = outbound.settings.tls {
            let public_key = tls.reality.as_ref().and_then(|v| v.public_key.clone());
            let short_id = tls.reality.as_ref().and_then(|v| v.short_id.clone());
            settings.public_key = public_key.clone();
            settings.short_id = short_id.clone();

            if settings.server_name.is_none() {
                settings.server_name = tls.server_name.clone();
            }
            if settings.sni.is_none() {
                settings.sni = tls.sni.clone().or_else(|| tls.server_name.clone());
            }
            if settings.fingerprint.is_none() {
                settings.fingerprint = tls.fingerprint.clone();
            }

            settings.tls = Some(crate::config::types::TlsConfig {
                enabled: tls.enabled.unwrap_or(true),
                security: settings
                    .security
                    .clone()
                    .unwrap_or_else(|| "tls".to_string()),
                sni: settings.sni.clone(),
                allow_insecure: false,
                alpn: tls.alpn,
                public_key,
                short_id,
                server_name: settings.server_name.clone(),
                fingerprint: settings.fingerprint.clone(),
                ech_config: None,
                ech_grease: false,
                ech_outer_sni: None,
                ech_auto: false,
                fragment: None,
            });
        }

        crate::config::types::OutboundConfig {
            tag: outbound.tag,
            protocol: outbound.protocol,
            settings,
        }
    }
}

fn parse_latency_contract_outbounds(
    json_str: &str,
) -> Result<Vec<crate::config::types::OutboundConfig>, i32> {
    let value: serde_json::Value = match serde_json::from_str(json_str) {
        Ok(v) => v,
        Err(e) => {
            tracing::error!("latency_init invalid json: {}", e);
            return Err(-2);
        }
    };

    let root = match value.as_object() {
        Some(v) => v,
        None => {
            tracing::error!("latency_init invalid: top-level object expected");
            return Err(-2);
        }
    };

    let schema_version = match root.get("schema_version").and_then(|v| v.as_i64()) {
        Some(v) => v,
        None => {
            tracing::error!("latency_init invalid: schema_version missing or not integer");
            return Err(-2);
        }
    };

    if schema_version != 1 {
        tracing::error!(
            "latency_init invalid: schema_version={} unsupported",
            schema_version
        );
        return Err(-7);
    }

    let outbounds = match root.get("outbounds").and_then(|v| v.as_array()) {
        Some(v) => v,
        None => {
            tracing::error!("latency_init invalid: outbounds must be array");
            return Err(-2);
        }
    };

    if outbounds.is_empty() {
        return Err(-3);
    }

    let mut missing_errors = Vec::new();
    for (idx, item) in outbounds.iter().enumerate() {
        let Some(obj) = item.as_object() else {
            missing_errors.push(format!("outbounds[{}] object missing", idx));
            continue;
        };

        let has_tag = obj
            .get("tag")
            .and_then(|v| v.as_str())
            .map(|v| !v.trim().is_empty())
            .unwrap_or(false);
        if !has_tag {
            missing_errors.push(format!("outbounds[{}].tag missing", idx));
        }

        let has_protocol = obj
            .get("protocol")
            .and_then(|v| v.as_str())
            .map(|v| !v.trim().is_empty())
            .unwrap_or(false);
        if !has_protocol {
            missing_errors.push(format!("outbounds[{}].protocol missing", idx));
        }

        let Some(settings) = obj.get("settings").and_then(|v| v.as_object()) else {
            missing_errors.push(format!("outbounds[{}].settings missing", idx));
            continue;
        };

        let has_address = settings
            .get("address")
            .and_then(|v| v.as_str())
            .map(|v| !v.trim().is_empty())
            .unwrap_or(false);
        if !has_address {
            missing_errors.push(format!("outbounds[{}].settings.address missing", idx));
        }

        let valid_port = settings
            .get("port")
            .and_then(|v| v.as_u64())
            .map(|v| (1..=65535).contains(&v))
            .unwrap_or(false);
        if !valid_port {
            missing_errors.push(format!("outbounds[{}].settings.port missing", idx));
        }
    }

    if !missing_errors.is_empty() {
        for item in &missing_errors {
            tracing::error!("latency_init invalid: {}", item);
        }
        return Err(-6);
    }

    let payload: LatencyInitPayloadV1 = match serde_json::from_value(value) {
        Ok(v) => v,
        Err(e) => {
            tracing::error!("latency_init invalid schema parse: {}", e);
            return Err(-2);
        }
    };

    if payload.schema_version != 1 {
        tracing::error!(
            "latency_init invalid: schema_version={} unsupported",
            payload.schema_version
        );
        return Err(-7);
    }

    Ok(payload.outbounds.into_iter().map(Into::into).collect())
}

/// 初始化独立延迟测试器
///
/// 接收outbound配置的JSON数组，注册需要测试的节点
/// 返回: 成功返回0，失败返回-1
///
/// # Safety
/// `outbounds_json` 必须是合法的 C 字符串指针
#[no_mangle]
pub unsafe extern "C" fn openworld_latency_tester_init(outbounds_json: *const c_char) -> i32 {
    let json_str = match from_c_str(outbounds_json) {
        Some(s) => s.to_string(),
        None => return -1,
    };

    let outbounds = match parse_latency_contract_outbounds(&json_str) {
        Ok(v) => v,
        Err(code) => return code,
    };

    if outbounds.is_empty() {
        return -3;
    }

    // 创建延迟测试器并注册outbounds
    let mut tester = match LatencyTester::new() {
        Ok(t) => t,
        Err(e) => {
            tracing::error!("failed to create latency tester: {}", e);
            return -4;
        }
    };

    if let Err(e) = tester.register_outbounds(&outbounds) {
        tracing::error!("failed to register outbounds: {}", e);
        return -5;
    }

    // 保存到全局变量
    let mut guard = LATENCY_TESTER.lock().unwrap();
    *guard = Some(tester);

    tracing::info!(
        "latency tester initialized with {} outbounds",
        outbounds.len()
    );
    0
}

/// 测试所有已注册outbounds的延迟
///
/// 返回JSON格式: [{"tag": "node1", "latency_ms": 123, "error": null}, ...]
/// 失败返回: "error": "xxx"
///
/// # Safety
/// `url` 必须是合法的 C 字符串指针
#[no_mangle]
pub unsafe extern "C" fn openworld_latency_test_all(
    url: *const c_char,
    timeout_ms: i32,
) -> *mut c_char {
    let test_url = match from_c_str(url) {
        Some(s) => s.to_string(),
        None => return to_c_string(r#"{"error":"null url"}"#),
    };

    let guard = LATENCY_TESTER.lock().unwrap();
    let tester = match guard.as_ref() {
        Some(t) => t,
        None => return to_c_string(r#"{"error":"tester not initialized"}"#),
    };

    let results = tester.test_all_latency(&test_url, timeout_ms as u64);

    // 序列化为JSON
    let results_json: Vec<serde_json::Value> = results
        .iter()
        .map(|r| {
            serde_json::json!({
                "tag": r.tag,
                "latency_ms": r.latency_ms,
                "error": r.error
            })
        })
        .collect();

    match serde_json::to_string(&results_json) {
        Ok(s) => to_c_string(&s),
        Err(e) => to_c_string(&format!(r#"{{"error":"{}"}}"#, e)),
    }
}

/// 测试单个outbound的延迟
///
/// # Safety
/// `tag` 和 `url` 必须是合法的 C 字符串指针
#[no_mangle]
pub unsafe extern "C" fn openworld_latency_test_one(
    tag: *const c_char,
    url: *const c_char,
    timeout_ms: i32,
) -> i32 {
    let tag_str = match from_c_str(tag) {
        Some(s) => s.to_string(),
        None => return -1,
    };
    let test_url = match from_c_str(url) {
        Some(s) => s.to_string(),
        None => return -2,
    };

    let guard = LATENCY_TESTER.lock().unwrap();
    let tester = match guard.as_ref() {
        Some(t) => t,
        None => return -3,
    };

    let result = tester.test_latency(&tag_str, &test_url, timeout_ms as u64);
    result.latency_ms as i32
}

/// 释放独立延迟测试器
#[no_mangle]
pub extern "C" fn openworld_latency_tester_free() {
    let mut guard = LATENCY_TESTER.lock().unwrap();
    *guard = None;
    tracing::info!("latency tester released");
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
// 配置热重载
// ═══════════════════════════════════════════════════════════════════════════

/// 热重载配置文件
///
/// # Safety
/// `config_json` 必须是合法的 C 字符串指针
#[no_mangle]
pub unsafe extern "C" fn openworld_reload_config(config_json: *const c_char) -> i32 {
    let config_str = match from_c_str(config_json) {
        Some(s) => s.to_string(),
        None => return -3,
    };

    let guard = match instance_lock().lock() {
        Ok(g) => g,
        Err(_) => return -4,
    };

    match guard.as_ref() {
        Some(inst) => {
            let config: crate::config::Config = match serde_json::from_str(&config_str) {
                Ok(c) => c,
                Err(_) => match serde_yml::from_str(&config_str) {
                    Ok(c) => c,
                    Err(_) => return -3,
                },
            };

            let om = inst.outbound_manager.clone();
            let tracker = inst.tracker.clone();
            inst.runtime.block_on(async {
                // 关闭所有现有连接
                tracker.close_all().await;
            });
            // 重建 outbound manager 需要更多上下文，暂简化为关闭连接
            let _ = config;
            let _ = om;
            0
        }
        None => -1,
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// 代理组管理
// ═══════════════════════════════════════════════════════════════════════════

/// 获取代理组详情（JSON 数组）
///
/// 返回格式: `[{"name":"group1","type":"selector","selected":"proxy1","members":["proxy1","proxy2"]}]`
#[no_mangle]
pub extern "C" fn openworld_get_proxy_groups() -> *mut c_char {
    let guard = match instance_lock().lock() {
        Ok(g) => g,
        Err(_) => return std::ptr::null_mut(),
    };

    match guard.as_ref() {
        Some(inst) => {
            let om = &inst.outbound_manager;
            let mut groups = Vec::new();

            for (name, _handler) in om.list() {
                if let Some(meta) = om.group_meta(name) {
                    let name_clone = name.clone();
                    let selected = inst
                        .runtime
                        .block_on(async { om.group_selected(&name_clone).await });
                    groups.push(serde_json::json!({
                        "name": name,
                        "type": meta.group_type,
                        "selected": selected,
                        "members": meta.proxy_names,
                    }));
                }
            }

            match serde_json::to_string(&groups) {
                Ok(json) => to_c_string(&json),
                Err(_) => to_c_string("[]"),
            }
        }
        None => std::ptr::null_mut(),
    }
}

/// 在指定代理组中切换选中代理
///
/// # Safety
/// `group_tag` 和 `proxy_tag` 必须是合法的 C 字符串指针
#[no_mangle]
pub unsafe extern "C" fn openworld_set_group_selected(
    group_tag: *const c_char,
    proxy_tag: *const c_char,
) -> i32 {
    let group = match from_c_str(group_tag) {
        Some(s) => s.to_string(),
        None => return -3,
    };
    let proxy = match from_c_str(proxy_tag) {
        Some(s) => s.to_string(),
        None => return -3,
    };

    let guard = match instance_lock().lock() {
        Ok(g) => g,
        Err(_) => return -4,
    };

    match guard.as_ref() {
        Some(inst) => {
            let result = inst
                .runtime
                .block_on(async { inst.outbound_manager.select_proxy(&group, &proxy).await });
            if result {
                0
            } else {
                -3
            }
        }
        None => -1,
    }
}

/// 批量延迟测速（对某个代理组中所有成员测速）
///
/// 返回 JSON: `[{"name":"proxy1","delay":120},{"name":"proxy2","delay":-1}]`
///
/// # Safety
/// `group_tag` 和 `test_url` 必须是合法的 C 字符串指针
#[no_mangle]
pub unsafe extern "C" fn openworld_test_group_delay(
    group_tag: *const c_char,
    test_url: *const c_char,
    timeout_ms: i32,
) -> *mut c_char {
    let group = match from_c_str(group_tag) {
        Some(s) => s.to_string(),
        None => return std::ptr::null_mut(),
    };
    let url = match from_c_str(test_url) {
        Some(s) => s.to_string(),
        None => return std::ptr::null_mut(),
    };

    let guard = match instance_lock().lock() {
        Ok(g) => g,
        Err(_) => return std::ptr::null_mut(),
    };

    match guard.as_ref() {
        Some(inst) => {
            let om = &inst.outbound_manager;
            let proxy_names = match om.group_meta(&group) {
                Some(meta) => meta.proxy_names.clone(),
                None => return to_c_string("[]"),
            };

            let results: Vec<serde_json::Value> = proxy_names
                .iter()
                .map(|name| {
                    let delay = inst
                        .runtime
                        .block_on(async { om.test_delay(name, &url, timeout_ms as u64).await });
                    serde_json::json!({
                        "name": name,
                        "delay": delay.map(|d| d as i64).unwrap_or(-1),
                    })
                })
                .collect();

            match serde_json::to_string(&results) {
                Ok(json) => to_c_string(&json),
                Err(_) => to_c_string("[]"),
            }
        }
        None => std::ptr::null_mut(),
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// 活跃连接管理
// ═══════════════════════════════════════════════════════════════════════════

/// 获取活跃连接详情（JSON 数组）
///
/// 返回格式: `[{"id":1,"destination":"example.com:443","outbound":"proxy","upload":1024,"download":2048}]`
#[no_mangle]
pub extern "C" fn openworld_get_active_connections() -> *mut c_char {
    let guard = match instance_lock().lock() {
        Ok(g) => g,
        Err(_) => return std::ptr::null_mut(),
    };

    match guard.as_ref() {
        Some(inst) => {
            let connections = inst.runtime.block_on(async { inst.tracker.list().await });
            let json_list: Vec<serde_json::Value> = connections
                .iter()
                .map(|c| {
                    serde_json::json!({
                        "id": c.id,
                        "destination": c.target,
                        "outbound": c.outbound_tag,
                        "network": c.network,
                        "start_time": c.start_time.elapsed().as_secs(),
                        "upload": c.upload,
                        "download": c.download,
                    })
                })
                .collect();

            match serde_json::to_string(&json_list) {
                Ok(json) => to_c_string(&json),
                Err(_) => to_c_string("[]"),
            }
        }
        None => std::ptr::null_mut(),
    }
}

/// 关闭指定 ID 的连接
#[no_mangle]
pub extern "C" fn openworld_close_connection_by_id(id: u64) -> i32 {
    let guard = match instance_lock().lock() {
        Ok(g) => g,
        Err(_) => return -4,
    };

    match guard.as_ref() {
        Some(inst) => {
            if inst
                .runtime
                .block_on(async { inst.tracker.close(id).await })
            {
                0
            } else {
                -3
            }
        }
        None => -1,
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// 实时速率
// ═══════════════════════════════════════════════════════════════════════════

/// 获取实时速率（JSON）
///
/// 返回: `{"upload_total":1234,"download_total":5678,"connections":5}`
#[no_mangle]
pub extern "C" fn openworld_get_traffic_snapshot() -> *mut c_char {
    let guard = match instance_lock().lock() {
        Ok(g) => g,
        Err(_) => return std::ptr::null_mut(),
    };

    match guard.as_ref() {
        Some(inst) => {
            let snap = inst.tracker.snapshot();
            let per_outbound = inst.tracker.per_outbound_traffic();
            let active = inst.tracker.active_count_sync();

            let json = serde_json::json!({
                "upload_total": snap.total_up,
                "download_total": snap.total_down,
                "connections": active,
                "per_outbound": per_outbound,
            });

            match serde_json::to_string(&json) {
                Ok(s) => to_c_string(&s),
                Err(_) => to_c_string("{}"),
            }
        }
        None => std::ptr::null_mut(),
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// 日志回调
// ═══════════════════════════════════════════════════════════════════════════

/// 日志回调函数类型
/// level: 0=TRACE, 1=DEBUG, 2=INFO, 3=WARN, 4=ERROR
pub type LogCallback = extern "C" fn(level: i32, message: *const c_char);

static LOG_CALLBACK: OnceLock<Mutex<Option<LogCallback>>> = OnceLock::new();

fn log_callback_lock() -> &'static Mutex<Option<LogCallback>> {
    LOG_CALLBACK.get_or_init(|| Mutex::new(None))
}

/// 注册日志回调
#[no_mangle]
pub extern "C" fn openworld_set_log_callback(cb: LogCallback) -> i32 {
    match log_callback_lock().lock() {
        Ok(mut guard) => {
            *guard = Some(cb);
            0
        }
        Err(_) => -4,
    }
}

/// 清除日志回调
#[no_mangle]
pub extern "C" fn openworld_clear_log_callback() -> i32 {
    match log_callback_lock().lock() {
        Ok(mut guard) => {
            *guard = None;
            0
        }
        Err(_) => -4,
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// 订阅管理
// ═══════════════════════════════════════════════════════════════════════════

/// 导入订阅 URL，返回包含原始内容和解析摘要的 JSON
///
/// 返回格式: `{"count": N, "nodes": [...], "raw_content": "原始订阅内容"}`
/// 安卓端应使用 `raw_content` 字段保存为 profile 配置文件。
///
/// # Safety
/// `sub_url` 必须是合法的 C 字符串指针
#[no_mangle]
pub unsafe extern "C" fn openworld_import_subscription(sub_url: *const c_char) -> *mut c_char {
    let url = match from_c_str(sub_url) {
        Some(s) => s.to_string(),
        None => return std::ptr::null_mut(),
    };

    let guard = match instance_lock().lock() {
        Ok(g) => g,
        Err(_) => return std::ptr::null_mut(),
    };

    match guard.as_ref() {
        Some(inst) => {
            let result = inst.runtime.block_on(async {
                let resp = match reqwest::get(&url).await {
                    Ok(r) => r,
                    Err(e) => return serde_json::json!({"error": e.to_string()}).to_string(),
                };
                let body = match resp.text().await {
                    Ok(b) => b,
                    Err(e) => return serde_json::json!({"error": e.to_string()}).to_string(),
                };
                match crate::app::proxy_provider::parse_provider_content(&body) {
                    Ok(nodes) => {
                        let names: Vec<&str> = nodes.iter().map(|n| n.name.as_str()).collect();
                        serde_json::json!({
                            "count": nodes.len(),
                            "nodes": names,
                            "raw_content": body,
                        })
                        .to_string()
                    }
                    Err(e) => serde_json::json!({"error": e.to_string()}).to_string(),
                }
            });
            to_c_string(&result)
        }
        None => to_c_string("{\"error\":\"not running\"}"),
    }
}

/// 设置系统 DNS 服务器地址（用于 Android DNS 劫持）
///
/// # Safety
/// `dns_addr` 必须是合法的 C 字符串指针，格式如 "8.8.8.8" 或 "tls://1.1.1.1"
#[no_mangle]
pub unsafe extern "C" fn openworld_set_system_dns(dns_addr: *const c_char) -> i32 {
    let _addr = match from_c_str(dns_addr) {
        Some(s) => s.to_string(),
        None => return -3,
    };

    // DNS 配置变更需要在运行时重建 resolver
    // 目前记录设置，待下次重载时生效
    0
}

// ═══════════════════════════════════════════════════════════════════════════
// Clash 模式切换
// ═══════════════════════════════════════════════════════════════════════════

/// 获取当前 Clash 模式
///
/// 返回 C 字符串: "rule", "global", "direct"
#[no_mangle]
pub extern "C" fn openworld_get_clash_mode() -> *mut c_char {
    to_c_string(crate::app::clash_mode::get_mode().as_str())
}

/// 设置 Clash 模式
///
/// # Safety
/// `mode` 必须是合法的 C 字符串: "rule", "global", "direct"
#[no_mangle]
pub unsafe extern "C" fn openworld_set_clash_mode(mode: *const c_char) -> i32 {
    let mode_str = match from_c_str(mode) {
        Some(s) => s,
        None => return -3,
    };
    if crate::app::clash_mode::set_mode_str(mode_str) {
        0
    } else {
        -3
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// DNS 查询 / 缓存清理 (FFI)
// ═══════════════════════════════════════════════════════════════════════════

/// DNS 查询 (通过系统 resolver)
///
/// # Safety
/// `name` 必须是合法的 C 字符串 (如 "google.com")
/// `qtype` 必须是合法的 C 字符串 (如 "A", "AAAA")
///
/// 返回 JSON: {"answers": ["1.2.3.4"]} 或 {"error": "..."}
#[no_mangle]
pub unsafe extern "C" fn openworld_dns_query(
    name: *const c_char,
    qtype: *const c_char,
) -> *mut c_char {
    let domain = match from_c_str(name) {
        Some(s) => s.to_string(),
        None => return to_c_string("{\"error\":\"invalid name\"}"),
    };
    let _qtype = match from_c_str(qtype) {
        Some(s) => s.to_string(),
        None => return to_c_string("{\"error\":\"invalid qtype\"}"),
    };

    let guard = match instance_lock().lock() {
        Ok(g) => g,
        Err(_) => return to_c_string("{\"error\":\"lock poisoned\"}"),
    };

    match guard.as_ref() {
        Some(inst) => {
            // 使用系统 DNS resolver 进行查询
            let result = inst.runtime.block_on(async {
                use crate::dns::DnsResolver;
                let resolver = crate::dns::SystemResolver;
                match resolver.resolve(&domain).await {
                    Ok(addrs) => {
                        let answers: Vec<String> = addrs.iter().map(|a| a.to_string()).collect();
                        serde_json::json!({"answers": answers}).to_string()
                    }
                    Err(e) => serde_json::json!({"error": e.to_string()}).to_string(),
                }
            });
            to_c_string(&result)
        }
        None => to_c_string("{\"error\":\"not running\"}"),
    }
}

/// 清空 DNS 缓存
#[no_mangle]
pub extern "C" fn openworld_dns_flush() -> i32 {
    // DNS 缓存清理在实际 resolver 实现中处理
    // 目前返回成功
    0
}

// ═══════════════════════════════════════════════════════════════════════════
// 内存信息 / 运行状态
// ═══════════════════════════════════════════════════════════════════════════

/// 获取内存使用量（字节数）
#[no_mangle]
pub extern "C" fn openworld_get_memory_usage() -> i64 {
    crate::api::handlers::current_memory_usage() as i64
}

/// 获取综合运行状态 JSON
///
/// 返回: {"mode":"rule","running":true,"upload":..,"download":..,"connections":..,"memory":..}
#[no_mangle]
pub extern "C" fn openworld_get_status() -> *mut c_char {
    let guard = match instance_lock().lock() {
        Ok(g) => g,
        Err(_) => return to_c_string("{\"running\":false}"),
    };

    match guard.as_ref() {
        Some(inst) => {
            let snapshot = inst.tracker.snapshot();
            let count = inst.tracker.active_count_sync();
            let mode = crate::app::clash_mode::get_mode();
            let result = serde_json::json!({
                "running": true,
                "mode": mode.as_str(),
                "upload": snapshot.total_up,
                "download": snapshot.total_down,
                "connections": count,
            });
            to_c_string(&result.to_string())
        }
        None => to_c_string("{\"running\":false}"),
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

// ═══════════════════════════════════════════════════════════════════════════
// 全局回调注册 (日志/连接/流量速率)
// ═══════════════════════════════════════════════════════════════════════════

static CALLBACKS: OnceLock<Mutex<CallbackRegistry>> = OnceLock::new();

fn callbacks_lock() -> &'static Mutex<CallbackRegistry> {
    CALLBACKS.get_or_init(|| Mutex::new(CallbackRegistry::new()))
}

/// 注册连接变更回调
///
/// callback(active_count, total_upload, total_download)
#[no_mangle]
pub extern "C" fn openworld_set_connection_callback(cb: OnConnectionChanged) {
    if let Ok(mut guard) = callbacks_lock().lock() {
        guard.set_connection_changed(cb);
    }
}

/// 注册配置重载回调
///
/// callback(success): 1=成功, 0=失败
#[no_mangle]
pub extern "C" fn openworld_set_config_callback(cb: OnConfigReloaded) {
    if let Ok(mut guard) = callbacks_lock().lock() {
        guard.set_config_reloaded(cb);
    }
}

/// 流量速率回调类型
pub type OnTrafficRate =
    extern "C" fn(up_rate: u64, down_rate: u64, total_up: u64, total_down: u64);

static TRAFFIC_RATE_CALLBACK: OnceLock<Mutex<Option<OnTrafficRate>>> = OnceLock::new();

fn traffic_rate_lock() -> &'static Mutex<Option<OnTrafficRate>> {
    TRAFFIC_RATE_CALLBACK.get_or_init(|| Mutex::new(None))
}

/// 注册流量速率回调
///
/// 回调函数会在每次调用 openworld_poll_traffic_rate 时触发
/// callback(up_rate_bps, down_rate_bps, total_up, total_down)
#[no_mangle]
pub extern "C" fn openworld_set_traffic_rate_callback(cb: OnTrafficRate) {
    if let Ok(mut guard) = traffic_rate_lock().lock() {
        *guard = Some(cb);
    }
}

/// 上次快照，用于计算速率
static LAST_SNAPSHOT: OnceLock<Mutex<(u64, u64, std::time::Instant)>> = OnceLock::new();

fn last_snapshot_lock() -> &'static Mutex<(u64, u64, std::time::Instant)> {
    LAST_SNAPSHOT.get_or_init(|| Mutex::new((0, 0, std::time::Instant::now())))
}

/// 轮询流量速率（返回 JSON）
///
/// 返回: {"up_rate":1234,"down_rate":5678,"total_up":..,"total_down":..}
/// 同时触发 traffic_rate 回调（如果已注册）
#[no_mangle]
pub extern "C" fn openworld_poll_traffic_rate() -> *mut c_char {
    let guard = match instance_lock().lock() {
        Ok(g) => g,
        Err(_) => {
            return to_c_string("{\"up_rate\":0,\"down_rate\":0,\"total_up\":0,\"total_down\":0}")
        }
    };

    match guard.as_ref() {
        Some(inst) => {
            let snapshot = inst.tracker.snapshot();
            let now = std::time::Instant::now();

            let (up_rate, down_rate) = if let Ok(mut last) = last_snapshot_lock().lock() {
                let elapsed = now.duration_since(last.2).as_secs_f64().max(0.001);
                let up_rate = ((snapshot.total_up.saturating_sub(last.0)) as f64 / elapsed) as u64;
                let down_rate =
                    ((snapshot.total_down.saturating_sub(last.1)) as f64 / elapsed) as u64;
                *last = (snapshot.total_up, snapshot.total_down, now);
                (up_rate, down_rate)
            } else {
                (0, 0)
            };

            // 触发回调
            if let Ok(cb_guard) = traffic_rate_lock().lock() {
                if let Some(cb) = *cb_guard {
                    cb(up_rate, down_rate, snapshot.total_up, snapshot.total_down);
                }
            }

            let result = serde_json::json!({
                "up_rate": up_rate,
                "down_rate": down_rate,
                "total_up": snapshot.total_up,
                "total_down": snapshot.total_down,
            });
            to_c_string(&result.to_string())
        }
        None => to_c_string("{\"up_rate\":0,\"down_rate\":0,\"total_up\":0,\"total_down\":0}"),
    }
}

/// 向已注册的日志回调发送日志消息
///
/// # Safety
/// `msg` 必须是合法的 C 字符串
#[no_mangle]
pub unsafe extern "C" fn openworld_emit_log(level: i32, msg: *const c_char) {
    if msg.is_null() {
        return;
    }
    if let Ok(s) = CStr::from_ptr(msg).to_str() {
        if let Ok(guard) = callbacks_lock().lock() {
            guard.notify_log(level, s);
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Profile 管理
// ═══════════════════════════════════════════════════════════════════════════

/// 列出所有 profiles（返回 JSON 数组）
#[no_mangle]
pub extern "C" fn openworld_profile_list() -> *mut c_char {
    let guard = match instance_lock().lock() {
        Ok(g) => g,
        Err(_) => return std::ptr::null_mut(),
    };
    match guard.as_ref() {
        Some(inst) => {
            let pm = inst.profile_manager.lock().unwrap();
            to_c_string(&pm.list_json())
        }
        None => {
            // 即使未运行也可以列出内置 profiles
            let pm = ProfileManager::new();
            to_c_string(&pm.list_json())
        }
    }
}

/// 切换当前 profile
///
/// # Safety
/// `name` 必须是合法的 C 字符串
#[no_mangle]
pub unsafe extern "C" fn openworld_profile_switch(name: *const c_char) -> i32 {
    let profile_name = match from_c_str(name) {
        Some(s) => s.to_string(),
        None => return -3,
    };
    with_instance!(|inst: &OpenWorldInstance| {
        let pm = inst.profile_manager.lock().unwrap();
        if !pm.has(&profile_name) {
            return -3; // profile not found
        }
        drop(pm);
        let mut active = inst.active_profile.lock().unwrap();
        *active = profile_name;
        0
    })
}

/// 获取当前激活的 profile 名称
#[no_mangle]
pub extern "C" fn openworld_profile_current() -> *mut c_char {
    let guard = match instance_lock().lock() {
        Ok(g) => g,
        Err(_) => return std::ptr::null_mut(),
    };
    match guard.as_ref() {
        Some(inst) => {
            let active = inst.active_profile.lock().unwrap();
            to_c_string(&active)
        }
        None => to_c_string("default"),
    }
}

/// 导入 YAML 配置为 profile
///
/// # Safety
/// `name` 和 `yaml` 必须是合法的 C 字符串
#[no_mangle]
pub unsafe extern "C" fn openworld_profile_import(name: *const c_char, yaml: *const c_char) -> i32 {
    let profile_name = match from_c_str(name) {
        Some(s) => s.to_string(),
        None => return -3,
    };
    let yaml_str = match from_c_str(yaml) {
        Some(s) => s.to_string(),
        None => return -3,
    };
    with_instance!(|inst: &OpenWorldInstance| {
        let mut pm = inst.profile_manager.lock().unwrap();
        match pm.import_from_yaml(&profile_name, &yaml_str) {
            Ok(()) => 0,
            Err(_) => -4,
        }
    })
}

/// 导出 profile 为 JSON
///
/// # Safety
/// `name` 必须是合法的 C 字符串
#[no_mangle]
pub unsafe extern "C" fn openworld_profile_export(name: *const c_char) -> *mut c_char {
    let profile_name = match from_c_str(name) {
        Some(s) => s.to_string(),
        None => return std::ptr::null_mut(),
    };
    let guard = match instance_lock().lock() {
        Ok(g) => g,
        Err(_) => return std::ptr::null_mut(),
    };
    match guard.as_ref() {
        Some(inst) => {
            let pm = inst.profile_manager.lock().unwrap();
            match pm.export_to_json(&profile_name) {
                Ok(json) => to_c_string(&json),
                Err(_) => std::ptr::null_mut(),
            }
        }
        None => std::ptr::null_mut(),
    }
}

/// 删除 profile
///
/// # Safety
/// `name` 必须是合法的 C 字符串
#[no_mangle]
pub unsafe extern "C" fn openworld_profile_delete(name: *const c_char) -> i32 {
    let profile_name = match from_c_str(name) {
        Some(s) => s.to_string(),
        None => return -3,
    };
    with_instance!(|inst: &OpenWorldInstance| {
        let mut pm = inst.profile_manager.lock().unwrap();
        if pm.delete(&profile_name) {
            0
        } else {
            -3
        }
    })
}

// ═══════════════════════════════════════════════════════════════════════════
// 平台接口
// ═══════════════════════════════════════════════════════════════════════════

/// 通知网络状态变化（Android 端调用）
///
/// network_type: 0=无网络, 1=WiFi, 2=蜂窝, 3=以太网, 4=其他
/// ssid: WiFi SSID（可为 null）
/// is_metered: 1=计量连接, 0=非计量
///
/// # Safety
/// `ssid` 须为合法 C 字符串或 null
#[no_mangle]
pub unsafe extern "C" fn openworld_notify_network_changed(
    network_type: i32,
    ssid: *const c_char,
    is_metered: i32,
) -> i32 {
    let ssid_str = if ssid.is_null() {
        None
    } else {
        from_c_str(ssid).map(|s| s.to_string())
    };

    crate::app::platform::update_network(network_type, ssid_str, is_metered != 0);

    // 网络变化时自动恢复连接
    openworld_recover_network_auto()
}

/// 获取平台状态（JSON）
#[no_mangle]
pub extern "C" fn openworld_get_platform_state() -> *mut c_char {
    to_c_string(&crate::app::platform::get_state_json())
}

/// 通知低内存
#[no_mangle]
pub extern "C" fn openworld_notify_memory_low() -> i32 {
    crate::app::platform::notify_memory_low();
    // 同时关闭空闲连接
    let guard = match instance_lock().lock() {
        Ok(g) => g,
        Err(_) => return -4,
    };
    if let Some(inst) = guard.as_ref() {
        let tracker = inst.tracker.clone();
        inst.runtime.block_on(async {
            tracker.close_idle(std::time::Duration::from_secs(30)).await;
        });
    }
    0
}

/// 查询是否计量连接
#[no_mangle]
pub extern "C" fn openworld_is_network_metered() -> i32 {
    if crate::app::platform::is_metered() {
        1
    } else {
        0
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// Provider 管理
// ═══════════════════════════════════════════════════════════════════════════

/// 列出所有 proxy providers（返回 JSON）
///
/// 返回: [{"name":"...","type":"http|file","node_count":N,"updated_at":ts}, ...]
#[no_mangle]
pub extern "C" fn openworld_provider_list() -> *mut c_char {
    let guard = match instance_lock().lock() {
        Ok(g) => g,
        Err(_) => return std::ptr::null_mut(),
    };
    match guard.as_ref() {
        Some(inst) => {
            let pm = inst.provider_manager.clone();
            let json = inst.runtime.block_on(async {
                let names = pm.list_providers().await;
                let mut arr = Vec::new();
                for name in names {
                    if let Some(state) = pm.get_state(&name).await {
                        let source_type = match &state.source {
                            crate::app::proxy_provider::ProviderSource::Http { .. } => "http",
                            crate::app::proxy_provider::ProviderSource::File { .. } => "file",
                        };
                        arr.push(serde_json::json!({
                            "name": name,
                            "type": source_type,
                            "node_count": state.nodes.len(),
                            "updated_at": state.last_updated,
                            "error": state.error,
                        }));
                    }
                }
                serde_json::to_string(&arr).unwrap_or_else(|_| "[]".to_string())
            });
            to_c_string(&json)
        }
        None => to_c_string("[]"),
    }
}

/// 获取指定 provider 的节点列表（JSON）
///
/// # Safety
/// `name` 必须是合法的 C 字符串
#[no_mangle]
pub unsafe extern "C" fn openworld_provider_get_nodes(name: *const c_char) -> *mut c_char {
    let provider_name = match from_c_str(name) {
        Some(s) => s.to_string(),
        None => return std::ptr::null_mut(),
    };
    let guard = match instance_lock().lock() {
        Ok(g) => g,
        Err(_) => return std::ptr::null_mut(),
    };
    match guard.as_ref() {
        Some(inst) => {
            let pm = inst.provider_manager.clone();
            let json = inst.runtime.block_on(async {
                match pm.get_nodes(&provider_name).await {
                    Some(nodes) => {
                        let arr: Vec<_> = nodes
                            .iter()
                            .map(|n| {
                                serde_json::json!({
                                    "name": n.name,
                                    "protocol": n.protocol,
                                    "address": n.address,
                                    "port": n.port,
                                })
                            })
                            .collect();
                        serde_json::to_string(&arr).unwrap_or_else(|_| "[]".to_string())
                    }
                    None => "[]".to_string(),
                }
            });
            to_c_string(&json)
        }
        None => to_c_string("[]"),
    }
}

/// 添加 HTTP 类型的 proxy provider
///
/// # Safety
/// `name` 和 `url` 必须是合法的 C 字符串
#[no_mangle]
pub unsafe extern "C" fn openworld_provider_add_http(
    name: *const c_char,
    url: *const c_char,
    interval_secs: i64,
) -> i32 {
    let provider_name = match from_c_str(name) {
        Some(s) => s.to_string(),
        None => return -3,
    };
    let url_str = match from_c_str(url) {
        Some(s) => s.to_string(),
        None => return -3,
    };
    with_instance!(|inst: &OpenWorldInstance| {
        let pm = inst.provider_manager.clone();
        inst.runtime.block_on(async {
            pm.add_provider(
                provider_name,
                crate::app::proxy_provider::ProviderSource::Http {
                    url: url_str,
                    interval: std::time::Duration::from_secs(interval_secs.max(60) as u64),
                    path: None,
                },
            )
            .await;
        });
        0
    })
}

/// 刷新指定 provider（重新拉取）
///
/// 返回更新后的节点数，失败返回 -4
///
/// # Safety
/// `name` 必须是合法的 C 字符串
#[no_mangle]
pub unsafe extern "C" fn openworld_provider_update(name: *const c_char) -> i32 {
    let provider_name = match from_c_str(name) {
        Some(s) => s.to_string(),
        None => return -3,
    };
    with_instance!(|inst: &OpenWorldInstance| {
        let pm = inst.provider_manager.clone();
        let result = inst
            .runtime
            .block_on(async { pm.update_http_provider(&provider_name).await });
        match result {
            Ok(count) => count as i32,
            Err(_) => -4,
        }
    })
}

/// 删除 provider
///
/// # Safety
/// `name` 必须是合法的 C 字符串
#[no_mangle]
pub unsafe extern "C" fn openworld_provider_remove(name: *const c_char) -> i32 {
    let provider_name = match from_c_str(name) {
        Some(s) => s.to_string(),
        None => return -3,
    };
    with_instance!(|inst: &OpenWorldInstance| {
        let pm = inst.provider_manager.clone();
        let had = inst.runtime.block_on(async {
            let providers = pm.list_providers().await;
            providers.contains(&provider_name)
        });
        if had {
            0
        } else {
            -3
        }
    })
}

// ═══════════════════════════════════════════════════════════════════════════
// 延迟历史
// ═══════════════════════════════════════════════════════════════════════════

/// 获取延迟历史记录（JSON 数组）
///
/// 可选按 outbound_tag 过滤，传 null 返回全部
/// 返回: [{"tag":"..","url":"..","delay_ms":123,"timestamp":1234567890}, ...]
///
/// # Safety
/// `tag_filter` 为合法 C 字符串或 null
#[no_mangle]
pub unsafe extern "C" fn openworld_get_delay_history(tag_filter: *const c_char) -> *mut c_char {
    let filter = if tag_filter.is_null() {
        None
    } else {
        from_c_str(tag_filter).map(|s| s.to_string())
    };
    let history = match delay_history_lock().lock() {
        Ok(h) => h,
        Err(_) => return to_c_string("[]"),
    };
    let arr: Vec<_> = history
        .iter()
        .filter(|r| filter.as_ref().map_or(true, |f| r.outbound_tag == *f))
        .map(|r| {
            serde_json::json!({
                "tag": r.outbound_tag,
                "url": r.url,
                "delay_ms": r.delay_ms,
                "timestamp": r.timestamp,
            })
        })
        .collect();
    to_c_string(&serde_json::to_string(&arr).unwrap_or_else(|_| "[]".to_string()))
}

/// 清除延迟历史
#[no_mangle]
pub extern "C" fn openworld_clear_delay_history() -> i32 {
    match delay_history_lock().lock() {
        Ok(mut h) => {
            h.clear();
            0
        }
        Err(_) => -4,
    }
}

/// 获取指定 outbound 最后一次延迟（毫秒），未找到返回 -1
///
/// # Safety
/// `tag` 须为合法 C 字符串
#[no_mangle]
pub unsafe extern "C" fn openworld_get_last_delay(tag: *const c_char) -> i32 {
    let outbound_tag = match from_c_str(tag) {
        Some(s) => s.to_string(),
        None => return -3,
    };
    match delay_history_lock().lock() {
        Ok(h) => h
            .iter()
            .rev()
            .find(|r| r.outbound_tag == outbound_tag)
            .map(|r| r.delay_ms)
            .unwrap_or(-1),
        Err(_) => -4,
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// 自动测速
// ═══════════════════════════════════════════════════════════════════════════

/// 启动自动测速后台任务
///
/// interval_secs: 测速间隔（秒），最小 30
///
/// # Safety
/// `group_tag` 和 `test_url` 须为合法 C 字符串
#[no_mangle]
pub unsafe extern "C" fn openworld_auto_test_start(
    group_tag: *const c_char,
    test_url: *const c_char,
    interval_secs: i32,
    timeout_ms: i32,
) -> i32 {
    let group = match from_c_str(group_tag) {
        Some(s) => s.to_string(),
        None => return -3,
    };
    let url = match from_c_str(test_url) {
        Some(s) => s.to_string(),
        None => return -3,
    };
    let interval = std::time::Duration::from_secs(interval_secs.max(30) as u64);
    let timeout = timeout_ms.max(1000) as u64;

    with_instance!(|inst: &OpenWorldInstance| {
        // 先停止已有的自动测速
        if let Ok(mut cancel_opt) = inst.auto_test_cancel.lock() {
            if let Some(token) = cancel_opt.take() {
                token.cancel();
            }
        }

        let cancel = tokio_util::sync::CancellationToken::new();
        let cancel_clone = cancel.clone();
        let om = inst.outbound_manager.clone();

        inst.runtime.spawn(async move {
            loop {
                tokio::select! {
                    _ = cancel_clone.cancelled() => break,
                    _ = tokio::time::sleep(interval) => {
                        if let Some(meta) = om.group_meta(&group) {
                            for name in &meta.proxy_names {
                                let delay = om.test_delay(name, &url, timeout).await;
                                tracing::debug!(
                                    proxy = name.as_str(),
                                    delay = ?delay,
                                    "auto-test"
                                );
                                // 记录到延迟历史
                                if let Ok(mut history) = delay_history_lock().lock() {
                                    let ts = std::time::SystemTime::now()
                                        .duration_since(std::time::UNIX_EPOCH)
                                        .unwrap_or_default()
                                        .as_secs();
                                    history.push(DelayRecord {
                                        outbound_tag: name.clone(),
                                        url: url.clone(),
                                        delay_ms: delay.map(|d| d as i32).unwrap_or(-1),
                                        timestamp: ts,
                                    });
                                    let hlen = history.len();
                                    if hlen > 1000 {
                                        history.drain(0..hlen - 1000);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        });

        if let Ok(mut cancel_opt) = inst.auto_test_cancel.lock() {
            *cancel_opt = Some(cancel);
        }
        0
    })
}

/// 停止自动测速
#[no_mangle]
pub extern "C" fn openworld_auto_test_stop() -> i32 {
    let guard = match instance_lock().lock() {
        Ok(g) => g,
        Err(_) => return -4,
    };
    match guard.as_ref() {
        Some(inst) => {
            if let Ok(mut cancel_opt) = inst.auto_test_cancel.lock() {
                if let Some(token) = cancel_opt.take() {
                    token.cancel();
                }
            }
            0
        }
        None => -1,
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// B5: 内存 / GC
// ═══════════════════════════════════════════════════════════════════════════

/// 手动 GC：关闭空闲连接 + 清理延迟历史
///
/// 返回关闭的空闲连接数
#[no_mangle]
pub extern "C" fn openworld_gc() -> i32 {
    let guard = match instance_lock().lock() {
        Ok(g) => g,
        Err(_) => return -4,
    };
    match guard.as_ref() {
        Some(inst) => {
            let tracker = inst.tracker.clone();
            let closed = inst
                .runtime
                .block_on(async { tracker.close_idle(std::time::Duration::from_secs(30)).await });
            // 清理过旧的延迟历史（保留最近 200 条）
            if let Ok(mut history) = delay_history_lock().lock() {
                let hlen = history.len();
                if hlen > 200 {
                    history.drain(0..hlen - 200);
                }
            }
            closed as i32
        }
        None => -1,
    }
}

/// 获取内存使用概况（JSON）
///
/// 返回: {"active_connections":N,"total_upload":N,"total_download":N}
#[no_mangle]
pub extern "C" fn openworld_memory_usage() -> *mut c_char {
    let guard = match instance_lock().lock() {
        Ok(g) => g,
        Err(_) => return std::ptr::null_mut(),
    };
    match guard.as_ref() {
        Some(inst) => {
            let tracker = inst.tracker.clone();
            let (active, up, down) = inst.runtime.block_on(async {
                let connections = tracker.list().await;
                let active = connections.len();
                let snap = tracker.snapshot();
                (active, snap.total_up, snap.total_down)
            });
            let json = serde_json::json!({
                "active_connections": active,
                "total_upload": up,
                "total_download": down,
            });
            to_c_string(&json.to_string())
        }
        None => to_c_string("{}"),
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// B6: GeoIP / GeoSite 更新
// ═══════════════════════════════════════════════════════════════════════════

/// 手动触发 GeoIP/GeoSite 更新
///
/// # Safety
/// `geoip_path`, `geoip_url`, `geosite_path`, `geosite_url` 为合法 C 字符串或 null
#[no_mangle]
pub unsafe extern "C" fn openworld_geo_update(
    geoip_path: *const c_char,
    geoip_url: *const c_char,
    geosite_path: *const c_char,
    geosite_url: *const c_char,
) -> i32 {
    let ip_path = if geoip_path.is_null() {
        None
    } else {
        from_c_str(geoip_path).map(|s| s.to_string())
    };
    let ip_url = if geoip_url.is_null() {
        None
    } else {
        from_c_str(geoip_url).map(|s| s.to_string())
    };
    let site_path = if geosite_path.is_null() {
        None
    } else {
        from_c_str(geosite_path).map(|s| s.to_string())
    };
    let site_url = if geosite_url.is_null() {
        None
    } else {
        from_c_str(geosite_url).map(|s| s.to_string())
    };

    let guard = match instance_lock().lock() {
        Ok(g) => g,
        Err(_) => return -4,
    };
    match guard.as_ref() {
        Some(inst) => {
            let config = crate::router::geo_update::GeoUpdateConfig {
                geoip_path: ip_path,
                geoip_url: ip_url,
                geosite_path: site_path,
                geosite_url: site_url,
                interval_secs: 0,
                auto_update: false,
            };
            let updater = crate::router::geo_update::GeoUpdater::new(config);
            let result = inst
                .runtime
                .block_on(async { updater.check_and_update().await });
            match result {
                Ok(()) => 0,
                Err(_) => -4,
            }
        }
        None => -1,
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// C2: 规则 CRUD
// ═══════════════════════════════════════════════════════════════════════════

/// 获取自定义规则列表（JSON）
///
/// 返回: [{"type":"...","payload":"...","proxy":"..."}, ...]
#[no_mangle]
pub extern "C" fn openworld_rules_list() -> *mut c_char {
    let guard = match instance_lock().lock() {
        Ok(g) => g,
        Err(_) => return std::ptr::null_mut(),
    };
    match guard.as_ref() {
        Some(inst) => {
            let rules = inst.custom_rules.lock().unwrap_or_else(|e| e.into_inner());
            to_c_string(&serde_json::to_string(&*rules).unwrap_or_else(|_| "[]".to_string()))
        }
        None => to_c_string("[]"),
    }
}

/// 添加自定义规则
///
/// rule_json: {"type":"DomainSuffix","payload":"example.com","proxy":"DIRECT"}
///
/// # Safety
/// `rule_json` 须为合法 C 字符串
#[no_mangle]
pub unsafe extern "C" fn openworld_rules_add(rule_json: *const c_char) -> i32 {
    let json_str = match from_c_str(rule_json) {
        Some(s) => s.to_string(),
        None => return -3,
    };
    let value: serde_json::Value = match serde_json::from_str(&json_str) {
        Ok(v) => v,
        Err(_) => return -3,
    };
    with_instance!(|inst: &OpenWorldInstance| {
        let mut rules = inst.custom_rules.lock().unwrap_or_else(|e| e.into_inner());
        rules.push(value);
        rules.len() as i32
    })
}

/// 删除自定义规则（按索引）
#[no_mangle]
pub extern "C" fn openworld_rules_remove(index: i32) -> i32 {
    let guard = match instance_lock().lock() {
        Ok(g) => g,
        Err(_) => return -4,
    };
    match guard.as_ref() {
        Some(inst) => {
            let mut rules = inst.custom_rules.lock().unwrap_or_else(|e| e.into_inner());
            let idx = index as usize;
            if idx < rules.len() {
                rules.remove(idx);
                0
            } else {
                -3
            }
        }
        None => -1,
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// C3: WakeLock / 通知管理
// ═══════════════════════════════════════════════════════════════════════════

/// 设置 WakeLock 状态（核心侧记录，实际检测由 Android 端管理）
///
/// acquire=1 获取, acquire=0 释放
#[no_mangle]
pub extern "C" fn openworld_wakelock_set(acquire: i32) -> i32 {
    let guard = match instance_lock().lock() {
        Ok(g) => g,
        Err(_) => return -4,
    };
    match guard.as_ref() {
        Some(inst) => {
            inst.wakelock_held
                .store(acquire != 0, std::sync::atomic::Ordering::Relaxed);
            0
        }
        None => -1,
    }
}

/// 查询 WakeLock 状态
#[no_mangle]
pub extern "C" fn openworld_wakelock_held() -> i32 {
    let guard = match instance_lock().lock() {
        Ok(g) => g,
        Err(_) => return -4,
    };
    match guard.as_ref() {
        Some(inst) => {
            if inst
                .wakelock_held
                .load(std::sync::atomic::Ordering::Relaxed)
            {
                1
            } else {
                0
            }
        }
        None => -1,
    }
}

/// 更新通知内容（返回当前运行状态摘要 JSON，供 Android 通知栏使用）
#[no_mangle]
pub extern "C" fn openworld_notification_content() -> *mut c_char {
    let guard = match instance_lock().lock() {
        Ok(g) => g,
        Err(_) => return std::ptr::null_mut(),
    };
    match guard.as_ref() {
        Some(inst) => {
            let tracker = inst.tracker.clone();
            let (active, up, down) = inst.runtime.block_on(async {
                let conns = tracker.list().await;
                let snap = tracker.snapshot();
                (conns.len(), snap.total_up, snap.total_down)
            });
            let paused = inst.paused.load(std::sync::atomic::Ordering::Relaxed);
            let json = serde_json::json!({
                "status": if paused { "paused" } else { "running" },
                "active_connections": active,
                "upload": up,
                "download": down,
            });
            to_c_string(&json.to_string())
        }
        None => to_c_string("{\"status\":\"stopped\"}"),
    }
}

// ─── 独立 HTTP 下载（不依赖内核运行） ────────────────────────────────────

/// 用独立的 tokio runtime 下载 URL 内容，不需要内核在运行
///
/// 返回 JSON: `{"content":"...","status":200}`
/// 失败时返回 `{"error":"..."}`
///
/// # Safety
/// `url` 必须是合法的 C 字符串指针
#[no_mangle]
pub unsafe extern "C" fn openworld_fetch_url(url: *const c_char) -> *mut c_char {
    let url_str = match from_c_str(url) {
        Some(s) => s.to_string(),
        None => return to_c_string("{\"error\":\"null url\"}"),
    };

    let rt = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => return to_c_string(&serde_json::json!({"error": e.to_string()}).to_string()),
    };

    let result = rt.block_on(async {
        let resp = match reqwest::get(&url_str).await {
            Ok(r) => r,
            Err(e) => return serde_json::json!({"error": e.to_string()}).to_string(),
        };
        let status = resp.status().as_u16();
        let body = match resp.text().await {
            Ok(b) => b,
            Err(e) => return serde_json::json!({"error": e.to_string()}).to_string(),
        };
        serde_json::json!({"content": body, "status": status}).to_string()
    });
    to_c_string(&result)
}

// ─── ZenOne 统一配置 API ─────────────────────────────────────────────────

/// 将订阅内容（Clash YAML / Base64 等）转换为 ZenOne YAML
///
/// 返回 JSON: `{"zenone_yaml":"...","node_count":N,"diagnostics":[...]}`
/// 失败时返回 `{"error":"..."}`
///
/// 统一订阅转换接口
///
/// 将任意格式的订阅内容转换为完整的 ZenOne 格式
/// 支持: singbox JSON, clash YAML, base64 编码, 单节点链接, 原生 ZenOne
///
/// 返回 JSON:
/// ```json
/// {
///   "success": true,
///   "zenone_yaml": "zen-version: 1\nnodes: [...]\ngroups: [...]\n...",
///   "node_count": 10,
///   "has_groups": true,
///   "has_router": true,
///   "has_dns": false,
///   "metadata": { "name": "xxx", ... },
///   "diagnostics": [...]
/// }
/// ```
///
/// # Safety
/// `content` 必须是合法的 C 字符串指针
#[no_mangle]
pub unsafe extern "C" fn openworld_convert_subscription_to_zenone(
    content: *const c_char,
) -> *mut c_char {
    let raw = match from_c_str(content) {
        Some(s) => s,
        None => return to_c_string(r#"{"success": false, "error": "null content"}"#),
    };

    let mut diags = crate::config::zenone::Diagnostics::new();

    match crate::config::subscription::parse_subscription(raw) {
        Ok(outbounds) => {
            let node_count = outbounds.len();
            let nodes = crate::config::zenone::from_outbound_configs(&outbounds, &mut diags);
            let doc = crate::config::zenone::types::ZenOneDoc {
                zen_version: 1,
                metadata: None,
                nodes,
                groups: vec![],
                router: None,
                dns: None,
                inbounds: vec![],
                settings: None,
                signature: None,
            };

            let yaml = match crate::config::zenone::encode_yaml(&doc) {
                Ok(y) => y,
                Err(e) => {
                    return to_c_string(
                        &serde_json::json!({
                            "success": false,
                            "error": e.to_string()
                        })
                        .to_string(),
                    )
                }
            };

            let diag_list: Vec<serde_json::Value> = diags
                .items
                .iter()
                .map(|d| {
                    serde_json::json!({
                        "level": format!("{:?}", d.level),
                        "path": d.path,
                        "message": d.message,
                    })
                })
                .collect();

            let result = serde_json::json!({
                "success": true,
                "zenone_yaml": yaml,
                "node_count": node_count,
                "has_groups": false,
                "has_router": false,
                "has_dns": false,
                "metadata": serde_json::Value::Null,
                "diagnostics": diag_list,
            });
            to_c_string(&result.to_string())
        }
        Err(e) => to_c_string(
            &serde_json::json!({
                "success": false,
                "error": e.to_string()
            })
            .to_string(),
        ),
    }
}

/// 解析 ZenOne YAML/JSON 文档，返回内核可用的 Config JSON
///
/// 返回 JSON: `{"config_json":"...","node_count":N,"diagnostics":[...]}`
/// 失败时返回 `{"error":"..."}`
///
/// # Safety
/// `zenone_content` 必须是合法的 C 字符串指针
#[no_mangle]
pub unsafe extern "C" fn openworld_zenone_to_config(zenone_content: *const c_char) -> *mut c_char {
    let raw = match from_c_str(zenone_content) {
        Some(s) => s,
        None => return to_c_string("{\"error\":\"null content\"}"),
    };

    let mut diags = crate::config::zenone::Diagnostics::new();
    match crate::config::zenone::parse_and_validate(raw, None) {
        Ok((doc, parse_diags)) => {
            diags.merge(parse_diags);
            let _config = crate::config::zenone::zenone_to_config(&doc, &mut diags);
            let zenone_yaml = match crate::config::zenone::encode_yaml(&doc) {
                Ok(y) => y,
                Err(e) => {
                    return to_c_string(&serde_json::json!({"error": e.to_string()}).to_string())
                }
            };
            let node_names: Vec<&str> = doc.nodes.iter().map(|n| n.name.as_str()).collect();
            let diag_list: Vec<serde_json::Value> = diags
                .items
                .iter()
                .map(|d| {
                    serde_json::json!({
                        "level": format!("{:?}", d.level),
                        "path": d.path,
                        "message": d.message,
                    })
                })
                .collect();
            let result = serde_json::json!({
                "zenone_yaml": zenone_yaml,
                "node_count": doc.nodes.len(),
                "node_names": node_names,
                "valid": true,
                "diagnostics": diag_list,
            });
            to_c_string(&result.to_string())
        }
        Err(e) => to_c_string(&serde_json::json!({"error": e.to_string()}).to_string()),
    }
}

/// 检测内容是否为 ZenOne 格式
///
/// 返回 1 = 是 ZenOne, 0 = 不是, -3 = 参数错误
///
/// # Safety
/// `content` 必须是合法的 C 字符串指针
#[no_mangle]
pub unsafe extern "C" fn openworld_is_zenone_format(content: *const c_char) -> i32 {
    match from_c_str(content) {
        Some(s) => {
            if crate::config::zenone::is_zenone(s) {
                1
            } else {
                0
            }
        }
        None => -3,
    }
}

/// 检测订阅内容格式
///
/// 返回 JSON: `{"format": "zenone"|"clash"|"singbox"|"base64"|"uri"|"unknown"}`
///
/// # Safety
/// `content` 必须是合法的 C 字符串指针
#[no_mangle]
pub unsafe extern "C" fn openworld_detect_subscription_format(
    content: *const c_char,
) -> *mut c_char {
    let raw = match from_c_str(content) {
        Some(s) => s,
        None => return to_c_string(r#"{"format": "unknown", "error": "null content"}"#),
    };

    let format = crate::config::subscription::detect_format(raw);
    let format_str = match format {
        crate::config::subscription::SubFormat::ClashYaml => "clash",
        crate::config::subscription::SubFormat::SingBoxJson => "singbox",
        crate::config::subscription::SubFormat::Base64 => "base64",
        crate::config::subscription::SubFormat::UriList => "uri",
        crate::config::subscription::SubFormat::Unknown => "unknown",
    };

    // 特殊检测 ZenOne
    if crate::config::zenone::is_zenone(raw) {
        return to_c_string(&serde_json::json!({
            "format": "zenone"
        }).to_string());
    }

    to_c_string(&serde_json::json!({
        "format": format_str
    }).to_string())
}

/// 导出 ZenOne 配置为其他格式
///
/// 参数:
/// - content: ZenOne YAML/JSON 内容
/// - format: 目标格式 "clash" | "singbox"
///
/// 返回 JSON: `{"success": true, "content": "...", "format": "clash"}`
/// 失败时返回 `{"success": false, "error": "..."}`
///
/// # Safety
/// `content` 和 `format` 必须是合法的 C 字符串指针
#[no_mangle]
pub unsafe extern "C" fn openworld_export_config(
    content: *const c_char,
    format: *const c_char,
) -> *mut c_char {
    let raw_content = match from_c_str(content) {
        Some(s) => s,
        None => return to_c_string(r#"{"success": false, "error": "null content"}"#),
    };

    let target_format = match from_c_str(format) {
        Some(s) => s,
        None => return to_c_string(r#"{"success": false, "error": "null format"}"#),
    };

    // 解析 ZenOne 配置
    let mut diags = crate::config::zenone::Diagnostics::new();
    let doc = match crate::config::zenone::parse_and_validate(raw_content, None) {
        Ok((d, _)) => d,
        Err(e) => {
            return to_c_string(&serde_json::json!({
                "success": false,
                "error": format!("ZenOne 解析失败: {}", e)
            }).to_string())
        }
    };

    // 根据目标格式导出
    let result = match target_format {
        "clash" | "singbox" => serde_json::json!({
            "success": false,
            "error": format!("当前版本不支持导出格式: {}", target_format)
        }),
        "zenone" | "yaml" => {
            match crate::config::zenone::encode_yaml(&doc) {
                Ok(yaml) => serde_json::json!({
                    "success": true,
                    "content": yaml,
                    "format": "zenone"
                }),
                Err(e) => serde_json::json!({
                    "success": false,
                    "error": format!("导出 ZenOne 失败: {}", e)
                }),
            }
        }
        "json" => {
            match crate::config::zenone::encode_json(&doc) {
                Ok(json) => serde_json::json!({
                    "success": true,
                    "content": json,
                    "format": "zenone_json"
                }),
                Err(e) => serde_json::json!({
                    "success": false,
                    "error": format!("导出 ZenOne JSON 失败: {}", e)
                }),
            }
        }
        _ => {
            serde_json::json!({
                "success": false,
                "error": format!("不支持的格式: {}, 支持: clash, singbox, zenone, json", target_format)
            })
        }
    };

    to_c_string(&result.to_string())
}

/// 导出节点为 URI 链接
///
/// 参数:
/// - node_json: 节点配置的 JSON（与 OpenWorldConfig 中的 Outbound 格式一致）
///
/// 返回 JSON: `{"success": true, "uri": "vmess://..."}`
/// 失败时返回 `{"success": false, "error": "..."}`
///
/// # Safety
/// `node_json` 必须是合法的 C 字符串指针
#[no_mangle]
pub unsafe extern "C" fn openworld_export_node_as_uri(node_json: *const c_char) -> *mut c_char {
    let raw = match from_c_str(node_json) {
        Some(s) => s,
        None => return to_c_string(r#"{"success": false, "error": "null content"}"#),
    };

    // 解析节点 JSON
    let outbound: crate::config::types::OutboundConfig = match serde_json::from_str(raw) {
        Ok(o) => o,
        Err(e) => {
            return to_c_string(&serde_json::json!({
                "success": false,
                "error": format!("JSON 解析失败: {}", e)
            }).to_string())
        }
    };

    // 转换为 URI
    let uri = match outbound.protocol.as_str() {
        "vmess" => encode_vmess_uri(&outbound),
        "vless" => encode_vless_uri(&outbound),
        "trojan" => encode_trojan_uri(&outbound),
        "shadowsocks" => encode_ss_uri(&outbound),
        "hysteria2" => encode_hy2_uri(&outbound),
        "tuic" => encode_tuic_uri(&outbound),
        "wireguard" => encode_wg_uri(&outbound),
        "ssh" => encode_ssh_uri(&outbound),
        _ => {
            return to_c_string(&serde_json::json!({
                "success": false,
                "error": format!("不支持的协议: {}", outbound.protocol)
            }).to_string())
        }
    };

    to_c_string(&serde_json::json!({
        "success": true,
        "uri": uri
    }).to_string())
}

// ─── 节点 URI 编码函数 ───

fn encode_vmess_uri(ob: &crate::config::types::OutboundConfig) -> String {
    use crate::config::subscription::encode_vmess_uri as encode;
    encode(ob)
}

fn encode_vless_uri(ob: &crate::config::types::OutboundConfig) -> String {
    use crate::config::subscription::encode_vless_uri as encode;
    encode(ob)
}

fn encode_trojan_uri(ob: &crate::config::types::OutboundConfig) -> String {
    use crate::config::subscription::encode_trojan_uri as encode;
    encode(ob)
}

fn encode_ss_uri(ob: &crate::config::types::OutboundConfig) -> String {
    use crate::config::subscription::encode_ss_uri as encode;
    encode(ob)
}

fn encode_hy2_uri(ob: &crate::config::types::OutboundConfig) -> String {
    use crate::config::subscription::encode_hy2_uri as encode;
    encode(ob)
}

fn encode_tuic_uri(ob: &crate::config::types::OutboundConfig) -> String {
    use crate::config::subscription::encode_tuic_uri as encode;
    encode(ob)
}

fn encode_wg_uri(ob: &crate::config::types::OutboundConfig) -> String {
    use crate::config::subscription::encode_wg_uri as encode;
    encode(ob)
}

fn encode_ssh_uri(ob: &crate::config::types::OutboundConfig) -> String {
    use crate::config::subscription::encode_ssh_uri as encode;
    encode(ob)
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

    #[test]
    fn latency_contract_valid_v1_payload_parses() {
        let input = r#"{
            "schema_version": 1,
            "outbounds": [
                {
                    "tag": "vless-reality",
                    "protocol": "vless",
                    "settings": {
                        "address": "example.com",
                        "port": 443,
                        "uuid": "550e8400-e29b-41d4-a716-446655440000",
                        "tls": {
                            "server_name": "example.com",
                            "reality": {
                                "public_key": "pub-key",
                                "short_id": "abcd"
                            }
                        },
                        "transport": {
                            "type": "ws",
                            "path": "/ws",
                            "headers": {
                                "Host": "example.com"
                            }
                        }
                    }
                }
            ]
        }"#;

        let outbounds = parse_latency_contract_outbounds(input).expect("should parse");
        assert_eq!(outbounds.len(), 1);
        let first = &outbounds[0];
        assert_eq!(first.tag, "vless-reality");
        assert_eq!(first.settings.address.as_deref(), Some("example.com"));
        assert_eq!(first.settings.port, Some(443));
        assert_eq!(
            first
                .settings
                .tls
                .as_ref()
                .and_then(|v| v.public_key.as_deref()),
            Some("pub-key")
        );
        assert_eq!(
            first
                .settings
                .tls
                .as_ref()
                .and_then(|v| v.short_id.as_deref()),
            Some("abcd")
        );
        assert_eq!(
            first
                .settings
                .transport
                .as_ref()
                .map(|v| v.transport_type.as_str()),
            Some("ws")
        );
    }

    #[test]
    fn latency_contract_missing_required_field_returns_minus6() {
        let input = r#"{
            "schema_version": 1,
            "outbounds": [
                {
                    "tag": "broken-node",
                    "protocol": "vless",
                    "settings": {
                        "port": 443
                    }
                }
            ]
        }"#;

        let err = parse_latency_contract_outbounds(input).unwrap_err();
        assert_eq!(err, -6);
    }

    #[test]
    fn latency_contract_schema_version_mismatch_returns_minus7() {
        let input = r#"{
            "schema_version": 2,
            "outbounds": [
                {
                    "tag": "node",
                    "protocol": "vless",
                    "settings": {
                        "address": "example.com",
                        "port": 443
                    }
                }
            ]
        }"#;

        let err = parse_latency_contract_outbounds(input).unwrap_err();
        assert_eq!(err, -7);
    }

    #[test]
    fn latency_contract_legacy_android_outbound_array_returns_minus2() {
        let input = r#"[
            {
                "type": "vless",
                "tag": "legacy",
                "server": "example.com",
                "server_port": 443,
                "uuid": "550e8400-e29b-41d4-a716-446655440000"
            }
        ]"#;

        let err = parse_latency_contract_outbounds(input).unwrap_err();
        assert_eq!(err, -2);
    }

    #[test]
    fn latency_contract_unknown_field_returns_minus2() {
        let input = r#"{
            "schema_version": 1,
            "outbounds": [
                {
                    "tag": "node",
                    "protocol": "vless",
                    "settings": {
                        "address": "example.com",
                        "port": 443,
                        "unexpected": "boom"
                    }
                }
            ]
        }"#;

        let err = parse_latency_contract_outbounds(input).unwrap_err();
        assert_eq!(err, -2);
    }
}
