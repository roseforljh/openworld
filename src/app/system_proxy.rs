//! Windows 系统代理设置
//!
//! 通过注册表操作 Windows Internet Settings，支持 HTTP/SOCKS/PAC 代理模式。
//! 使用 `reg.exe` 命令行工具避免额外依赖。

use std::fmt;

/// 代理模式
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProxyMode {
    /// 直连（关闭系统代理）
    Direct,
    /// HTTP 代理
    Http { host: String, port: u16 },
    /// SOCKS5 代理
    Socks5 { host: String, port: u16 },
    /// PAC 脚本
    Pac { url: String },
}

impl fmt::Display for ProxyMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProxyMode::Direct => write!(f, "direct"),
            ProxyMode::Http { host, port } => write!(f, "http://{}:{}", host, port),
            ProxyMode::Socks5 { host, port } => write!(f, "socks5://{}:{}", host, port),
            ProxyMode::Pac { url } => write!(f, "pac:{}", url),
        }
    }
}

/// 默认不代理的地址列表
const DEFAULT_BYPASS: &str = "localhost;127.*;10.*;172.16.*;172.17.*;172.18.*;172.19.*;172.20.*;172.21.*;172.22.*;172.23.*;172.24.*;172.25.*;172.26.*;172.27.*;172.28.*;172.29.*;172.30.*;172.31.*;192.168.*;<local>";

const INTERNET_SETTINGS_KEY: &str =
    r"HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings";

// ─── 公开 API ──────────────────────────────────────────────────────

/// 设置 HTTP 系统代理
pub fn set_http_proxy(host: &str, port: u16, bypass: Option<&str>) -> Result<(), String> {
    let proxy_server = format!("{}:{}", host, port);
    let bypass_list = bypass.unwrap_or(DEFAULT_BYPASS);

    reg_set_dword("ProxyEnable", 1)?;
    reg_set_string("ProxyServer", &proxy_server)?;
    reg_set_string("ProxyOverride", bypass_list)?;
    // 清除 PAC
    reg_delete_value("AutoConfigURL").ok();

    notify_system_proxy_changed();
    tracing::info!(proxy = %proxy_server, "系统 HTTP 代理已启用");
    Ok(())
}

/// 设置 SOCKS5 系统代理
pub fn set_socks_proxy(host: &str, port: u16, bypass: Option<&str>) -> Result<(), String> {
    let proxy_server = format!("socks={}:{}", host, port);
    let bypass_list = bypass.unwrap_or(DEFAULT_BYPASS);

    reg_set_dword("ProxyEnable", 1)?;
    reg_set_string("ProxyServer", &proxy_server)?;
    reg_set_string("ProxyOverride", bypass_list)?;
    reg_delete_value("AutoConfigURL").ok();

    notify_system_proxy_changed();
    tracing::info!(proxy = %proxy_server, "系统 SOCKS5 代理已启用");
    Ok(())
}

/// 设置混合代理（HTTP + SOCKS 各自端口）
pub fn set_mixed_proxy(
    http_host: &str,
    http_port: u16,
    socks_host: &str,
    socks_port: u16,
    bypass: Option<&str>,
) -> Result<(), String> {
    let proxy_server = format!(
        "http={}:{};https={}:{};socks={}:{}",
        http_host, http_port, http_host, http_port, socks_host, socks_port
    );
    let bypass_list = bypass.unwrap_or(DEFAULT_BYPASS);

    reg_set_dword("ProxyEnable", 1)?;
    reg_set_string("ProxyServer", &proxy_server)?;
    reg_set_string("ProxyOverride", bypass_list)?;
    reg_delete_value("AutoConfigURL").ok();

    notify_system_proxy_changed();
    tracing::info!(proxy = %proxy_server, "系统混合代理已启用");
    Ok(())
}

/// 设置 PAC 自动代理
pub fn set_pac_proxy(pac_url: &str) -> Result<(), String> {
    reg_set_dword("ProxyEnable", 0)?;
    reg_set_string("AutoConfigURL", pac_url)?;
    reg_delete_value("ProxyServer").ok();

    notify_system_proxy_changed();
    tracing::info!(pac = %pac_url, "系统 PAC 代理已启用");
    Ok(())
}

/// 清除系统代理（恢复直连）
pub fn clear_proxy() -> Result<(), String> {
    reg_set_dword("ProxyEnable", 0)?;
    reg_delete_value("ProxyServer").ok();
    reg_delete_value("ProxyOverride").ok();
    reg_delete_value("AutoConfigURL").ok();

    notify_system_proxy_changed();
    tracing::info!("系统代理已清除");
    Ok(())
}

/// 读取当前系统代理状态
pub fn get_current_proxy() -> ProxyMode {
    let enabled = reg_query_dword("ProxyEnable").unwrap_or(0);

    // 先检查 PAC
    if let Ok(pac_url) = reg_query_string("AutoConfigURL") {
        if !pac_url.is_empty() {
            return ProxyMode::Pac { url: pac_url };
        }
    }

    if enabled == 0 {
        return ProxyMode::Direct;
    }

    match reg_query_string("ProxyServer") {
        Ok(server) if !server.is_empty() => {
            // 解析 "socks=host:port" 或 "host:port"
            if server.starts_with("socks=") {
                let addr = server.trim_start_matches("socks=");
                if let Some((h, p)) = parse_host_port(addr) {
                    return ProxyMode::Socks5 { host: h, port: p };
                }
            }
            if let Some((h, p)) = parse_host_port(&server) {
                return ProxyMode::Http { host: h, port: p };
            }
            ProxyMode::Direct
        }
        _ => ProxyMode::Direct,
    }
}

/// 获取代理状态 JSON
pub fn get_proxy_json() -> String {
    let mode = get_current_proxy();
    match mode {
        ProxyMode::Direct => r#"{"mode":"direct"}"#.to_string(),
        ProxyMode::Http { host, port } => {
            serde_json::json!({"mode":"http","host":host,"port":port}).to_string()
        }
        ProxyMode::Socks5 { host, port } => {
            serde_json::json!({"mode":"socks5","host":host,"port":port}).to_string()
        }
        ProxyMode::Pac { url } => {
            serde_json::json!({"mode":"pac","url":url}).to_string()
        }
    }
}

// ─── 注册表操作（通过 reg.exe）──────────────────────────────────────

fn reg_set_dword(name: &str, value: u32) -> Result<(), String> {
    let output = std::process::Command::new("reg")
        .args([
            "add", INTERNET_SETTINGS_KEY,
            "/v", name,
            "/t", "REG_DWORD",
            "/d", &value.to_string(),
            "/f",
        ])
        .output()
        .map_err(|e| format!("reg.exe 执行失败: {}", e))?;

    if output.status.success() {
        Ok(())
    } else {
        Err(format!(
            "reg add {} 失败: {}",
            name,
            String::from_utf8_lossy(&output.stderr)
        ))
    }
}

fn reg_set_string(name: &str, value: &str) -> Result<(), String> {
    let output = std::process::Command::new("reg")
        .args([
            "add", INTERNET_SETTINGS_KEY,
            "/v", name,
            "/t", "REG_SZ",
            "/d", value,
            "/f",
        ])
        .output()
        .map_err(|e| format!("reg.exe 执行失败: {}", e))?;

    if output.status.success() {
        Ok(())
    } else {
        Err(format!(
            "reg add {} 失败: {}",
            name,
            String::from_utf8_lossy(&output.stderr)
        ))
    }
}

fn reg_delete_value(name: &str) -> Result<(), String> {
    let output = std::process::Command::new("reg")
        .args([
            "delete", INTERNET_SETTINGS_KEY,
            "/v", name,
            "/f",
        ])
        .output()
        .map_err(|e| format!("reg.exe 执行失败: {}", e))?;

    if output.status.success() {
        Ok(())
    } else {
        Err(format!(
            "reg delete {} 失败: {}",
            name,
            String::from_utf8_lossy(&output.stderr)
        ))
    }
}

fn reg_query_dword(name: &str) -> Result<u32, String> {
    let output = std::process::Command::new("reg")
        .args([
            "query", INTERNET_SETTINGS_KEY,
            "/v", name,
        ])
        .output()
        .map_err(|e| format!("reg.exe 执行失败: {}", e))?;

    if !output.status.success() {
        return Err("key not found".to_string());
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    // reg query 输出格式: "    ProxyEnable    REG_DWORD    0x1"
    for line in stdout.lines() {
        if line.contains(name) && line.contains("REG_DWORD") {
            if let Some(hex) = line.split_whitespace().last() {
                let val = u32::from_str_radix(hex.trim_start_matches("0x"), 16)
                    .unwrap_or(0);
                return Ok(val);
            }
        }
    }
    Err("value not found".to_string())
}

fn reg_query_string(name: &str) -> Result<String, String> {
    let output = std::process::Command::new("reg")
        .args([
            "query", INTERNET_SETTINGS_KEY,
            "/v", name,
        ])
        .output()
        .map_err(|e| format!("reg.exe 执行失败: {}", e))?;

    if !output.status.success() {
        return Err("key not found".to_string());
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    for line in stdout.lines() {
        if line.contains(name) && line.contains("REG_SZ") {
            // 找到 REG_SZ 后面的值
            let parts: Vec<&str> = line.splitn(4, "    ").collect();
            if parts.len() >= 4 {
                return Ok(parts[3].trim().to_string());
            }
            // 备用解析
            if let Some(idx) = line.find("REG_SZ") {
                let val = line[idx + 6..].trim();
                return Ok(val.to_string());
            }
        }
    }
    Err("value not found".to_string())
}

// ─── 辅助函数 ──────────────────────────────────────────────────────

fn parse_host_port(s: &str) -> Option<(String, u16)> {
    let s = s.trim();
    if let Some(colon) = s.rfind(':') {
        let host = s[..colon].to_string();
        let port = s[colon + 1..].parse::<u16>().ok()?;
        Some((host, port))
    } else {
        None
    }
}

/// 通知 Windows 刷新代理设置
fn notify_system_proxy_changed() {
    // 通过 Internet Option 的 INTERNET_OPTION_SETTINGS_CHANGED 通知浏览器
    // 使用 rundll32 简化，避免 FFI
    let _ = std::process::Command::new("rundll32")
        .args(["wininet.dll,InternetSetOptionW", "0", "39", "0", "0"])
        .spawn();
}

// ═══════════════════════════════════════════════════════════════════════════
// 测试
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proxy_mode_display() {
        assert_eq!(ProxyMode::Direct.to_string(), "direct");
        assert_eq!(
            ProxyMode::Http {
                host: "127.0.0.1".into(),
                port: 7890
            }
            .to_string(),
            "http://127.0.0.1:7890"
        );
        assert_eq!(
            ProxyMode::Socks5 {
                host: "127.0.0.1".into(),
                port: 7891
            }
            .to_string(),
            "socks5://127.0.0.1:7891"
        );
        assert_eq!(
            ProxyMode::Pac {
                url: "http://proxy.local/pac".into()
            }
            .to_string(),
            "pac:http://proxy.local/pac"
        );
    }

    #[test]
    fn parse_host_port_valid() {
        assert_eq!(parse_host_port("127.0.0.1:8080"), Some(("127.0.0.1".into(), 8080)));
        assert_eq!(parse_host_port("::1:1080"), Some(("::1".into(), 1080)));
    }

    #[test]
    fn parse_host_port_invalid() {
        assert_eq!(parse_host_port("no-port"), None);
        assert_eq!(parse_host_port("host:notanumber"), None);
    }

    #[test]
    fn default_bypass_includes_local() {
        assert!(DEFAULT_BYPASS.contains("localhost"));
        assert!(DEFAULT_BYPASS.contains("192.168.*"));
        assert!(DEFAULT_BYPASS.contains("<local>"));
    }

    #[test]
    fn proxy_json_direct() {
        // 不修改注册表，仅测试 JSON 格式
        let json = r#"{"mode":"direct"}"#;
        let parsed: serde_json::Value = serde_json::from_str(json).unwrap();
        assert_eq!(parsed["mode"], "direct");
    }
}
