/// DHCP DNS — 从系统网络接口获取 DHCP 分配的 DNS 服务器。
///
/// Clash/mihomo 风格配置: `dhcp://en0`, `dhcp://auto`
///
/// 实现原理:
/// - Windows: `GetAdaptersAddresses` API 或解析 `netsh interface ip show dns`
/// - macOS: `scutil --dns` 解析
/// - Linux: 解析 `/etc/resolv.conf` 或 `systemd-resolve --status`
/// - Android/iOS: 通过 FFI 设置
use std::net::IpAddr;

use anyhow::{bail, Result};
use tracing::debug;

/// 获取系统 DNS 服务器列表。
///
/// `interface_hint` 是可选的网络接口名（如 "en0", "eth0", "auto"）。
/// 传 `None` 或 `"auto"` 时自动检测。
pub fn get_system_dns_servers(interface_hint: Option<&str>) -> Result<Vec<IpAddr>> {
    let _iface = match interface_hint {
        Some("auto") | None => None,
        Some(iface) => Some(iface),
    };

    let servers = detect_system_dns()?;

    if servers.is_empty() {
        bail!("no system DNS servers found");
    }

    debug!(
        count = servers.len(),
        servers = ?servers,
        "DHCP DNS: discovered system DNS servers"
    );

    Ok(servers)
}

/// 平台无关的系统 DNS 检测入口
fn detect_system_dns() -> Result<Vec<IpAddr>> {
    #[cfg(target_os = "windows")]
    {
        detect_dns_windows()
    }
    #[cfg(target_os = "macos")]
    {
        detect_dns_macos()
    }
    #[cfg(target_os = "linux")]
    {
        detect_dns_linux()
    }
    #[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
    {
        // Android/iOS 等平台，使用 fallback
        detect_dns_resolv_conf()
    }
}

/// Windows: 解析 `netsh interface ip show dns`
#[cfg(target_os = "windows")]
fn detect_dns_windows() -> Result<Vec<IpAddr>> {
    let output = std::process::Command::new("netsh")
        .args(["interface", "ip", "show", "dns"])
        .output()?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut servers = Vec::new();

    for line in stdout.lines() {
        let trimmed = line.trim();
        // 寻找 IP 地址行 (以数字开头的行通常是 DNS 服务器)
        if let Some(ip_str) = extract_ip_from_line(trimmed) {
            if let Ok(ip) = ip_str.parse::<IpAddr>() {
                if !servers.contains(&ip) {
                    servers.push(ip);
                }
            }
        }
    }

    // Fallback: 使用 ipconfig /all
    if servers.is_empty() {
        let output = std::process::Command::new("ipconfig")
            .arg("/all")
            .output()?;
        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut in_dns_section = false;

        for line in stdout.lines() {
            let trimmed = line.trim();
            if trimmed.contains("DNS Servers") || trimmed.contains("DNS 服务器") {
                in_dns_section = true;
                if let Some(ip_str) = extract_ip_after_colon(trimmed) {
                    if let Ok(ip) = ip_str.parse::<IpAddr>() {
                        if !servers.contains(&ip) {
                            servers.push(ip);
                        }
                    }
                }
            } else if in_dns_section {
                // 续行也可能是 DNS 服务器的 IP
                if let Ok(ip) = trimmed.parse::<IpAddr>() {
                    if !servers.contains(&ip) {
                        servers.push(ip);
                    }
                } else {
                    in_dns_section = false;
                }
            }
        }
    }

    Ok(servers)
}

/// macOS: 使用 `scutil --dns`
#[cfg(target_os = "macos")]
fn detect_dns_macos() -> Result<Vec<IpAddr>> {
    let output = std::process::Command::new("scutil").arg("--dns").output()?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut servers = Vec::new();

    for line in stdout.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("nameserver[") || trimmed.starts_with("nameserver :") {
            if let Some(ip_str) = extract_ip_after_colon(trimmed) {
                if let Ok(ip) = ip_str.parse::<IpAddr>() {
                    if !servers.contains(&ip) {
                        servers.push(ip);
                    }
                }
            }
        }
    }

    Ok(servers)
}

/// Linux: 解析 `/etc/resolv.conf`
#[cfg(target_os = "linux")]
fn detect_dns_linux() -> Result<Vec<IpAddr>> {
    detect_dns_resolv_conf()
}

/// 解析 /etc/resolv.conf（Linux/Android/BSD 通用）
#[cfg(any(
    target_os = "linux",
    not(any(target_os = "windows", target_os = "macos"))
))]
fn detect_dns_resolv_conf() -> Result<Vec<IpAddr>> {
    let content = std::fs::read_to_string("/etc/resolv.conf").unwrap_or_default();
    let mut servers = Vec::new();

    for line in content.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("nameserver") {
            let ip_str = rest.trim();
            // 去掉可能的 scope id (%eth0)
            let ip_str = ip_str.split('%').next().unwrap_or(ip_str);
            if let Ok(ip) = ip_str.parse::<IpAddr>() {
                if !servers.contains(&ip) {
                    servers.push(ip);
                }
            }
        }
    }

    Ok(servers)
}

/// 从行内提取冒号后面的 IP 地址
fn extract_ip_after_colon(line: &str) -> Option<&str> {
    let pos = line.rfind(':')?;
    let candidate = line[pos + 1..].trim();
    if candidate.is_empty() {
        None
    } else {
        Some(candidate)
    }
}

/// 从行内提取看起来像 IP 地址的部分
#[cfg(target_os = "windows")]
fn extract_ip_from_line(line: &str) -> Option<&str> {
    let trimmed = line.trim();
    // 如果行以数字开头且看起来像 IP
    if trimmed.chars().next().map_or(false, |c| c.is_ascii_digit()) {
        // 取第一个词
        let word = trimmed.split_whitespace().next()?;
        if word.contains('.') || word.contains(':') {
            return Some(word);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extract_ip_after_colon_basic() {
        assert_eq!(
            extract_ip_after_colon("nameserver : 8.8.8.8"),
            Some("8.8.8.8")
        );
        assert_eq!(
            extract_ip_after_colon("DNS Servers . . . : 1.1.1.1"),
            Some("1.1.1.1")
        );
        assert_eq!(extract_ip_after_colon("no colon here"), None);
        assert_eq!(extract_ip_after_colon("trailing:"), None);
    }

    #[test]
    fn get_system_dns_does_not_panic() {
        // 即使检测失败，也不应 panic
        let _ = get_system_dns_servers(None);
    }

    #[test]
    fn get_system_dns_auto() {
        let _ = get_system_dns_servers(Some("auto"));
    }
}
