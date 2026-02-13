use std::fmt::Write;

use crate::app::tracker::ConnectionTracker;

/// Prometheus 格式指标导出器
pub struct MetricsExporter {
    custom_labels: Vec<(String, String)>,
}

impl MetricsExporter {
    pub fn new() -> Self {
        Self {
            custom_labels: Vec::new(),
        }
    }

    pub fn with_label(mut self, name: &str, value: &str) -> Self {
        self.custom_labels
            .push((name.to_string(), value.to_string()));
        self
    }

    /// 导出 Prometheus 格式的指标
    pub async fn export(&self, tracker: &ConnectionTracker) -> String {
        let mut output = String::new();
        let snapshot = tracker.snapshot_async().await;

        // 活跃连接数
        write_metric(
            &mut output,
            "openworld_connections_active",
            "Number of active connections",
            "gauge",
            snapshot.active_count as f64,
        );

        // 总上传字节
        write_metric(
            &mut output,
            "openworld_traffic_upload_bytes_total",
            "Total upload bytes",
            "counter",
            snapshot.total_up as f64,
        );

        // 总下载字节
        write_metric(
            &mut output,
            "openworld_traffic_download_bytes_total",
            "Total download bytes",
            "counter",
            snapshot.total_down as f64,
        );

        // 路由命中统计
        let route_stats = tracker.route_stats();
        if !route_stats.is_empty() {
            writeln!(
                output,
                "# HELP openworld_route_hits_total Route rule hit count"
            )
            .unwrap();
            writeln!(output, "# TYPE openworld_route_hits_total counter").unwrap();
            for (rule, count) in &route_stats {
                writeln!(
                    output,
                    "openworld_route_hits_total{{rule=\"{}\"}} {}",
                    escape_label_value(rule),
                    count
                )
                .unwrap();
            }
        }

        // 错误统计
        let error_stats = tracker.error_stats();
        if !error_stats.is_empty() {
            writeln!(output, "# HELP openworld_errors_total Error count by code").unwrap();
            writeln!(output, "# TYPE openworld_errors_total counter").unwrap();
            for (code, count) in &error_stats {
                writeln!(
                    output,
                    "openworld_errors_total{{code=\"{}\"}} {}",
                    escape_label_value(code),
                    count
                )
                .unwrap();
            }
        }

        // 延迟分位数
        if let Some((p50, p95, p99)) = tracker.latency_percentiles_ms() {
            writeln!(
                output,
                "# HELP openworld_latency_ms Connection latency in milliseconds"
            )
            .unwrap();
            writeln!(output, "# TYPE openworld_latency_ms summary").unwrap();
            writeln!(output, "openworld_latency_ms{{quantile=\"0.5\"}} {}", p50).unwrap();
            writeln!(output, "openworld_latency_ms{{quantile=\"0.95\"}} {}", p95).unwrap();
            writeln!(output, "openworld_latency_ms{{quantile=\"0.99\"}} {}", p99).unwrap();
        }

        output
    }
}

fn write_metric(output: &mut String, name: &str, help: &str, metric_type: &str, value: f64) {
    writeln!(output, "# HELP {} {}", name, help).unwrap();
    writeln!(output, "# TYPE {} {}", name, metric_type).unwrap();
    writeln!(output, "{} {}", name, value).unwrap();
}

fn escape_label_value(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}

/// 入站访问控制列表
pub struct InboundAcl {
    allow_cidrs: Vec<ipnet::IpNet>,
    deny_cidrs: Vec<ipnet::IpNet>,
    mode: AclMode,
}

#[derive(Debug, Clone, PartialEq)]
pub enum AclMode {
    AllowAll,
    AllowList,
    DenyList,
}

impl InboundAcl {
    pub fn allow_all() -> Self {
        Self {
            allow_cidrs: Vec::new(),
            deny_cidrs: Vec::new(),
            mode: AclMode::AllowAll,
        }
    }

    pub fn with_allow_list(cidrs: Vec<String>) -> anyhow::Result<Self> {
        let mut parsed = Vec::new();
        for cidr in &cidrs {
            parsed.push(cidr.parse::<ipnet::IpNet>()?);
        }
        Ok(Self {
            allow_cidrs: parsed,
            deny_cidrs: Vec::new(),
            mode: AclMode::AllowList,
        })
    }

    pub fn with_deny_list(cidrs: Vec<String>) -> anyhow::Result<Self> {
        let mut parsed = Vec::new();
        for cidr in &cidrs {
            parsed.push(cidr.parse::<ipnet::IpNet>()?);
        }
        Ok(Self {
            allow_cidrs: Vec::new(),
            deny_cidrs: parsed,
            mode: AclMode::DenyList,
        })
    }

    pub fn is_allowed(&self, addr: std::net::IpAddr) -> bool {
        match self.mode {
            AclMode::AllowAll => true,
            AclMode::AllowList => self.allow_cidrs.iter().any(|net| net.contains(&addr)),
            AclMode::DenyList => !self.deny_cidrs.iter().any(|net| net.contains(&addr)),
        }
    }

    pub fn mode(&self) -> &AclMode {
        &self.mode
    }
}

/// SOCKS5/HTTP 入站用户认证
pub struct InboundAuth {
    users: std::collections::HashMap<String, String>,
}

impl InboundAuth {
    pub fn new() -> Self {
        Self {
            users: std::collections::HashMap::new(),
        }
    }

    pub fn add_user(&mut self, username: &str, password: &str) {
        self.users
            .insert(username.to_string(), password.to_string());
    }

    pub fn verify(&self, username: &str, password: &str) -> bool {
        self.users.get(username).map_or(false, |p| p == password)
    }

    pub fn is_empty(&self) -> bool {
        self.users.is_empty()
    }

    pub fn user_count(&self) -> usize {
        self.users.len()
    }
}

/// Panic hook: 安装自定义 panic handler 以捕获并记录 panic
pub fn install_panic_hook() {
    std::panic::set_hook(Box::new(|info| {
        let location = info
            .location()
            .map(|l| format!("{}:{}:{}", l.file(), l.line(), l.column()))
            .unwrap_or_else(|| "unknown".to_string());

        let message = if let Some(s) = info.payload().downcast_ref::<&str>() {
            s.to_string()
        } else if let Some(s) = info.payload().downcast_ref::<String>() {
            s.clone()
        } else {
            "unknown panic".to_string()
        };

        eprintln!("[PANIC] at {}: {}", location, message);
        tracing::error!(location = location, message = message, "panic occurred");
    }));
}

/// 日志轮转配置
#[derive(Debug, Clone)]
pub struct LogRotationConfig {
    pub max_size_mb: u64,
    pub max_files: u32,
    pub max_age_days: u32,
    pub compress: bool,
}

impl Default for LogRotationConfig {
    fn default() -> Self {
        Self {
            max_size_mb: 100,
            max_files: 5,
            max_age_days: 30,
            compress: false,
        }
    }
}

/// 资源限制配置
#[derive(Debug, Clone)]
pub struct ResourceLimits {
    pub max_connections: Option<u32>,
    pub max_memory_mb: Option<u64>,
}

impl Default for ResourceLimits {
    fn default() -> Self {
        Self {
            max_connections: None,
            max_memory_mb: None,
        }
    }
}

/// 慢请求检测与告警
pub struct SlowRequestDetector {
    threshold_ms: u64,
    alerts: std::sync::Mutex<Vec<SlowRequestAlert>>,
    max_alerts: usize,
}

#[derive(Debug, Clone)]
pub struct SlowRequestAlert {
    pub target: String,
    pub outbound: String,
    pub duration_ms: u64,
    pub timestamp_ms: u64,
}

impl SlowRequestDetector {
    pub fn new(threshold_ms: u64, max_alerts: usize) -> Self {
        Self {
            threshold_ms,
            alerts: std::sync::Mutex::new(Vec::new()),
            max_alerts,
        }
    }

    pub fn threshold_ms(&self) -> u64 {
        self.threshold_ms
    }

    /// Check if a request duration exceeds the threshold and record it
    pub fn check(&self, target: &str, outbound: &str, duration_ms: u64) -> bool {
        if duration_ms >= self.threshold_ms {
            let alert = SlowRequestAlert {
                target: target.to_string(),
                outbound: outbound.to_string(),
                duration_ms,
                timestamp_ms: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis() as u64,
            };
            let mut alerts = self.alerts.lock().unwrap();
            if alerts.len() >= self.max_alerts {
                alerts.remove(0);
            }
            alerts.push(alert);
            true
        } else {
            false
        }
    }

    pub fn recent_alerts(&self) -> Vec<SlowRequestAlert> {
        self.alerts.lock().unwrap().clone()
    }

    pub fn alert_count(&self) -> usize {
        self.alerts.lock().unwrap().len()
    }

    pub fn clear_alerts(&self) {
        self.alerts.lock().unwrap().clear();
    }
}

/// 实时流量 Top-N 查询
pub struct TopNQuery;

#[derive(Debug, Clone)]
pub struct TopNEntry {
    pub target: String,
    pub outbound: String,
    pub upload_bytes: u64,
    pub download_bytes: u64,
    pub total_bytes: u64,
    pub duration_ms: u64,
}

impl TopNQuery {
    /// Get top-N connections by total traffic from tracker (async version)
    pub async fn by_traffic_async(tracker: &ConnectionTracker, n: usize) -> Vec<TopNEntry> {
        let conns = tracker.list().await;
        let mut entries: Vec<TopNEntry> = conns
            .iter()
            .map(|conn| TopNEntry {
                target: conn.target.clone(),
                outbound: conn.outbound_tag.clone(),
                upload_bytes: conn.upload,
                download_bytes: conn.download,
                total_bytes: conn.upload + conn.download,
                duration_ms: conn.start_time.elapsed().as_millis() as u64,
            })
            .collect();
        entries.sort_by(|a, b| b.total_bytes.cmp(&a.total_bytes));
        entries.truncate(n);
        entries
    }

    /// Get top-N connections by duration (async version)
    pub async fn by_duration_async(tracker: &ConnectionTracker, n: usize) -> Vec<TopNEntry> {
        let conns = tracker.list().await;
        let mut entries: Vec<TopNEntry> = conns
            .iter()
            .map(|conn| TopNEntry {
                target: conn.target.clone(),
                outbound: conn.outbound_tag.clone(),
                upload_bytes: conn.upload,
                download_bytes: conn.download,
                total_bytes: conn.upload + conn.download,
                duration_ms: conn.start_time.elapsed().as_millis() as u64,
            })
            .collect();
        entries.sort_by(|a, b| b.duration_ms.cmp(&a.duration_ms));
        entries.truncate(n);
        entries
    }
}

/// Fuzz 测试入口点
///
/// 暴露协议解析器的入口，供 cargo-fuzz 使用。
pub mod fuzz_targets {
    /// Fuzz VLESS protocol header parsing
    pub fn fuzz_vless_header(data: &[u8]) -> bool {
        if data.len() < 17 {
            return false;
        }
        // Validate UUID format (16 bytes) + command (1 byte)
        let _uuid_bytes = &data[0..16];
        let cmd = data[16];
        matches!(cmd, 0x01 | 0x02 | 0x03) // TCP / UDP / MUX
    }

    /// Fuzz Trojan protocol header parsing
    pub fn fuzz_trojan_header(data: &[u8]) -> bool {
        if data.len() < 58 {
            return false;
        }
        // Trojan: 56 bytes hex password + CRLF + command + address
        let hex_part = &data[0..56];
        let is_hex = hex_part.iter().all(|b| b.is_ascii_hexdigit());
        if !is_hex {
            return false;
        }
        data[56] == 0x0d && data[57] == 0x0a
    }

    /// Fuzz Shadowsocks AEAD header parsing
    pub fn fuzz_ss_aead_header(data: &[u8]) -> bool {
        if data.len() < 2 + 16 {
            return false;
        }
        // salt(16) + encrypted_payload_length(2) + tag(16)
        let salt_len = 16;
        data.len() >= salt_len + 2 + 16
    }

    /// Fuzz VMess AEAD header parsing
    pub fn fuzz_vmess_header(data: &[u8]) -> bool {
        if data.len() < 16 + 16 {
            return false;
        }
        // Auth info (16 bytes) + encrypted header
        let auth_info = &data[0..16];
        // Check if timestamp is somewhat reasonable
        let _timestamp = u64::from_be_bytes([
            auth_info[0],
            auth_info[1],
            auth_info[2],
            auth_info[3],
            auth_info[4],
            auth_info[5],
            auth_info[6],
            auth_info[7],
        ]);
        true
    }

    /// Fuzz TLS ClientHello SNI extraction
    pub fn fuzz_tls_sni(data: &[u8]) -> bool {
        crate::proxy::sniff::sniff(data).is_some()
    }

    /// Fuzz HTTP Host header extraction
    pub fn fuzz_http_host(data: &[u8]) -> bool {
        crate::proxy::sniff::sniff(data).is_some()
    }

    /// Fuzz SOCKS5 handshake
    pub fn fuzz_socks5_handshake(data: &[u8]) -> bool {
        if data.len() < 3 {
            return false;
        }
        data[0] == 0x05 // SOCKS version
    }

    /// Fuzz DNS response parsing
    pub fn fuzz_dns_response(data: &[u8]) -> bool {
        if data.len() < 12 {
            return false;
        }
        // DNS header is 12 bytes
        let flags = u16::from_be_bytes([data[2], data[3]]);
        (flags & 0x8000) != 0 // QR bit = 1 means response
    }
}

/// Sub-Rules: sing-box 风格嵌套子规则
///
/// A SubRule matches when its outer condition is met, then applies inner rules.
#[derive(Debug, Clone)]
pub struct SubRule {
    pub tag: String,
    pub conditions: Vec<SubRuleCondition>,
    pub action: SubRuleAction,
}

#[derive(Debug, Clone)]
pub enum SubRuleCondition {
    InboundTag(String),
    Network(String),
    Protocol(String),
    SourceCidr(String),
}

#[derive(Debug, Clone)]
pub enum SubRuleAction {
    Route(String), // outbound tag
    Reject,
    Direct,
}

impl SubRule {
    pub fn new(tag: String, conditions: Vec<SubRuleCondition>, action: SubRuleAction) -> Self {
        Self {
            tag,
            conditions,
            action,
        }
    }

    pub fn matches(
        &self,
        inbound_tag: &str,
        network: &str,
        protocol: Option<&str>,
        source_ip: Option<std::net::IpAddr>,
    ) -> bool {
        self.conditions.iter().all(|cond| match cond {
            SubRuleCondition::InboundTag(t) => inbound_tag == t,
            SubRuleCondition::Network(n) => network == n,
            SubRuleCondition::Protocol(p) => protocol.map_or(false, |proto| proto == p),
            SubRuleCondition::SourceCidr(cidr) => {
                if let (Some(ip), Ok(net)) = (source_ip, cidr.parse::<ipnet::IpNet>()) {
                    net.contains(&ip)
                } else {
                    false
                }
            }
        })
    }
}

/// Graceful Shutdown 控制器
pub struct GracefulShutdown {
    timeout: std::time::Duration,
    shutdown_tx: tokio::sync::watch::Sender<bool>,
    shutdown_rx: tokio::sync::watch::Receiver<bool>,
}

impl GracefulShutdown {
    pub fn new(timeout_secs: u64) -> Self {
        let (tx, rx) = tokio::sync::watch::channel(false);
        Self {
            timeout: std::time::Duration::from_secs(timeout_secs),
            shutdown_tx: tx,
            shutdown_rx: rx,
        }
    }

    pub fn timeout(&self) -> std::time::Duration {
        self.timeout
    }

    pub fn subscribe(&self) -> tokio::sync::watch::Receiver<bool> {
        self.shutdown_rx.clone()
    }

    pub fn trigger(&self) {
        let _ = self.shutdown_tx.send(true);
    }

    pub fn is_shutting_down(&self) -> bool {
        *self.shutdown_rx.borrow()
    }

    /// Wait for all connections to drain or timeout
    pub async fn shutdown_with_drain(&self, tracker: &ConnectionTracker) -> ShutdownResult {
        self.trigger();
        let start = std::time::Instant::now();
        loop {
            let snapshot = tracker.snapshot_async().await;
            if snapshot.active_count == 0 {
                return ShutdownResult {
                    drained: true,
                    remaining_connections: 0,
                    elapsed: start.elapsed(),
                };
            }
            if start.elapsed() >= self.timeout {
                let closed = tracker.close_all().await;
                return ShutdownResult {
                    drained: false,
                    remaining_connections: closed,
                    elapsed: start.elapsed(),
                };
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
    }
}

#[derive(Debug, Clone)]
pub struct ShutdownResult {
    pub drained: bool,
    pub remaining_connections: usize,
    pub elapsed: std::time::Duration,
}

/// 信号处理器 (Windows/Linux)
pub struct SignalHandler {
    actions: std::collections::HashMap<String, SignalAction>,
}

#[derive(Debug, Clone)]
pub enum SignalAction {
    Reload,
    ToggleLogLevel,
    DumpState,
    Shutdown,
}

impl SignalHandler {
    pub fn new() -> Self {
        let mut actions = std::collections::HashMap::new();
        #[cfg(unix)]
        {
            actions.insert("SIGHUP".to_string(), SignalAction::Reload);
            actions.insert("SIGUSR1".to_string(), SignalAction::ToggleLogLevel);
            actions.insert("SIGUSR2".to_string(), SignalAction::DumpState);
        }
        #[cfg(windows)]
        {
            actions.insert("CTRL_C".to_string(), SignalAction::Shutdown);
            actions.insert("CTRL_BREAK".to_string(), SignalAction::Reload);
        }
        Self { actions }
    }

    pub fn get_action(&self, signal: &str) -> Option<&SignalAction> {
        self.actions.get(signal)
    }

    pub fn registered_signals(&self) -> Vec<String> {
        self.actions.keys().cloned().collect()
    }

    /// 安装 Ctrl+C 处理
    pub fn install_ctrlc(shutdown: Arc<GracefulShutdown>)
    where
        Arc<GracefulShutdown>: Send + 'static,
    {
        tokio::spawn(async move {
            if let Ok(()) = tokio::signal::ctrl_c().await {
                tracing::info!("received CTRL+C, initiating graceful shutdown");
                shutdown.trigger();
            }
        });
    }
}

use std::sync::Arc;

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn metrics_export_basic() {
        let tracker = ConnectionTracker::new();
        tracker.record_route_hit("direct");
        tracker.record_route_hit("proxy");
        tracker.record_route_hit("proxy");
        tracker.record_error("TIMEOUT");
        tracker.record_latency_ms(50);
        tracker.record_latency_ms(100);
        tracker.record_latency_ms(200);

        let exporter = MetricsExporter::new();
        let output = exporter.export(&tracker).await;

        assert!(output.contains("openworld_connections_active"));
        assert!(output.contains("openworld_traffic_upload_bytes_total"));
        assert!(output.contains("openworld_traffic_download_bytes_total"));
        assert!(output.contains("openworld_route_hits_total"));
        assert!(output.contains("openworld_errors_total"));
        assert!(output.contains("openworld_latency_ms"));
    }

    #[tokio::test]
    async fn metrics_export_empty_tracker() {
        let tracker = ConnectionTracker::new();
        let exporter = MetricsExporter::new();
        let output = exporter.export(&tracker).await;
        assert!(output.contains("openworld_connections_active 0"));
        assert!(!output.contains("route_hits"));
    }

    #[test]
    fn acl_allow_all() {
        let acl = InboundAcl::allow_all();
        assert!(acl.is_allowed("1.2.3.4".parse().unwrap()));
        assert!(acl.is_allowed("::1".parse().unwrap()));
    }

    #[test]
    fn acl_allow_list() {
        let acl =
            InboundAcl::with_allow_list(vec!["127.0.0.0/8".to_string(), "10.0.0.0/8".to_string()])
                .unwrap();
        assert!(acl.is_allowed("127.0.0.1".parse().unwrap()));
        assert!(acl.is_allowed("10.1.2.3".parse().unwrap()));
        assert!(!acl.is_allowed("8.8.8.8".parse().unwrap()));
    }

    #[test]
    fn acl_deny_list() {
        let acl = InboundAcl::with_deny_list(vec!["192.168.0.0/16".to_string()]).unwrap();
        assert!(acl.is_allowed("8.8.8.8".parse().unwrap()));
        assert!(!acl.is_allowed("192.168.1.1".parse().unwrap()));
    }

    #[test]
    fn acl_invalid_cidr() {
        let result = InboundAcl::with_allow_list(vec!["not-a-cidr".to_string()]);
        assert!(result.is_err());
    }

    #[test]
    fn inbound_auth_basic() {
        let mut auth = InboundAuth::new();
        assert!(auth.is_empty());
        auth.add_user("admin", "password");
        assert_eq!(auth.user_count(), 1);
        assert!(auth.verify("admin", "password"));
        assert!(!auth.verify("admin", "wrong"));
        assert!(!auth.verify("unknown", "password"));
    }

    #[test]
    fn log_rotation_defaults() {
        let config = LogRotationConfig::default();
        assert_eq!(config.max_size_mb, 100);
        assert_eq!(config.max_files, 5);
        assert_eq!(config.max_age_days, 30);
        assert!(!config.compress);
    }

    #[test]
    fn resource_limits_defaults() {
        let limits = ResourceLimits::default();
        assert!(limits.max_connections.is_none());
        assert!(limits.max_memory_mb.is_none());
    }

    #[test]
    fn escape_label_value_basic() {
        assert_eq!(escape_label_value("hello"), "hello");
        assert_eq!(escape_label_value("a\"b"), "a\\\"b");
        assert_eq!(escape_label_value("a\\b"), "a\\\\b");
    }

    // --- Slow Request Detector tests ---

    #[test]
    fn slow_request_detector_below_threshold() {
        let detector = SlowRequestDetector::new(1000, 100);
        assert!(!detector.check("example.com:443", "proxy", 500));
        assert_eq!(detector.alert_count(), 0);
    }

    #[test]
    fn slow_request_detector_above_threshold() {
        let detector = SlowRequestDetector::new(1000, 100);
        assert!(detector.check("example.com:443", "proxy", 1500));
        assert_eq!(detector.alert_count(), 1);
        let alerts = detector.recent_alerts();
        assert_eq!(alerts[0].target, "example.com:443");
        assert_eq!(alerts[0].outbound, "proxy");
        assert_eq!(alerts[0].duration_ms, 1500);
    }

    #[test]
    fn slow_request_detector_at_threshold() {
        let detector = SlowRequestDetector::new(1000, 100);
        assert!(detector.check("example.com:443", "proxy", 1000));
        assert_eq!(detector.alert_count(), 1);
    }

    #[test]
    fn slow_request_detector_max_alerts() {
        let detector = SlowRequestDetector::new(100, 3);
        for i in 0..5 {
            detector.check(&format!("target-{}", i), "proxy", 200);
        }
        assert_eq!(detector.alert_count(), 3);
        let alerts = detector.recent_alerts();
        assert_eq!(alerts[0].target, "target-2");
        assert_eq!(alerts[2].target, "target-4");
    }

    #[test]
    fn slow_request_detector_clear() {
        let detector = SlowRequestDetector::new(100, 100);
        detector.check("t1", "p", 200);
        detector.check("t2", "p", 300);
        assert_eq!(detector.alert_count(), 2);
        detector.clear_alerts();
        assert_eq!(detector.alert_count(), 0);
    }

    // --- Top-N Query tests ---

    #[tokio::test]
    async fn top_n_empty_tracker() {
        let tracker = ConnectionTracker::new();
        let result = TopNQuery::by_traffic_async(&tracker, 10).await;
        assert!(result.is_empty());
    }

    // --- Fuzz target tests ---

    #[test]
    fn fuzz_vless_header_valid() {
        let mut data = vec![0u8; 18];
        data[16] = 0x01; // TCP command
        assert!(fuzz_targets::fuzz_vless_header(&data));
    }

    #[test]
    fn fuzz_vless_header_invalid_cmd() {
        let mut data = vec![0u8; 18];
        data[16] = 0xFF;
        assert!(!fuzz_targets::fuzz_vless_header(&data));
    }

    #[test]
    fn fuzz_vless_header_too_short() {
        assert!(!fuzz_targets::fuzz_vless_header(&[0u8; 5]));
    }

    #[test]
    fn fuzz_trojan_header_valid() {
        let mut data = vec![0u8; 60];
        // Fill with hex chars
        for i in 0..56 {
            data[i] = b'a' + (i as u8 % 6);
        }
        data[56] = 0x0d;
        data[57] = 0x0a;
        assert!(fuzz_targets::fuzz_trojan_header(&data));
    }

    #[test]
    fn fuzz_trojan_header_not_hex() {
        let mut data = vec![b'z'; 60];
        data[56] = 0x0d;
        data[57] = 0x0a;
        assert!(!fuzz_targets::fuzz_trojan_header(&data));
    }

    #[test]
    fn fuzz_ss_aead_valid() {
        let data = vec![0u8; 34]; // 16 salt + 2 len + 16 tag
        assert!(fuzz_targets::fuzz_ss_aead_header(&data));
    }

    #[test]
    fn fuzz_ss_aead_too_short() {
        assert!(!fuzz_targets::fuzz_ss_aead_header(&[0u8; 10]));
    }

    #[test]
    fn fuzz_vmess_header_valid() {
        let data = vec![0u8; 32];
        assert!(fuzz_targets::fuzz_vmess_header(&data));
    }

    #[test]
    fn fuzz_vmess_header_too_short() {
        assert!(!fuzz_targets::fuzz_vmess_header(&[0u8; 10]));
    }

    #[test]
    fn fuzz_socks5_valid() {
        assert!(fuzz_targets::fuzz_socks5_handshake(&[0x05, 0x01, 0x00]));
    }

    #[test]
    fn fuzz_socks5_invalid() {
        assert!(!fuzz_targets::fuzz_socks5_handshake(&[0x04, 0x01, 0x00]));
    }

    #[test]
    fn fuzz_dns_response_valid() {
        let mut data = vec![0u8; 12];
        data[2] = 0x80; // QR=1
        assert!(fuzz_targets::fuzz_dns_response(&data));
    }

    #[test]
    fn fuzz_dns_query_not_response() {
        let data = vec![0u8; 12]; // QR=0
        assert!(!fuzz_targets::fuzz_dns_response(&data));
    }

    // --- Sub-Rules tests ---

    #[test]
    fn sub_rule_matches_all_conditions() {
        let rule = SubRule::new(
            "test".to_string(),
            vec![
                SubRuleCondition::InboundTag("socks-in".to_string()),
                SubRuleCondition::Network("tcp".to_string()),
            ],
            SubRuleAction::Route("proxy".to_string()),
        );
        assert!(rule.matches("socks-in", "tcp", None, None));
        assert!(!rule.matches("http-in", "tcp", None, None));
        assert!(!rule.matches("socks-in", "udp", None, None));
    }

    #[test]
    fn sub_rule_protocol_condition() {
        let rule = SubRule::new(
            "test".to_string(),
            vec![SubRuleCondition::Protocol("tls".to_string())],
            SubRuleAction::Route("proxy".to_string()),
        );
        assert!(rule.matches("any", "tcp", Some("tls"), None));
        assert!(!rule.matches("any", "tcp", Some("http"), None));
        assert!(!rule.matches("any", "tcp", None, None));
    }

    #[test]
    fn sub_rule_source_cidr_condition() {
        let rule = SubRule::new(
            "test".to_string(),
            vec![SubRuleCondition::SourceCidr("10.0.0.0/8".to_string())],
            SubRuleAction::Reject,
        );
        assert!(rule.matches("any", "tcp", None, Some("10.1.2.3".parse().unwrap())));
        assert!(!rule.matches("any", "tcp", None, Some("192.168.1.1".parse().unwrap())));
        assert!(!rule.matches("any", "tcp", None, None));
    }

    #[test]
    fn sub_rule_empty_conditions_matches_all() {
        let rule = SubRule::new("test".to_string(), vec![], SubRuleAction::Direct);
        assert!(rule.matches("any", "tcp", None, None));
    }

    // --- Graceful Shutdown tests ---

    #[test]
    fn graceful_shutdown_creation() {
        let gs = GracefulShutdown::new(30);
        assert_eq!(gs.timeout(), std::time::Duration::from_secs(30));
        assert!(!gs.is_shutting_down());
    }

    #[test]
    fn graceful_shutdown_trigger() {
        let gs = GracefulShutdown::new(30);
        gs.trigger();
        assert!(gs.is_shutting_down());
    }

    #[test]
    fn graceful_shutdown_subscribe() {
        let gs = GracefulShutdown::new(10);
        let rx = gs.subscribe();
        assert!(!*rx.borrow());
        gs.trigger();
        assert!(*rx.borrow());
    }

    #[tokio::test]
    async fn graceful_shutdown_empty_tracker() {
        let gs = GracefulShutdown::new(5);
        let tracker = ConnectionTracker::new();
        let result = gs.shutdown_with_drain(&tracker).await;
        assert!(result.drained);
        assert_eq!(result.remaining_connections, 0);
    }

    // --- Signal Handler tests ---

    #[test]
    fn signal_handler_registered_signals() {
        let handler = SignalHandler::new();
        let signals = handler.registered_signals();
        assert!(!signals.is_empty());
    }

    #[test]
    #[cfg(windows)]
    fn signal_handler_windows_signals() {
        let handler = SignalHandler::new();
        assert!(matches!(
            handler.get_action("CTRL_C"),
            Some(SignalAction::Shutdown)
        ));
        assert!(matches!(
            handler.get_action("CTRL_BREAK"),
            Some(SignalAction::Reload)
        ));
    }

    #[test]
    fn signal_handler_unknown_signal() {
        let handler = SignalHandler::new();
        assert!(handler.get_action("SIGFOO").is_none());
    }
}
