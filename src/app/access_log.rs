//! Structured access logging for connections.
//!
//! Provides detailed connection-level logging with:
//! - JSON and text output formats
//! - File output with rotation support
//! - Configurable fields and filtering
//! - Integration with connection tracking

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use serde::Serialize;
use tokio::fs::{File, OpenOptions};
use tokio::io::AsyncWriteExt;
use tokio::sync::RwLock;
use tracing::{debug, error, info};

/// Access log configuration
#[derive(Debug, Clone)]
pub struct AccessLogConfig {
    /// Enable access logging
    pub enabled: bool,
    /// Output format: "json" or "text"
    pub format: AccessLogFormat,
    /// Optional file path for log output (None = stdout via tracing)
    pub file_path: Option<PathBuf>,
    /// Maximum file size before rotation (bytes), 0 = no rotation
    pub max_file_size: u64,
    /// Maximum number of rotated files to keep
    pub max_rotated_files: u32,
    /// Log only failed connections
    pub log_errors_only: bool,
}

impl Default for AccessLogConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            format: AccessLogFormat::Text,
            file_path: None,
            max_file_size: 10 * 1024 * 1024, // 10MB
            max_rotated_files: 5,
            log_errors_only: false,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessLogFormat {
    Json,
    Text,
}

impl AccessLogFormat {
    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "json" => Self::Json,
            _ => Self::Text,
        }
    }
}

/// Connection information for access log entry
#[derive(Debug, Clone, Serialize)]
pub struct AccessLogEntry {
    /// Timestamp (ISO 8601)
    pub timestamp: String,
    /// Connection ID
    pub conn_id: u64,
    /// Source address (client)
    pub source: String,
    /// Target address (destination)
    pub target: String,
    /// Network type: "tcp" or "udp"
    pub network: String,
    /// Inbound tag
    pub inbound: String,
    /// Outbound tag
    pub outbound: String,
    /// Matched rule (if any)
    pub rule: Option<String>,
    /// Upload bytes
    pub upload: u64,
    /// Download bytes
    pub download: u64,
    /// Connection duration in milliseconds
    pub duration_ms: u64,
    /// Result: "OK" or "FAIL"
    pub status: String,
    /// Error message (if failed)
    pub error: Option<String>,
    /// Protocol detected via sniffing
    pub protocol: Option<String>,
}

impl AccessLogEntry {
    /// Create a new access log entry
    pub fn new(
        conn_id: u64,
        source: Option<SocketAddr>,
        target: &str,
        network: &str,
        inbound: &str,
        outbound: &str,
        rule: Option<&str>,
        upload: u64,
        download: u64,
        duration: Duration,
        status: &str,
        error: Option<&str>,
        protocol: Option<&str>,
    ) -> Self {
        let timestamp = chrono_like_timestamp();
        Self {
            timestamp,
            conn_id,
            source: source.map(|s| s.to_string()).unwrap_or_default(),
            target: target.to_string(),
            network: network.to_string(),
            inbound: inbound.to_string(),
            outbound: outbound.to_string(),
            rule: rule.map(|s| s.to_string()),
            upload,
            download,
            duration_ms: duration.as_millis() as u64,
            status: status.to_string(),
            error: error.map(|s| s.to_string()),
            protocol: protocol.map(|s| s.to_string()),
        }
    }

    /// Format as text line
    pub fn to_text(&self) -> String {
        let rule_part = self.rule.as_deref().unwrap_or("-");
        let protocol_part = self.protocol.as_deref().unwrap_or("-");
        let error_part = self.error.as_deref().map(|e| format!(" error={}", e)).unwrap_or_default();
        
        format!(
            "[{}] conn={} src={} dst={} net={} in={} out={} rule={} up={} down={} dur={}ms status={} proto={}{}",
            self.timestamp,
            self.conn_id,
            self.source,
            self.target,
            self.network,
            self.inbound,
            self.outbound,
            rule_part,
            self.upload,
            self.download,
            self.duration_ms,
            self.status,
            protocol_part,
            error_part,
        )
    }

    /// Format as JSON line
    pub fn to_json(&self) -> String {
        match serde_json::to_string(self) {
            Ok(s) => s,
            Err(_) => format!("{{\"error\":\"serialization failed\",\"conn_id\":{}}}", self.conn_id),
        }
    }
}

/// Access logger with file rotation support
pub struct AccessLogger {
    config: AccessLogConfig,
    file: RwLock<Option<File>>,
    current_size: RwLock<u64>,
}

impl AccessLogger {
    pub fn new(config: AccessLogConfig) -> Self {
        Self {
            config,
            file: RwLock::new(None),
            current_size: RwLock::new(0),
        }
    }

    /// Log an access entry
    pub async fn log(&self, entry: &AccessLogEntry) {
        if !self.config.enabled {
            return;
        }

        if self.config.log_errors_only && entry.status == "OK" {
            return;
        }

        let line = match self.config.format {
            AccessLogFormat::Json => entry.to_json(),
            AccessLogFormat::Text => entry.to_text(),
        };

        // Output via tracing (always)
        info!("{}", line);

        // Output to file if configured
        if let Some(ref path) = self.config.file_path {
            if let Err(e) = self.write_to_file(path, &line).await {
                error!(error = %e, path = %path.display(), "failed to write access log");
            }
        }
    }

    async fn write_to_file(&self, path: &PathBuf, line: &str) -> std::io::Result<()> {
        let mut file_guard = self.file.write().await;
        let mut size_guard = self.current_size.write().await;

        // Open file if not already open
        if file_guard.is_none() {
            let file = OpenOptions::new()
                .create(true)
                .append(true)
                .open(path)
                .await?;
            *file_guard = Some(file);
        }

        let file = file_guard.as_mut().unwrap();
        let line_with_newline = format!("{}\n", line);
        let bytes = line_with_newline.as_bytes();

        file.write_all(bytes).await?;
        file.flush().await?;

        *size_guard += bytes.len() as u64;

        // Check for rotation
        if self.config.max_file_size > 0 && *size_guard >= self.config.max_file_size {
            self.rotate_file(path).await?;
            *size_guard = 0;
        }

        Ok(())
    }

    async fn rotate_file(&self, path: &PathBuf) -> std::io::Result<()> {
        let mut file_guard = self.file.write().await;
        
        // Close current file
        *file_guard = None;

        // Rotate existing files
        for i in (1..self.config.max_rotated_files).rev() {
            let old_path = format!("{}.{}", path.display(), i);
            let new_path = format!("{}.{}", path.display(), i + 1);
            let old = PathBuf::from(&old_path);
            let new = PathBuf::from(&new_path);
            if old.exists() {
                tokio::fs::rename(&old, &new).await?;
            }
        }

        // Move current file to .1
        let rotated = PathBuf::from(format!("{}.1", path.display()));
        if path.exists() {
            tokio::fs::rename(path, &rotated).await?;
        }

        debug!(path = %path.display(), "access log rotated");
        Ok(())
    }

    /// Flush any buffered data
    pub async fn flush(&self) {
        let mut file_guard = self.file.write().await;
        if let Some(ref mut file) = *file_guard {
            let _ = file.flush().await;
        }
    }
}

/// Get ISO 8601 timestamp
fn chrono_like_timestamp() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    
    let secs = now.as_secs();
    let nanos = now.subsec_nanos();
    
    // Convert to UTC datetime components
    let days = secs / 86400;
    let remaining = secs % 86400;
    let hours = remaining / 3600;
    let minutes = (remaining % 3600) / 60;
    let seconds = remaining % 60;
    
    // Unix epoch (1970-01-01) to Gregorian
    // This is a simplified calculation
    let (year, month, day) = unix_days_to_date(days as i64 + 719163); // 719163 = days from 0000-01-01 to 1970-01-01
    
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z",
        year, month, day, hours, minutes, seconds, nanos / 1_000_000
    )
}

/// Convert Unix days to Gregorian date
fn unix_days_to_date(days: i64) -> (i32, u32, u32) {
    // Unix epoch is 1970-01-01
    // Days since Unix epoch
    // Use a simpler algorithm
    
    // Number of days from 1970-01-01
    let mut remaining_days = days;
    
    // Calculate year
    let mut year = 1970i32;
    loop {
        let days_in_year = if is_leap_year(year) { 366 } else { 365 };
        if remaining_days < days_in_year as i64 {
            break;
        }
        remaining_days -= days_in_year as i64;
        year += 1;
    }
    
    // Calculate month and day
    let days_in_months = if is_leap_year(year) {
        [31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    } else {
        [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    };
    
    let mut month = 1u32;
    for &days_in_month in &days_in_months {
        if remaining_days < days_in_month as i64 {
            break;
        }
        remaining_days -= days_in_month as i64;
        month += 1;
    }
    
    let day = (remaining_days + 1) as u32; // Days are 1-indexed
    
    (year, month, day)
}

fn is_leap_year(year: i32) -> bool {
    (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn access_log_entry_to_text() {
        let entry = AccessLogEntry::new(
            123,
            Some("192.168.1.1:54321".parse().unwrap()),
            "example.com:443",
            "tcp",
            "mixed-in",
            "proxy-out",
            Some("domain-suffix:com"),
            1024,
            2048,
            Duration::from_millis(150),
            "OK",
            None,
            Some("tls"),
        );
        
        let text = entry.to_text();
        assert!(text.contains("conn=123"));
        assert!(text.contains("src=192.168.1.1:54321"));
        assert!(text.contains("dst=example.com:443"));
        assert!(text.contains("up=1024"));
        assert!(text.contains("down=2048"));
        assert!(text.contains("status=OK"));
    }

    #[test]
    fn access_log_entry_to_json() {
        let entry = AccessLogEntry::new(
            456,
            None,
            "test.com:80",
            "tcp",
            "http-in",
            "direct",
            None,
            100,
            200,
            Duration::from_millis(50),
            "FAIL",
            Some("connection refused"),
            None,
        );
        
        let json = entry.to_json();
        assert!(json.contains("\"conn_id\":456"));
        assert!(json.contains("\"status\":\"FAIL\""));
        assert!(json.contains("\"error\":\"connection refused\""));
    }

    #[test]
    fn access_log_format_from_str() {
        assert_eq!(AccessLogFormat::from_str("json"), AccessLogFormat::Json);
        assert_eq!(AccessLogFormat::from_str("JSON"), AccessLogFormat::Json);
        assert_eq!(AccessLogFormat::from_str("text"), AccessLogFormat::Text);
        assert_eq!(AccessLogFormat::from_str("anything"), AccessLogFormat::Text);
    }

    #[test]
    fn unix_days_to_date_known() {
        // 1970-01-01 = day 0
        let (y, m, d) = unix_days_to_date(0);
        assert_eq!(y, 1970);
        assert_eq!(m, 1);
        assert_eq!(d, 1);
        
        // 2024-01-01
        let days = (2024 - 1970) * 365 + 13; // 13 leap years
        let (y, m, d) = unix_days_to_date(days);
        assert_eq!(y, 2024);
        assert_eq!(m, 1);
        assert_eq!(d, 1);
    }

    #[tokio::test]
    async fn access_logger_disabled() {
        let config = AccessLogConfig {
            enabled: false,
            ..Default::default()
        };
        let logger = AccessLogger::new(config);
        
        let entry = AccessLogEntry::new(
            1, None, "test", "tcp", "in", "out", None, 0, 0, Duration::ZERO, "OK", None, None,
        );
        
        // Should not panic or write
        logger.log(&entry).await;
    }
}
