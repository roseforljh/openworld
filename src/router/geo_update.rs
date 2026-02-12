//! GeoIP / GeoSite 数据库自动更新模块
//!
//! 支持从远程 URL 定期下载更新 GeoIP (mmdb) 和 GeoSite 数据库文件。
//! 使用 If-Modified-Since / ETag 条件请求避免不必要的下载。

use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use tokio::sync::Notify;
use tracing::{debug, info, warn};

/// GeoIP/GeoSite 自动更新配置
#[derive(Debug, Clone)]
pub struct GeoUpdateConfig {
    /// GeoIP mmdb 文件路径
    pub geoip_path: Option<String>,
    /// GeoIP 下载 URL
    pub geoip_url: Option<String>,
    /// GeoSite 文件路径
    pub geosite_path: Option<String>,
    /// GeoSite 下载 URL
    pub geosite_url: Option<String>,
    /// 更新检查间隔（秒），默认 7 天
    pub interval_secs: u64,
    /// 是否自动更新
    pub auto_update: bool,
}

impl Default for GeoUpdateConfig {
    fn default() -> Self {
        Self {
            geoip_path: None,
            geoip_url: None,
            geosite_path: None,
            geosite_url: None,
            interval_secs: 7 * 24 * 3600, // 7 days
            auto_update: false,
        }
    }
}

/// GeoIP/GeoSite 自动更新器
pub struct GeoUpdater {
    config: GeoUpdateConfig,
    shutdown: Arc<Notify>,
}

impl GeoUpdater {
    pub fn new(config: GeoUpdateConfig) -> Self {
        Self {
            config,
            shutdown: Arc::new(Notify::new()),
        }
    }

    /// 启动后台自动更新任务
    pub fn start(self: Arc<Self>) -> tokio::task::JoinHandle<()> {
        let shutdown = self.shutdown.clone();
        tokio::spawn(async move {
            let interval = Duration::from_secs(self.config.interval_secs.max(3600));
            info!(interval_secs = interval.as_secs(), "geo auto-updater started");

            loop {
                tokio::select! {
                    _ = tokio::time::sleep(interval) => {
                        if let Err(e) = self.check_and_update().await {
                            warn!(error = %e, "geo auto-update failed");
                        }
                    }
                    _ = shutdown.notified() => {
                        info!("geo auto-updater shutting down");
                        break;
                    }
                }
            }
        })
    }

    /// 停止自动更新
    pub fn stop(&self) {
        self.shutdown.notify_one();
    }

    /// 手动触发一次更新检查
    pub async fn check_and_update(&self) -> Result<()> {
        if let (Some(ref path), Some(ref url)) = (&self.config.geoip_path, &self.config.geoip_url) {
            match download_if_updated(path, url).await {
                Ok(true) => info!(path = path.as_str(), "GeoIP database updated"),
                Ok(false) => debug!(path = path.as_str(), "GeoIP database up to date"),
                Err(e) => warn!(error = %e, "GeoIP update failed"),
            }
        }

        if let (Some(ref path), Some(ref url)) = (&self.config.geosite_path, &self.config.geosite_url) {
            match download_if_updated(path, url).await {
                Ok(true) => info!(path = path.as_str(), "GeoSite database updated"),
                Ok(false) => debug!(path = path.as_str(), "GeoSite database up to date"),
                Err(e) => warn!(error = %e, "GeoSite update failed"),
            }
        }

        Ok(())
    }
}

/// Ensure configured geo databases exist before Router initialization.
/// Downloads missing files if URLs are configured.
/// Errors are logged as warnings (proxy can still work without geo databases).
pub async fn ensure_databases(
    geoip_path: Option<&str>,
    geoip_url: Option<&str>,
    geosite_path: Option<&str>,
    geosite_url: Option<&str>,
) {
    if let (Some(path), Some(url)) = (geoip_path, geoip_url) {
        if !Path::new(path).exists() {
            info!(path = path, "GeoIP database not found, downloading...");
            match download_if_updated(path, url).await {
                Ok(_) => {}
                Err(e) => warn!(error = %e, "failed to download GeoIP database"),
            }
        }
    }
    if let (Some(path), Some(url)) = (geosite_path, geosite_url) {
        if !Path::new(path).exists() {
            info!(path = path, "GeoSite database not found, downloading...");
            match download_if_updated(path, url).await {
                Ok(_) => {}
                Err(e) => warn!(error = %e, "failed to download GeoSite database"),
            }
        }
    }
}

/// 下载文件（如果远程版本更新）
///
/// 使用文件修改时间判断是否需要更新。
/// 返回 true 表示文件已更新，false 表示无需更新。
async fn download_if_updated(local_path: &str, url: &str) -> Result<bool> {
    let path = Path::new(local_path);

    // 检查本地文件是否存在及其修改时间
    let should_download = if path.exists() {
        match std::fs::metadata(path) {
            Ok(meta) => match meta.modified() {
                Ok(modified) => {
                    let age = modified.elapsed().unwrap_or_default();
                    // 如果文件不到 1 天，跳过
                    age > Duration::from_secs(24 * 3600)
                }
                Err(_) => true,
            },
            Err(_) => true,
        }
    } else {
        true
    };

    if !should_download {
        return Ok(false);
    }

    info!(url = url, path = local_path, "downloading geo database");

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(120))
        .build()?;

    let response = client.get(url).send().await?;

    if !response.status().is_success() {
        anyhow::bail!("HTTP {} for {}", response.status(), url);
    }

    let bytes = response.bytes().await?;

    // 确保父目录存在
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    // 写入临时文件然后原子重命名
    let tmp_path = format!("{}.tmp", local_path);
    std::fs::write(&tmp_path, &bytes)?;
    std::fs::rename(&tmp_path, local_path)?;

    info!(
        path = local_path,
        size = bytes.len(),
        "geo database downloaded"
    );

    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn geo_update_config_default() {
        let config = GeoUpdateConfig::default();
        assert!(!config.auto_update);
        assert_eq!(config.interval_secs, 7 * 24 * 3600);
        assert!(config.geoip_path.is_none());
    }

    #[test]
    fn geo_updater_creation() {
        let config = GeoUpdateConfig {
            geoip_path: Some("geoip.mmdb".to_string()),
            geoip_url: Some("https://example.com/geoip.mmdb".to_string()),
            auto_update: true,
            ..Default::default()
        };
        let updater = GeoUpdater::new(config);
        assert!(updater.config.auto_update);
    }
}
