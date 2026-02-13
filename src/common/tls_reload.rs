//! TLS 证书热重载模块
//!
//! 监控 TLS 证书和私钥文件变化，自动重新加载 ServerConfig。
//! 使用 `Arc<ArcSwap<rustls::ServerConfig>>` 实现无锁热替换。

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use anyhow::Result;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio::sync::watch;
use tracing::{debug, error, info, warn};

/// 证书热重载器
pub struct CertReloader {
    cert_path: PathBuf,
    key_path: PathBuf,
    /// 轮询间隔
    poll_interval: Duration,
    /// 停止信号
    cancel_tx: watch::Sender<bool>,
    cancel_rx: watch::Receiver<bool>,
}

/// 可热重载的 TLS 配置持有者
pub struct ReloadableServerConfig {
    inner: Arc<tokio::sync::RwLock<Arc<rustls::ServerConfig>>>,
}

impl ReloadableServerConfig {
    /// 创建新的可重载配置
    pub fn new(config: rustls::ServerConfig) -> Self {
        Self {
            inner: Arc::new(tokio::sync::RwLock::new(Arc::new(config))),
        }
    }

    /// 获取当前 ServerConfig 的引用
    pub async fn current(&self) -> Arc<rustls::ServerConfig> {
        self.inner.read().await.clone()
    }

    /// 替换为新的 ServerConfig
    pub async fn replace(&self, new_config: rustls::ServerConfig) {
        let mut guard = self.inner.write().await;
        *guard = Arc::new(new_config);
    }

    /// 获取 inner Arc 用于 clone
    pub fn shared(&self) -> Arc<tokio::sync::RwLock<Arc<rustls::ServerConfig>>> {
        self.inner.clone()
    }
}

impl Clone for ReloadableServerConfig {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

impl CertReloader {
    /// 创建新的证书热重载器
    ///
    /// - `cert_path`: PEM 证书文件路径
    /// - `key_path`: PEM 私钥文件路径
    /// - `poll_interval`: 轮询检查间隔（默认 30 秒）
    pub fn new(cert_path: impl AsRef<Path>, key_path: impl AsRef<Path>) -> Self {
        let (cancel_tx, cancel_rx) = watch::channel(false);
        Self {
            cert_path: cert_path.as_ref().to_path_buf(),
            key_path: key_path.as_ref().to_path_buf(),
            poll_interval: Duration::from_secs(30),
            cancel_tx,
            cancel_rx,
        }
    }

    /// 设置轮询间隔
    pub fn with_interval(mut self, interval: Duration) -> Self {
        self.poll_interval = interval;
        self
    }

    /// 加载证书并构建初始 ServerConfig
    pub fn load_initial(&self) -> Result<ReloadableServerConfig> {
        let config = load_server_config(&self.cert_path, &self.key_path)?;
        info!(
            cert = %self.cert_path.display(),
            key = %self.key_path.display(),
            "TLS certificates loaded"
        );
        Ok(ReloadableServerConfig::new(config))
    }

    /// 启动热重载后台任务
    pub fn start_watching(
        &self,
        reloadable: ReloadableServerConfig,
    ) -> tokio::task::JoinHandle<()> {
        let cert_path = self.cert_path.clone();
        let key_path = self.key_path.clone();
        let poll_interval = self.poll_interval;
        let mut cancel_rx = self.cancel_rx.clone();

        tokio::spawn(async move {
            let mut last_cert_mtime = get_mtime(&cert_path);
            let mut last_key_mtime = get_mtime(&key_path);

            info!(
                cert = %cert_path.display(),
                key = %key_path.display(),
                interval = ?poll_interval,
                "TLS certificate hot-reload watcher started"
            );

            loop {
                tokio::select! {
                    _ = tokio::time::sleep(poll_interval) => {}
                    _ = cancel_rx.changed() => {
                        info!("TLS certificate watcher stopped");
                        break;
                    }
                }

                // 检查文件修改时间
                let cert_mtime = get_mtime(&cert_path);
                let key_mtime = get_mtime(&key_path);

                let changed = cert_mtime != last_cert_mtime || key_mtime != last_key_mtime;
                if !changed {
                    continue;
                }

                debug!(
                    cert = %cert_path.display(),
                    "TLS certificate file changed, reloading..."
                );

                match load_server_config(&cert_path, &key_path) {
                    Ok(new_config) => {
                        reloadable.replace(new_config).await;
                        last_cert_mtime = cert_mtime;
                        last_key_mtime = key_mtime;
                        info!("TLS certificates reloaded successfully");
                    }
                    Err(e) => {
                        warn!(error = %e, "TLS certificate reload failed, keeping old config");
                    }
                }
            }
        })
    }

    /// 停止热重载
    pub fn stop(&self) {
        let _ = self.cancel_tx.send(true);
    }
}

/// 从 PEM 文件加载证书和私钥，构建 ServerConfig
fn load_server_config(cert_path: &Path, key_path: &Path) -> Result<rustls::ServerConfig> {
    // 读取证书链
    let cert_data = std::fs::read(cert_path)
        .map_err(|e| anyhow::anyhow!("read cert file {}: {}", cert_path.display(), e))?;
    let certs = load_certs_from_pem(&cert_data)?;

    if certs.is_empty() {
        anyhow::bail!("no certificates found in {}", cert_path.display());
    }

    // 读取私钥
    let key_data = std::fs::read(key_path)
        .map_err(|e| anyhow::anyhow!("read key file {}: {}", key_path.display(), e))?;
    let key = load_private_key_from_pem(&key_data)?;

    // 构建 ServerConfig
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| anyhow::anyhow!("TLS version config: {}", e))?
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| anyhow::anyhow!("TLS cert/key config: {}", e))?;

    Ok(config)
}

/// 从 PEM 数据解析证书链
fn load_certs_from_pem(data: &[u8]) -> Result<Vec<CertificateDer<'static>>> {
    let mut reader = std::io::BufReader::new(data);
    let certs: Vec<_> = rustls_pemfile::certs(&mut reader)
        .filter_map(|r| r.ok())
        .collect();
    Ok(certs)
}

/// 从 PEM 数据解析私钥
fn load_private_key_from_pem(data: &[u8]) -> Result<PrivateKeyDer<'static>> {
    let mut reader = std::io::BufReader::new(data);

    // 尝试 PKCS8
    let pkcs8_keys: Vec<_> = rustls_pemfile::pkcs8_private_keys(&mut reader)
        .filter_map(|r| r.ok())
        .collect();
    if let Some(key) = pkcs8_keys.into_iter().next() {
        return Ok(PrivateKeyDer::Pkcs8(key));
    }

    // 重新读取尝试 RSA
    let mut reader = std::io::BufReader::new(data);
    let rsa_keys: Vec<_> = rustls_pemfile::rsa_private_keys(&mut reader)
        .filter_map(|r| r.ok())
        .collect();
    if let Some(key) = rsa_keys.into_iter().next() {
        return Ok(PrivateKeyDer::Pkcs1(key));
    }

    // 尝试 EC
    let mut reader = std::io::BufReader::new(data);
    let ec_keys: Vec<_> = rustls_pemfile::ec_private_keys(&mut reader)
        .filter_map(|r| r.ok())
        .collect();
    if let Some(key) = ec_keys.into_iter().next() {
        return Ok(PrivateKeyDer::Sec1(key));
    }

    anyhow::bail!("no private key found in PEM data")
}

/// 获取文件修改时间
fn get_mtime(path: &Path) -> Option<SystemTime> {
    std::fs::metadata(path)
        .ok()
        .and_then(|m| m.modified().ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cert_reloader_creation() {
        let reloader = CertReloader::new("/tmp/cert.pem", "/tmp/key.pem")
            .with_interval(Duration::from_secs(60));
        assert_eq!(reloader.poll_interval, Duration::from_secs(60));
        assert_eq!(reloader.cert_path.to_str().unwrap(), "/tmp/cert.pem");
    }

    #[test]
    fn get_mtime_nonexistent() {
        assert!(get_mtime(Path::new("/nonexistent/file.pem")).is_none());
    }

    #[test]
    fn load_certs_from_empty_pem() {
        let result = load_certs_from_pem(b"");
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }

    #[test]
    fn load_private_key_from_empty_pem_fails() {
        let result = load_private_key_from_pem(b"");
        assert!(result.is_err());
    }
}
