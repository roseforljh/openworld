use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::RwLock;
use tracing::{debug, info};

use crate::common::Address;
use crate::proxy::{Network, OutboundHandler, Session};

/// 健康检查器：定期测试代理延迟
pub struct HealthChecker {
    proxies: Vec<Arc<dyn OutboundHandler>>,
    proxy_names: Vec<String>,
    url: String,
    interval: u64,
    /// proxy_name -> Option<latency_ms>，None 表示不可用
    latencies: RwLock<HashMap<String, Option<u64>>>,
}

impl HealthChecker {
    pub fn new(
        proxies: Vec<Arc<dyn OutboundHandler>>,
        proxy_names: Vec<String>,
        url: String,
        interval: u64,
    ) -> Self {
        let latencies = RwLock::new(HashMap::new());
        Self {
            proxies,
            proxy_names,
            url,
            interval,
            latencies,
        }
    }

    /// 获取所有代理的延迟数据
    pub async fn latencies(&self) -> HashMap<String, Option<u64>> {
        self.latencies.read().await.clone()
    }

    /// 测试单个代理的延迟
    pub async fn test_proxy(
        proxy: &dyn OutboundHandler,
        url: &str,
        timeout: Duration,
    ) -> Option<u64> {
        let (host, port, path) = parse_url(url);

        let session = Session {
            target: Address::Domain(host.clone(), port),
            source: None,
            inbound_tag: "health-check".to_string(),
            network: Network::Tcp,
            sniff: false,
        };

        let start = Instant::now();

        let connect_result = tokio::time::timeout(timeout, proxy.connect(&session)).await;

        let mut stream = match connect_result {
            Ok(Ok(s)) => s,
            Ok(Err(_)) | Err(_) => return None,
        };

        // 发送简单 HTTP GET 请求
        let request = format!(
            "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
            path, host
        );

        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        match tokio::time::timeout(timeout, stream.write_all(request.as_bytes())).await {
            Ok(Ok(_)) => {}
            _ => return None,
        }

        // 读取响应的第一部分就够了
        let mut buf = [0u8; 512];
        match tokio::time::timeout(timeout, stream.read(&mut buf)).await {
            Ok(Ok(n)) if n > 0 => {
                let elapsed = start.elapsed().as_millis() as u64;
                Some(elapsed)
            }
            _ => None,
        }
    }

    /// 对所有代理执行一轮检查
    pub async fn check_all(&self) {
        let timeout = Duration::from_secs(5);
        let mut results = HashMap::new();

        for (idx, proxy) in self.proxies.iter().enumerate() {
            let name = &self.proxy_names[idx];
            let latency = Self::test_proxy(proxy.as_ref(), &self.url, timeout).await;
            debug!(
                proxy = name,
                latency = ?latency,
                "health check result"
            );
            results.insert(name.clone(), latency);
        }

        *self.latencies.write().await = results;
    }

    /// 测试单个代理（外部调用，用于 API 延迟测试）
    pub async fn test_single(&self, name: &str, url: &str, timeout_ms: u64) -> Option<u64> {
        let idx = self.proxy_names.iter().position(|n| n == name)?;
        let proxy = &self.proxies[idx];
        let timeout = Duration::from_millis(timeout_ms);
        Self::test_proxy(proxy.as_ref(), url, timeout).await
    }

    /// 后台循环执行健康检查
    pub async fn run_loop(&self, group_name: String) {
        // 首次检查稍微延迟
        tokio::time::sleep(Duration::from_secs(1)).await;
        info!(group = group_name, "starting health check loop");
        self.check_all().await;

        let mut interval = tokio::time::interval(Duration::from_secs(self.interval));
        interval.tick().await; // 跳过首次立即触发
        loop {
            interval.tick().await;
            self.check_all().await;
        }
    }
}

/// 解析简单 URL 为 (host, port, path)
fn parse_url(url: &str) -> (String, u16, String) {
    let (scheme, rest) = if let Some(r) = url.strip_prefix("https://") {
        ("https", r)
    } else if let Some(r) = url.strip_prefix("http://") {
        ("http", r)
    } else {
        ("http", url)
    };

    let (host_port, path) = match rest.find('/') {
        Some(idx) => (&rest[..idx], &rest[idx..]),
        None => (rest, "/"),
    };

    let default_port: u16 = if scheme == "https" { 443 } else { 80 };

    let (host, port) = match host_port.rfind(':') {
        Some(idx) => {
            let port_str = &host_port[idx + 1..];
            match port_str.parse::<u16>() {
                Ok(p) => (host_port[..idx].to_string(), p),
                Err(_) => (host_port.to_string(), default_port),
            }
        }
        None => (host_port.to_string(), default_port),
    };

    (host, port, path.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_url_http() {
        let (host, port, path) = parse_url("http://www.gstatic.com/generate_204");
        assert_eq!(host, "www.gstatic.com");
        assert_eq!(port, 80);
        assert_eq!(path, "/generate_204");
    }

    #[test]
    fn parse_url_https() {
        let (host, port, path) = parse_url("https://example.com/test");
        assert_eq!(host, "example.com");
        assert_eq!(port, 443);
        assert_eq!(path, "/test");
    }

    #[test]
    fn parse_url_with_port() {
        let (host, port, path) = parse_url("http://localhost:8080/health");
        assert_eq!(host, "localhost");
        assert_eq!(port, 8080);
        assert_eq!(path, "/health");
    }

    #[test]
    fn parse_url_no_path() {
        let (host, port, path) = parse_url("http://example.com");
        assert_eq!(host, "example.com");
        assert_eq!(port, 80);
        assert_eq!(path, "/");
    }
}
