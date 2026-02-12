//! Phase 5: API 绔偣闆嗘垚娴嬭瘯

use std::sync::Arc;

use openworld::api;
use openworld::app::dispatcher::Dispatcher;
use openworld::app::outbound_manager::OutboundManager;
use openworld::app::tracker::ConnectionTracker;
use openworld::config::types::{OutboundConfig, OutboundSettings, RouterConfig};
use openworld::dns::DnsResolver;
use openworld::router::Router;
use tokio_util::sync::CancellationToken;

struct MockResolver;

#[async_trait::async_trait]
impl DnsResolver for MockResolver {
    async fn resolve(&self, _host: &str) -> anyhow::Result<Vec<std::net::IpAddr>> {
        Ok(vec![std::net::IpAddr::V4(std::net::Ipv4Addr::new(
            127, 0, 0, 1,
        ))])
    }
}

/// 启动一个测试 API 服务器，返回基础 URL
async fn start_test_api() -> String {
    let router_cfg = RouterConfig {
        rules: vec![],
        default: "direct".to_string(),
        ..Default::default()
    };
    let router = Arc::new(Router::new(&router_cfg).unwrap());

    let outbounds = vec![OutboundConfig {
        tag: "direct".to_string(),
        protocol: "direct".to_string(),
        settings: OutboundSettings::default(),
    }];
    let outbound_manager = Arc::new(OutboundManager::new(&outbounds, &[]).unwrap());
    let tracker = Arc::new(ConnectionTracker::new());

    let dispatcher = Arc::new(Dispatcher::new(router, outbound_manager, tracker, Arc::new(MockResolver) as Arc<dyn DnsResolver>, None, CancellationToken::new()));

    // 鎵嬪姩鍒涘缓 API 鏈嶅姟鍣ㄤ互鑾峰彇瀹為檯绔彛
    let state = openworld::api::handlers::AppState {
        dispatcher,
        secret: None,
        config_path: None,
        log_broadcaster: openworld::api::log_broadcast::LogBroadcaster::new(16),
        start_time: std::time::Instant::now(),
    };

    let app = axum::Router::new()
        .route("/version", axum::routing::get(api::handlers::get_version))
        .route("/proxies", axum::routing::get(api::handlers::get_proxies))
        .route(
            "/proxies/{name}",
            axum::routing::get(api::handlers::get_proxy),
        )
        .route(
            "/connections",
            axum::routing::get(api::handlers::get_connections)
                .delete(api::handlers::close_all_connections),
        )
        .route(
            "/connections/{id}",
            axum::routing::delete(api::handlers::close_connection),
        )
        .route("/rules", axum::routing::get(api::handlers::get_rules))
        .route("/stats", axum::routing::get(api::handlers::get_stats))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    format!("http://{}", addr)
}

#[tokio::test]
async fn api_version_endpoint() {
    let base = start_test_api().await;
    let resp = reqwest::get(format!("{}/version", base)).await.unwrap();
    assert_eq!(resp.status(), 200);

    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(body["version"].is_string());
    assert_eq!(body["premium"], false);
}

#[tokio::test]
async fn api_proxies_endpoint() {
    let base = start_test_api().await;
    let resp = reqwest::get(format!("{}/proxies", base)).await.unwrap();
    assert_eq!(resp.status(), 200);

    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(body["proxies"].is_object());
    assert!(body["proxies"]["direct"].is_object());
}

#[tokio::test]
async fn api_proxy_detail_found() {
    let base = start_test_api().await;
    let resp = reqwest::get(format!("{}/proxies/direct", base))
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["name"], "direct");
}

#[tokio::test]
async fn api_proxy_detail_not_found() {
    let base = start_test_api().await;
    let resp = reqwest::get(format!("{}/proxies/nonexistent", base))
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);
}

#[tokio::test]
async fn api_connections_endpoint() {
    let base = start_test_api().await;
    let resp = reqwest::get(format!("{}/connections", base)).await.unwrap();
    assert_eq!(resp.status(), 200);

    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(body["connections"].is_array());
    assert!(body["downloadTotal"].is_number());
    assert!(body["uploadTotal"].is_number());
}

#[tokio::test]
async fn api_close_all_connections() {
    let base = start_test_api().await;
    let client = reqwest::Client::new();
    let resp = client
        .delete(format!("{}/connections", base))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 204);
}

#[tokio::test]
async fn api_close_nonexistent_connection() {
    let base = start_test_api().await;
    let client = reqwest::Client::new();
    let resp = client
        .delete(format!("{}/connections/999999", base))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);
}

#[tokio::test]
async fn api_rules_endpoint() {
    let base = start_test_api().await;
    let resp = reqwest::get(format!("{}/rules", base)).await.unwrap();
    assert_eq!(resp.status(), 200);

    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(body["rules"].is_array());
}

#[tokio::test]
async fn api_stats_endpoint() {
    let base = start_test_api().await;
    let resp = reqwest::get(format!("{}/stats", base)).await.unwrap();
    assert_eq!(resp.status(), 200);

    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(body["routeStats"].is_object());
    assert!(body["errorStats"].is_object());
    assert!(body["dnsStats"].is_object());
    assert!(body["dnsStats"]["cacheHit"].is_number());
    assert!(body["dnsStats"]["cacheMiss"].is_number());
    assert!(body["dnsStats"]["negativeHit"].is_number());
    assert!(body["latency"].is_object());
    assert!(body["latency"]["p50"].is_null());
    assert!(body["latency"]["p95"].is_null());
    assert!(body["latency"]["p99"].is_null());
}
