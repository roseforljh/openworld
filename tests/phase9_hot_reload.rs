//! Phase 4E: 配置热重载测试

use std::sync::Arc;

use openworld::app::dispatcher::Dispatcher;
use openworld::app::outbound_manager::OutboundManager;
use openworld::app::tracker::ConnectionTracker;
use openworld::config::types::{OutboundConfig, OutboundSettings, RouterConfig, RuleConfig};
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

/// 测试 Dispatcher 热更新 Router
#[tokio::test]
async fn dispatcher_hot_swap_router() {
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
    let om = Arc::new(OutboundManager::new(&outbounds, &[]).unwrap());
    let tracker = Arc::new(ConnectionTracker::new());
    let dispatcher = Dispatcher::new(router, om, tracker, Arc::new(MockResolver) as Arc<dyn DnsResolver>, None, CancellationToken::new());

    // 初始状态无规则
    assert!(dispatcher.router().await.rules().is_empty());

    // 创建带规则的新 Router
    let new_cfg = RouterConfig {
        rules: vec![RuleConfig {
            rule_type: "domain-suffix".to_string(),
            values: vec!["example.com".to_string()],
            outbound: "direct".to_string(),
            action: "route".to_string(),
            override_address: None,
            override_port: None,
            sniff: false,
            resolve_strategy: None,
        }],
        default: "direct".to_string(),
        ..Default::default()
    };
    let new_router = Arc::new(Router::new(&new_cfg).unwrap());
    dispatcher.update_router(new_router).await;

    // 验证规则已更新
    assert_eq!(dispatcher.router().await.rules().len(), 1);
}

/// 测试 Dispatcher 热更新 OutboundManager
#[tokio::test]
async fn dispatcher_hot_swap_outbound_manager() {
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
    let om = Arc::new(OutboundManager::new(&outbounds, &[]).unwrap());
    let tracker = Arc::new(ConnectionTracker::new());
    let dispatcher = Dispatcher::new(router, om, tracker, Arc::new(MockResolver) as Arc<dyn DnsResolver>, None, CancellationToken::new());

    // 初始只有 direct
    assert!(dispatcher.outbound_manager().await.get("direct").is_some());
    assert!(dispatcher
        .outbound_manager()
        .await
        .get("direct-2")
        .is_none());

    // 新增一个 outbound
    let new_outbounds = vec![
        OutboundConfig {
            tag: "direct".to_string(),
            protocol: "direct".to_string(),
            settings: OutboundSettings::default(),
        },
        OutboundConfig {
            tag: "direct-2".to_string(),
            protocol: "direct".to_string(),
            settings: OutboundSettings::default(),
        },
    ];
    let new_om = Arc::new(OutboundManager::new(&new_outbounds, &[]).unwrap());
    dispatcher.update_outbound_manager(new_om).await;

    assert!(dispatcher
        .outbound_manager()
        .await
        .get("direct-2")
        .is_some());
}

/// 测试快照模式：在 dispatch 期间 Router 更新不影响正在进行的连接
#[tokio::test]
async fn dispatcher_snapshot_isolation() {
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
    let om = Arc::new(OutboundManager::new(&outbounds, &[]).unwrap());
    let tracker = Arc::new(ConnectionTracker::new());
    let dispatcher = Arc::new(Dispatcher::new(router, om, tracker, Arc::new(MockResolver) as Arc<dyn DnsResolver>, None, CancellationToken::new()));

    // 获取快照
    let snapshot_router = dispatcher.router().await;
    assert!(snapshot_router.rules().is_empty());

    // 更新 Dispatcher 中的 Router
    let new_cfg = RouterConfig {
        rules: vec![RuleConfig {
            rule_type: "domain-suffix".to_string(),
            values: vec!["test.com".to_string()],
            outbound: "direct".to_string(),
            action: "route".to_string(),
            override_address: None,
            override_port: None,
            sniff: false,
            resolve_strategy: None,
        }],
        default: "direct".to_string(),
        ..Default::default()
    };
    dispatcher
        .update_router(Arc::new(Router::new(&new_cfg).unwrap()))
        .await;

    // 旧快照不受影响
    assert!(snapshot_router.rules().is_empty());
    // 新快照有规则
    assert_eq!(dispatcher.router().await.rules().len(), 1);
}

/// 测试 PATCH /configs 端点 - 成功重载
#[tokio::test]
async fn api_reload_config_success() {
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
    let om = Arc::new(OutboundManager::new(&outbounds, &[]).unwrap());
    let tracker = Arc::new(ConnectionTracker::new());
    let dispatcher = Arc::new(Dispatcher::new(router, om, tracker, Arc::new(MockResolver) as Arc<dyn DnsResolver>, None, CancellationToken::new()));

    // 创建临时配置文件
    let tmp = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(
        tmp.path(),
        r#"
inbounds:
  - tag: socks-in
    protocol: socks5
    listen: "127.0.0.1"
    port: 1080
outbounds:
  - tag: direct
    protocol: direct
router:
  default: direct
  rules:
    - type: domain-suffix
      values: ["reloaded.com"]
      outbound: direct
"#,
    )
    .unwrap();

    let state = openworld::api::handlers::AppState {
        dispatcher: dispatcher.clone(),
        secret: None,
        config_path: None,
        log_broadcaster: openworld::api::log_broadcast::LogBroadcaster::new(16),
        start_time: std::time::Instant::now(),
        ss_inbound: None,
    };

    let app = axum::Router::new()
        .route(
            "/configs",
            axum::routing::patch(openworld::api::handlers::reload_config),
        )
        .with_state(state);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    let client = reqwest::Client::new();
    let resp = client
        .patch(format!("http://{}/configs", addr))
        .json(&serde_json::json!({"path": tmp.path().to_str().unwrap()}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 204);

    // 验证规则已更新
    assert_eq!(dispatcher.router().await.rules().len(), 1);
}

/// 测试 PATCH /configs 端点 - 配置文件不存在
#[tokio::test]
async fn api_reload_config_file_not_found() {
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
    let om = Arc::new(OutboundManager::new(&outbounds, &[]).unwrap());
    let tracker = Arc::new(ConnectionTracker::new());
    let dispatcher = Arc::new(Dispatcher::new(router, om, tracker, Arc::new(MockResolver) as Arc<dyn DnsResolver>, None, CancellationToken::new()));

    let state = openworld::api::handlers::AppState {
        dispatcher,
        secret: None,
        config_path: None,
        log_broadcaster: openworld::api::log_broadcast::LogBroadcaster::new(16),
        start_time: std::time::Instant::now(),
        ss_inbound: None,
    };

    let app = axum::Router::new()
        .route(
            "/configs",
            axum::routing::patch(openworld::api::handlers::reload_config),
        )
        .with_state(state);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    let client = reqwest::Client::new();
    let resp = client
        .patch(format!("http://{}/configs", addr))
        .json(&serde_json::json!({"path": "/nonexistent/path/config.yaml"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);

    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(body["message"]
        .as_str()
        .unwrap()
        .contains("failed to load config"));
}

/// 测试 PATCH /configs 端点 - 无效配置内容
#[tokio::test]
async fn api_reload_config_invalid_config() {
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
    let om = Arc::new(OutboundManager::new(&outbounds, &[]).unwrap());
    let tracker = Arc::new(ConnectionTracker::new());
    let dispatcher = Arc::new(Dispatcher::new(router, om, tracker, Arc::new(MockResolver) as Arc<dyn DnsResolver>, None, CancellationToken::new()));

    // 创建无效配置
    let tmp = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(tmp.path(), "not: valid: yaml: config:").unwrap();

    let state = openworld::api::handlers::AppState {
        dispatcher: dispatcher.clone(),
        secret: None,
        config_path: None,
        log_broadcaster: openworld::api::log_broadcast::LogBroadcaster::new(16),
        start_time: std::time::Instant::now(),
        ss_inbound: None,
    };

    let app = axum::Router::new()
        .route(
            "/configs",
            axum::routing::patch(openworld::api::handlers::reload_config),
        )
        .with_state(state);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    let client = reqwest::Client::new();
    let resp = client
        .patch(format!("http://{}/configs", addr))
        .json(&serde_json::json!({"path": tmp.path().to_str().unwrap()}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);

    // 验证原始状态未被改变
    assert!(dispatcher.router().await.rules().is_empty());
}

/// 测试使用 config_path 回退
#[tokio::test]
async fn api_reload_config_uses_default_path() {
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
    let om = Arc::new(OutboundManager::new(&outbounds, &[]).unwrap());
    let tracker = Arc::new(ConnectionTracker::new());
    let dispatcher = Arc::new(Dispatcher::new(router, om, tracker, Arc::new(MockResolver) as Arc<dyn DnsResolver>, None, CancellationToken::new()));

    let tmp = tempfile::NamedTempFile::new().unwrap();
    std::fs::write(
        tmp.path(),
        r#"
inbounds:
  - tag: socks-in
    protocol: socks5
    listen: "127.0.0.1"
    port: 1080
outbounds:
  - tag: direct
    protocol: direct
router:
  default: direct
"#,
    )
    .unwrap();

    let state = openworld::api::handlers::AppState {
        dispatcher: dispatcher.clone(),
        secret: None,
        config_path: Some(tmp.path().to_str().unwrap().to_string()),
        log_broadcaster: openworld::api::log_broadcast::LogBroadcaster::new(16),
        start_time: std::time::Instant::now(),
        ss_inbound: None,
    };

    let app = axum::Router::new()
        .route(
            "/configs",
            axum::routing::patch(openworld::api::handlers::reload_config),
        )
        .with_state(state);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    // 不提供 path，使用 config_path 回退
    let client = reqwest::Client::new();
    let resp = client
        .patch(format!("http://{}/configs", addr))
        .json(&serde_json::json!({}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 204);
}

/// 测试 Tracker 在热重载后保持不变
#[tokio::test]
async fn dispatcher_tracker_persists_across_reload() {
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
    let om = Arc::new(OutboundManager::new(&outbounds, &[]).unwrap());
    let tracker = Arc::new(ConnectionTracker::new());
    let dispatcher = Dispatcher::new(router, om, tracker, Arc::new(MockResolver) as Arc<dyn DnsResolver>, None, CancellationToken::new());

    // 获取 tracker 引用
    let tracker_before = Arc::as_ptr(dispatcher.tracker());

    // 更新 router 和 outbound_manager
    let new_cfg = RouterConfig {
        rules: vec![],
        default: "direct".to_string(),
        ..Default::default()
    };
    dispatcher
        .update_router(Arc::new(Router::new(&new_cfg).unwrap()))
        .await;
    dispatcher
        .update_outbound_manager(Arc::new(OutboundManager::new(&outbounds, &[]).unwrap()))
        .await;

    // Tracker 是同一个实例
    let tracker_after = Arc::as_ptr(dispatcher.tracker());
    assert_eq!(tracker_before, tracker_after);
}
