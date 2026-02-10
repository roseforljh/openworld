//! Phase 4A: 代理组功能测试

use std::sync::Arc;

use openworld::app::outbound_manager::OutboundManager;
use openworld::config::types::{OutboundConfig, OutboundSettings, ProxyGroupConfig};
use openworld::proxy::group::loadbalance::LoadBalanceGroup;
use openworld::proxy::group::selector::SelectorGroup;
use openworld::proxy::outbound::direct::DirectOutbound;
use openworld::proxy::OutboundHandler;

fn make_direct_proxies(count: usize) -> (Vec<Arc<dyn OutboundHandler>>, Vec<String>) {
    let mut proxies: Vec<Arc<dyn OutboundHandler>> = Vec::new();
    let mut names = Vec::new();
    for i in 0..count {
        let tag = format!("direct-{}", i);
        proxies.push(Arc::new(DirectOutbound::new(tag.clone())));
        names.push(tag);
    }
    (proxies, names)
}

// --- SelectorGroup 测试 ---

#[tokio::test]
async fn selector_default_selects_first() {
    let (proxies, names) = make_direct_proxies(3);
    let group = SelectorGroup::new("my-selector".to_string(), proxies, names);
    assert_eq!(group.selected_name().await, "direct-0");
}

#[tokio::test]
async fn selector_switch_valid() {
    let (proxies, names) = make_direct_proxies(3);
    let group = SelectorGroup::new("my-selector".to_string(), proxies, names);
    assert!(group.select("direct-2").await);
    assert_eq!(group.selected_name().await, "direct-2");
}

#[tokio::test]
async fn selector_switch_invalid() {
    let (proxies, names) = make_direct_proxies(3);
    let group = SelectorGroup::new("my-selector".to_string(), proxies, names);
    assert!(!group.select("nonexistent").await);
    assert_eq!(group.selected_name().await, "direct-0");
}

#[tokio::test]
async fn selector_proxy_names() {
    let (proxies, names) = make_direct_proxies(2);
    let group = SelectorGroup::new("my-selector".to_string(), proxies, names);
    assert_eq!(group.proxy_names(), &["direct-0", "direct-1"]);
}

#[tokio::test]
async fn selector_tag() {
    let (proxies, names) = make_direct_proxies(1);
    let group = SelectorGroup::new("test-tag".to_string(), proxies, names);
    assert_eq!(group.tag(), "test-tag");
}

#[tokio::test]
async fn selector_as_any_downcast() {
    let (proxies, names) = make_direct_proxies(2);
    let group: Arc<dyn OutboundHandler> =
        Arc::new(SelectorGroup::new("sel".to_string(), proxies, names));
    let any = group.as_any();
    assert!(any.downcast_ref::<SelectorGroup>().is_some());
    assert!(any.downcast_ref::<LoadBalanceGroup>().is_none());
}

// --- LoadBalanceGroup 测试 ---

#[tokio::test]
async fn loadbalance_round_robin() {
    let (proxies, names) = make_direct_proxies(3);
    let group = LoadBalanceGroup::new("lb".to_string(), proxies, names);
    // 轮询分配: 0, 1, 2, 0, 1, 2
    assert_eq!(group.tag(), "lb");
    assert_eq!(group.proxy_names(), &["direct-0", "direct-1", "direct-2"]);
}

#[tokio::test]
async fn loadbalance_as_any_downcast() {
    let (proxies, names) = make_direct_proxies(2);
    let group: Arc<dyn OutboundHandler> =
        Arc::new(LoadBalanceGroup::new("lb".to_string(), proxies, names));
    assert!(group.as_any().downcast_ref::<LoadBalanceGroup>().is_some());
}

// --- OutboundManager 代理组注册测试 ---

fn make_outbound_configs() -> Vec<OutboundConfig> {
    vec![
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
    ]
}

#[test]
fn outbound_manager_with_selector_group() {
    let outbounds = make_outbound_configs();
    let groups = vec![ProxyGroupConfig {
        name: "my-selector".to_string(),
        group_type: "selector".to_string(),
        proxies: vec!["direct".to_string(), "direct-2".to_string()],
        url: None,
        interval: 300,
        tolerance: 150,
    }];

    let manager = OutboundManager::new(&outbounds, &groups).unwrap();
    assert!(manager.get("my-selector").is_some());
    assert!(manager.is_group("my-selector"));
    assert!(!manager.is_group("direct"));
}

#[test]
fn outbound_manager_with_loadbalance_group() {
    let outbounds = make_outbound_configs();
    let groups = vec![ProxyGroupConfig {
        name: "my-lb".to_string(),
        group_type: "load-balance".to_string(),
        proxies: vec!["direct".to_string(), "direct-2".to_string()],
        url: None,
        interval: 300,
        tolerance: 150,
    }];

    let manager = OutboundManager::new(&outbounds, &groups).unwrap();
    assert!(manager.get("my-lb").is_some());
    assert!(manager.is_group("my-lb"));
}

#[tokio::test]
async fn outbound_manager_selector_select_and_query() {
    let outbounds = make_outbound_configs();
    let groups = vec![ProxyGroupConfig {
        name: "sel".to_string(),
        group_type: "selector".to_string(),
        proxies: vec!["direct".to_string(), "direct-2".to_string()],
        url: None,
        interval: 300,
        tolerance: 150,
    }];

    let manager = OutboundManager::new(&outbounds, &groups).unwrap();

    // 默认选中第一个
    assert_eq!(
        manager.group_selected("sel").await,
        Some("direct".to_string())
    );

    // 切换
    assert!(manager.select_proxy("sel", "direct-2").await);
    assert_eq!(
        manager.group_selected("sel").await,
        Some("direct-2".to_string())
    );

    // 无效切换
    assert!(!manager.select_proxy("sel", "nonexistent").await);
    // 仍然是 direct-2
    assert_eq!(
        manager.group_selected("sel").await,
        Some("direct-2".to_string())
    );
}

#[tokio::test]
async fn outbound_manager_select_non_selector_fails() {
    let outbounds = make_outbound_configs();
    let groups = vec![ProxyGroupConfig {
        name: "lb".to_string(),
        group_type: "load-balance".to_string(),
        proxies: vec!["direct".to_string(), "direct-2".to_string()],
        url: None,
        interval: 300,
        tolerance: 150,
    }];

    let manager = OutboundManager::new(&outbounds, &groups).unwrap();

    // load-balance 不支持手动选择
    assert!(!manager.select_proxy("lb", "direct").await);
}

#[tokio::test]
async fn outbound_manager_group_selected_nonexistent() {
    let outbounds = make_outbound_configs();
    let manager = OutboundManager::new(&outbounds, &[]).unwrap();
    assert_eq!(manager.group_selected("nonexistent").await, None);
}

#[test]
fn outbound_manager_unknown_proxy_in_group_fails() {
    let outbounds = make_outbound_configs();
    let groups = vec![ProxyGroupConfig {
        name: "bad-group".to_string(),
        group_type: "selector".to_string(),
        proxies: vec!["nonexistent-proxy".to_string()],
        url: None,
        interval: 300,
        tolerance: 150,
    }];

    assert!(OutboundManager::new(&outbounds, &groups).is_err());
}

#[test]
fn outbound_manager_unsupported_group_type_fails() {
    let outbounds = make_outbound_configs();
    let groups = vec![ProxyGroupConfig {
        name: "bad".to_string(),
        group_type: "unknown-type".to_string(),
        proxies: vec!["direct".to_string()],
        url: None,
        interval: 300,
        tolerance: 150,
    }];

    assert!(OutboundManager::new(&outbounds, &groups).is_err());
}

// --- Config validation 代理组测试 ---

#[test]
fn config_validate_proxy_group_reference_ok() {
    use openworld::config::types::*;

    let config = Config {
        log: LogConfig::default(),
        inbounds: vec![InboundConfig {
            tag: "socks-in".to_string(),
            protocol: "socks5".to_string(),
            listen: "127.0.0.1".to_string(),
            port: 1080,
        }],
        outbounds: vec![OutboundConfig {
            tag: "direct".to_string(),
            protocol: "direct".to_string(),
            settings: OutboundSettings::default(),
        }],
        router: RouterConfig {
            rules: vec![],
            default: "direct".to_string(),
            geoip_db: None,
            geosite_db: None,
        },
        api: None,
        dns: None,
        proxy_groups: vec![ProxyGroupConfig {
            name: "my-group".to_string(),
            group_type: "selector".to_string(),
            proxies: vec!["direct".to_string()],
            url: None,
            interval: 300,
            tolerance: 150,
        }],
    };

    assert!(config.validate().is_ok());
}

#[test]
fn config_validate_proxy_group_unknown_proxy_fails() {
    use openworld::config::types::*;

    let config = Config {
        log: LogConfig::default(),
        inbounds: vec![InboundConfig {
            tag: "socks-in".to_string(),
            protocol: "socks5".to_string(),
            listen: "127.0.0.1".to_string(),
            port: 1080,
        }],
        outbounds: vec![OutboundConfig {
            tag: "direct".to_string(),
            protocol: "direct".to_string(),
            settings: OutboundSettings::default(),
        }],
        router: RouterConfig {
            rules: vec![],
            default: "direct".to_string(),
            geoip_db: None,
            geosite_db: None,
        },
        api: None,
        dns: None,
        proxy_groups: vec![ProxyGroupConfig {
            name: "my-group".to_string(),
            group_type: "selector".to_string(),
            proxies: vec!["nonexistent".to_string()],
            url: None,
            interval: 300,
            tolerance: 150,
        }],
    };

    let err = config.validate().unwrap_err();
    assert!(
        err.to_string().contains("unknown proxy"),
        "unexpected error: {}",
        err
    );
}

#[test]
fn config_validate_router_default_can_be_group() {
    use openworld::config::types::*;

    let config = Config {
        log: LogConfig::default(),
        inbounds: vec![InboundConfig {
            tag: "socks-in".to_string(),
            protocol: "socks5".to_string(),
            listen: "127.0.0.1".to_string(),
            port: 1080,
        }],
        outbounds: vec![OutboundConfig {
            tag: "direct".to_string(),
            protocol: "direct".to_string(),
            settings: OutboundSettings::default(),
        }],
        router: RouterConfig {
            rules: vec![],
            default: "my-group".to_string(),
            geoip_db: None,
            geosite_db: None,
        },
        api: None,
        dns: None,
        proxy_groups: vec![ProxyGroupConfig {
            name: "my-group".to_string(),
            group_type: "selector".to_string(),
            proxies: vec!["direct".to_string()],
            url: None,
            interval: 300,
            tolerance: 150,
        }],
    };

    assert!(config.validate().is_ok());
}

// --- API 代理组端点测试 ---

#[tokio::test]
async fn api_proxies_includes_group() {
    let base = start_test_api_with_group().await;
    let resp = reqwest::get(format!("{}/proxies", base)).await.unwrap();
    assert_eq!(resp.status(), 200);

    let body: serde_json::Value = resp.json().await.unwrap();
    let proxies = &body["proxies"];
    assert!(proxies["my-selector"].is_object());
    assert_eq!(proxies["my-selector"]["type"], "Selector");
    assert!(proxies["my-selector"]["all"].is_array());
    assert!(proxies["my-selector"]["now"].is_string());
}

#[tokio::test]
async fn api_proxy_group_detail() {
    let base = start_test_api_with_group().await;
    let resp = reqwest::get(format!("{}/proxies/my-selector", base))
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);

    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["name"], "my-selector");
    assert_eq!(body["type"], "Selector");
    assert_eq!(body["now"], "direct");
    let all = body["all"].as_array().unwrap();
    assert_eq!(all.len(), 2);
}

#[tokio::test]
async fn api_select_proxy() {
    let base = start_test_api_with_group().await;
    let client = reqwest::Client::new();

    // 切换到 direct-2
    let resp = client
        .put(format!("{}/proxies/my-selector", base))
        .json(&serde_json::json!({"name": "direct-2"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 204);

    // 验证已切换
    let resp = reqwest::get(format!("{}/proxies/my-selector", base))
        .await
        .unwrap();
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(body["now"], "direct-2");
}

#[tokio::test]
async fn api_select_proxy_invalid_name() {
    let base = start_test_api_with_group().await;
    let client = reqwest::Client::new();

    let resp = client
        .put(format!("{}/proxies/my-selector", base))
        .json(&serde_json::json!({"name": "nonexistent"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
}

#[tokio::test]
async fn api_select_proxy_non_selector_fails() {
    let base = start_test_api_with_group().await;
    let client = reqwest::Client::new();

    // direct 不是 selector
    let resp = client
        .put(format!("{}/proxies/direct", base))
        .json(&serde_json::json!({"name": "something"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 400);
}

#[tokio::test]
async fn api_select_proxy_nonexistent_group() {
    let base = start_test_api_with_group().await;
    let client = reqwest::Client::new();

    let resp = client
        .put(format!("{}/proxies/nonexistent", base))
        .json(&serde_json::json!({"name": "something"}))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 404);
}

/// 启动带代理组的测试 API 服务器
async fn start_test_api_with_group() -> String {
    use openworld::api;
    use openworld::app::tracker::ConnectionTracker;
    use openworld::router::Router;

    let router_cfg = openworld::config::types::RouterConfig {
        rules: vec![],
        default: "direct".to_string(),
        geoip_db: None,
        geosite_db: None,
    };
    let router = Arc::new(Router::new(&router_cfg).unwrap());

    let outbounds = vec![
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
    let groups = vec![ProxyGroupConfig {
        name: "my-selector".to_string(),
        group_type: "selector".to_string(),
        proxies: vec!["direct".to_string(), "direct-2".to_string()],
        url: None,
        interval: 300,
        tolerance: 150,
    }];
    let outbound_manager = Arc::new(OutboundManager::new(&outbounds, &groups).unwrap());
    let tracker = Arc::new(ConnectionTracker::new());

    let state = api::handlers::AppState {
        router,
        outbound_manager,
        tracker,
        secret: None,
    };

    let app = axum::Router::new()
        .route("/version", axum::routing::get(api::handlers::get_version))
        .route("/proxies", axum::routing::get(api::handlers::get_proxies))
        .route(
            "/proxies/{name}",
            axum::routing::get(api::handlers::get_proxy).put(api::handlers::select_proxy),
        )
        .route(
            "/proxies/{name}/delay",
            axum::routing::get(api::handlers::test_proxy_delay),
        )
        .route(
            "/connections",
            axum::routing::get(api::handlers::get_connections)
                .delete(api::handlers::close_all_connections),
        )
        .route("/rules", axum::routing::get(api::handlers::get_rules))
        .with_state(state);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    format!("http://{}", addr)
}
