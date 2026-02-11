use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::ws::{Message, WebSocket};
use axum::extract::{Path, Query, State, WebSocketUpgrade};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use tokio::sync::broadcast;
use tokio::time::interval;
use tracing::{debug, info};

use crate::app::dispatcher::Dispatcher;
use crate::app::outbound_manager::OutboundManager;
use crate::proxy::group::fallback::FallbackGroup;
use crate::proxy::group::loadbalance::LoadBalanceGroup;
use crate::proxy::group::selector::SelectorGroup;
use crate::proxy::group::urltest::UrlTestGroup;

use super::models::*;

/// 共享应用状态
#[derive(Clone)]
pub struct AppState {
    pub dispatcher: Arc<Dispatcher>,
    pub secret: Option<String>,
    pub config_path: Option<String>,
    pub log_broadcaster: crate::api::log_broadcast::LogBroadcaster,
    pub start_time: std::time::Instant,
}

/// GET /version
pub async fn get_version() -> Json<VersionResponse> {
    Json(VersionResponse {
        version: env!("CARGO_PKG_VERSION").to_string(),
        premium: false,
    })
}

/// 从 handler 构建 ProxyInfo（含代理组信息）
async fn build_proxy_info(
    name: &str,
    handler: &dyn crate::proxy::OutboundHandler,
    _outbound_manager: &OutboundManager,
) -> ProxyInfo {
    let any = handler.as_any();

    // 检查是否为代理组
    if let Some(selector) = any.downcast_ref::<SelectorGroup>() {
        return ProxyInfo {
            name: name.to_string(),
            proxy_type: "Selector".to_string(),
            udp: false,
            history: vec![],
            all: Some(selector.proxy_names().to_vec()),
            now: Some(selector.selected_name().await),
        };
    }
    if let Some(urltest) = any.downcast_ref::<UrlTestGroup>() {
        return ProxyInfo {
            name: name.to_string(),
            proxy_type: "URLTest".to_string(),
            udp: false,
            history: vec![],
            all: Some(urltest.proxy_names().to_vec()),
            now: Some(urltest.selected_name().await),
        };
    }
    if let Some(fallback) = any.downcast_ref::<FallbackGroup>() {
        return ProxyInfo {
            name: name.to_string(),
            proxy_type: "Fallback".to_string(),
            udp: false,
            history: vec![],
            all: Some(fallback.proxy_names().to_vec()),
            now: Some(fallback.selected_name().await),
        };
    }
    if let Some(lb) = any.downcast_ref::<LoadBalanceGroup>() {
        return ProxyInfo {
            name: name.to_string(),
            proxy_type: "LoadBalance".to_string(),
            udp: false,
            history: vec![],
            all: Some(lb.proxy_names().to_vec()),
            now: None,
        };
    }

    // 普通出站
    ProxyInfo {
        name: name.to_string(),
        proxy_type: "Unknown".to_string(),
        udp: false,
        history: vec![],
        all: None,
        now: None,
    }
}

/// GET /proxies
pub async fn get_proxies(State(state): State<AppState>) -> Json<ProxiesResponse> {
    let outbound_manager = state.dispatcher.outbound_manager().await;
    let handlers = outbound_manager.list();
    let mut proxies = HashMap::new();
    for (tag, handler) in handlers {
        let info = build_proxy_info(tag, handler.as_ref(), &outbound_manager).await;
        proxies.insert(tag.clone(), info);
    }
    Json(ProxiesResponse { proxies })
}

/// GET /proxies/:name
pub async fn get_proxy(
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> impl IntoResponse {
    let outbound_manager = state.dispatcher.outbound_manager().await;
    match outbound_manager.get(&name) {
        Some(handler) => {
            let info = build_proxy_info(&name, handler.as_ref(), &outbound_manager).await;
            match serde_json::to_value(info) {
                Ok(v) => (StatusCode::OK, Json(v)).into_response(),
                Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
            }
        }
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

/// PUT /proxies/:name - 切换 selector 代理组
pub async fn select_proxy(
    State(state): State<AppState>,
    Path(group_name): Path<String>,
    Json(body): Json<SelectProxyRequest>,
) -> StatusCode {
    let outbound_manager = state.dispatcher.outbound_manager().await;
    let handler = match outbound_manager.get(&group_name) {
        Some(h) => h,
        None => return StatusCode::NOT_FOUND,
    };

    let any = handler.as_any();
    if let Some(selector) = any.downcast_ref::<SelectorGroup>() {
        if selector.select(&body.name).await {
            StatusCode::NO_CONTENT
        } else {
            StatusCode::BAD_REQUEST
        }
    } else {
        StatusCode::BAD_REQUEST
    }
}

/// GET /proxies/:name/delay - 延迟测试
pub async fn test_proxy_delay(
    State(state): State<AppState>,
    Path(name): Path<String>,
    Query(params): Query<HashMap<String, String>>,
) -> impl IntoResponse {
    let url = params
        .get("url")
        .cloned()
        .unwrap_or_else(|| "http://www.gstatic.com/generate_204".to_string());
    let timeout: u64 = params
        .get("timeout")
        .and_then(|t| t.parse().ok())
        .unwrap_or(5000);

    match state
        .dispatcher
        .outbound_manager()
        .await
        .test_delay(&name, &url, timeout)
        .await
    {
        Some(delay) => (StatusCode::OK, Json(serde_json::json!({"delay": delay}))).into_response(),
        None => (
            StatusCode::REQUEST_TIMEOUT,
            Json(serde_json::json!({"message": "timeout"})),
        )
            .into_response(),
    }
}

/// GET /connections
pub async fn get_connections(State(state): State<AppState>) -> Json<ConnectionsResponse> {
    let tracker = state.dispatcher.tracker();
    let connections = tracker.list().await;
    let snapshot = tracker.snapshot();

    let items: Vec<ConnectionItem> = connections
        .into_iter()
        .map(|c| {
            let elapsed = c.start_time.elapsed();
            let start = chrono_like_start(elapsed);

            ConnectionItem {
                id: c.id.to_string(),
                metadata: ConnectionMetadata {
                    network: c.network.clone(),
                    conn_type: c.inbound_tag.clone(),
                    source_ip: c.source.map(|s| s.ip().to_string()).unwrap_or_default(),
                    source_port: c.source.map(|s| s.port().to_string()).unwrap_or_default(),
                    destination_ip: String::new(),
                    destination_port: String::new(),
                    host: c.target.clone(),
                    dns_mode: String::new(),
                },
                upload: c.upload,
                download: c.download,
                start,
                chains: vec![c.outbound_tag.clone()],
                rule: c.matched_rule.clone(),
                route_tag: c.route_tag.clone(),
            }
        })
        .collect();

    Json(ConnectionsResponse {
        download_total: snapshot.total_down,
        upload_total: snapshot.total_up,
        connections: items,
    })
}

/// DELETE /connections
pub async fn close_all_connections(State(state): State<AppState>) -> StatusCode {
    let closed = state.dispatcher.tracker().close_all().await;
    debug!(count = closed, "closed all connections via API");
    StatusCode::NO_CONTENT
}

/// DELETE /connections/:id
pub async fn close_connection(State(state): State<AppState>, Path(id): Path<String>) -> StatusCode {
    if let Ok(id) = id.parse::<u64>() {
        if state.dispatcher.tracker().close(id).await {
            return StatusCode::NO_CONTENT;
        }
    }
    StatusCode::NOT_FOUND
}

/// GET /traffic (WebSocket)
pub async fn traffic_ws(
    State(state): State<AppState>,
    Query(params): Query<HashMap<String, String>>,
    ws: WebSocketUpgrade,
) -> impl IntoResponse {
    if let Some(ref secret) = state.secret {
        let token = params.get("token").map(|s| s.as_str()).unwrap_or("");
        if token != secret {
            return StatusCode::UNAUTHORIZED.into_response();
        }
    }

    ws.on_upgrade(move |socket| handle_traffic_ws(socket, state))
        .into_response()
}

async fn handle_traffic_ws(mut socket: WebSocket, state: AppState) {
    let mut ticker = interval(Duration::from_secs(1));
    let tracker = state.dispatcher.tracker().clone();
    let mut last_up = tracker.snapshot().total_up;
    let mut last_down = tracker.snapshot().total_down;

    loop {
        ticker.tick().await;
        let snap = tracker.snapshot();
        let item = TrafficItem {
            up: snap.total_up.saturating_sub(last_up),
            down: snap.total_down.saturating_sub(last_down),
        };
        last_up = snap.total_up;
        last_down = snap.total_down;

        let json = match serde_json::to_string(&item) {
            Ok(j) => j,
            Err(_) => break,
        };
        if socket.send(Message::Text(json.into())).await.is_err() {
            break;
        }
    }
}

/// GET /rules
pub async fn get_rules(State(state): State<AppState>) -> Json<RulesResponse> {
    let router = state.dispatcher.router().await;
    let rules: Vec<RuleItem> = router
        .rules()
        .iter()
        .map(|(rule, outbound)| RuleItem {
            rule_type: rule_type_name(rule),
            payload: format!("{}", rule),
            proxy: outbound.clone(),
        })
        .collect();

    Json(RulesResponse { rules })
}

/// GET /stats
pub async fn get_stats(State(state): State<AppState>) -> Json<StatsResponse> {
    let tracker = state.dispatcher.tracker();
    let (p50, p95, p99) = tracker
        .latency_percentiles_ms()
        .map(|(a, b, c)| (Some(a), Some(b), Some(c)))
        .unwrap_or((None, None, None));

    Json(StatsResponse {
        route_stats: tracker.route_stats(),
        error_stats: tracker.error_stats(),
        dns_stats: DnsStats {
            cache_hit: 0,
            cache_miss: 0,
            negative_hit: 0,
        },
        latency: LatencyStats {
            p50_ms: p50,
            p95_ms: p95,
            p99_ms: p99,
        },
    })
}

/// GET /logs (WebSocket) - 实时日志流
pub async fn logs_ws(
    State(state): State<AppState>,
    Query(params): Query<HashMap<String, String>>,
    ws: WebSocketUpgrade,
) -> impl IntoResponse {
    // WebSocket 认证检查
    if let Some(ref secret) = state.secret {
        let token = params.get("token").map(|s| s.as_str()).unwrap_or("");
        if token != secret {
            return StatusCode::UNAUTHORIZED.into_response();
        }
    }

    let level_filter = params
        .get("level")
        .cloned()
        .unwrap_or_else(|| "info".to_string());
    let broadcaster = state.log_broadcaster.clone();

    ws.on_upgrade(move |socket| handle_logs_ws(socket, broadcaster, level_filter))
        .into_response()
}

async fn handle_logs_ws(
    mut socket: WebSocket,
    broadcaster: crate::api::log_broadcast::LogBroadcaster,
    level_filter: String,
) {
    let mut rx = broadcaster.subscribe();

    loop {
        match rx.recv().await {
            Ok(entry) => {
                if !should_include_level(&entry.level, &level_filter) {
                    continue;
                }
                let json = match serde_json::to_string(&entry) {
                    Ok(j) => j,
                    Err(_) => continue,
                };
                if socket.send(Message::Text(json.into())).await.is_err() {
                    break;
                }
            }
            Err(broadcast::error::RecvError::Lagged(_)) => continue,
            Err(broadcast::error::RecvError::Closed) => break,
        }
    }
}

fn should_include_level(entry_level: &str, filter: &str) -> bool {
    let level_value = |l: &str| match l {
        "error" => 0,
        "warning" => 1,
        "info" => 2,
        "debug" => 3,
        _ => 4,
    };
    level_value(entry_level) <= level_value(filter)
}

/// PATCH /configs - 热重载配置
pub async fn reload_config(
    State(state): State<AppState>,
    Json(body): Json<ReloadConfigRequest>,
) -> impl IntoResponse {
    let path = body
        .path
        .or(state.config_path.clone())
        .unwrap_or_else(|| "config.yaml".to_string());

    let config = match crate::config::load_config(&path) {
        Ok(c) => c,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"message": format!("failed to load config: {}", e)})),
            )
                .into_response();
        }
    };

    let new_router = match crate::router::Router::new(&config.router) {
        Ok(r) => std::sync::Arc::new(r),
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"message": format!("failed to build router: {}", e)})),
            )
                .into_response();
        }
    };

    let new_om = match OutboundManager::new(&config.outbounds, &config.proxy_groups) {
        Ok(om) => std::sync::Arc::new(om),
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"message": format!("failed to build outbound manager: {}", e)})),
            )
                .into_response();
        }
    };

    state.dispatcher.update_router(new_router).await;
    state.dispatcher.update_outbound_manager(new_om).await;

    info!(path = path, "config reloaded via API");
    StatusCode::NO_CONTENT.into_response()
}

fn rule_type_name(rule: &crate::router::rules::Rule) -> String {
    use crate::router::rules::Rule;
    match rule {
        Rule::DomainSuffix(_) => "DomainSuffix".to_string(),
        Rule::DomainKeyword(_) => "DomainKeyword".to_string(),
        Rule::DomainFull(_) => "Domain".to_string(),
        Rule::IpCidr(_) => "IPCIDR".to_string(),
        Rule::GeoIp(_) => "GeoIP".to_string(),
        Rule::GeoSite(_) => "GeoSite".to_string(),
        Rule::RuleSet { .. } => "RuleSet".to_string(),
        Rule::DstPort(_) => "DstPort".to_string(),
        Rule::SrcPort(_) => "SrcPort".to_string(),
        Rule::Network(_) => "Network".to_string(),
        Rule::InTag(_) => "InTag".to_string(),
        Rule::ProcessName(_) => "ProcessName".to_string(),
        Rule::ProcessPath(_) => "ProcessPath".to_string(),
        Rule::IpAsn(_) => "IPASN".to_string(),
        Rule::Uid(_) => "UID".to_string(),
        Rule::And(_) => "AND".to_string(),
        Rule::Or(_) => "OR".to_string(),
        Rule::Not(_) => "NOT".to_string(),
    }
}

fn chrono_like_start(elapsed: Duration) -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let start_secs = now.as_secs().saturating_sub(elapsed.as_secs());
    format!("{}s", start_secs)
}

/// GET /memory
pub async fn get_memory() -> Json<MemoryResponse> {
    Json(MemoryResponse {
        in_use: current_memory_usage(),
        os_limit: 0,
    })
}

fn current_memory_usage() -> u64 {
    #[cfg(windows)]
    {
        use std::mem;
        #[repr(C)]
        #[allow(non_snake_case)]
        struct ProcessMemoryCounters {
            cb: u32,
            PageFaultCount: u32,
            PeakWorkingSetSize: usize,
            WorkingSetSize: usize,
            QuotaPeakPagedPoolUsage: usize,
            QuotaPagedPoolUsage: usize,
            QuotaPeakNonPagedPoolUsage: usize,
            QuotaNonPagedPoolUsage: usize,
            PagefileUsage: usize,
            PeakPagefileUsage: usize,
        }
        extern "system" {
            fn GetCurrentProcess() -> isize;
            fn K32GetProcessMemoryInfo(
                process: isize,
                ppsmemcounters: *mut ProcessMemoryCounters,
                cb: u32,
            ) -> i32;
        }
        unsafe {
            let mut pmc: ProcessMemoryCounters = mem::zeroed();
            pmc.cb = mem::size_of::<ProcessMemoryCounters>() as u32;
            if K32GetProcessMemoryInfo(GetCurrentProcess(), &mut pmc, pmc.cb) != 0 {
                return pmc.WorkingSetSize as u64;
            }
        }
        0
    }
    #[cfg(not(windows))]
    {
        0
    }
}

/// GET /uptime
pub async fn get_uptime(State(state): State<AppState>) -> Json<UptimeResponse> {
    let tracker = state.dispatcher.tracker();
    let snap = tracker.snapshot_async().await;

    Json(UptimeResponse {
        uptime_secs: state.start_time.elapsed().as_secs(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        active_connections: snap.active_count,
    })
}

/// GET /providers/rules
pub async fn get_rule_providers(State(state): State<AppState>) -> Json<RuleProvidersResponse> {
    let router = state.dispatcher.router().await;
    let providers = router.providers();
    let mut result = HashMap::new();

    for (name, data) in providers {
        let snapshot = data.snapshot();
        let rule_count = snapshot.domain_rules.len() + snapshot.ip_cidrs.len();
        result.insert(
            name.clone(),
            RuleProviderInfo {
                name: name.clone(),
                provider_type: data.provider_type().to_string(),
                rule_count,
                updated_at: String::new(),
                behavior: if !snapshot.ip_cidrs.is_empty() && snapshot.domain_rules.is_empty() {
                    "ipcidr".to_string()
                } else if snapshot.ip_cidrs.is_empty() && !snapshot.domain_rules.is_empty() {
                    "domain".to_string()
                } else {
                    "classical".to_string()
                },
            },
        );
    }

    Json(RuleProvidersResponse { providers: result })
}
