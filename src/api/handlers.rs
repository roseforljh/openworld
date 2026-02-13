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
use crate::proxy::group::latency_weighted::LatencyWeightedGroup;
use crate::proxy::group::loadbalance::LoadBalanceGroup;
use crate::proxy::group::selector::SelectorGroup;
use crate::proxy::group::urltest::UrlTestGroup;
use crate::proxy::outbound::chain::ProxyChain;
use crate::proxy::outbound::direct::DirectOutbound;
use crate::proxy::outbound::http::HttpOutbound;
use crate::proxy::outbound::hysteria2::Hysteria2Outbound;
use crate::proxy::outbound::reject::{BlackholeOutbound, RejectOutbound};
use crate::proxy::outbound::shadowsocks::ShadowsocksOutbound;
use crate::proxy::outbound::ssh::SshOutbound;
use crate::proxy::outbound::tor::TorOutbound;
use crate::proxy::outbound::trojan::TrojanOutbound;
use crate::proxy::outbound::tuic::TuicOutbound;
use crate::proxy::outbound::vless::VlessOutbound;
use crate::proxy::outbound::vmess::VmessOutbound;
use crate::proxy::outbound::wireguard::WireGuardOutbound;

use super::models::*;

/// 共享应用状态
#[derive(Clone)]
pub struct AppState {
    pub dispatcher: Arc<Dispatcher>,
    pub secret: Option<String>,
    pub config_path: Option<String>,
    pub log_broadcaster: crate::api::log_broadcast::LogBroadcaster,
    pub start_time: std::time::Instant,
    pub ss_inbound: Option<Arc<crate::proxy::inbound::shadowsocks::ShadowsocksInbound>>,
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

    // 普通出站 — 检测具体协议类型
    let proxy_type = detect_proxy_type(any);

    ProxyInfo {
        name: name.to_string(),
        proxy_type,
        udp: false,
        history: vec![],
        all: None,
        now: None,
    }
}

/// 检测出站处理器的具体协议类型
fn detect_proxy_type(any: &dyn std::any::Any) -> String {
    if any.downcast_ref::<DirectOutbound>().is_some() {
        return "Direct".to_string();
    }
    if any.downcast_ref::<RejectOutbound>().is_some() {
        return "Reject".to_string();
    }
    if any.downcast_ref::<BlackholeOutbound>().is_some() {
        return "Blackhole".to_string();
    }
    if any.downcast_ref::<VlessOutbound>().is_some() {
        return "VLESS".to_string();
    }
    if any.downcast_ref::<VmessOutbound>().is_some() {
        return "VMess".to_string();
    }
    if any.downcast_ref::<TrojanOutbound>().is_some() {
        return "Trojan".to_string();
    }
    if any.downcast_ref::<ShadowsocksOutbound>().is_some() {
        return "Shadowsocks".to_string();
    }
    if any.downcast_ref::<Hysteria2Outbound>().is_some() {
        return "Hysteria2".to_string();
    }
    if any.downcast_ref::<WireGuardOutbound>().is_some() {
        return "WireGuard".to_string();
    }
    if any.downcast_ref::<HttpOutbound>().is_some() {
        return "HTTP".to_string();
    }
    if any.downcast_ref::<SshOutbound>().is_some() {
        return "SSH".to_string();
    }
    if any.downcast_ref::<TuicOutbound>().is_some() {
        return "TUIC".to_string();
    }
    if any.downcast_ref::<TorOutbound>().is_some() {
        return "Tor".to_string();
    }
    if any.downcast_ref::<ProxyChain>().is_some() {
        return "Chain".to_string();
    }
    if any.downcast_ref::<LatencyWeightedGroup>().is_some() {
        return "LatencyWeighted".to_string();
    }
    "Unknown".to_string()
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

/// GET /proxies/:name/healthcheck - 代理组健康检查（并发测试组内所有代理延迟）
pub async fn healthcheck_proxy(
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

    let outbound_manager = state.dispatcher.outbound_manager().await;
    let handler = match outbound_manager.get(&name) {
        Some(h) => h,
        None => return StatusCode::NOT_FOUND.into_response(),
    };

    // 获取组内代理列表
    let any = handler.as_any();
    let proxy_names = if let Some(selector) = any.downcast_ref::<SelectorGroup>() {
        selector.proxy_names().to_vec()
    } else if let Some(urltest) = any.downcast_ref::<UrlTestGroup>() {
        urltest.proxy_names().to_vec()
    } else if let Some(fallback) = any.downcast_ref::<FallbackGroup>() {
        fallback.proxy_names().to_vec()
    } else if let Some(lb) = any.downcast_ref::<LoadBalanceGroup>() {
        lb.proxy_names().to_vec()
    } else {
        // 非代理组，直接测试单个代理
        return match outbound_manager.test_delay(&name, &url, timeout).await {
            Some(delay) => {
                (StatusCode::OK, Json(serde_json::json!({"delay": delay}))).into_response()
            }
            None => (
                StatusCode::REQUEST_TIMEOUT,
                Json(serde_json::json!({"message": "timeout"})),
            )
                .into_response(),
        };
    };

    // 并发测试所有代理
    let mut tasks = Vec::new();
    for pname in &proxy_names {
        let om = outbound_manager.clone();
        let pname = pname.clone();
        let url = url.clone();
        tasks.push(tokio::spawn(async move {
            let delay = om.test_delay(&pname, &url, timeout).await;
            (pname, delay)
        }));
    }

    let mut results = HashMap::new();
    for task in tasks {
        if let Ok((pname, delay)) = task.await {
            if let Some(d) = delay {
                results.insert(pname, d);
            }
        }
    }

    (StatusCode::OK, Json(serde_json::json!(results))).into_response()
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
    let snap = tracker.snapshot_async().await;
    let mut last_up = snap.total_up;
    let mut last_down = snap.total_down;

    loop {
        ticker.tick().await;
        let snap = tracker.snapshot_async().await;
        let item = TrafficItem {
            up: snap.total_up.saturating_sub(last_up),
            down: snap.total_down.saturating_sub(last_down),
            memory: current_memory_usage(),
            conn_active: snap.active_count,
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
        .map(|(rule, action)| RuleItem {
            rule_type: rule_type_name(rule),
            payload: format!("{}", rule),
            proxy: action.outbound_tag().unwrap_or("reject").to_string(),
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

/// GET /metrics - Prometheus metrics export
pub async fn get_metrics(State(state): State<AppState>) -> impl IntoResponse {
    let tracker = state.dispatcher.tracker();
    let snap = tracker.snapshot_async().await;
    let route_stats = tracker.route_stats();
    let error_stats = tracker.error_stats();
    let latency = tracker.latency_percentiles_ms();

    let mut out = String::with_capacity(2048);

    // Active connections (gauge)
    out.push_str("# HELP openworld_connections_active Current active connections\n");
    out.push_str("# TYPE openworld_connections_active gauge\n");
    out.push_str(&format!(
        "openworld_connections_active {}\n\n",
        snap.active_count
    ));

    // Total traffic (counters)
    out.push_str("# HELP openworld_traffic_bytes_total Total traffic in bytes\n");
    out.push_str("# TYPE openworld_traffic_bytes_total counter\n");
    out.push_str(&format!(
        "openworld_traffic_bytes_total{{direction=\"upload\"}} {}\n",
        snap.total_up
    ));
    out.push_str(&format!(
        "openworld_traffic_bytes_total{{direction=\"download\"}} {}\n\n",
        snap.total_down
    ));

    // Route hits (counter with label)
    if !route_stats.is_empty() {
        out.push_str("# HELP openworld_route_hits_total Route match hit count\n");
        out.push_str("# TYPE openworld_route_hits_total counter\n");
        let mut sorted: Vec<_> = route_stats.iter().collect();
        sorted.sort_by(|(a, _), (b, _)| a.cmp(b));
        for (route, count) in sorted {
            out.push_str(&format!(
                "openworld_route_hits_total{{route=\"{}\"}} {}\n",
                prom_escape(route),
                count
            ));
        }
        out.push('\n');
    }

    // Error counts (counter with label)
    if !error_stats.is_empty() {
        out.push_str("# HELP openworld_errors_total Error count by category\n");
        out.push_str("# TYPE openworld_errors_total counter\n");
        let mut sorted: Vec<_> = error_stats.iter().collect();
        sorted.sort_by(|(a, _), (b, _)| a.cmp(b));
        for (code, count) in sorted {
            out.push_str(&format!(
                "openworld_errors_total{{code=\"{}\"}} {}\n",
                prom_escape(code),
                count
            ));
        }
        out.push('\n');
    }

    // Latency summary
    if let Some((p50, p95, p99)) = latency {
        out.push_str(
            "# HELP openworld_connection_duration_ms Connection latency in milliseconds\n",
        );
        out.push_str("# TYPE openworld_connection_duration_ms summary\n");
        out.push_str(&format!(
            "openworld_connection_duration_ms{{quantile=\"0.5\"}} {}\n",
            p50
        ));
        out.push_str(&format!(
            "openworld_connection_duration_ms{{quantile=\"0.95\"}} {}\n",
            p95
        ));
        out.push_str(&format!(
            "openworld_connection_duration_ms{{quantile=\"0.99\"}} {}\n\n",
            p99
        ));
    }

    // Uptime (gauge)
    let uptime_secs = state.start_time.elapsed().as_secs();
    out.push_str("# HELP openworld_uptime_seconds Process uptime in seconds\n");
    out.push_str("# TYPE openworld_uptime_seconds gauge\n");
    out.push_str(&format!("openworld_uptime_seconds {}\n", uptime_secs));

    (
        [(
            axum::http::header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        out,
    )
}

fn prom_escape(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
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
    // 处理模式切换
    if let Some(ref mode) = body.mode {
        if !crate::app::clash_mode::set_mode_str(mode) {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"message": format!("invalid mode: {}", mode)})),
            )
                .into_response();
        }
        // 如果只是切换模式（没有 path），直接返回
        if body.path.is_none() {
            return StatusCode::NO_CONTENT.into_response();
        }
    }

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
        Rule::DomainRegex(_) => "DomainRegex".to_string(),
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
        Rule::Protocol(_) => "Protocol".to_string(),
        Rule::And(_) => "AND".to_string(),
        Rule::Or(_) => "OR".to_string(),
        Rule::Not(_) => "NOT".to_string(),
        Rule::WifiSsid(_) => "WifiSSID".to_string(),
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

pub fn current_memory_usage() -> u64 {
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

/// GET /dns/query?name=example.com&type=A
pub async fn dns_query(
    State(state): State<AppState>,
    Query(params): Query<HashMap<String, String>>,
) -> impl IntoResponse {
    let name = match params.get("name") {
        Some(n) => n.clone(),
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"message": "missing 'name' parameter"})),
            )
                .into_response();
        }
    };

    let resolver = state.dispatcher.resolver().await;
    match resolver.resolve(&name).await {
        Ok(addrs) => {
            let answers: Vec<serde_json::Value> = addrs
                .iter()
                .map(|ip| {
                    serde_json::json!({
                        "type": if ip.is_ipv4() { "A" } else { "AAAA" },
                        "data": ip.to_string(),
                        "ttl": 300,
                    })
                })
                .collect();
            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "Status": 0,
                    "Question": [{"name": name, "type": params.get("type").unwrap_or(&"A".to_string())}],
                    "Answer": answers,
                })),
            )
                .into_response()
        }
        Err(e) => (
            StatusCode::OK,
            Json(serde_json::json!({
                "Status": 2,
                "Question": [{"name": name}],
                "Answer": [],
                "Comment": format!("resolve failed: {}", e),
            })),
        )
            .into_response(),
    }
}

/// GET /connections (WebSocket) - 实时连接流
pub async fn connections_ws(
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

    ws.on_upgrade(move |socket| handle_connections_ws(socket, state))
        .into_response()
}

async fn handle_connections_ws(mut socket: WebSocket, state: AppState) {
    let mut ticker = interval(Duration::from_secs(1));
    let tracker = state.dispatcher.tracker().clone();

    loop {
        ticker.tick().await;
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

        let resp = serde_json::json!({
            "downloadTotal": snapshot.total_down,
            "uploadTotal": snapshot.total_up,
            "connections": items,
        });

        let json = match serde_json::to_string(&resp) {
            Ok(j) => j,
            Err(_) => break,
        };
        if socket.send(Message::Text(json.into())).await.is_err() {
            break;
        }
    }
}

/// GET /providers/proxies
pub async fn get_proxy_providers(State(state): State<AppState>) -> Json<ProxyProvidersResponse> {
    let outbound_manager = state.dispatcher.outbound_manager().await;
    let mut providers = HashMap::new();

    // 将代理组作为 proxy provider 暴露
    for (name, handler) in outbound_manager.list() {
        let any = handler.as_any();
        let (group_type, proxy_names) = if let Some(selector) = any.downcast_ref::<SelectorGroup>()
        {
            ("Selector", selector.proxy_names().to_vec())
        } else if let Some(urltest) = any.downcast_ref::<UrlTestGroup>() {
            ("URLTest", urltest.proxy_names().to_vec())
        } else if let Some(fallback) = any.downcast_ref::<FallbackGroup>() {
            ("Fallback", fallback.proxy_names().to_vec())
        } else if let Some(lb) = any.downcast_ref::<LoadBalanceGroup>() {
            ("LoadBalance", lb.proxy_names().to_vec())
        } else {
            continue;
        };

        let mut proxies = Vec::new();
        for pname in &proxy_names {
            if let Some(ph) = outbound_manager.get(pname) {
                let info = build_proxy_info(pname, ph.as_ref(), &outbound_manager).await;
                proxies.push(info);
            }
        }

        providers.insert(
            name.clone(),
            ProxyProviderInfo {
                name: name.clone(),
                provider_type: group_type.to_string(),
                proxies,
                vehicle_type: "Compatible".to_string(),
            },
        );
    }

    Json(ProxyProvidersResponse { providers })
}

/// POST /dns/flush
pub async fn flush_dns(State(state): State<AppState>) -> StatusCode {
    state.dispatcher.resolver().await.flush_cache().await;
    info!("DNS cache flushed via API");
    StatusCode::NO_CONTENT
}

/// PUT /providers/proxies/:name
pub async fn refresh_proxy_provider(
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> impl IntoResponse {
    let outbound_manager = state.dispatcher.outbound_manager().await;
    let handler = match outbound_manager.get(&name) {
        Some(h) => h,
        None => return StatusCode::NOT_FOUND.into_response(),
    };

    let any = handler.as_any();
    let proxy_names = if let Some(selector) = any.downcast_ref::<SelectorGroup>() {
        selector.proxy_names().to_vec()
    } else if let Some(urltest) = any.downcast_ref::<UrlTestGroup>() {
        urltest.proxy_names().to_vec()
    } else if let Some(fallback) = any.downcast_ref::<FallbackGroup>() {
        fallback.proxy_names().to_vec()
    } else if let Some(lb) = any.downcast_ref::<LoadBalanceGroup>() {
        lb.proxy_names().to_vec()
    } else {
        return StatusCode::BAD_REQUEST.into_response();
    };

    // 对组内所有代理触发延迟测试
    let url = "http://www.gstatic.com/generate_204".to_string();
    let timeout = 5000u64;
    let mut results = HashMap::new();
    for pname in &proxy_names {
        if let Some(delay) = outbound_manager.test_delay(pname, &url, timeout).await {
            results.insert(pname.clone(), delay);
        }
    }

    info!(
        provider = name.as_str(),
        tested = results.len(),
        "proxy provider refreshed via API"
    );
    (StatusCode::OK, Json(serde_json::json!({"tested": results}))).into_response()
}

/// GET /providers/rules/:name
pub async fn get_rule_provider(
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> impl IntoResponse {
    let router = state.dispatcher.router().await;
    let providers = router.providers();
    match providers.get(&name) {
        Some(data) => {
            let snapshot = data.snapshot();
            let rule_count = snapshot.domain_rules.len() + snapshot.ip_cidrs.len();
            let info = RuleProviderInfo {
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
            };
            (StatusCode::OK, Json(serde_json::json!(info))).into_response()
        }
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

/// PUT /providers/rules/:name
pub async fn refresh_rule_provider(
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> impl IntoResponse {
    let router = state.dispatcher.router().await;
    let provider = match router.providers().get(&name) {
        Some(p) => p.clone(),
        None => return StatusCode::NOT_FOUND.into_response(),
    };

    let provider_for_refresh = provider.clone();
    let refresh_result =
        tokio::task::spawn_blocking(move || provider_for_refresh.refresh_http_provider()).await;

    match refresh_result {
        Ok(Ok(changed)) => {
            if changed {
                let current_router = state.dispatcher.router().await;
                state.dispatcher.update_router(current_router).await;
                info!(
                    provider = name.as_str(),
                    "rule provider refreshed and router updated via API"
                );
            }
            StatusCode::NO_CONTENT.into_response()
        }
        Ok(Err(e)) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"message": format!("refresh failed: {}", e)})),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({"message": format!("task join error: {}", e)})),
        )
            .into_response(),
    }
}

/// GET /configs
pub async fn get_configs(State(state): State<AppState>) -> Json<ConfigsResponse> {
    let outbound_manager = state.dispatcher.outbound_manager().await;
    let router = state.dispatcher.router().await;

    let outbound_count = outbound_manager.list().len();
    let rule_count = router.rules().len();
    let provider_count = router.providers().len();

    Json(ConfigsResponse {
        port: 0,
        socks_port: 0,
        mixed_port: 0,
        mode: crate::app::clash_mode::get_mode().as_str().to_string(),
        log_level: "info".to_string(),
        allow_lan: false,
        outbound_count,
        rule_count,
        provider_count,
    })
}

/// GET /traffic/sse — SSE 版流量推送
pub async fn traffic_sse(
    State(state): State<AppState>,
) -> axum::response::sse::Sse<
    impl futures_util::Stream<Item = Result<axum::response::sse::Event, std::convert::Infallible>>,
> {
    let tracker = state.dispatcher.tracker().clone();

    let stream = futures_util::stream::unfold(
        (tracker, 0u64, 0u64, true),
        |(tracker, mut last_up, mut last_down, first)| async move {
            if first {
                let snap = tracker.snapshot_async().await;
                last_up = snap.total_up;
                last_down = snap.total_down;
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
            let snap = tracker.snapshot_async().await;
            let item = TrafficItem {
                up: snap.total_up.saturating_sub(last_up),
                down: snap.total_down.saturating_sub(last_down),
                memory: current_memory_usage(),
                conn_active: snap.active_count,
            };
            last_up = snap.total_up;
            last_down = snap.total_down;
            let json = serde_json::to_string(&item).unwrap_or_default();
            let event = axum::response::sse::Event::default().data(json);
            Some((Ok(event), (tracker, last_up, last_down, false)))
        },
    );

    axum::response::sse::Sse::new(stream).keep_alive(axum::response::sse::KeepAlive::default())
}

/// GET /connections/sse — SSE 版连接列表推送
pub async fn connections_sse(
    State(state): State<AppState>,
) -> axum::response::sse::Sse<
    impl futures_util::Stream<Item = Result<axum::response::sse::Event, std::convert::Infallible>>,
> {
    let tracker = state.dispatcher.tracker().clone();

    let stream = futures_util::stream::unfold(tracker, |tracker| async move {
        tokio::time::sleep(Duration::from_secs(1)).await;
        let connections = tracker.list().await;
        let snapshot = tracker.snapshot_async().await;

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

        let resp = serde_json::json!({
            "downloadTotal": snapshot.total_down,
            "uploadTotal": snapshot.total_up,
            "connections": items,
        });

        let json = serde_json::to_string(&resp).unwrap_or_default();
        let event = axum::response::sse::Event::default().data(json);
        Some((Ok(event), tracker))
    });

    axum::response::sse::Sse::new(stream).keep_alive(axum::response::sse::KeepAlive::default())
}

// ==================== SSM API ====================

/// SSM 添加用户请求体
#[derive(serde::Deserialize)]
pub struct SsmAddUserRequest {
    pub name: String,
    pub password: String,
}

/// GET /ssm/users — 列出所有 SS 用户
pub async fn ssm_list_users(State(state): State<AppState>) -> impl IntoResponse {
    match &state.ss_inbound {
        Some(ss) => {
            let users = ss.list_users().await;
            (StatusCode::OK, Json(serde_json::json!({ "users": users }))).into_response()
        }
        None => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({
                "error": "SS 入站未启用"
            })),
        )
            .into_response(),
    }
}

/// POST /ssm/users — 添加 SS 用户
pub async fn ssm_add_user(
    State(state): State<AppState>,
    Json(body): Json<SsmAddUserRequest>,
) -> impl IntoResponse {
    match &state.ss_inbound {
        Some(ss) => match ss.add_user(body.name.clone(), &body.password).await {
            Ok(()) => (
                StatusCode::CREATED,
                Json(serde_json::json!({
                    "message": format!("用户 '{}' 已添加", body.name)
                })),
            )
                .into_response(),
            Err(e) => (
                StatusCode::CONFLICT,
                Json(serde_json::json!({
                    "error": e.to_string()
                })),
            )
                .into_response(),
        },
        None => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({
                "error": "SS 入站未启用"
            })),
        )
            .into_response(),
    }
}

/// DELETE /ssm/users/{name} — 删除 SS 用户
pub async fn ssm_remove_user(
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> impl IntoResponse {
    match &state.ss_inbound {
        Some(ss) => {
            if ss.remove_user(&name).await {
                (
                    StatusCode::OK,
                    Json(serde_json::json!({
                        "message": format!("用户 '{}' 已删除", name)
                    })),
                )
                    .into_response()
            } else {
                (
                    StatusCode::NOT_FOUND,
                    Json(serde_json::json!({
                        "error": format!("用户 '{}' 不存在", name)
                    })),
                )
                    .into_response()
            }
        }
        None => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({
                "error": "SS 入站未启用"
            })),
        )
            .into_response(),
    }
}

/// POST /ssm/users/{name}/reset — 重置用户流量
pub async fn ssm_reset_traffic(
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> impl IntoResponse {
    match &state.ss_inbound {
        Some(ss) => {
            if ss.reset_user_traffic(&name).await {
                (
                    StatusCode::OK,
                    Json(serde_json::json!({
                        "message": format!("用户 '{}' 流量已重置", name)
                    })),
                )
                    .into_response()
            } else {
                (
                    StatusCode::NOT_FOUND,
                    Json(serde_json::json!({
                        "error": format!("用户 '{}' 不存在", name)
                    })),
                )
                    .into_response()
            }
        }
        None => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({
                "error": "SS 入站未启用"
            })),
        )
            .into_response(),
    }
}

/// GET /ssm/stats — SS 服务器统计
pub async fn ssm_stats(State(state): State<AppState>) -> impl IntoResponse {
    match &state.ss_inbound {
        Some(ss) => {
            let users = ss.list_users().await;
            let total_up: u64 = users.iter().map(|u| u.traffic_up).sum();
            let total_down: u64 = users.iter().map(|u| u.traffic_down).sum();
            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "user_count": users.len(),
                    "total_upload": total_up,
                    "total_download": total_down,
                    "method": format!("{:?}", ss.cipher_kind()),
                })),
            )
                .into_response()
        }
        None => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({
                "error": "SS 入站未启用"
            })),
        )
            .into_response(),
    }
}
