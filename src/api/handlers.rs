use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::ws::{Message, WebSocket};
use axum::extract::{Path, Query, State, WebSocketUpgrade};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::Json;
use tokio::time::interval;
use tracing::debug;

use crate::app::outbound_manager::OutboundManager;
use crate::app::tracker::ConnectionTracker;
use crate::router::Router;

use super::models::*;

/// 共享应用状态
#[derive(Clone)]
pub struct AppState {
    pub router: Arc<Router>,
    pub outbound_manager: Arc<OutboundManager>,
    pub tracker: Arc<ConnectionTracker>,
    pub secret: Option<String>,
}

/// GET /version
pub async fn get_version() -> Json<VersionResponse> {
    Json(VersionResponse {
        version: env!("CARGO_PKG_VERSION").to_string(),
        premium: false,
    })
}

/// GET /proxies
pub async fn get_proxies(State(state): State<AppState>) -> Json<ProxiesResponse> {
    let handlers = state.outbound_manager.list();
    let mut proxies = HashMap::new();
    for (tag, _handler) in handlers {
        proxies.insert(
            tag.clone(),
            ProxyInfo {
                name: tag.clone(),
                proxy_type: "Unknown".to_string(),
                udp: false,
                history: vec![],
            },
        );
    }
    Json(ProxiesResponse { proxies })
}

/// GET /proxies/:name
pub async fn get_proxy(
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> impl IntoResponse {
    match state.outbound_manager.get(&name) {
        Some(_handler) => {
            let info = ProxyInfo {
                name: name.clone(),
                proxy_type: "Unknown".to_string(),
                udp: false,
                history: vec![],
            };
            (StatusCode::OK, Json(serde_json::to_value(info).unwrap())).into_response()
        }
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

/// GET /connections
pub async fn get_connections(State(state): State<AppState>) -> Json<ConnectionsResponse> {
    let connections = state.tracker.list().await;
    let snapshot = state.tracker.snapshot();

    let items: Vec<ConnectionItem> = connections
        .into_iter()
        .map(|c| {
            let elapsed = c.start_time.elapsed();
            let start = chrono_like_start(elapsed);

            ConnectionItem {
                id: c.id.to_string(),
                metadata: ConnectionMetadata {
                    network: "tcp".to_string(),
                    conn_type: c.inbound_tag.clone(),
                    source_ip: String::new(),
                    source_port: String::new(),
                    destination_ip: String::new(),
                    destination_port: String::new(),
                    host: c.target.clone(),
                    dns_mode: String::new(),
                },
                upload: c.upload,
                download: c.download,
                start,
                chains: vec![c.outbound_tag.clone()],
                rule: String::new(),
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
    let closed = state.tracker.close_all().await;
    debug!(count = closed, "closed all connections via API");
    StatusCode::NO_CONTENT
}

/// DELETE /connections/:id
pub async fn close_connection(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> StatusCode {
    if let Ok(id) = id.parse::<u64>() {
        if state.tracker.close(id).await {
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
    // WebSocket 认证（通过查询参数）
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
    let mut last_up = state.tracker.snapshot().total_up;
    let mut last_down = state.tracker.snapshot().total_down;

    loop {
        ticker.tick().await;
        let snap = state.tracker.snapshot();
        let item = TrafficItem {
            up: snap.total_up.saturating_sub(last_up),
            down: snap.total_down.saturating_sub(last_down),
        };
        last_up = snap.total_up;
        last_down = snap.total_down;

        let json = serde_json::to_string(&item).unwrap();
        if socket.send(Message::Text(json.into())).await.is_err() {
            break;
        }
    }
}

/// GET /rules
pub async fn get_rules(State(state): State<AppState>) -> Json<RulesResponse> {
    let rules: Vec<RuleItem> = state
        .router
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

/// GET /logs (WebSocket) - 占位
pub async fn logs_ws(ws: WebSocketUpgrade) -> impl IntoResponse {
    ws.on_upgrade(|mut socket: WebSocket| async move {
        // 占位：暂不实现日志推送
        let _ = socket
            .send(Message::Text(
                r#"{"type":"info","payload":"log streaming not yet implemented"}"#.into(),
            ))
            .await;
    })
}

/// 从 Rule 提取类型名
fn rule_type_name(rule: &crate::router::rules::Rule) -> String {
    use crate::router::rules::Rule;
    match rule {
        Rule::DomainSuffix(_) => "DomainSuffix".to_string(),
        Rule::DomainKeyword(_) => "DomainKeyword".to_string(),
        Rule::DomainFull(_) => "Domain".to_string(),
        Rule::IpCidr(_) => "IPCIDR".to_string(),
        Rule::GeoIp(_) => "GeoIP".to_string(),
        Rule::GeoSite(_) => "GeoSite".to_string(),
    }
}

/// 简易时间格式化：从 elapsed 推算出 ISO 风格的起始时间字符串
fn chrono_like_start(elapsed: Duration) -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let start_secs = now.as_secs().saturating_sub(elapsed.as_secs());
    // 简化：返回 Unix 时间戳
    format!("{}s", start_secs)
}
