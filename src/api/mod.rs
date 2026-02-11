pub mod handlers;
pub mod log_broadcast;
pub mod models;

use std::sync::Arc;

use anyhow::Result;
use axum::extract::Request;
use axum::http::{header, StatusCode};
use axum::middleware::{self, Next};
use axum::response::Response;
use axum::routing::{delete, get, patch};
use tokio::task::JoinHandle;
use tower_http::cors::CorsLayer;
use tracing::info;

use crate::app::dispatcher::Dispatcher;
use crate::config::types::ApiConfig;

use handlers::AppState;

/// 启动 API 服务器
pub fn start(
    config: &ApiConfig,
    dispatcher: Arc<Dispatcher>,
    config_path: Option<String>,
    log_broadcaster: log_broadcast::LogBroadcaster,
) -> Result<JoinHandle<()>> {
    let state = AppState {
        dispatcher,
        secret: config.secret.clone(),
        config_path,
        log_broadcaster,
    };

    let mut app = axum::Router::new()
        .route("/version", get(handlers::get_version))
        .route("/proxies", get(handlers::get_proxies))
        .route("/proxies/{name}", get(handlers::get_proxy).put(handlers::select_proxy))
        .route("/proxies/{name}/delay", get(handlers::test_proxy_delay))
        .route(
            "/connections",
            get(handlers::get_connections).delete(handlers::close_all_connections),
        )
        .route(
            "/connections/{id}",
            delete(handlers::close_connection),
        )
        .route("/traffic", get(handlers::traffic_ws))
        .route("/rules", get(handlers::get_rules))
        .route("/logs", get(handlers::logs_ws))
        .route("/configs", patch(handlers::reload_config))
        .layer(CorsLayer::permissive());

    // 如果配置了 secret，添加认证中间件
    if let Some(secret) = config.secret.clone() {
        app = app.layer(middleware::from_fn(move |req, next| {
            auth_middleware(req, next, secret.clone())
        }));
    }

    let app = app.with_state(state);

    let bind_addr = format!("{}:{}", config.listen, config.port);
    info!(addr = bind_addr, "API server starting");

    let handle = tokio::spawn(async move {
        let listener = match tokio::net::TcpListener::bind(&bind_addr).await {
            Ok(l) => l,
            Err(e) => {
                tracing::error!(addr = bind_addr, error = %e, "API server bind failed");
                return;
            }
        };
        info!(addr = bind_addr, "API server listening");
        if let Err(e) = axum::serve(listener, app).await {
            tracing::error!(error = %e, "API server error");
        }
    });

    Ok(handle)
}

/// Bearer token 认证中间件
async fn auth_middleware(req: Request, next: Next, secret: String) -> Result<Response, StatusCode> {
    // WebSocket 升级请求跳过 header 认证（通过查询参数认证）
    if req.headers().contains_key(header::UPGRADE) {
        return Ok(next.run(req).await);
    }

    // /version 端点不需要认证
    if req.uri().path() == "/version" {
        return Ok(next.run(req).await);
    }

    if let Some(auth) = req.headers().get(header::AUTHORIZATION) {
        if let Ok(auth_str) = auth.to_str() {
            if let Some(token) = auth_str.strip_prefix("Bearer ") {
                if token == secret {
                    return Ok(next.run(req).await);
                }
            }
        }
    }

    Err(StatusCode::UNAUTHORIZED)
}
