use anyhow::Result;
use tracing::info;
use tracing_subscriber::prelude::*;

#[tokio::main]
async fn main() -> Result<()> {
    // 创建日志广播器
    let log_broadcaster = openworld::api::log_broadcast::LogBroadcaster::new(256);

    // 构建 tracing subscriber: fmt layer + log broadcast layer
    let fmt_layer = tracing_subscriber::fmt::layer().with_filter(
        tracing_subscriber::EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
    );

    let log_layer = openworld::api::log_broadcast::LogLayer::new(log_broadcaster.clone());

    tracing_subscriber::registry()
        .with(fmt_layer)
        .with(log_layer)
        .init();

    info!("OpenWorld starting...");

    let config_path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "config.yaml".to_string());

    let config = openworld::config::load_config(&config_path)?;
    info!("config loaded");

    let app = openworld::app::App::new(config, Some(config_path), Some(log_broadcaster)).await?;
    app.run().await?;

    Ok(())
}
