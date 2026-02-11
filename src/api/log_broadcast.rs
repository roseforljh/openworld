use serde::Serialize;
use tokio::sync::broadcast;
use tracing::field::{Field, Visit};
use tracing::Subscriber;
use tracing_subscriber::layer::Context;
use tracing_subscriber::Layer;

/// 日志条目
#[derive(Clone, Serialize, Debug)]
pub struct LogEntry {
    #[serde(rename = "type")]
    pub level: String,
    pub payload: String,
}

/// 日志广播器
#[derive(Clone)]
pub struct LogBroadcaster {
    tx: broadcast::Sender<LogEntry>,
}

impl LogBroadcaster {
    pub fn new(capacity: usize) -> Self {
        let (tx, _) = broadcast::channel(capacity);
        Self { tx }
    }

    pub fn subscribe(&self) -> broadcast::Receiver<LogEntry> {
        self.tx.subscribe()
    }
}

/// 自定义 tracing Layer，将日志事件发送到 broadcast channel
pub struct LogLayer {
    broadcaster: LogBroadcaster,
}

impl LogLayer {
    pub fn new(broadcaster: LogBroadcaster) -> Self {
        Self { broadcaster }
    }
}

/// 用于提取 tracing 事件的 message 字段
struct MessageVisitor {
    message: String,
    fields: Vec<(String, String)>,
}

impl MessageVisitor {
    fn new() -> Self {
        Self {
            message: String::new(),
            fields: Vec::new(),
        }
    }

    fn format_output(&self) -> String {
        let mut output = self.message.clone();
        for (k, v) in &self.fields {
            output.push_str(&format!(" {}={}", k, v));
        }
        output
    }
}

impl Visit for MessageVisitor {
    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            self.message = format!("{:?}", value);
        } else {
            self.fields
                .push((field.name().to_string(), format!("{:?}", value)));
        }
    }

    fn record_str(&mut self, field: &Field, value: &str) {
        if field.name() == "message" {
            self.message = value.to_string();
        } else {
            self.fields
                .push((field.name().to_string(), value.to_string()));
        }
    }
}

impl<S> Layer<S> for LogLayer
where
    S: Subscriber,
{
    fn on_event(&self, event: &tracing::Event<'_>, _ctx: Context<'_, S>) {
        let level = match *event.metadata().level() {
            tracing::Level::ERROR => "error",
            tracing::Level::WARN => "warning",
            tracing::Level::INFO => "info",
            tracing::Level::DEBUG => "debug",
            tracing::Level::TRACE => "debug",
        };

        let mut visitor = MessageVisitor::new();
        event.record(&mut visitor);

        let entry = LogEntry {
            level: level.to_string(),
            payload: visitor.format_output(),
        };

        // 发送失败（没有订阅者）是正常的，忽略
        let _ = self.broadcaster.tx.send(entry);
    }
}
