use std::collections::HashMap;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Result;
use tokio::io::AsyncReadExt;
use tracing::{debug, error, info, Instrument};

use crate::common::{Address, BoxUdpTransport, PrefixedStream};
use crate::dns::DnsResolver;
use crate::proxy::{relay::relay, sniff, InboundResult, Network, Session};
use crate::proxy::outbound::direct::DirectOutbound;
use crate::router::Router;

use super::outbound_manager::OutboundManager;
use super::resilience::{self, CircuitBreaker, CircuitBreakerConfig, RetryPolicy};
use super::tracker::ConnectionTracker;

/// NAT 表条目超时时间
const NAT_ENTRY_TTL_SECS: i64 = 120;
/// NAT 表清理检查间隔
const NAT_CLEANUP_INTERVAL_SECS: u64 = 30;

/// 获取当前 epoch 毫秒
fn now_millis() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}

/// NAT 表条目，包含传输和活跃时间
#[derive(Clone)]
struct NatEntry {
    transport: Arc<BoxUdpTransport>,
    last_active: Arc<AtomicI64>,
}

impl NatEntry {
    fn new(transport: Arc<BoxUdpTransport>) -> Self {
        Self {
            transport,
            last_active: Arc::new(AtomicI64::new(now_millis())),
        }
    }

    fn touch(&self) {
        self.last_active.store(now_millis(), Ordering::Relaxed);
    }

    fn is_expired(&self) -> bool {
        let elapsed_ms = now_millis() - self.last_active.load(Ordering::Relaxed);
        elapsed_ms > NAT_ENTRY_TTL_SECS * 1000
    }
}

pub struct Dispatcher {
    router: tokio::sync::RwLock<Arc<Router>>,
    outbound_manager: tokio::sync::RwLock<Arc<OutboundManager>>,
    tracker: Arc<ConnectionTracker>,
    resolver: Arc<dyn DnsResolver>,
    retry_policy: RetryPolicy,
    circuit_breakers: tokio::sync::RwLock<HashMap<String, Arc<CircuitBreaker>>>,
}

impl Dispatcher {
    pub fn new(
        router: Arc<Router>,
        outbound_manager: Arc<OutboundManager>,
        tracker: Arc<ConnectionTracker>,
        resolver: Arc<dyn DnsResolver>,
    ) -> Self {
        Self {
            router: tokio::sync::RwLock::new(router),
            outbound_manager: tokio::sync::RwLock::new(outbound_manager),
            tracker,
            resolver,
            retry_policy: RetryPolicy::default(),
            circuit_breakers: tokio::sync::RwLock::new(HashMap::new()),
        }
    }

    async fn circuit_breaker_for(&self, tag: &str) -> Arc<CircuitBreaker> {
        if let Some(cb) = self.circuit_breakers.read().await.get(tag).cloned() {
            return cb;
        }
        let mut guard = self.circuit_breakers.write().await;
        guard
            .entry(tag.to_string())
            .or_insert_with(|| {
                Arc::new(CircuitBreaker::new(
                    tag.to_string(),
                    CircuitBreakerConfig::default(),
                ))
            })
            .clone()
    }

    /// 获取当前 Router 快照
    pub async fn router(&self) -> Arc<Router> {
        self.router.read().await.clone()
    }

    /// 获取当前 OutboundManager 快照
    pub async fn outbound_manager(&self) -> Arc<OutboundManager> {
        self.outbound_manager.read().await.clone()
    }

    /// 获取 ConnectionTracker
    pub fn tracker(&self) -> &Arc<ConnectionTracker> {
        &self.tracker
    }

    /// 热更新 Router
    pub async fn update_router(&self, new_router: Arc<Router>) {
        *self.router.write().await = new_router;
    }

    /// 热更新 OutboundManager
    pub async fn update_outbound_manager(&self, new_om: Arc<OutboundManager>) {
        *self.outbound_manager.write().await = new_om;
    }

    pub async fn dispatch(&self, result: InboundResult) -> Result<()> {
        let InboundResult {
            mut session,
            stream: mut inbound_stream,
            udp_transport,
        } = result;

        if session.network == Network::Udp {
            let inbound_udp = udp_transport
                .ok_or_else(|| anyhow::anyhow!("udp session missing inbound transport"))?;
            return self
                .dispatch_udp(session, inbound_stream, inbound_udp)
                .await;
        }

        // TCP 路径：可选协议嗅探
        if session.sniff {
            let mut peek_buf = vec![0u8; 4096];
            let n = inbound_stream.read(&mut peek_buf).await?;
            peek_buf.truncate(n);

            if let Some(host) = sniff::sniff(&peek_buf) {
                let port = session.target.port();
                let original = format!("{}", session.target);
                session.target = crate::common::Address::Domain(host.clone(), port);
                debug!(
                    original = original,
                    sniffed = host,
                    "protocol sniffing overrode destination"
                );
            }

            inbound_stream = Box::new(PrefixedStream::new(peek_buf, inbound_stream));
        }

        // 快照当前 router/outbound_manager（热重载安全）
        let router = self.router().await;
        let outbound_manager = self.outbound_manager().await;

        let (outbound_tag, matched_rule) = router.route_with_rule(&session);
        let route_tag = matched_rule.as_deref().unwrap_or("MATCH").to_string();

        let outbound = match outbound_manager.get(outbound_tag) {
            Some(o) => o,
            None => {
                self.tracker.record_error("OUTBOUND_NOT_FOUND");
                error!(error_code = "OUTBOUND_NOT_FOUND", outbound_tag = outbound_tag, "outbound not found");
                return Err(anyhow::anyhow!("outbound '{}' not found", outbound_tag));
            }
        };

        let guard = self
            .tracker
            .track(&session, outbound.tag(), &route_tag, matched_rule.as_deref())
            .await;
        let circuit_breaker = self.circuit_breaker_for(outbound.tag()).await;

        info!(
            conn_id = guard.id(),
            dest = %session.target,
            inbound = session.inbound_tag,
            outbound = outbound.tag(),
            route_tag = %route_tag,
            "dispatching TCP"
        );

        // Create tracing context for this connection
        let tracing_ctx = TracingContext::new(
            guard.id(),
            &session,
            outbound.tag(),
            matched_rule.as_deref(),
        );
        let span = tracing_ctx.span();

        // Instrument the connect + relay with the connection span
        let result = async {
            let connect_session = if matches!(session.target, Address::Domain(_, _))
                && outbound.as_any().is::<DirectOutbound>()
            {
                let resolved = session.target.resolve_with(Some(self.resolver.as_ref())).await?;
                let mut s = session.clone();
                s.target = Address::Ip(resolved);
                debug!(
                    conn_id = guard.id(),
                    original = %session.target,
                    resolved = %s.target,
                    "resolved domain target with configured DNS"
                );
                s
            } else {
                session.clone()
            };

            if !circuit_breaker.allow_request() {
                self.tracker.record_error("OUTBOUND_CIRCUIT_OPEN");
                error!(
                    conn_id = guard.id(),
                    error_code = "OUTBOUND_CIRCUIT_OPEN",
                    outbound_tag = outbound.tag(),
                    "circuit breaker open, request rejected"
                );
                return Err(anyhow::anyhow!(
                    "outbound '{}' circuit is open",
                    outbound.tag()
                ));
            }

            let connect_outbound = outbound.clone();
            let outbound_stream = match resilience::retry_with_backoff(&self.retry_policy, move |_| {
                let outbound = connect_outbound.clone();
                let session = connect_session.clone();
                async move { outbound.connect(&session).await }
            }).await {
                Ok(s) => s,
                Err(e) => {
                    circuit_breaker.record_failure();
                    self.tracker.record_error("OUTBOUND_CONNECT_FAILED");
                    error!(conn_id = guard.id(), error_code = "OUTBOUND_CONNECT_FAILED", outbound_tag = outbound.tag(), error = %e, "outbound connect failed");
                    return Err(e);
                }
            };

            circuit_breaker.record_success();

            let (up, down) = match relay(inbound_stream, outbound_stream).await {
                Ok(v) => v,
                Err(e) => {
                    self.tracker.record_error("RELAY_FAILED");
                    error!(conn_id = guard.id(), error_code = "RELAY_FAILED", outbound_tag = outbound.tag(), error = %e, "relay failed");
                    return Err(e);
                }
            };

            self.tracker
                .record_latency_ms(tracing_ctx.elapsed_ms());
            guard.add_upload(up);
            guard.add_download(down);

            Ok(())
        }
        .instrument(span)
        .await;

        // tracing_ctx is dropped here, logging connection close + duration
        drop(tracing_ctx);

        result
    }

    async fn dispatch_udp(
        &self,
        session: Session,
        mut tcp_control: crate::common::ProxyStream,
        inbound_udp: BoxUdpTransport,
    ) -> Result<()> {
        info!(inbound = session.inbound_tag, "dispatching UDP session");

        let inbound_udp = Arc::new(inbound_udp);
        // NAT 表: outbound_tag -> NatEntry (transport + last_active)
        let nat_table: Arc<tokio::sync::Mutex<HashMap<String, NatEntry>>> =
            Arc::new(tokio::sync::Mutex::new(HashMap::new()));

        // 用于通知所有任务退出
        let (shutdown_tx, _) = tokio::sync::broadcast::channel::<()>(1);

        // 入站 -> 出站 转发任务
        let inbound_udp_recv = inbound_udp.clone();
        let router = self.router().await;
        let outbound_manager = self.outbound_manager().await;
        let nat_table_clone = nat_table.clone();
        let inbound_udp_send = inbound_udp.clone();
        let session_clone = session.clone();
        let tracker = self.tracker.clone();
        let mut shutdown_rx = shutdown_tx.subscribe();
        let shutdown_tx_forward = shutdown_tx.clone();

        // NAT 表过期清理任务
        let nat_table_cleanup = nat_table.clone();
        let mut cleanup_shutdown_rx = shutdown_tx.subscribe();
        tokio::spawn(async move {
            let mut interval =
                tokio::time::interval(Duration::from_secs(NAT_CLEANUP_INTERVAL_SECS));
            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        let mut table = nat_table_cleanup.lock().await;
                        let before = table.len();
                        table.retain(|tag, entry| {
                            let expired = entry.is_expired();
                            if expired {
                                debug!(tag = tag, "UDP NAT entry expired, removing");
                            }
                            !expired
                        });
                        let removed = before - table.len();
                        if removed > 0 {
                            debug!(removed = removed, remaining = table.len(), "UDP NAT cleanup done");
                        }
                    }
                    _ = cleanup_shutdown_rx.recv() => {
                        break;
                    }
                }
            }
        });

        let forward_task = tokio::spawn(async move {
            loop {
                tokio::select! {
                    result = inbound_udp_recv.recv() => {
                        let packet = match result {
                            Ok(p) => p,
                            Err(e) => {
                                tracker.record_error("UDP_INBOUND_RECV_FAILED");
                                debug!(error_code = "UDP_INBOUND_RECV_FAILED", error = %e, "UDP inbound recv error");
                                break;
                            }
                        };

                        // 路由匹配
                        let temp_session = Session {
                            target: packet.addr.clone(),
                            source: session_clone.source,
                            inbound_tag: session_clone.inbound_tag.clone(),
                            network: Network::Udp,
                            sniff: false,
                        };
                        let (outbound_tag_ref, matched_rule) = router.route_with_rule(&temp_session);
                        let outbound_tag = outbound_tag_ref.to_string();
                        let route_tag = matched_rule
                            .as_deref()
                            .unwrap_or("MATCH")
                            .to_string();
                        tracker.record_route_hit(&route_tag);

                        // 查找或创建出站 UDP transport（避免在持锁时 await）
                        let existing = {
                            let table = nat_table_clone.lock().await;
                            table.get(&outbound_tag).cloned()
                        };

                        let (outbound_udp, nat_entry) = if let Some(entry) = existing {
                            (entry.transport.clone(), entry)
                        } else {
                            let outbound = match outbound_manager.get(&outbound_tag) {
                                Some(o) => o,
                                None => {
                                    tracker.record_error("UDP_OUTBOUND_NOT_FOUND");
                                    error!(error_code = "UDP_OUTBOUND_NOT_FOUND", tag = outbound_tag, route_tag = route_tag, "outbound not found for UDP");
                                    continue;
                                }
                            };

                            let transport = match outbound.connect_udp(&temp_session).await {
                                Ok(t) => Arc::new(t),
                                Err(e) => {
                                    tracker.record_error("UDP_OUTBOUND_CONNECT_FAILED");
                                    error!(error_code = "UDP_OUTBOUND_CONNECT_FAILED", tag = outbound_tag, route_tag = route_tag, error = %e, "UDP outbound connect failed");
                                    continue;
                                }
                            };
                            let new_entry = NatEntry::new(transport.clone());

                            let (selected_transport, selected_entry, should_spawn_reverse) = {
                                let mut table = nat_table_clone.lock().await;
                                if let Some(entry) = table.get(&outbound_tag) {
                                    (entry.transport.clone(), entry.clone(), false)
                                } else {
                                    table.insert(outbound_tag.clone(), new_entry.clone());
                                    (transport.clone(), new_entry.clone(), true)
                                }
                            };

                            if should_spawn_reverse {
                                // 启动反向转发任务: outbound -> inbound
                                let outbound_udp_recv = selected_transport.clone();
                                let inbound_udp_reply = inbound_udp_send.clone();
                                let tag = outbound_tag.clone();
                                let reverse_entry = selected_entry.clone();
                                let reverse_tracker = tracker.clone();
                                let mut reverse_shutdown_rx = shutdown_tx_forward.subscribe();
                                tokio::spawn(async move {
                                    loop {
                                        tokio::select! {
                                            result = outbound_udp_recv.recv() => {
                                                match result {
                                                    Ok(reply) => {
                                                        if let Err(e) = inbound_udp_reply.send(reply).await {
                                                            reverse_tracker.record_error("UDP_INBOUND_SEND_FAILED");
                                                            debug!(error_code = "UDP_INBOUND_SEND_FAILED", error = %e, tag = tag, "UDP reply send failed");
                                                            break;
                                                        }
                                                        reverse_entry.touch();
                                                    }
                                                    Err(e) => {
                                                        reverse_tracker.record_error("UDP_OUTBOUND_RECV_FAILED");
                                                        debug!(error_code = "UDP_OUTBOUND_RECV_FAILED", error = %e, tag = tag, "UDP outbound recv error");
                                                        break;
                                                    }
                                                }
                                            }
                                            _ = reverse_shutdown_rx.recv() => {
                                                break;
                                            }
                                        }
                                    }
                                });
                            }

                            (selected_transport, selected_entry)
                        };

                        debug!(
                            dest = %packet.addr,
                            outbound = outbound_tag,
                            route_tag = route_tag,
                            len = packet.data.len(),
                            "UDP packet forwarding"
                        );

                        if let Err(e) = outbound_udp.send(packet).await {
                            tracker.record_error("UDP_OUTBOUND_SEND_FAILED");
                            debug!(error_code = "UDP_OUTBOUND_SEND_FAILED", error = %e, outbound = outbound_tag, route_tag = route_tag, "UDP outbound send failed");
                        } else {
                            nat_entry.touch();
                        }
                    }
                    _ = shutdown_rx.recv() => {
                        break;
                    }
                }
            }
        });

        // 监控 TCP 控制连接关闭
        let mut buf = [0u8; 1];
        let _ = tcp_control.read(&mut buf).await;
        debug!("UDP: TCP control connection closed, cleaning up");

        // 通知所有任务退出
        let _ = shutdown_tx.send(());
        forward_task.abort();

        Ok(())
    }
}

/// Connection-level tracing context.
///
/// Creates a `tracing::Span` with connection metadata and logs
/// connection close + duration on drop.
pub struct TracingContext {
    pub conn_id: u64,
    pub target: String,
    pub inbound_tag: String,
    pub outbound_tag: String,
    pub matched_rule: Option<String>,
    pub start_time: Instant,
}

impl TracingContext {
    pub fn new(
        conn_id: u64,
        session: &Session,
        outbound_tag: &str,
        matched_rule: Option<&str>,
    ) -> Self {
        Self {
            conn_id,
            target: format!("{}", session.target),
            inbound_tag: session.inbound_tag.clone(),
            outbound_tag: outbound_tag.to_string(),
            matched_rule: matched_rule.map(|s| s.to_string()),
            start_time: Instant::now(),
        }
    }

    /// Create an `info_span!` carrying connection metadata.
    pub fn span(&self) -> tracing::Span {
        tracing::info_span!(
            "connection",
            conn_id = self.conn_id,
            target = %self.target,
            inbound = %self.inbound_tag,
            outbound = %self.outbound_tag,
            matched_rule = self.matched_rule.as_deref().unwrap_or("MATCH"),
        )
    }

    /// Elapsed milliseconds since context creation.
    pub fn elapsed_ms(&self) -> u64 {
        self.start_time.elapsed().as_millis() as u64
    }
}

impl Drop for TracingContext {
    fn drop(&mut self) {
        debug!(
            conn_id = self.conn_id,
            target = %self.target,
            outbound = %self.outbound_tag,
            duration_ms = self.elapsed_ms(),
            "connection closed"
        );
    }
}
