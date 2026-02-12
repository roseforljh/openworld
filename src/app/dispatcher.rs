use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Result;
use tokio::io::AsyncReadExt;
use tracing::{debug, error, info, Instrument};

use tokio_util::sync::CancellationToken;

use crate::common::{Address, BoxUdpTransport, PrefixedStream, ProxyError};
use crate::dns::fakeip::FakeIpPool;
use crate::dns::DnsResolver;
use crate::proxy::nat::{NatKey, NatTable};
use crate::proxy::relay::{relay_proxy_streams, RelayOptions, RelayStats};
use crate::proxy::outbound::direct::DirectOutbound;
use crate::proxy::{sniff, InboundResult, Network, Session};
use crate::router::Router;

use super::outbound_manager::OutboundManager;
use super::resilience::{self, CircuitBreaker, CircuitBreakerConfig, RetryPolicy};
use super::tracker::ConnectionTracker;

pub struct Dispatcher {
    router: tokio::sync::RwLock<Arc<Router>>,
    outbound_manager: tokio::sync::RwLock<Arc<OutboundManager>>,
    tracker: Arc<ConnectionTracker>,
    resolver: Arc<dyn DnsResolver>,
    retry_policy: RetryPolicy,
    circuit_breakers: tokio::sync::RwLock<HashMap<String, Arc<CircuitBreaker>>>,
    /// Full Cone NAT table for UDP
    nat_table: Arc<NatTable>,
    /// FakeIP pool for reverse lookup
    fakeip_pool: Option<Arc<FakeIpPool>>,
    /// Cancellation token for graceful shutdown
    cancel_token: CancellationToken,
}

impl Dispatcher {
    pub fn new(
        router: Arc<Router>,
        outbound_manager: Arc<OutboundManager>,
        tracker: Arc<ConnectionTracker>,
        resolver: Arc<dyn DnsResolver>,
        fakeip_pool: Option<Arc<FakeIpPool>>,
        cancel_token: CancellationToken,
    ) -> Self {
        Self {
            router: tokio::sync::RwLock::new(router),
            outbound_manager: tokio::sync::RwLock::new(outbound_manager),
            tracker,
            resolver,
            retry_policy: RetryPolicy::default(),
            circuit_breakers: tokio::sync::RwLock::new(HashMap::new()),
            nat_table: Arc::new(NatTable::new()),
            fakeip_pool,
            cancel_token,
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

    /// 获取 NAT table (for API/stats)
    pub fn nat_table(&self) -> &Arc<NatTable> {
        &self.nat_table
    }

    /// 获取 DNS resolver
    pub fn resolver(&self) -> &Arc<dyn DnsResolver> {
        &self.resolver
    }

    /// Spawn periodic cleanup tasks for connection pools in outbound handlers.
    pub async fn spawn_pool_cleanup(&self, cancel_token: CancellationToken) {
        let outbound_manager = self.outbound_manager().await;
        for (tag, handler) in outbound_manager.list() {
            if let Some(direct) = handler.as_any().downcast_ref::<DirectOutbound>() {
                let pool = direct.pool().clone();
                let cancel = cancel_token.clone();
                let tag = tag.clone();
                tokio::spawn(async move {
                    let mut interval = tokio::time::interval(Duration::from_secs(30));
                    interval.tick().await;
                    loop {
                        tokio::select! {
                            _ = cancel.cancelled() => break,
                            _ = interval.tick() => {
                                let cleaned = pool.cleanup().await;
                                if cleaned > 0 {
                                    debug!(outbound = tag.as_str(), cleaned = cleaned, "connection pool cleanup");
                                }
                            }
                        }
                    }
                });
            }
        }
    }

    /// Spawn DNS prefetch background task to refresh popular domains before cache expiry.
    pub fn spawn_dns_prefetch(&self, cancel_token: CancellationToken) {
        let resolver = self.resolver.clone();
        
        // Check if resolver is a CachedResolver with prefetch support
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60));
            interval.tick().await;
            
            loop {
                tokio::select! {
                    _ = cancel_token.cancelled() => break,
                    _ = interval.tick() => {
                        // Try to get prefetch candidates and refresh them
                        // The CachedResolver has get_prefetch_candidates method
                        // We need to check if the resolver supports it
                        if let Some(cached) = resolver.as_any().downcast_ref::<crate::dns::cache::CachedResolver>() {
                            let candidates = cached.get_prefetch_candidates().await;
                            if !candidates.is_empty() {
                                debug!(count = candidates.len(), "DNS prefetch: refreshing popular domains");
                                for host in candidates {
                                    // Refresh in background, don't wait
                                    let resolver_clone = resolver.clone();
                                    tokio::spawn(async move {
                                        let _ = resolver_clone.resolve(&host).await;
                                    });
                                }
                            }
                        }
                    }
                }
            }
        });
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
                .ok_or_else(|| ProxyError::Protocol("udp session missing inbound transport".to_string()))?;
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

            session.detected_protocol = sniff::detect_protocol(&peek_buf).map(|s| s.to_string());

            inbound_stream = Box::new(PrefixedStream::new(peek_buf, inbound_stream));
        }

        // FakeIP 反查：将 FakeIP 地址还原为真实域名
        if let Some(ref pool) = self.fakeip_pool {
            if let Address::Ip(addr) = &session.target {
                if pool.is_fake_ip(addr.ip()) {
                    if let Some(domain) = pool.lookup(addr.ip()).await {
                        let port = addr.port();
                        debug!(
                            fakeip = %addr.ip(),
                            domain = domain,
                            "FakeIP reverse lookup restored domain"
                        );
                        session.target = Address::Domain(domain, port);
                    }
                }
            }
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
                return Err(ProxyError::Config(
                    format!("outbound '{}' not found", outbound_tag)
                ).into());
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

        // Real-time stats for this connection
        let relay_stats = RelayStats::new();
        let relay_stats_clone = relay_stats.clone();

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
                return Err(ProxyError::CircuitBreakerOpen(
                    format!("outbound '{}'", outbound.tag())
                ).into());
            }

            let connect_outbound = outbound.clone();
            eprintln!("dispatch: connecting outbound {} to {}", outbound.tag(), connect_session.target);
            let outbound_stream = match resilience::retry_with_backoff(&self.retry_policy, move |_| {
                let outbound = connect_outbound.clone();
                let session = connect_session.clone();
                async move { outbound.connect(&session).await }
            }).await {
                Ok(s) => {
                    eprintln!("dispatch: outbound connected");
                    s
                },
                Err(e) => {
                    let error_kind = ProxyError::classify(&e);
                    circuit_breaker.record_failure();
                    self.tracker.record_error(error_kind.as_str());
                    error!(conn_id = guard.id(), error_code = error_kind.as_str(), outbound_tag = outbound.tag(), error = %e, "outbound connect failed");
                    return Err(e);
                }
            };

            circuit_breaker.record_success();

            // Use enhanced relay with idle timeout, half-close, and real-time stats
            let opts = RelayOptions {
                idle_timeout: Duration::from_secs(300),
                stats: Some(relay_stats_clone),
                upload_limiter: None,
                download_limiter: None,
                cancel: Some(self.cancel_token.clone()),
            };

            eprintln!(
                "dispatch: inbound_is_tcp={} outbound_is_tcp={}",
                inbound_stream.as_any().is::<tokio::net::TcpStream>(),
                outbound_stream.as_any().is::<tokio::net::TcpStream>()
            );
            let (up, down) = match relay_proxy_streams(inbound_stream, outbound_stream, opts).await {
                Ok(v) => {
                    eprintln!("dispatch relay finished: up={}, down={}", v.0, v.1);
                    v
                },
                Err(e) => {
                    let error_kind = ProxyError::classify(&e);
                    self.tracker.record_error(error_kind.as_str());
                    error!(conn_id = guard.id(), error_code = error_kind.as_str(), outbound_tag = outbound.tag(), error = %e, "relay failed");
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
        // Structured access log
        let duration_ms = tracing_ctx.elapsed_ms();
        let upload = guard.upload.load(std::sync::atomic::Ordering::Relaxed);
        let download = guard.download.load(std::sync::atomic::Ordering::Relaxed);
        let status = if result.is_ok() { "OK" } else { "FAIL" };
        let source_str = session.source.map(|s| s.to_string()).unwrap_or_default();
        info!(
            conn_id = guard.id(),
            source = source_str.as_str(),
            target = tracing_ctx.target.as_str(),
            network = ?session.network,
            inbound = tracing_ctx.inbound_tag.as_str(),
            outbound = tracing_ctx.outbound_tag.as_str(),
            rule = tracing_ctx.matched_rule.as_deref().unwrap_or("MATCH"),
            upload = upload,
            download = download,
            duration_ms = duration_ms,
            status = status,
            "access"
        );
        drop(tracing_ctx);

        result
    }

    /// UDP dispatch with Full Cone NAT semantics.
    ///
    /// NAT key = (source_addr, dest_addr) — each unique flow gets its own entry.
    /// Any external host can send packets back through the mapped port.
    async fn dispatch_udp(
        &self,
        session: Session,
        mut tcp_control: crate::common::ProxyStream,
        inbound_udp: BoxUdpTransport,
    ) -> Result<()> {
        info!(inbound = session.inbound_tag, "dispatching UDP session (Full Cone NAT)");

        let inbound_udp = Arc::new(inbound_udp);
        let nat_table = self.nat_table.clone();

        // 用于通知所有任务退出
        let (shutdown_tx, _) = tokio::sync::broadcast::channel::<()>(1);

        // Spawn NAT cleanup task
        let cancel_token = tokio_util::sync::CancellationToken::new();
        let _cleanup_handle = nat_table.spawn_cleanup_task(cancel_token.clone());

        // 入站 → 出站 转发任务
        let inbound_udp_recv = inbound_udp.clone();
        let router = self.router().await;
        let outbound_manager = self.outbound_manager().await;
        let inbound_udp_send = inbound_udp.clone();
        let session_clone = session.clone();
        let tracker = self.tracker.clone();
        let mut shutdown_rx = shutdown_tx.subscribe();
        let shutdown_tx_forward = shutdown_tx.clone();

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

                        // Build session for routing
                        let temp_session = Session {
                            target: packet.addr.clone(),
                            source: session_clone.source,
                            inbound_tag: session_clone.inbound_tag.clone(),
                            network: Network::Udp,
                            sniff: false,
                            detected_protocol: None,
                        };
                        let (outbound_tag_ref, matched_rule) = router.route_with_rule(&temp_session);
                        let outbound_tag = outbound_tag_ref.to_string();
                        let route_tag = matched_rule
                            .as_deref()
                            .unwrap_or("MATCH")
                            .to_string();
                        tracker.record_route_hit(&route_tag);

                        // Full Cone NAT key: (source, dest)
                        let source_addr = session_clone.source.unwrap_or_else(|| {
                            SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 0)
                        });
                        let nat_key = NatKey {
                            source: source_addr,
                            dest: packet.addr.clone(),
                        };

                        // Look up or create NAT entry
                        let existing = nat_table.get(&nat_key).await;

                        let (entry, is_new) = if let Some(entry) = existing {
                            entry.touch();
                            (entry, false)
                        } else {
                            // Full Cone: check if same source already has a transport for this outbound
                            let existing_transport = nat_table
                                .get_transport_for_source(source_addr, &outbound_tag)
                                .await;

                            let transport = if let Some(t) = existing_transport {
                                debug!(
                                    source = %source_addr,
                                    outbound = outbound_tag,
                                    dest = %packet.addr,
                                    "Full Cone: reusing existing transport for new destination"
                                );
                                t
                            } else {
                                // Create new outbound transport
                                let outbound = match outbound_manager.get(&outbound_tag) {
                                    Some(o) => o,
                                    None => {
                                        tracker.record_error("UDP_OUTBOUND_NOT_FOUND");
                                        error!(error_code = "UDP_OUTBOUND_NOT_FOUND", tag = outbound_tag, "outbound not found for UDP");
                                        continue;
                                    }
                                };

                                match outbound.connect_udp(&temp_session).await {
                                    Ok(t) => Arc::new(t),
                                    Err(e) => {
                                        tracker.record_error("UDP_OUTBOUND_CONNECT_FAILED");
                                        error!(error_code = "UDP_OUTBOUND_CONNECT_FAILED", tag = outbound_tag, error = %e, "UDP outbound connect failed");
                                        continue;
                                    }
                                }
                            };

                            let (entry, is_new) = nat_table
                                .get_or_insert(nat_key.clone(), transport, outbound_tag.clone())
                                .await;
                            (entry, is_new)
                        };

                        // Spawn reverse relay for new entries (Full Cone: any remote can reply)
                        if is_new {
                            let outbound_udp_recv = entry.transport.clone();
                            let inbound_udp_reply = inbound_udp_send.clone();
                            let tag = outbound_tag.clone();
                            let reverse_entry_ref = entry.clone();
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
                                                    reverse_entry_ref.touch();
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

                        debug!(
                            dest = %packet.addr,
                            outbound = outbound_tag,
                            route_tag = route_tag,
                            len = packet.data.len(),
                            new_flow = is_new,
                            "UDP packet forwarding"
                        );

                        if let Err(e) = entry.transport.send(packet).await {
                            tracker.record_error("UDP_OUTBOUND_SEND_FAILED");
                            debug!(error_code = "UDP_OUTBOUND_SEND_FAILED", error = %e, outbound = outbound_tag, "UDP outbound send failed");
                        } else {
                            entry.touch();
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
        cancel_token.cancel();
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
