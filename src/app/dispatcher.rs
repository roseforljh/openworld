use std::collections::HashMap;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use anyhow::Result;
use tokio::io::AsyncReadExt;
use tracing::{debug, error, info};

use crate::common::{BoxUdpTransport, PrefixedStream};
use crate::proxy::{relay::relay, sniff, InboundResult, Network, Session};
use crate::router::Router;

use super::outbound_manager::OutboundManager;
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
    router: RwLock<Arc<Router>>,
    outbound_manager: RwLock<Arc<OutboundManager>>,
    tracker: Arc<ConnectionTracker>,
}

impl Dispatcher {
    pub fn new(
        router: Arc<Router>,
        outbound_manager: Arc<OutboundManager>,
        tracker: Arc<ConnectionTracker>,
    ) -> Self {
        Self {
            router: RwLock::new(router),
            outbound_manager: RwLock::new(outbound_manager),
            tracker,
        }
    }

    /// 获取当前 Router 快照
    pub fn router(&self) -> Arc<Router> {
        self.router.read().unwrap().clone()
    }

    /// 获取当前 OutboundManager 快照
    pub fn outbound_manager(&self) -> Arc<OutboundManager> {
        self.outbound_manager.read().unwrap().clone()
    }

    /// 获取 ConnectionTracker
    pub fn tracker(&self) -> &Arc<ConnectionTracker> {
        &self.tracker
    }

    /// 热更新 Router
    pub fn update_router(&self, new_router: Arc<Router>) {
        *self.router.write().unwrap() = new_router;
    }

    /// 热更新 OutboundManager
    pub fn update_outbound_manager(&self, new_om: Arc<OutboundManager>) {
        *self.outbound_manager.write().unwrap() = new_om;
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
        let router = self.router();
        let outbound_manager = self.outbound_manager();

        let outbound_tag = router.route(&session);

        let outbound = outbound_manager
            .get(outbound_tag)
            .ok_or_else(|| anyhow::anyhow!("outbound '{}' not found", outbound_tag))?;

        info!(
            dest = %session.target,
            inbound = session.inbound_tag,
            outbound = outbound.tag(),
            "dispatching TCP"
        );

        let guard = self.tracker.track(&session, outbound.tag()).await;
        let outbound_stream = outbound.connect(&session).await?;
        let (up, down) = relay(inbound_stream, outbound_stream).await?;
        guard.add_upload(up);
        guard.add_download(down);

        Ok(())
    }

    async fn dispatch_udp(
        &self,
        session: Session,
        mut tcp_control: crate::common::ProxyStream,
        inbound_udp: BoxUdpTransport,
    ) -> Result<()> {
        info!(
            inbound = session.inbound_tag,
            "dispatching UDP session"
        );

        let inbound_udp = Arc::new(inbound_udp);
        // NAT 表: outbound_tag -> NatEntry (transport + last_active)
        let nat_table: Arc<tokio::sync::Mutex<HashMap<String, NatEntry>>> =
            Arc::new(tokio::sync::Mutex::new(HashMap::new()));

        // 用于通知所有任务退出
        let (shutdown_tx, _) = tokio::sync::broadcast::channel::<()>(1);

        // 入站 -> 出站 转发任务
        let inbound_udp_recv = inbound_udp.clone();
        let router = self.router();
        let outbound_manager = self.outbound_manager();
        let nat_table_clone = nat_table.clone();
        let inbound_udp_send = inbound_udp.clone();
        let session_clone = session.clone();
        let mut shutdown_rx = shutdown_tx.subscribe();
        let shutdown_tx_forward = shutdown_tx.clone();

        // NAT 表过期清理任务
        let nat_table_cleanup = nat_table.clone();
        let mut cleanup_shutdown_rx = shutdown_tx.subscribe();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(NAT_CLEANUP_INTERVAL_SECS));
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
                                debug!(error = %e, "UDP inbound recv error");
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
                        let outbound_tag = router.route(&temp_session).to_string();

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
                                    error!(tag = outbound_tag, "outbound not found for UDP");
                                    continue;
                                }
                            };

                            let transport = match outbound.connect_udp(&temp_session).await {
                                Ok(t) => Arc::new(t),
                                Err(e) => {
                                    error!(tag = outbound_tag, error = %e, "UDP outbound connect failed");
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
                                let mut reverse_shutdown_rx = shutdown_tx_forward.subscribe();
                                tokio::spawn(async move {
                                    loop {
                                        tokio::select! {
                                            result = outbound_udp_recv.recv() => {
                                                match result {
                                                    Ok(reply) => {
                                                        if let Err(e) = inbound_udp_reply.send(reply).await {
                                                            debug!(error = %e, tag = tag, "UDP reply send failed");
                                                            break;
                                                        }
                                                        reverse_entry.touch();
                                                    }
                                                    Err(e) => {
                                                        debug!(error = %e, tag = tag, "UDP outbound recv error");
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
                            len = packet.data.len(),
                            "UDP packet forwarding"
                        );

                        if let Err(e) = outbound_udp.send(packet).await {
                            debug!(error = %e, outbound = outbound_tag, "UDP outbound send failed");
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
