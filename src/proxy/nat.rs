//! Full Cone NAT table for UDP relay.
//!
//! Unlike the previous implementation that keyed NAT entries by outbound tag,
//! this module implements proper Full Cone NAT semantics:
//!
//! - NAT key = (source_addr, dest_addr) — each unique flow gets its own entry
//! - Any external host can send packets back through the mapped port (Full Cone)
//! - Entries expire after configurable idle timeout
//! - Periodic cleanup of expired entries

use std::collections::HashMap;
use std::fmt;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::Mutex;
use tracing::debug;

use crate::common::{Address, BoxUdpTransport};

/// Default NAT entry TTL: 120 seconds
const DEFAULT_NAT_TTL_SECS: i64 = 120;
/// Cleanup interval: 30 seconds
const CLEANUP_INTERVAL_SECS: u64 = 30;

/// NAT key: uniquely identifies a UDP flow.
/// Full Cone NAT uses (source, destination) as the key.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct NatKey {
    /// Client source address
    pub source: SocketAddr,
    /// Target destination address
    pub dest: Address,
}

impl fmt::Display for NatKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}→{}", self.source, self.dest)
    }
}

/// A single NAT table entry.
#[derive(Clone)]
pub struct NatEntry {
    /// The outbound UDP transport for this flow
    pub transport: Arc<BoxUdpTransport>,
    /// Outbound tag used for this flow
    pub outbound_tag: String,
    /// Last activity timestamp (epoch millis)
    last_active: Arc<AtomicI64>,
    /// TTL in milliseconds
    ttl_ms: i64,
}

impl NatEntry {
    pub fn new(transport: Arc<BoxUdpTransport>, outbound_tag: String, ttl_secs: i64) -> Self {
        Self {
            transport,
            outbound_tag,
            last_active: Arc::new(AtomicI64::new(now_millis())),
            ttl_ms: ttl_secs * 1000,
        }
    }

    /// Update the last-active timestamp.
    pub fn touch(&self) {
        self.last_active.store(now_millis(), Ordering::Relaxed);
    }

    /// Check if this entry has expired.
    pub fn is_expired(&self) -> bool {
        let elapsed = now_millis() - self.last_active.load(Ordering::Relaxed);
        elapsed > self.ttl_ms
    }
}

/// Full Cone NAT table.
pub struct NatTable {
    /// (source, dest) → NatEntry
    entries: Mutex<HashMap<NatKey, NatEntry>>,
    /// Reverse mapping: for Full Cone, we also need to route incoming packets
    /// from the remote back to the correct client.
    /// outbound_tag → Vec<(NatKey, source_addr)>
    reverse: Mutex<HashMap<String, Vec<(NatKey, SocketAddr)>>>,
    /// Full Cone source mapping: (source_addr, outbound_tag) → transport
    /// Ensures same source always maps to the same outbound port
    source_map: Mutex<HashMap<(SocketAddr, String), Arc<BoxUdpTransport>>>,
    /// Entry TTL in seconds
    ttl_secs: i64,
}

impl NatTable {
    pub fn new() -> Self {
        Self::with_ttl(DEFAULT_NAT_TTL_SECS)
    }

    pub fn with_ttl(ttl_secs: i64) -> Self {
        Self {
            entries: Mutex::new(HashMap::new()),
            reverse: Mutex::new(HashMap::new()),
            source_map: Mutex::new(HashMap::new()),
            ttl_secs,
        }
    }

    /// Look up an existing NAT entry for the given flow.
    pub async fn get(&self, key: &NatKey) -> Option<NatEntry> {
        let table = self.entries.lock().await;
        table.get(key).filter(|e| !e.is_expired()).cloned()
    }

    /// Insert a new NAT entry. Returns false if an entry already exists (race condition).
    pub async fn insert(&self, key: NatKey, entry: NatEntry) -> bool {
        let mut table = self.entries.lock().await;
        if table.contains_key(&key) {
            return false;
        }
        let outbound_tag = entry.outbound_tag.clone();
        let source = key.source;
        let transport = entry.transport.clone();
        table.insert(key.clone(), entry);

        // Update reverse mapping
        drop(table);
        let mut reverse = self.reverse.lock().await;
        reverse
            .entry(outbound_tag.clone())
            .or_default()
            .push((key, source));

        // Update Full Cone source mapping
        drop(reverse);
        let mut source_map = self.source_map.lock().await;
        source_map
            .entry((source, outbound_tag))
            .or_insert(transport);

        true
    }

    /// Full Cone lookup: get existing transport for the same source and outbound.
    /// This ensures the same client source always uses the same outbound port
    /// regardless of destination, which is the Full Cone NAT requirement.
    pub async fn get_transport_for_source(
        &self,
        source: SocketAddr,
        outbound_tag: &str,
    ) -> Option<Arc<BoxUdpTransport>> {
        let source_map = self.source_map.lock().await;
        source_map.get(&(source, outbound_tag.to_string())).cloned()
    }

    /// Get or create a NAT entry. Returns (entry, is_new).
    /// If `is_new` is true, the caller should spawn a reverse relay task.
    pub async fn get_or_insert(
        &self,
        key: NatKey,
        transport: Arc<BoxUdpTransport>,
        outbound_tag: String,
    ) -> (NatEntry, bool) {
        // Fast path: entry exists
        if let Some(entry) = self.get(&key).await {
            entry.touch();
            return (entry, false);
        }

        // Slow path: create new entry
        let entry = NatEntry::new(transport, outbound_tag, self.ttl_secs);
        let is_new = self.insert(key, entry.clone()).await;
        (entry, is_new)
    }

    /// Remove expired entries. Returns the number of entries removed.
    pub async fn cleanup(&self) -> usize {
        let mut table = self.entries.lock().await;
        let before = table.len();

        let expired_keys: Vec<NatKey> = table
            .iter()
            .filter(|(_, entry)| entry.is_expired())
            .map(|(key, _)| key.clone())
            .collect();

        let mut expired_sources: Vec<(SocketAddr, String)> = Vec::new();
        for key in &expired_keys {
            if let Some(entry) = table.remove(key) {
                expired_sources.push((key.source, entry.outbound_tag.clone()));
                debug!(
                    flow = %key,
                    outbound = entry.outbound_tag,
                    "NAT entry expired"
                );
            }
        }

        let removed = before - table.len();

        // Also clean up reverse mapping and source mapping
        if removed > 0 {
            drop(table);
            let mut reverse = self.reverse.lock().await;
            for (_, entries) in reverse.iter_mut() {
                entries.retain(|(k, _)| !expired_keys.contains(k));
            }
            reverse.retain(|_, v| !v.is_empty());

            // Clean source_map entries that have no remaining flows
            drop(reverse);
            let active_table = self.entries.lock().await;
            let mut source_map = self.source_map.lock().await;
            for (source, outbound_tag) in &expired_sources {
                let has_active = active_table.iter().any(|(k, e)| {
                    k.source == *source && e.outbound_tag == *outbound_tag
                });
                if !has_active {
                    source_map.remove(&(*source, outbound_tag.clone()));
                }
            }
        }

        removed
    }

    /// Get the number of active entries.
    pub async fn len(&self) -> usize {
        self.entries.lock().await.len()
    }

    /// Check if the table is empty.
    pub async fn is_empty(&self) -> bool {
        self.entries.lock().await.is_empty()
    }

    /// Spawn a background cleanup task that periodically removes expired entries.
    pub fn spawn_cleanup_task(
        self: &Arc<Self>,
        cancel: tokio_util::sync::CancellationToken,
    ) -> tokio::task::JoinHandle<()> {
        let table = self.clone();
        tokio::spawn(async move {
            let mut interval =
                tokio::time::interval(Duration::from_secs(CLEANUP_INTERVAL_SECS));
            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        let removed = table.cleanup().await;
                        if removed > 0 {
                            let remaining = table.len().await;
                            debug!(
                                removed = removed,
                                remaining = remaining,
                                "NAT table cleanup"
                            );
                        }
                    }
                    _ = cancel.cancelled() => {
                        break;
                    }
                }
            }
        })
    }
}

fn now_millis() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::common::udp::{UdpPacket, UdpTransport};
    use async_trait::async_trait;
    use std::net::{IpAddr, Ipv4Addr};

    struct DummyTransport;

    #[async_trait]
    impl UdpTransport for DummyTransport {
        async fn send(&self, _packet: UdpPacket) -> anyhow::Result<()> {
            Ok(())
        }
        async fn recv(&self) -> anyhow::Result<UdpPacket> {
            // Block forever
            futures_util::future::pending().await
        }
    }

    fn test_source() -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)), 12345)
    }

    fn test_dest() -> Address {
        Address::Ip(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            53,
        ))
    }

    fn test_key() -> NatKey {
        NatKey {
            source: test_source(),
            dest: test_dest(),
        }
    }

    #[tokio::test]
    async fn nat_table_insert_and_get() {
        let table = NatTable::new();
        let transport: Arc<BoxUdpTransport> = Arc::new(Box::new(DummyTransport));

        let key = test_key();
        let entry = NatEntry::new(transport, "direct".to_string(), 120);
        assert!(table.insert(key.clone(), entry).await);

        let found = table.get(&key).await;
        assert!(found.is_some());
        assert_eq!(found.unwrap().outbound_tag, "direct");
    }

    #[tokio::test]
    async fn nat_table_duplicate_insert_fails() {
        let table = NatTable::new();
        let transport: Arc<BoxUdpTransport> = Arc::new(Box::new(DummyTransport));

        let key = test_key();
        let entry1 = NatEntry::new(transport.clone(), "direct".to_string(), 120);
        let entry2 = NatEntry::new(transport, "proxy".to_string(), 120);

        assert!(table.insert(key.clone(), entry1).await);
        assert!(!table.insert(key, entry2).await); // should fail
    }

    #[tokio::test]
    async fn nat_table_expiry() {
        let table = NatTable::with_ttl(0); // immediate expiry
        let transport: Arc<BoxUdpTransport> = Arc::new(Box::new(DummyTransport));

        let key = test_key();
        let entry = NatEntry::new(transport, "direct".to_string(), 0);
        table.insert(key.clone(), entry).await;

        // Should be expired immediately
        tokio::time::sleep(Duration::from_millis(10)).await;
        assert!(table.get(&key).await.is_none());
    }

    #[tokio::test]
    async fn nat_table_cleanup() {
        let table = NatTable::with_ttl(0);
        let transport: Arc<BoxUdpTransport> = Arc::new(Box::new(DummyTransport));

        for i in 0..5 {
            let key = NatKey {
                source: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, i)), 1000 + i as u16),
                dest: test_dest(),
            };
            let entry = NatEntry::new(transport.clone(), "direct".to_string(), 0);
            table.insert(key, entry).await;
        }

        assert_eq!(table.len().await, 5);
        tokio::time::sleep(Duration::from_millis(10)).await;
        let removed = table.cleanup().await;
        assert_eq!(removed, 5);
        assert_eq!(table.len().await, 0);
    }

    #[tokio::test]
    async fn nat_table_touch_prevents_expiry() {
        let table = NatTable::with_ttl(1); // 1 second TTL
        let transport: Arc<BoxUdpTransport> = Arc::new(Box::new(DummyTransport));

        let key = test_key();
        let entry = NatEntry::new(transport, "direct".to_string(), 1);
        let entry_clone = entry.clone();
        table.insert(key.clone(), entry).await;

        // Touch before expiry
        tokio::time::sleep(Duration::from_millis(500)).await;
        entry_clone.touch();

        // Should still be alive
        tokio::time::sleep(Duration::from_millis(600)).await;
        assert!(table.get(&key).await.is_some());
    }

    #[tokio::test]
    async fn nat_table_get_or_insert() {
        let table = NatTable::new();
        let transport: Arc<BoxUdpTransport> = Arc::new(Box::new(DummyTransport));

        let key = test_key();

        let (entry, is_new) =
            table.get_or_insert(key.clone(), transport.clone(), "direct".to_string()).await;
        assert!(is_new);
        assert_eq!(entry.outbound_tag, "direct");

        let (entry2, is_new2) =
            table.get_or_insert(key, transport, "direct".to_string()).await;
        assert!(!is_new2);
        assert_eq!(entry2.outbound_tag, "direct");
    }

    #[test]
    fn nat_key_display() {
        let key = test_key();
        let s = format!("{}", key);
        assert!(s.contains("192.168.1.100:12345"));
        assert!(s.contains("8.8.8.8:53"));
    }
}
