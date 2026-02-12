use std::sync::Arc;

use openworld::app::tracker::ConnectionTracker;

#[test]
fn tracker_latency_percentiles() {
    let tracker = ConnectionTracker::new();
    tracker.record_latency_ms(10);
    tracker.record_latency_ms(30);
    tracker.record_latency_ms(20);

    let (p50, p95, p99) = tracker.latency_percentiles_ms().unwrap();
    assert_eq!(p50, 20);
    assert_eq!(p95, 30);
    assert_eq!(p99, 30);
}

#[test]
fn tracker_error_stats_accumulate() {
    let tracker = ConnectionTracker::new();
    tracker.record_error("OUTBOUND_CONNECT_FAILED");
    tracker.record_error("OUTBOUND_CONNECT_FAILED");
    tracker.record_error("RELAY_FAILED");

    let stats = tracker.error_stats();
    assert_eq!(stats.get("OUTBOUND_CONNECT_FAILED"), Some(&2));
    assert_eq!(stats.get("RELAY_FAILED"), Some(&1));
}

#[test]
fn tracker_route_hit_accumulate() {
    let tracker = ConnectionTracker::new();
    tracker.record_route_hit("MATCH");
    tracker.record_route_hit("MATCH");
    tracker.record_route_hit("domain-suffix(example.com)");

    let stats = tracker.route_stats();
    assert_eq!(stats.get("MATCH"), Some(&2));
    assert_eq!(stats.get("domain-suffix(example.com)"), Some(&1));
}

#[test]
fn tracker_route_stats_from_track() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    rt.block_on(async {
        let tracker = Arc::new(ConnectionTracker::new());
        let session = openworld::proxy::Session {
            target: openworld::common::Address::Domain("example.com".to_string(), 443),
            source: None,
            inbound_tag: "test-in".to_string(),
            network: openworld::proxy::Network::Tcp,
            sniff: false,
            detected_protocol: None,
        };

        let _guard = tracker
            .track(&session, "direct", "domain-suffix(example.com)", Some("domain-suffix(example.com)"))
            .await;

        let stats = tracker.route_stats();
        assert_eq!(stats.get("domain-suffix(example.com)"), Some(&1));
    });
}
