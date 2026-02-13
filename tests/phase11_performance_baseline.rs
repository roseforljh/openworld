use std::time::Instant;

use openworld::app::tracker::ConnectionTracker;
use openworld::config::types::{RuleConfig, RouterConfig};
use openworld::proxy::{Network, Session};
use openworld::router::Router;

#[test]
#[ignore = "manual baseline"]
fn baseline_router_match_three_scenarios() {
    let router_cfg = RouterConfig {
        rules: vec![
            RuleConfig {
                rule_type: "domain-suffix".to_string(),
                values: vec!["example.com".to_string()],
                outbound: "proxy-a".to_string(),
                action: "route".to_string(),
                override_address: None,
                override_port: None,
                sniff: false,
                resolve_strategy: None,
            },
            RuleConfig {
                rule_type: "domain-keyword".to_string(),
                values: vec!["google".to_string()],
                outbound: "proxy-b".to_string(),
                action: "route".to_string(),
                override_address: None,
                override_port: None,
                sniff: false,
                resolve_strategy: None,
            },
            RuleConfig {
                rule_type: "ip-cidr".to_string(),
                values: vec!["10.0.0.0/8".to_string()],
                outbound: "proxy-c".to_string(),
                action: "route".to_string(),
                override_address: None,
                override_port: None,
                sniff: false,
                resolve_strategy: None,
            },
        ],
        default: "direct".to_string(),
        ..Default::default()
    };

    let router = Router::new(&router_cfg).unwrap();

    let scenario1 = Session {
        target: openworld::common::Address::Domain("www.example.com".to_string(), 443),
        source: None,
        inbound_tag: "bench".to_string(),
        network: Network::Tcp,
        sniff: false,
        detected_protocol: None,
    };
    let scenario2 = Session {
        target: openworld::common::Address::Domain("www.google.com".to_string(), 443),
        source: None,
        inbound_tag: "bench".to_string(),
        network: Network::Tcp,
        sniff: false,
        detected_protocol: None,
    };
    let scenario3 = Session {
        target: openworld::common::Address::Ip("10.1.2.3:443".parse().unwrap()),
        source: None,
        inbound_tag: "bench".to_string(),
        network: Network::Tcp,
        sniff: false,
        detected_protocol: None,
    };

    let loops = 100_000;

    let start = Instant::now();
    for _ in 0..loops {
        assert_eq!(router.route(&scenario1), "proxy-a");
    }
    let d1 = start.elapsed();

    let start = Instant::now();
    for _ in 0..loops {
        assert_eq!(router.route(&scenario2), "proxy-b");
    }
    let d2 = start.elapsed();

    let start = Instant::now();
    for _ in 0..loops {
        assert_eq!(router.route(&scenario3), "proxy-c");
    }
    let d3 = start.elapsed();

    println!(
        "baseline_router_match: domain-suffix={:?}, domain-keyword={:?}, ip-cidr={:?}, loops={}",
        d1, d2, d3, loops
    );
}

#[test]
#[ignore = "manual baseline"]
fn baseline_tracker_percentile_calculation() {
    let tracker = ConnectionTracker::new();
    let loops = 200_000u64;

    let start = Instant::now();
    for i in 0..loops {
        tracker.record_latency_ms((i % 500) + 1);
    }
    let write_cost = start.elapsed();

    let start = Instant::now();
    let p = tracker.latency_percentiles_ms().unwrap();
    let read_cost = start.elapsed();

    println!(
        "baseline_tracker_latency: write={:?}, calc={:?}, p50/p95/p99={:?}",
        write_cost, read_cost, p
    );
}
