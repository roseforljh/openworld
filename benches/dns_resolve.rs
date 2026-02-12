use criterion::{black_box, criterion_group, criterion_main, Criterion};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, Instant};

/// Simulated DNS cache for benchmarking (mirrors CachedResolver's cache logic).
struct BenchDnsCache {
    cache: HashMap<String, (Vec<IpAddr>, Instant)>,
    ttl: Duration,
}

impl BenchDnsCache {
    fn new(ttl_secs: u64) -> Self {
        Self {
            cache: HashMap::new(),
            ttl: Duration::from_secs(ttl_secs),
        }
    }

    fn insert(&mut self, host: &str, addrs: Vec<IpAddr>) {
        self.cache
            .insert(host.to_string(), (addrs, Instant::now() + self.ttl));
    }

    fn lookup(&self, host: &str) -> Option<&Vec<IpAddr>> {
        self.cache.get(host).and_then(|(addrs, expires)| {
            if Instant::now() < *expires {
                Some(addrs)
            } else {
                None
            }
        })
    }
}

fn bench_dns_cache_lookup_hit(c: &mut Criterion) {
    let mut cache = BenchDnsCache::new(300);
    for i in 0..1000u32 {
        let host = format!("host{}.example.com", i);
        cache.insert(
            &host,
            vec![IpAddr::V4(Ipv4Addr::new(10, 0, (i >> 8) as u8, i as u8))],
        );
    }

    c.bench_function("dns_cache_lookup_hit", |b| {
        b.iter(|| {
            black_box(cache.lookup("host500.example.com"));
        });
    });
}

fn bench_dns_cache_lookup_miss(c: &mut Criterion) {
    let mut cache = BenchDnsCache::new(300);
    for i in 0..1000u32 {
        let host = format!("host{}.example.com", i);
        cache.insert(
            &host,
            vec![IpAddr::V4(Ipv4Addr::new(10, 0, (i >> 8) as u8, i as u8))],
        );
    }

    c.bench_function("dns_cache_lookup_miss", |b| {
        b.iter(|| {
            black_box(cache.lookup("nonexistent.example.com"));
        });
    });
}

fn bench_dns_cache_insert(c: &mut Criterion) {
    c.bench_function("dns_cache_insert_1000", |b| {
        b.iter(|| {
            let mut cache = BenchDnsCache::new(300);
            for i in 0..1000u32 {
                cache.insert(
                    &format!("host{}.example.com", i),
                    vec![IpAddr::V4(Ipv4Addr::new(10, 0, (i >> 8) as u8, i as u8))],
                );
            }
            black_box(&cache.cache.len());
        });
    });
}

fn bench_dns_cache_mixed_workload(c: &mut Criterion) {
    let mut cache = BenchDnsCache::new(300);
    for i in 0..500u32 {
        cache.insert(
            &format!("host{}.example.com", i),
            vec![IpAddr::V4(Ipv4Addr::new(10, 0, (i >> 8) as u8, i as u8))],
        );
    }

    c.bench_function("dns_cache_mixed_hit_miss", |b| {
        let mut i = 0u32;
        b.iter(|| {
            let host = format!("host{}.example.com", i % 1000);
            black_box(cache.lookup(&host));
            i += 1;
        });
    });
}

criterion_group!(
    benches,
    bench_dns_cache_lookup_hit,
    bench_dns_cache_lookup_miss,
    bench_dns_cache_insert,
    bench_dns_cache_mixed_workload,
);
criterion_main!(benches);
