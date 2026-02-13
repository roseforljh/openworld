use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};
use std::time::Duration;
use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt};

use openworld::proxy::relay::{global_buffer_pool, relay, relay_with_options, RelayOptions, RelayStats};

// ─── Buffer Pool Benchmarks ────────────────────────────────────────────────

fn bench_buffer_pool_get_put(c: &mut Criterion) {
    let pool = global_buffer_pool();

    c.bench_function("buffer_pool_get_put_default", |b| {
        b.iter(|| {
            let buf = pool.get();
            pool.put(buf);
        });
    });
}

fn bench_buffer_pool_get_put_small(c: &mut Criterion) {
    let pool = global_buffer_pool();

    c.bench_function("buffer_pool_get_put_small", |b| {
        b.iter(|| {
            let buf = pool.get_small();
            pool.put(buf);
        });
    });
}

fn bench_buffer_pool_get_put_large(c: &mut Criterion) {
    let pool = global_buffer_pool();

    c.bench_function("buffer_pool_get_put_large", |b| {
        b.iter(|| {
            let buf = pool.get_large();
            pool.put(buf);
        });
    });
}

// ─── Relay Throughput Benchmarks ───────────────────────────────────────────

fn bench_relay_throughput(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();

    let sizes: &[(usize, &str)] = &[
        (1024, "1K"),
        (16384, "16K"),
        (65536, "64K"),
        (262144, "256K"),
    ];

    for &(size, label) in sizes {
        let mut group = c.benchmark_group("relay_throughput");
        group.throughput(Throughput::Bytes(size as u64));
        group.measurement_time(Duration::from_secs(5));

        group.bench_function(format!("simple_{}", label), |b| {
            b.iter(|| {
                rt.block_on(async {
                    let (mut client_a, server_a) = duplex(size * 2);
                    let (server_b, mut client_b) = duplex(size * 2);

                    let data = vec![0xABu8; size];
                    let relay_handle = tokio::spawn(async move {
                        relay(server_a, server_b).await
                    });

                    client_a.write_all(&data).await.unwrap();
                    drop(client_a); // Signal EOF

                    let mut received = vec![0u8; size];
                    client_b.read_exact(&mut received).await.unwrap();
                    black_box(received);

                    relay_handle.await.unwrap().unwrap();
                });
            });
        });

        group.finish();
    }
}

fn bench_relay_with_stats(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let size = 16384usize;

    let mut group = c.benchmark_group("relay_with_stats");
    group.throughput(Throughput::Bytes(size as u64));

    group.bench_function("tracked_16K", |b| {
        b.iter(|| {
            rt.block_on(async {
                let (mut client_a, server_a) = duplex(size * 2);
                let (server_b, mut client_b) = duplex(size * 2);

                let stats = RelayStats::new();
                let opts = RelayOptions {
                    idle_timeout: Duration::from_secs(30),
                    stats: Some(stats.clone()),
                    ..Default::default()
                };

                let relay_handle = tokio::spawn(async move {
                    relay_with_options(server_a, server_b, opts).await
                });

                let data = vec![0xCDu8; size];
                client_a.write_all(&data).await.unwrap();
                drop(client_a);

                let mut received = vec![0u8; size];
                client_b.read_exact(&mut received).await.unwrap();
                black_box(received);

                relay_handle.await.unwrap().unwrap();
                black_box(stats.upload());
                black_box(stats.download());
            });
        });
    });

    group.finish();
}

// ─── Concurrent Buffer Pool Benchmark ──────────────────────────────────────

fn bench_buffer_pool_contention(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let pool = global_buffer_pool();

    c.bench_function("buffer_pool_contention_8_tasks", |b| {
        b.iter(|| {
            rt.block_on(async {
                let mut handles = Vec::new();
                for _ in 0..8 {
                    handles.push(tokio::spawn(async {
                        let pool = global_buffer_pool();
                        for _ in 0..100 {
                            let buf = pool.get();
                            black_box(&buf);
                            pool.put(buf);
                        }
                    }));
                }
                for h in handles {
                    h.await.unwrap();
                }
            });
        });
    });

    // Also test pool stats after contention
    let (hits, misses) = pool.stats();
    println!("Pool stats after contention bench: hits={}, misses={}", hits, misses);
}

criterion_group!(
    benches,
    bench_buffer_pool_get_put,
    bench_buffer_pool_get_put_small,
    bench_buffer_pool_get_put_large,
    bench_relay_throughput,
    bench_relay_with_stats,
    bench_buffer_pool_contention,
);
criterion_main!(benches);
