use criterion::{black_box, criterion_group, criterion_main, Criterion};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use openworld::router::trie::{DomainTrie, IpPrefixTrie};

fn bench_domain_trie_insert(c: &mut Criterion) {
    c.bench_function("domain_trie_insert_1000", |b| {
        b.iter(|| {
            let mut trie = DomainTrie::new();
            for i in 0..1000 {
                trie.insert(&format!("sub{}.example{}.com", i % 50, i), i);
            }
            black_box(&trie);
        });
    });
}

fn bench_domain_trie_find(c: &mut Criterion) {
    let mut trie = DomainTrie::new();
    for i in 0..1000 {
        trie.insert(&format!("sub{}.example{}.com", i % 50, i), i);
    }
    trie.insert("google.com", 9999);
    trie.insert("cn", 8888);

    c.bench_function("domain_trie_find_hit", |b| {
        b.iter(|| {
            black_box(trie.find("www.sub0.example0.com"));
        });
    });

    c.bench_function("domain_trie_find_miss", |b| {
        b.iter(|| {
            black_box(trie.find("nonexistent.domain.org"));
        });
    });

    c.bench_function("domain_trie_find_suffix", |b| {
        b.iter(|| {
            black_box(trie.find("mail.google.com"));
        });
    });
}

fn bench_ip_prefix_trie_insert(c: &mut Criterion) {
    c.bench_function("ip_trie_insert_1000_v4", |b| {
        b.iter(|| {
            let mut trie = IpPrefixTrie::new();
            for i in 0u8..250 {
                for prefix in [8, 16, 24] {
                    let cidr: ipnet::IpNet =
                        format!("{}.0.0.0/{}", i, prefix).parse().unwrap();
                    trie.insert(&cidr, i as usize);
                }
            }
            black_box(&trie);
        });
    });
}

fn bench_ip_prefix_trie_lookup(c: &mut Criterion) {
    let mut trie = IpPrefixTrie::new();
    let cidrs = [
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "192.168.1.0/24",
        "8.8.8.0/24",
        "1.1.1.0/24",
        "100.64.0.0/10",
        "fd00::/8",
        "2001:db8::/32",
        "fe80::/10",
    ];
    for (i, cidr) in cidrs.iter().enumerate() {
        let net: ipnet::IpNet = cidr.parse().unwrap();
        trie.insert(&net, i);
    }

    c.bench_function("ip_trie_lookup_v4_hit", |b| {
        let addr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));
        b.iter(|| {
            black_box(trie.longest_prefix_match(addr));
        });
    });

    c.bench_function("ip_trie_lookup_v4_miss", |b| {
        let addr = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1));
        b.iter(|| {
            black_box(trie.longest_prefix_match(addr));
        });
    });

    c.bench_function("ip_trie_lookup_v6_hit", |b| {
        let addr = IpAddr::V6(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1));
        b.iter(|| {
            black_box(trie.longest_prefix_match(addr));
        });
    });
}

criterion_group!(
    benches,
    bench_domain_trie_insert,
    bench_domain_trie_find,
    bench_ip_prefix_trie_insert,
    bench_ip_prefix_trie_lookup,
);
criterion_main!(benches);
