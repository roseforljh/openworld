# OpenWorld

A high-performance proxy kernel written in Rust, designed as a modern alternative to mainstream proxy cores.

> **52,000+ lines Rust · 1050+ tests · Zero-copy relay · Three-platform native**

## Features

### Proxy Protocols

| Protocol | Outbound | Inbound | UDP | Notes |
|----------|:--------:|:-------:|:---:|-------|
| VLESS | ✅ | ✅ | ✅ | XTLS Vision, Reality |
| VMess | ✅ | ✅ | ✅ | AEAD + Legacy |
| Trojan | ✅ | ✅ | ✅ | |
| Shadowsocks | ✅ | ✅ | ✅ | AEAD + 2022 (Blake3) |
| Hysteria2 | ✅ | ✅ | ✅ | QUIC, Brutal CC, 0-RTT |
| Hysteria v1 | ✅ | — | — | QUIC, Salamander obfs |
| TUIC | ✅ | — | ✅ | QUIC, 0-RTT |
| NaiveProxy | ✅ | — | — | TLS + HTTP/2 CONNECT |
| WireGuard | ✅ | — | ✅ | |
| SOCKS5 | ✅ | ✅ | ✅ | |
| HTTP | — | ✅ | — | |
| SSH | ✅ | — | — | Tunnel mode |
| Tor | ✅ | — | — | Built-in Tor |
| Direct | ✅ | — | — | |
| Reject | ✅ | — | — | |

### Transport Layers

| Transport | Protocols |
|-----------|-----------|
| TCP / TLS | All |
| WebSocket | VLESS, VMess, Trojan |
| HTTP/2 | VLESS, VMess, Trojan |
| gRPC | VLESS, VMess |
| HTTPUpgrade | VLESS, VMess, Trojan |
| Reality | VLESS |
| ShadowTLS v3 | Shadowsocks |
| AnyTLS | Custom framing |
| MPTCP | All (Linux) |
| kTLS | All (Linux 4.13+) |

### TLS Features

- **uTLS fingerprint**: Chrome, Firefox, Safari, Edge, Random
- **ECH** (Encrypted Client Hello)
- **Reality** (XTLS Reality)
- **ALPN** negotiation

### DNS

- UDP, TCP, DoT (TLS), DoH, DoQ (QUIC), DoH3 (HTTP/3), DHCP
- Split resolver with pattern matching (suffix, keyword, regex, full)
- Fake IP mode
- DNS hijacking
- Hosts file
- Cache with configurable TTL

### Routing

- Domain: suffix, keyword, regex, full match
- IP CIDR
- GeoIP (MaxMind MMDB) with auto-update
- GeoSite
- Rule Sets (SRS binary format)
- Wi-Fi SSID matching
- Process name matching
- Rule Providers (remote HTTP + file, auto-refresh)

### Proxy Groups

- Selector (manual)
- URL-Test (auto best latency)
- Fallback
- Load Balance
- Relay (chained proxies)

### API

- Clash-compatible REST API (30+ endpoints: `/proxies`, `/rules`, `/connections`, `/traffic`, `/providers`, `/dns`, `/configs`, `/memory`)
- V2Ray Stats API (traffic counters)
- WebSocket / SSE real-time streaming (logs, traffic, connections)
- Prometheus metrics export (`/metrics`)
- External UI support (yacd, Metacubexd)

### Performance

- **Zero-copy relay**: io_uring splice → libc splice → buffered fallback
- **Buffer pool**: Lock-free 3-tier pool (4K/32K/64K) with hit/miss stats
- **TCP connection pool**: LIFO reuse with per-host limits & auto-expiry
- **Multiplexing**: SingMux with backpressure
- **Traffic stats persistence**: Cross-restart JSON-based counters

### Platform

| Feature | Linux | Windows | macOS | Android |
|---------|:-----:|:-------:|:-----:|:-------:|
| TUN | ✅ ioctl | ✅ WinTun | ✅ utun | ✅ fd |
| System proxy | ✅ env | ✅ Registry | ✅ networksetup | — |
| Service | ✅ systemd | ✅ SCM | — | — |
| Auto-start | ✅ systemd enable | ✅ Registry | — | — |
| Transparent | ✅ nftables/iptables | — | — | — |
| Zero-copy | ✅ io_uring/splice | — | — | — |
| Docker | ✅ | — | — | — |

## Quick Start

```bash
# Build
cargo build --release

# Run
./target/release/openworld -c config.yaml

# Run with API (access at http://127.0.0.1:9090)
./target/release/openworld -c config.yaml
```

### Linux Deployment

```bash
# One-click install
sudo ./deploy/install.sh config.yaml

# Manage
systemctl start openworld
systemctl enable openworld
journalctl -u openworld -f
```

### Docker

```bash
cd deploy
docker compose up -d
```

## Configuration

See [docs/CONFIG_REFERENCE.md](docs/CONFIG_REFERENCE.md) for the full configuration reference.

### Minimal Example

```yaml
log:
  level: info

inbounds:
  - tag: socks-in
    protocol: socks5
    listen: "127.0.0.1"
    port: 1080

outbounds:
  - tag: proxy
    protocol: vless
    settings:
      address: "server.example.com"
      port: 443
      uuid: "your-uuid"
      security: tls
      sni: "server.example.com"
  - tag: direct
    protocol: direct

router:
  rules:
    - type: geoip
      values: ["cn"]
      outbound: direct
  default: proxy
```

## Building

```bash
# Debug build
cargo build

# Release build (optimized for size)
cargo build --release

# Android cross-compile
./scripts/build-android.sh

# Run tests (1050+)
cargo test --lib

# Run benchmarks
cargo bench
```

## License

MIT
