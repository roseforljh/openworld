# OpenWorld

A high-performance proxy kernel written in Rust, designed as a modern alternative to sing-box / Clash / Xray.

## Features

### Proxy Protocols

| Protocol | Outbound | Inbound | UDP | Notes |
|----------|:--------:|:-------:|:---:|-------|
| VLESS | ✅ | ✅ | ✅ | XTLS Vision, Reality |
| VMess | ✅ | ✅ | ✅ | AEAD + Legacy |
| Trojan | ✅ | ✅ | ✅ | |
| Shadowsocks | ✅ | ✅ | ✅ | AEAD + 2022 (Blake3) |
| Hysteria2 | ✅ | ✅ | ✅ | QUIC, Brutal CC |
| Hysteria v1 | ✅ | — | — | QUIC, Salamander obfs |
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
- GeoIP (MaxMind MMDB)
- GeoSite
- Rule Sets (SRS binary format)
- Wi-Fi SSID matching
- Process name matching

### Proxy Groups

- Selector (manual)
- URL-Test (auto best latency)
- Fallback
- Load Balance

### API

- Clash-compatible REST API (`/proxies`, `/rules`, `/connections`, `/traffic`)
- V2Ray Stats API (traffic counters)
- WebSocket / SSE real-time streaming
- External UI support (yacd, Metacubexd)

### Platform

- Linux, macOS, Windows
- Android (via FFI/JNI, TUN fd mode)
- TUN stack (gVisor user-space TCP/IP)
- ICMP Echo proxy

## Quick Start

```bash
# Build
cargo build --release

# Run
./target/release/openworld -c config.yaml

# Run with API
./target/release/openworld -c config.yaml
# Access API: http://127.0.0.1:9090
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

# Release build
cargo build --release

# Android cross-compile
rustup target add aarch64-linux-android
cargo build --target aarch64-linux-android --release
```

## License

MIT
