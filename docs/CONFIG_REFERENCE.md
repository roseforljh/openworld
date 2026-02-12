# OpenWorld 配置参考

## 完整配置示例

```yaml
# ── 日志 ──
log:
  level: info  # trace | debug | info | warn | error

# ── 入站 ──
inbounds:
  - tag: socks-in
    protocol: socks5        # socks5 | http | mixed | tun | transparent
    listen: "127.0.0.1"
    port: 1080
    sniffing:
      enabled: true
      override_destination: false

  - tag: tun-in
    protocol: tun
    listen: "0.0.0.0"
    port: 0
    settings:
      auto_route: true
      mtu: 9000
      stack: gvisor          # gvisor | system

# ── 出站 ──
outbounds:
  # VLESS
  - tag: vless-out
    protocol: vless
    settings:
      address: "server.example.com"
      port: 443
      uuid: "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
      flow: "xtls-rprx-vision"     # 可选 XTLS Vision
      security: tls
      sni: "server.example.com"
      allow_insecure: false
      fingerprint: "chrome"         # 可选 uTLS 指纹
      transport:
        type: ws                     # tcp | ws | h2 | grpc | httpupgrade | shadow-tls | anytls
        path: "/ws"
        host: "server.example.com"
      dialer:
        bind_address: "0.0.0.0"    # 出口绑定
        routing_mark: 255           # Linux fwmark
        tcp_fast_open: true
        mptcp: true

  # VLESS + Reality
  - tag: vless-reality
    protocol: vless
    settings:
      address: "server.example.com"
      port: 443
      uuid: "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
      security: reality
      public_key: "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
      short_id: "abcdef"
      server_name: "www.microsoft.com"

  # VMess
  - tag: vmess-out
    protocol: vmess
    settings:
      address: "server.example.com"
      port: 443
      uuid: "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
      alter_id: 0                    # 0=AEAD, >0=legacy
      security: tls
      sni: "server.example.com"

  # Trojan
  - tag: trojan-out
    protocol: trojan
    settings:
      address: "server.example.com"
      port: 443
      password: "your-password"
      security: tls
      sni: "server.example.com"

  # Shadowsocks
  - tag: ss-out
    protocol: shadowsocks
    settings:
      address: "server.example.com"
      port: 8388
      password: "your-password"
      method: "2022-blake3-aes-256-gcm"   # 支持所有 AEAD 和 2022 方法
      identity_key: "base64-encoded-identity-psk"  # SS2022 multi-user

  # Hysteria2
  - tag: hy2-out
    protocol: hysteria2
    settings:
      address: "server.example.com"
      port: 443
      password: "your-password"
      sni: "server.example.com"
      allow_insecure: false
      up_mbps: 100                   # 上行带宽提示
      down_mbps: 200                 # 下行带宽提示
      congestion_control: bbr        # bbr | cubic | new_reno

  # Hysteria v1
  - tag: hy-v1-out
    protocol: hysteria
    settings:
      address: "server.example.com"
      port: 36712
      password: "your-password"
      sni: "server.example.com"
      obfs: "salamander"
      obfs-password: "obfs-key"
      up_mbps: 100
      down_mbps: 200

  # NaiveProxy
  - tag: naive-out
    protocol: naive
    settings:
      address: "server.example.com"
      port: 443
      uuid: "username"
      password: "password"

  # WireGuard
  - tag: wg-out
    protocol: wireguard
    settings:
      address: "server.example.com"
      port: 51820
      private_key: "base64-private-key"
      peer_public_key: "base64-public-key"
      preshared_key: "base64-psk"     # 可选
      local_address: "10.0.0.2/32"
      mtu: 1420

  # SOCKS5 出站
  - tag: socks5-out
    protocol: socks5
    settings:
      address: "proxy.example.com"
      port: 1080
      username: "user"
      password: "pass"

  # SSH
  - tag: ssh-out
    protocol: ssh
    settings:
      address: "server.example.com"
      port: 22
      username: "user"
      password: "pass"

  # 直连 / 拒绝
  - tag: direct
    protocol: direct
  - tag: reject
    protocol: reject

# ── 代理组 ──
proxy-groups:
  - name: Proxy
    type: selector              # selector | url-test | fallback | load-balance
    proxies: [vless-out, trojan-out, ss-out]

  - name: Auto
    type: url-test
    proxies: [vless-out, trojan-out]
    url: "http://www.gstatic.com/generate_204"
    interval: 300
    tolerance: 150

# ── 路由规则 ──
router:
  rules:
    - type: domain-suffix        # domain | domain-suffix | domain-keyword | domain-regex
      values: ["cn", "baidu.com"]
      outbound: direct
    - type: ip-cidr
      values: ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
      outbound: direct
    - type: geoip
      values: ["cn"]
      outbound: direct
    - type: geosite
      values: ["google", "telegram"]
      outbound: Proxy
    - type: wifi-ssid
      values: ["HomeWifi"]
      outbound: direct
    - type: rule-set
      values: ["custom-rules"]
      outbound: Proxy
  default: Proxy
  geoip_db: "Country.mmdb"
  geosite_db: "geosite.dat"
  rule_providers:
    custom-rules:
      type: http
      url: "https://example.com/rules.srs"
      format: srs
      interval: 86400

# ── DNS ──
dns:
  mode: split                   # split | fake-ip
  servers:
    - address: "tls://1.1.1.1"          # 支持: udp:// | tcp:// | tls:// | https:// | quic:// | h3:// | dhcp://
      domains: ["*"]
    - address: "https://dns.alidns.com/dns-query"
      domains: ["cn", "baidu.com"]
  fallback:
    - "tls://8.8.8.8"
  cache_size: 4096
  cache_ttl: 600
  hosts:
    "custom.local": "127.0.0.1"
  fake_ip:
    enabled: true
    ip_range: "198.18.0.0/15"

# ── API ──
api:
  listen: "127.0.0.1"
  port: 9090
  secret: "your-secret"
  external_ui: "/path/to/yacd"
```

## 传输层类型

| 类型 | 值 | 说明 |
|------|-----|------|
| TCP | `tcp` | 直接 TCP 连接 |
| WebSocket | `ws` | WebSocket 传输 |
| HTTP/2 | `h2` | HTTP/2 多路复用 |
| gRPC | `grpc` | gRPC 传输 |
| HTTPUpgrade | `httpupgrade` | HTTP Upgrade 协议 |
| ShadowTLS | `shadow-tls` | ShadowTLS v3 伪装 |
| AnyTLS | `anytls` | 抗审查 TLS 传输 |

## DNS 协议

| 协议 | 格式 | 示例 |
|------|------|------|
| UDP | `udp://host:port` | `udp://8.8.8.8:53` |
| TCP | `tcp://host:port` | `tcp://1.1.1.1:53` |
| DoT | `tls://host` | `tls://1.1.1.1` |
| DoH | `https://host/path` | `https://dns.google/dns-query` |
| DoQ | `quic://host` | `quic://dns.adguard.com` |
| DoH3 | `h3://host/path` | `h3://dns.google/dns-query` |
| DHCP | `dhcp://interface` | `dhcp://en0` |
