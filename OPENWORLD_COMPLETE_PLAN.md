# OpenWorld 代理内核完整计划文档

## 0. 文档说明

- **项目名称**：OpenWorld
- **文档类型**：完整实施计划（含已完成内容与后续规划）
- **当前范围**：代理内核（Rust）
- **当前状态**：Phase 1-3 + 4A 已完成；Phase 4B 待启动
- **运行环境**：Windows / PowerShell（也兼容 Linux）

---

## 1. 项目目标与边界

## 1.1 核心目标

构建一个高性能、模块化、可扩展的代理内核，支持：

1. **入站协议**：
   - SOCKS5（RFC 1928，TCP CONNECT + UDP ASSOCIATE）
   - HTTP CONNECT
2. **出站协议**：
   - Direct（直连）
   - VLESS over TLS / Reality / Vision
   - Hysteria2（TCP over QUIC）
3. **传输层**：
   - TCP、TLS、Reality、WebSocket
4. **路由规则**：
   - domain-suffix、domain-keyword、domain-full、ip-cidr
   - GeoIP（mmdb）、GeoSite（文本域名列表）
   - 首条命中优先，无命中走默认出站
5. **DNS**：
   - 系统 DNS、UDP DNS、DNS over TLS、DNS over HTTPS
   - 域名分流解析（SplitResolver）
6. **管理 API**：
   - Clash 兼容 RESTful API（代理管理、连接管理、流量统计、规则查询）
   - WebSocket 实时流量推送

## 1.2 已完成能力总览

| 能力 | 状态 | Phase |
|------|------|-------|
| SOCKS5 入站 | 已完成 | 1 |
| HTTP CONNECT 入站 | 已完成 | 1 |
| Direct 出站 | 已完成 | 1 |
| VLESS over TLS | 已完成 | 1 |
| Hysteria2 TCP | 已完成 | 1 |
| 基础路由（domain/ip-cidr） | 已完成 | 1 |
| XTLS-Vision 流控 | 已完成 | 2 |
| Reality 握手 | 已完成 | 2 |
| VLESS UDP 代理 | 已完成 | 2 |
| 公共 TLS 工具提取 | 已完成 | 3A |
| 配置结构改造（transport/tls） | 已完成 | 3A |
| StreamTransport trait + 实现 | 已完成 | 3A |
| WebSocket 传输 | 已完成 | 3A |
| VLESS 迁移至 StreamTransport | 已完成 | 3A |
| 优雅关闭 + 连接跟踪 | 已完成 | 3A |
| Clash 兼容 REST API | 已完成 | 3B |
| DNS 解析器模块 | 已完成 | 3C |
| GeoIP 路由 | 已完成 | 3C |
| GeoSite 路由 | 已完成 | 3C |
| API 代理组管理（选择/延迟测试） | 已完成 | 4A |

---

## 2. 总体架构

请求处理主链路：

```text
客户端连接
  -> InboundManager 接受 TCP 连接，每连接 spawn 一个 tokio task
  -> InboundHandler (SOCKS5/HTTP) 协议握手，产出 InboundResult(Session + Stream)
  -> Dispatcher 调用 Router 匹配路由规则，选择出站 tag
  -> OutboundManager 按 tag 查找 OutboundHandler
  -> OutboundHandler (Direct/VLESS/Hysteria2) 通过 StreamTransport 建立远端连接
  -> relay() 双向转发 (copy_bidirectional)
  -> ConnectionTracker 记录连接状态与流量统计
  -> 连接关闭时 ConnectionGuard 自动清理
```

架构分层：

- **common/** — 地址、错误、流抽象、公共 TLS 工具、UDP 包抽象
- **config/** — YAML 反序列化与校验（含 transport/tls 子结构）
- **proxy/** — 协议抽象、入/出站实现、传输层抽象
- **router/** — 规则引擎（含 GeoIP/GeoSite）
- **dns/** — DNS 解析器（System/Hickory/Split）
- **api/** — Clash 兼容 RESTful API
- **app/** — 组装器、调度器、监听器管理、连接跟踪

---

## 3. 技术选型与依赖

核心依赖：

| 依赖 | 用途 |
|---|---|
| `tokio` | 异步运行时 |
| `quinn` | QUIC 协议（Hysteria2） |
| `rustls` + `tokio-rustls` | TLS |
| `h3` + `h3-quinn` | HTTP/3（Hysteria2 认证） |
| `serde` + `serde_yml` | YAML 配置解析 |
| `tracing` + `tracing-subscriber` | 结构化日志 |
| `ipnet` | IP CIDR 匹配 |
| `uuid` | VLESS UUID |
| `bytes` | 协议编码 |
| `axum` | REST API 框架（含 WebSocket） |
| `tower-http` | CORS 中间件 |
| `serde_json` | JSON 序列化 |
| `hickory-resolver` | DNS 解析（UDP/DoT/DoH） |
| `maxminddb` | GeoIP mmdb 数据库 |
| `tokio-tungstenite` | WebSocket 传输层 |
| `tokio-util` | CancellationToken（优雅关闭） |
| `async-trait` | 异步 trait |
| `reqwest` | API 集成测试（dev） |

---

## 4. 目录与模块结构

```text
openworld/
├─ Cargo.toml
├─ config.yaml
└─ src/
   ├─ main.rs
   ├─ lib.rs
   ├─ common/
   │  ├─ mod.rs
   │  ├─ addr.rs
   │  ├─ error.rs
   │  ├─ stream.rs
   │  ├─ tls.rs              [Phase 3A] 公共 TLS 工具
   │  └─ udp.rs               [Phase 2] UDP 包抽象
   ├─ config/
   │  ├─ mod.rs
   │  └─ types.rs             含 TransportConfig / TlsConfig / DnsConfig / ApiConfig / ProxyGroupConfig
   ├─ proxy/
   │  ├─ mod.rs
   │  ├─ relay.rs
   │  ├─ inbound/
   │  │  ├─ mod.rs
   │  │  ├─ socks5.rs
   │  │  └─ http.rs
   │  ├─ outbound/
   │  │  ├─ mod.rs
   │  │  ├─ direct.rs
   │  │  ├─ vless/
   │  │  │  ├─ mod.rs          使用 StreamTransport
   │  │  │  ├─ protocol.rs
   │  │  │  ├─ tls.rs
   │  │  │  ├─ reality.rs     [Phase 2] Reality 握手
   │  │  │  └─ vision.rs      [Phase 2] XTLS-Vision
   │  │  └─ hysteria2/
   │  │     ├─ mod.rs
   │  │     ├─ auth.rs
   │  │     ├─ protocol.rs
   │  │     └─ quic.rs
   │  ├─ transport/           [Phase 3A] 传输层抽象
   │  │  ├─ mod.rs             StreamTransport trait + build_transport()
   │  │  ├─ tcp.rs
   │  │  ├─ tls.rs
   │  │  ├─ reality.rs
   │  │  └─ ws.rs
   │  └─ group/               [Phase 4A] 代理组
   │     ├─ mod.rs             build_proxy_groups() 工厂
   │     ├─ selector.rs        手动选择
   │     ├─ urltest.rs         延迟自动选择
   │     ├─ fallback.rs        故障转移
   │     ├─ loadbalance.rs     负载均衡
   │     └─ health.rs          健康检查器
   ├─ router/
   │  ├─ mod.rs
   │  ├─ rules.rs             含 GeoIp / GeoSite 规则
   │  ├─ geoip.rs             [Phase 3C] mmdb 查询
   │  └─ geosite.rs           [Phase 3C] 域名列表
   ├─ dns/                    [Phase 3C]
   │  ├─ mod.rs               DnsResolver trait
   │  └─ resolver.rs          System / Hickory / Split 解析器
   ├─ api/                    [Phase 3B]
   │  ├─ mod.rs               API 服务器启动与路由
   │  ├─ handlers.rs          端点处理函数（含代理组管理）
   │  └─ models.rs            Clash 兼容响应结构
   └─ app/
      ├─ mod.rs               App 组装（含 API 启动）
      ├─ dispatcher.rs        路由调度 + 连接跟踪
      ├─ inbound_manager.rs   TCP 监听 + CancellationToken
      ├─ outbound_manager.rs  出站注册表 + 代理组管理
      └─ tracker.rs           [Phase 3A] 连接跟踪器
```

测试文件：

```text
tests/
├─ phase3_baseline.rs          基础架构测试
├─ phase3_e2e.rs               端到端集成测试
├─ phase4_protocol_e2e.rs      协议层端到端测试
├─ phase5_api.rs               [Phase 3B] API 端点测试
├─ phase5_routing.rs           [Phase 3C] DNS + 路由增强测试
└─ phase6_proxy_groups.rs      [Phase 4A] 代理组 + API 测试
```

---

## 5. 数据模型与核心抽象

## 5.1 Address

- `Ip(SocketAddr)`
- `Domain(String, u16)`

能力：端口/主机读取、VLESS 地址编码、HY2 地址转换、DNS 解析、SOCKS5 地址解码

## 5.2 Session

```rust
Session {
    target: Address,
    source: Option<SocketAddr>,
    inbound_tag: String,
    network: Network(Tcp/Udp),
}
```

## 5.3 核心 trait

```rust
#[async_trait]
pub trait InboundHandler: Send + Sync {
    fn tag(&self) -> &str;
    async fn handle(&self, stream: ProxyStream, source: SocketAddr) -> Result<InboundResult>;
}

#[async_trait]
pub trait OutboundHandler: Send + Sync {
    fn tag(&self) -> &str;
    async fn connect(&self, session: &Session) -> Result<ProxyStream>;
    async fn connect_udp(&self, session: &Session) -> Result<Box<dyn UdpTransport>>;
}

#[async_trait]
pub trait StreamTransport: Send + Sync {
    async fn connect(&self, addr: &Address) -> Result<ProxyStream>;
}

#[async_trait]
pub trait DnsResolver: Send + Sync {
    async fn resolve(&self, host: &str) -> Result<Vec<IpAddr>>;
}
```

## 5.4 连接跟踪

```rust
ConnectionTracker {
    track(session, outbound_tag) -> ConnectionGuard,
    list() -> Vec<ConnectionInfo>,
    snapshot() -> TrafficSnapshot { total_up, total_down, active_count },
    close(id) -> bool,
    close_all() -> usize,
}
```

`ConnectionGuard` 实现 Drop 自动从 tracker 移除，持有 `upload/download: Arc<AtomicU64>` 供 relay 累加。

---

## 6. 协议实现详情

## 6.1 SOCKS5 入站

RFC 1928 TCP CONNECT + UDP ASSOCIATE 支持。

## 6.2 HTTP CONNECT 入站

仅 CONNECT 方法，返回 200 后进入透传。

## 6.3 Direct 出站

DNS 解析 -> TCP connect -> ProxyStream。

## 6.4 VLESS 出站

支持三种安全模式：
- **TLS**：标准 rustls TLS
- **Reality**：x25519 密钥交换 + 自定义握手
- **Vision**：XTLS 流控（检测内层 TLS 握手，完成后直通）

通过 StreamTransport 抽象传输层，VLESS 协议层仅关注头编码/解码。

## 6.5 Hysteria2 出站

QUIC 连接池 + HTTP/3 认证 + varint 帧编解码。保持内部 QuicManager 管理。

---

## 7. 路由系统

规则类型：
- `domain-suffix` — 域名后缀匹配
- `domain-keyword` — 域名关键词匹配
- `domain-full` — 完整域名精确匹配
- `ip-cidr` — IP CIDR 范围匹配
- `geoip` — 基于 mmdb 的国家级 IP 归属匹配
- `geosite` — 基于域名列表的分类匹配

匹配逻辑：配置顺序逐条匹配（first-match），全部不命中走 `router.default`。

API 接口：`Router::route(&Session) -> &str` + `Router::rules()` + `Router::default_outbound()`

---

## 8. DNS 系统

解析器类型：
- **SystemResolver**：使用 `tokio::net::lookup_host`
- **HickoryResolver**：hickory-resolver，支持 UDP / DoT / DoH
- **SplitResolver**：域名后缀分流，不同域名走不同上游 DNS

配置格式：
```yaml
dns:
  servers:
    - address: "223.5.5.5"                     # UDP
      domains: ["cn", "baidu.com"]
    - address: "tls://1.1.1.1"                 # DNS over TLS
    - address: "https://dns.google/dns-query"   # DNS over HTTPS
```

---

## 9. Clash 兼容 API

| 方法 | 路径 | 功能 |
|------|------|------|
| GET | /version | 版本信息 |
| GET | /proxies | 出站列表 |
| GET | /proxies/{name} | 单个出站详情 |
| PUT | /proxies/{name} | 切换代理组选中节点 |
| GET | /proxies/{name}/delay | 延迟测试 |
| GET | /connections | 活跃连接列表 |
| DELETE | /connections | 关闭所有连接 |
| DELETE | /connections/{id} | 关闭指定连接 |
| WS | /traffic | 实时流量推送（每秒） |
| WS | /logs | 实时日志流（占位） |
| GET | /rules | 路由规则列表 |

认证：Bearer token middleware + WebSocket `?token=xxx` 查询参数。

---

## 10. 配置系统

```yaml
log:
  level: info

dns:
  servers:
    - address: "223.5.5.5"
      domains: ["cn"]
    - address: "8.8.8.8"

api:
  listen: "127.0.0.1"
  port: 9090
  secret: "optional-secret"

inbounds:
  - tag: socks-in
    protocol: socks5
    listen: 127.0.0.1
    port: 1080

outbounds:
  - tag: direct
    protocol: direct
  - tag: my-vless
    protocol: vless
    settings:
      address: 1.2.3.4
      port: 443
      uuid: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
      tls:
        enabled: true
        security: tls
        sni: server.example.com
        allow_insecure: false
        alpn: ["h2", "http/1.1"]
      transport:
        type: ws
        path: /ws
        host: server.example.com

router:
  geoip_db: "GeoLite2-Country.mmdb"
  geosite_db: "geosite-cn.txt"
  rules:
    - type: geosite
      values: ["cn"]
      outbound: direct
    - type: geoip
      values: ["CN"]
      outbound: direct
    - type: domain-suffix
      values: ["cn", "baidu.com"]
      outbound: direct
  default: my-vless
```

---

## 11. 分阶段实施记录

## 11.1 Phase 1（已完成）

项目骨架、配置系统、核心 trait、Router、SOCKS5/HTTP 入站、Direct/VLESS/Hysteria2 出站、App 组装。

## 11.2 Phase 2（已完成）

- XTLS-Vision 流控
- Reality 握手协议
- VLESS UDP 代理（SOCKS5 UDP ASSOCIATE）
- 协议层端到端测试

## 11.3 Phase 3（已完成）

### Phase 3A：基础设施升级
- 3A-1: 提取公共 TLS 工具 (`common/tls.rs`)
- 3A-2: 配置结构改造 (TransportConfig / TlsConfig)
- 3A-3: StreamTransport trait + TCP/TLS/Reality 实现
- 3A-4: WebSocket 传输
- 3A-5: 迁移 VLESS 使用 StreamTransport
- 3A-6: Hysteria2 清理（复用公共 TLS）
- 3A-7: 优雅关闭 + 连接跟踪 (CancellationToken + ConnectionTracker)
- 3A-8: 测试适配

### Phase 3B：Clash API
- 3B-1: RESTful API 框架 (axum + WebSocket)
- 3B-2: API 集成测试

### Phase 3C：DNS + 路由增强
- 3C-1: DNS 解析器模块 (System/Hickory/Split)
- 3C-2: GeoIP 支持 (maxminddb)
- 3C-3: GeoSite 支持（文本域名列表）
- 3C-4: DNS + 路由测试

测试覆盖：163 项测试全部通过，0 警告。

## 11.4 Phase 4A（已完成）

- 代理组核心：SelectorGroup、UrlTestGroup、FallbackGroup、LoadBalanceGroup
- HealthChecker 健康检查（HTTP GET 延迟测试）
- OutboundHandler trait 扩展 as_any() 支持安全 downcasting
- OutboundManager 代理组注册与管理
- API 扩展：PUT /proxies/{name}（切换选中）、GET /proxies/{name}/delay（延迟测试）
- Config 扩展：proxy-groups 配置 + 验证

测试覆盖：191 项测试全部通过，0 警告。

---

## 12. Phase 4 规划（待启动）

### 目标：从"可用的代理工具"到"功能完备的代理客户端"

### Phase 4A：代理组 + 自动选择（已完成）

- **Proxy Group 抽象**：`selector`（手动选择）、`url-test`（延迟自动选择）、`fallback`（故障转移）、`load-balance`（负载均衡）
- 配置格式扩展：`proxy-groups` 区块
- API 扩展：`PUT /proxies/{group}/select` 切换选中节点
- 延迟测试：`GET /proxies/{name}/delay?url=...&timeout=...`

### Phase 4B：协议嗅探 (Sniffing)

- 入站流量协议检测（TLS ClientHello SNI / HTTP Host）
- 用检测到的域名覆盖 Session target（提高路由准确性）
- 可配置开关：`sniffing: { enabled: true, destinations: ["http", "tls"] }`

### Phase 4C：更多传输层

- gRPC 传输 (`grpc`)
- HTTP/2 传输 (`h2`)
- 传输层 TLS 组合（ws+tls / grpc+tls / h2+tls）

### Phase 4D：规则提供者 (Rule Provider)

- 远程规则列表（HTTP 拉取 + 本地缓存）
- 定时更新（interval 配置）
- 格式支持：文本域名列表、YAML 规则集

### Phase 4E：配置热重载

- 文件监听（notify crate）或 API 触发 (`PATCH /configs`)
- 支持出站/路由/DNS 配置热更新
- 入站监听器的平滑迁移

### Phase 4 执行顺序建议

```
4A (代理组) ──> 4B (嗅探) ──> 4C (传输层)
                              4D (规则提供者) ──> 4E (热重载)
```

4A 优先级最高，因为代理组是客户端核心交互能力。

---

## 13. 测试与验收

## 13.1 自动化测试

```powershell
cargo test       # 191 项测试
cargo check      # 编译检查
cargo build      # 构建
```

## 13.2 功能验收

```powershell
# SOCKS5
curl.exe --proxy socks5h://127.0.0.1:1080 https://httpbin.org/ip

# HTTP CONNECT
curl.exe --proxy http://127.0.0.1:1081 https://httpbin.org/ip

# API
curl.exe http://127.0.0.1:9090/version
curl.exe http://127.0.0.1:9090/proxies
curl.exe http://127.0.0.1:9090/connections
```

---

## 14. 安全与稳定性要求

1. 禁止硬编码敏感信息
2. `allow_insecure` 默认 false
3. 边界输入做格式校验
4. 连接失败有清晰错误日志
5. 不允许静默吞错
6. 关键路径必须有错误回传
7. API 支持 Bearer token 认证

---

## 15. 开发规范

1. 变更前先读相关模块与调用链
2. 新增协议必须接入统一 trait
3. 修改会影响路由/调度时必须做全链路回归
4. 仅做必要改动，避免过度重构
5. 文档与配置示例同步更新
6. 每个 Phase 完成后提交并更新本文档
