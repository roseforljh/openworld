# OpenWorld 代理内核完整计划文档

## 0. 文档说明

- **项目名称**：OpenWorld
- **文档类型**：完整实施计划（含已完成内容与后续规划）
- **当前范围**：代理内核（Rust）
- **当前状态**：Phase 1 已完成；Phase 2 待启动
- **运行环境**：Windows / PowerShell（也兼容 Linux）

---

## 1. 项目目标与边界

## 1.1 核心目标

构建一个高性能、模块化、可扩展的代理内核，支持：

1. **入站协议**：
   - SOCKS5（RFC 1928，TCP CONNECT）
   - HTTP CONNECT
2. **出站协议**：
   - Direct（直连）
   - VLESS over TLS
   - Hysteria2（TCP over QUIC）
3. **路由规则**：
   - domain-suffix
   - domain-keyword
   - domain-full
   - ip-cidr
   - 首条命中优先，无命中走默认出站

## 1.2 非目标（当前阶段）

以下功能不在当前交付范围内（规划到 Phase 2+）：

- XTLS-Vision
- Reality
- UDP 代理
- TUN/TAP
- 控制面 API / Web 面板

---

## 2. 总体架构

请求处理主链路：

```text
客户端连接
  -> 入站握手（SOCKS5 / HTTP CONNECT）
  -> 生成 Session(target/source/inbound/network)
  -> Router 按规则匹配 outbound tag
  -> Outbound 建立远端连接（Direct / VLESS / HY2）
  -> relay 双向转发(copy_bidirectional)
  -> 连接关闭与日志记录
```

架构分层：

- **common**：地址、错误、流抽象
- **config**：YAML 反序列化与校验
- **proxy**：协议抽象与入/出站实现
- **router**：规则引擎
- **app**：组装器、调度器、监听器管理

---

## 3. 技术选型与依赖

核心依赖（已落地）：

- `tokio`：异步运行时
- `quinn`：QUIC
- `rustls` + `tokio-rustls`：TLS
- `h3` + `h3-quinn`：HTTP/3（HY2 认证）
- `serde` + `serde_yml`：配置解析
- `tracing` + `tracing-subscriber`：结构化日志
- `ipnet`：CIDR 匹配
- `uuid`：VLESS UUID
- `bytes`：协议编码

设计原则：

- 统一 trait 抽象（InboundHandler / OutboundHandler）
- 协议实现与调度解耦
- 默认安全，允许显式 `allow_insecure`
- 最小可用核心优先，后续逐步增强

---

## 4. 目录与模块规划

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
   │  └─ stream.rs
   ├─ config/
   │  ├─ mod.rs
   │  └─ types.rs
   ├─ proxy/
   │  ├─ mod.rs
   │  ├─ relay.rs
   │  ├─ inbound/
   │  │  ├─ mod.rs
   │  │  ├─ socks5.rs
   │  │  └─ http.rs
   │  └─ outbound/
   │     ├─ mod.rs
   │     ├─ direct.rs
   │     ├─ vless/
   │     │  ├─ mod.rs
   │     │  ├─ protocol.rs
   │     │  └─ tls.rs
   │     └─ hysteria2/
   │        ├─ mod.rs
   │        ├─ auth.rs
   │        ├─ protocol.rs
   │        └─ quic.rs
   ├─ router/
   │  ├─ mod.rs
   │  └─ rules.rs
   └─ app/
      ├─ mod.rs
      ├─ dispatcher.rs
      ├─ inbound_manager.rs
      └─ outbound_manager.rs
```

---

## 5. 数据模型与核心抽象

## 5.1 Address

- `Ip(SocketAddr)`
- `Domain(String, u16)`

能力：

- 端口/主机读取
- VLESS 地址编码
- HY2 地址字符串转换
- DNS 解析
- SOCKS5 地址解码

## 5.2 Session

```text
Session {
  target: Address,
  source: Option<SocketAddr>,
  inbound_tag: String,
  network: Network(Tcp/Udp)
}
```

## 5.3 协议 trait

- `InboundHandler::handle(...) -> InboundResult`
- `OutboundHandler::connect(&Session) -> ProxyStream`

统一通过 `ProxyStream`（AsyncRead + AsyncWrite）进行后续转发。

---

## 6. 协议实现计划（详细）

## 6.1 SOCKS5 入站

范围：TCP CONNECT（cmd=0x01）

流程：

1. 读取版本和 methods
2. 返回无认证 `0x00`
3. 读取请求头（ver/cmd/rsv/atyp/addr/port）
4. 仅允许 CONNECT，其他命令返回不支持
5. 解析目标地址（IPv4/Domain/IPv6）
6. 返回成功响应
7. 构建 Session 并交给 Dispatcher

错误处理：

- 非 0x05 版本拒绝
- 非 CONNECT 拒绝
- 未支持地址类型拒绝

## 6.2 HTTP CONNECT 入站

范围：仅支持 `CONNECT host:port HTTP/1.1`

流程：

1. 读取请求行
2. 校验 method=CONNECT
3. 解析 `host:port`
4. 消费请求头直到空行
5. 返回 `200 Connection Established`
6. 构建 Session 进入调度

错误处理：

- 非 CONNECT 直接拒绝
- 目标地址格式非法拒绝

## 6.3 Direct 出站

流程：

1. `session.target.resolve()`
2. `TcpStream::connect()`
3. 返回 ProxyStream

## 6.4 VLESS over TLS 出站

流程：

1. TCP 连接到远端节点
2. 建立 TLS（SNI + 可选 insecure）
3. 编码并发送 VLESS 请求头
4. 读取并校验 VLESS 响应头
5. 进入数据透传

VLESS 请求头结构：

```text
[Version=0x00]
[UUID(16B)]
[AddonsLen=0x00]
[Command=0x01(TCP)]
[Port(2B, BE)]
[AddrType + Addr]
```

## 6.5 Hysteria2（TCP）出站

流程：

1. 获取/复用 QUIC 连接
2. 走 HTTP/3 `POST /auth` 认证（期望状态码 233）
3. 打开 QUIC 双向流
4. 发送 TCP 请求头（varint 编码）
5. 读取 TCP 响应（status/message/padding）
6. 包装为 AsyncRead/AsyncWrite 流

关键点：

- QUIC varint 编解码
- 连接池复用
- rustls 验证器切换（secure / insecure）

---

## 7. 路由与分流策略

规则类型：

- `domain-suffix`
- `domain-keyword`
- `domain-full`
- `ip-cidr`

匹配逻辑：

1. 按配置顺序逐条匹配（first-match）
2. 命中则返回该规则绑定的 outbound
3. 全部不命中则返回 `router.default`

注意事项：

- 域名匹配大小写不敏感
- IP CIDR 仅对 `Address::Ip` 生效
- 域名规则仅对 `Address::Domain` 生效

---

## 8. 配置系统计划

配置文件：`config.yaml`

主结构：

```yaml
log:
  level: info

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
      security: tls
      sni: server.example.com
      allow_insecure: false

router:
  rules:
    - type: domain-suffix
      values: ["cn", "baidu.com"]
      outbound: direct
  default: my-vless
```

校验要求：

- 至少 1 个 inbound
- 至少 1 个 outbound
- `router.default` 必须引用已存在 outbound tag
- 每条规则 `outbound` 必须存在

---

## 9. 分阶段实施计划

## 9.1 Phase 1（已完成）

### Step 1：项目骨架与公共类型（已完成）

- 创建基础目录与模块
- 引入依赖
- 完成 Address / Error / Stream 抽象

### Step 2：配置系统（已完成）

- YAML 结构定义
- `load_config()` + `validate()`
- 提供示例 `config.yaml`

### Step 3：核心 trait + Router 引擎（已完成）

- Session/InboundResult/Network
- InboundHandler/OutboundHandler
- Router + Rule
- `relay` 封装

### Step 4：SOCKS5 入站（已完成）

- RFC 1928 基础握手
- CONNECT 支持
- 目标解析与 Session 输出

### Step 5：HTTP CONNECT 入站（已完成）

- 请求行解析
- CONNECT 校验
- 200 建链响应

### Step 6：Direct 出站 + App 组装（已完成）

- OutboundManager
- Dispatcher
- InboundManager
- App 启动与多监听器

### Step 7：VLESS over TLS 出站（已完成）

- TLS 连接
- VLESS 请求/响应头
- 出站注册与调度接入

### Step 8：Hysteria2 TCP 出站（已完成）

- QUIC 连接管理
- HTTP/3 认证
- TCP 请求/响应帧
- 流包装与转发接入

## 9.2 Phase 2（待启动）

### 目标 A：XTLS-Vision

- 在 VLESS 出站中扩展 Vision 流控路径
- 增加配置项（flow）
- 明确与普通 TLS 的兼容策略

### 目标 B：Reality

- 新增 Reality 相关配置（public key / short id / server name）
- 完成 Reality 握手流程
- 与 allow_insecure 行为边界清晰化

### 目标 C：UDP 代理

- 扩展 `Network::Udp` 的端到端处理链路
- 增加 SOCKS5 UDP ASSOCIATE（或独立入站 UDP）
- 出站协议 UDP 能力映射与回包路径

Phase 2 原则：

1. 不破坏 Phase 1 稳定能力
2. 先补齐测试基线，再推进新协议
3. 每项能力独立开关、独立验收

---

## 10. 测试与验收计划

## 10.1 构建验收

```powershell
cargo check
cargo build
```

要求：

- 编译通过
- 无错误
- 无警告（目标）

## 10.2 功能验收

1. SOCKS5 + HTTP 目标
2. SOCKS5 + HTTPS 目标
3. HTTP CONNECT + HTTPS 目标
4. 域名路由规则命中验证
5. 默认路由兜底验证
6. Direct/VLESS/HY2 出站切换验证

示例命令：

```powershell
# SOCKS5
curl.exe --proxy socks5h://127.0.0.1:1080 https://httpbin.org/ip

# HTTP CONNECT（HTTPS 才会走 CONNECT）
curl.exe --proxy http://127.0.0.1:1081 https://httpbin.org/ip
```

## 10.3 回归验收

- 改动任一协议模块后必须回归：
  - 两类入站
  - 三类出站
  - 至少一条域名规则 + 一条 ip-cidr 规则

---

## 11. 安全与稳定性要求

1. 禁止硬编码敏感信息
2. `allow_insecure` 默认 false
3. 边界输入要做格式校验
4. 连接失败要有清晰错误日志
5. 不允许静默吞错
6. 关键路径必须有错误回传

---

## 12. 性能与可观测性规划

## 12.1 当前可观测性

- tracing 日志覆盖关键节点：
  - inbound 接入
  - route 命中
  - outbound 连接
  - relay 结束

## 12.2 后续性能项（Phase 2+）

- 路由规则预处理优化
- 连接池策略细化（空闲回收、最大连接数）
- 可选指标导出（Prometheus）

---

## 13. 风险清单与应对

1. **协议兼容风险**（VLESS/HY2 服务端差异）
   - 应对：保留严格日志，先覆盖标准路径
2. **证书与 SNI 配置错误**
   - 应对：配置校验 + 握手错误明示
3. **路由误分流**
   - 应对：规则顺序显式化 + 命中日志
4. **连接复用状态异常**（QUIC）
   - 应对：连接健康检查 + 断线重建

---

## 14. 交付物清单

## 14.1 已交付（Phase 1）

- 完整 Rust 项目骨架
- 两种入站协议实现
- 三种出站协议实现
- 路由引擎
- 配置系统与样例配置
- 应用组装与调度
- 基本功能测试链路

## 14.2 待交付（Phase 2）

- XTLS-Vision
- Reality
- UDP 代理
- 更完整自动化测试

---

## 15. 开发与变更规范

1. 变更前先读相关模块与调用链
2. 新增协议必须接入统一 trait
3. 修改会影响路由/调度时必须做全链路回归
4. 仅做必要改动，避免过度重构
5. 文档与配置示例同步更新

---

## 16. 下一步执行建议

建议按以下顺序进入 Phase 2：

1. 先补齐自动化测试（为后续协议扩展兜底）
2. 落地 XTLS-Vision（先完成最小可用）
3. 落地 Reality（配置与握手）
4. 最后做 UDP（影响面最大，放在基线稳定后）

---

## 17. 当前结论

OpenWorld 已具备可运行的 **Phase 1 代理内核能力**：

- 入站：SOCKS5 / HTTP CONNECT
- 出站：Direct / VLESS(TLS) / Hysteria2(TCP)
- 路由：domain + cidr 基础规则
