# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## 项目概述

OpenWorld 是一个 Rust 编写的高性能网络代理内核，类似 Xray-core / sing-box。当前处于 Phase 1 完成状态，Phase 2（XTLS-Vision、Reality、UDP 代理）待启动。

支持的协议：
- **入站**：SOCKS5 (RFC 1928 TCP CONNECT)、HTTP CONNECT
- **出站**：Direct（直连）、VLESS over TLS、Hysteria2 (TCP over QUIC)
- **路由**：domain-suffix、domain-keyword、domain-full、ip-cidr，首条命中优先

## 常用命令

```powershell
# 编译检查（不生成二进制）
cargo check

# 编译
cargo build

# 编译 release 版本
cargo build --release

# 运行（默认读取 config.yaml）
cargo run

# 指定配置文件运行
cargo run -- path/to/config.yaml

# 日志级别控制（通过环境变量）
$env:RUST_LOG="debug"; cargo run

# 手动测试 SOCKS5 代理
curl.exe --proxy socks5h://127.0.0.1:1080 https://httpbin.org/ip

# 手动测试 HTTP 代理
curl.exe --proxy http://127.0.0.1:1081 https://httpbin.org/ip
```

当前无自动化测试、无 rustfmt/clippy 自定义配置，使用 Rust 默认规则。

## 架构

### 数据流

```
客户端连接
  -> InboundManager 接受 TCP 连接，每连接 spawn 一个 tokio task
  -> InboundHandler (SOCKS5/HTTP) 协议握手，产出 InboundResult(Session + Stream)
  -> Dispatcher 调用 Router 匹配路由规则，选择出站 tag
  -> OutboundManager 按 tag 查找 OutboundHandler
  -> OutboundHandler (Direct/VLESS/Hysteria2) 建立远端连接，返回 ProxyStream
  -> relay() 双向转发 (tokio::io::copy_bidirectional)
```

### 模块结构

- **`common/`** — 共享抽象：`Address`（IP/Domain 枚举）、`Error`（thiserror 自定义错误）、`ProxyStream`（type-erased `Box<dyn AsyncRead+AsyncWrite>`）
- **`config/`** — YAML 配置加载（`load_config()`）和 serde 结构体定义（`types.rs`）
- **`proxy/`** — 协议核心
  - `mod.rs`：核心 trait（`InboundHandler`、`OutboundHandler`）和数据类型（`Session`、`Network`、`InboundResult`）
  - `relay.rs`：双向数据转发
  - `inbound/`：SOCKS5、HTTP CONNECT 入站实现
  - `outbound/`：Direct、VLESS（含 `protocol.rs` 头编码 + `tls.rs` TLS 配置）、Hysteria2（含 `auth.rs` HTTP/3 认证 + `protocol.rs` 帧编解码 + `quic.rs` QUIC 连接管理）
- **`router/`** — 路由引擎：`Router`（首条命中）+ `Rule`（规则类型定义与匹配逻辑）
- **`app/`** — 应用组装层
  - `mod.rs`：`App` 构造并串联所有组件
  - `dispatcher.rs`：路由 -> 出站 -> 转发的调度逻辑
  - `inbound_manager.rs`：TCP 监听器管理，per-connection task spawning
  - `outbound_manager.rs`：出站协议注册表（按 tag 索引）

### 核心 trait

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
}
```

新增协议只需实现对应 trait 并在 `OutboundManager`/`InboundManager` 中注册。

### 并发模型

- Tokio 异步运行时，`Arc` 共享 Router、OutboundManager、Dispatcher
- 每个入站连接独立 tokio task
- Hysteria2 的 QUIC 连接通过 `Arc<Mutex<QuicManager>>` 管理连接池/复用

## 配置文件

运行时配置为项目根目录的 `config.yaml`，结构：

```yaml
log:
  level: info
inbounds:       # 入站监听器列表（tag, protocol, listen, port）
outbounds:      # 出站协议列表（tag, protocol, settings）
router:
  rules:        # 路由规则列表（type, values, outbound）
  default:      # 默认出站 tag
```

## 关键依赖

| 依赖 | 用途 |
|---|---|
| `tokio` | 异步运行时 |
| `quinn` | QUIC 协议（Hysteria2） |
| `rustls` + `tokio-rustls` | TLS（VLESS、Hysteria2） |
| `h3` + `h3-quinn` | HTTP/3（Hysteria2 认证） |
| `serde` + `serde_yml` | YAML 配置解析 |
| `tracing` | 结构化日志 |
| `ipnet` | IP CIDR 匹配（路由规则） |
| `uuid` | VLESS 协议 UUID |

## 开发注意事项

- 运行环境为 Windows / PowerShell，PowerShell 不支持 `&&` 连接命令，使用 `;` 分隔
- `config.yaml` 中包含服务器地址和凭据，不应提交到版本控制
- 项目计划文档见 `OPENWORLD_COMPLETE_PLAN.md`，包含完整的架构设计、协议实现细节和后续规划
