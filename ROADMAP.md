# OpenWorld 终极补全路线图

> 目标：对标 sing-box / mihomo / clash.meta，做世界上最好的代理内核
> 当前状态：框架完整、协议覆盖广，但存在死代码、集成缺口、生产级特性缺失
> 原则：先修内功（能用 → 好用），再扩外延（功能全 → 生态强）

---

## 第一阶段：修复核心缺陷（Priority: CRITICAL）

不修复这些，代理内核无法正常工作。

### C1. 补全 reject/blackhole 出站
**现状**：OutboundManager 不支持 reject/block，路由规则无法阻断连接
**改动**：
- 新建 `src/proxy/outbound/reject.rs`
  - `RejectOutbound`：connect() 立即返回 `Err`
  - `BlackholeOutbound`：connect() 返回一个立即 EOF 的 stream
- `outbound_manager.rs` 的 match 分支添加 `"reject"` / `"blackhole"` / `"block"`
- 配置示例：`{ tag: "block", protocol: "reject" }`

### C2. 注册 TUIC / SSH / ProxyChain 到 OutboundManager
**现状**：`tuic/mod.rs`、`ssh.rs`、`chain.rs` 代码存在但未注册，是死代码
**改动**：
- `outbound_manager.rs` 添加 `use` 和 match 分支：
  - `"tuic"` → `TuicOutbound::new(config)?`
  - `"ssh"` → `SshOutbound::new(config)?`
  - `"chain"` → `ProxyChain::new(config, &handlers)?`（chain 需要引用已注册的出站）
- chain 的构造需要特殊处理（依赖其他出站），放在基础出站注册之后、代理组之前

### C3. FakeIP 与 Dispatcher 联动
**现状**：FakeIP 池已实现，但 Dispatcher 没有反查逻辑
**改动**：
- `Dispatcher` 添加 `fakeip_pool: Option<Arc<FakeIpPool>>` 字段
- `dispatch()` 中：当 `session.target` 是 IP 且命中 FakeIP 池范围时，反查真实域名
- `App::new()` 中：如果 DNS 配置启用了 fakeip，创建 FakeIpPool 并注入 Dispatcher
- TUN 入站的 DNS 劫持逻辑（见 C4）

### C4. TUN DNS 劫持
**现状**：TUN 模式下 DNS 查询包（UDP:53）直接走出站，不经过内置 DNS
**改动**：
- `tun.rs` 的 `run()` 方法中识别 UDP:53 包
- 截获后用内置 DnsResolver 处理，返回 FakeIP 或真实解析结果
- 配置开关：`tun.dns_hijack: ["udp://any:53", "tcp://any:53"]`

### C5. relay 增强
**现状**：relay.rs 只有 17 行的 `copy_bidirectional`，缺少超时、统计、限速
**改动**：
- 添加 idle timeout（连接空闲 N 秒自动断开，默认 300s）
- 添加实时流量统计回调（上传/下载字节数），对接 ConnectionTracker
- 集成 RateLimiter（按连接/全局限速）
- 支持 CancellationToken 优雅中断

---

## 第二阶段：功能补全（Priority: HIGH）

对标竞品的核心功能差距。

### H1. 入站认证
**现状**：`InboundAuth` 结构在 ops.rs 中定义但未集成
**改动**：
- SOCKS5 入站：支持 RFC 1929 用户名/密码认证 (method 0x02)
- HTTP 入站：支持 Proxy-Authorization Basic 认证
- 配置格式：`inbounds[].settings.auth: { users: [{username, password}] }`

### H2. 统一 Dialer 层
**现状**：各出站协议各自 `TcpStream::connect()`，无统一 socket 配置
**改动**：
- 新建 `src/common/dialer.rs`
- `Dialer` 结构体封装：
  - `bind_interface: Option<String>`（绑定网卡）
  - `bind_address: Option<IpAddr>`（绑定出口 IP）
  - `routing_mark: Option<u32>`（fwmark，对接已实现的 RoutingMark）
  - `tcp_fast_open: bool`
  - `tcp_multi_path: bool`（对接已实现的 MptcpConfig）
  - `domain_strategy: DomainStrategy`（prefer_ipv4 / prefer_ipv6 / ipv4_only / ipv6_only）
  - `connect_timeout: Duration`
  - `happy_eyeballs: bool`（对接已实现的 HappyEyeballs）
- 所有出站通过 Dialer 创建连接，而非直接 `TcpStream::connect()`
- 全局默认 dialer + 每出站可覆盖

### H3. 连接池集成
**现状**：`pool.rs` 已实现连接池但未接入任何出站
**改动**：
- Direct 出站可选启用连接池（keep-alive 复用）
- HTTP 出站连接池复用
- 连接池与 Dialer 结合

### H4. rule-provider HTTP 远程规则集
**现状**：provider.rs 支持本地文件加载，缺少 HTTP 远程自动更新
**改动**：
- `RuleProviderConfig` 添加 `url: Option<String>` 和 `interval: u64`
- 启动时下载远程规则集，保存到本地缓存目录
- 定时检查更新（基于 interval 和 If-Modified-Since）
- 下载失败时回退到本地缓存

### H5. GeoIP / GeoSite 自动下载
**现状**：需手动准备 .mmdb / geosite 文件
**改动**：
- 首次运行时自动下载（从 GitHub release）
- 支持配置自定义下载 URL
- 定时更新检查（每周一次）
- 数据目录：`~/.openworld/data/` 或配置指定

### H6. LoadBalance 完善
**现状**：loadbalance.rs 只有基础随机选择
**改动**：
- 添加策略：round-robin、consistent-hash（基于目标地址 hash）、sticky（基于源地址 hash，已有 `sticky.rs`）
- 配置格式：`strategy: round-robin | random | consistent-hash | sticky`
- 与 latency_weighted.rs 结合支持加权选择

---

## 第三阶段：CLI 与用户体验（Priority: HIGH）

### U1. CLI 子命令系统
**现状**：只有 `cargo run -- config.yaml` 一种用法
**改动**：
- 添加 `clap` 依赖（CI 中已间接依赖 criterion 引入了 clap）
- 子命令：
  - `run` — 启动代理（默认命令）
  - `check` — 验证配置文件语法和语义
  - `format` — 格式化配置文件（规范化输出）
  - `version` — 输出版本和构建信息
  - `encrypt-config` / `decrypt-config` — 配置文件加解密（对接已实现的 encryption.rs）
  - `generate` — 生成示例配置 / systemd unit / 自启注册表
  - `convert` — 导入 clash/sing-box 配置（对接已实现的 compat.rs）

### U2. 信号处理与优雅关闭
**现状**：CancellationToken 存在但 relay 不监听，进程 kill 时连接强制断开
**改动**：
- main.rs 注册 SIGINT/SIGTERM/CTRL+C 处理
- 收到信号后：停止接受新连接 → 等待活跃连接完成（最多 30s）→ 强制关闭
- relay 中添加 CancellationToken 监听，收到取消后 gracefully 关闭双向流

### U3. 热重载完善
**现状**：API 有 reload_config 端点，但缺少文件监听自动重载
**改动**：
- 支持 SIGHUP 触发热重载（Linux）
- 可选 fs watcher 监听 config.yaml 变更自动重载
- 热重载范围：router rules、outbound list、DNS 配置、proxy groups
- 不可热重载：inbound listen 地址/端口（需重启）

---

## 第四阶段：API 与面板（Priority: MEDIUM）

### M1. 完善 RESTful API（对齐 clash API 规范）
**现状**：已有 /proxies, /connections, /rules, /traffic, /logs 等基础端点
**缺少的端点**：
- `GET /dns/query?name=xxx&type=A` — DNS 查询接口
- `POST /dns/flush` — 清空 DNS 缓存
- `PUT /proxies/:group/:name` — 切换代理组中的节点
- `PATCH /proxies/:name/delay` — 批量测速
- `GET /providers/proxies` — 代理提供者列表
- `PUT /providers/proxies/:name` — 刷新代理提供者
- `GET /providers/rules/:name` — 规则提供者详情
- `PUT /providers/rules/:name` — 刷新规则提供者
- `GET /configs` — 获取当前运行配置
- `PATCH /configs` — 修改运行时配置（已有但需扩展）

### M2. 静态文件服务（Web 面板支持）
**改动**：
- API 服务器添加 `external-ui` 配置项
- 挂载指定目录到 `/ui/` 路径
- 支持 Yacd / Metacubexd / Zashboard 等面板
- 自动下载面板到 `external-ui-path` 目录（可选）

### M3. 流量实时推送增强
**现状**：/traffic WebSocket 存在但功能有限
**改动**：
- 每秒推送全局上传/下载速度
- 每连接实时流量推送
- 内存使用量推送
- 支持 SSE（Server-Sent Events）备选

---

## 第五阶段：高级代理特性（Priority: MEDIUM）

### A1. UDP Full Cone NAT
**现状**：UDP 通过 NAT 表转发，但不保证 Full Cone 语义
**改动**：
- 确保同一 (src_ip, src_port) 映射到固定出站端口
- 支持外部主机主动发包到映射端口
- 对 QUIC、游戏、VoIP 等场景至关重要

### A2. 嗅探增强
**现状**：sniff.rs 支持 TLS SNI 和 HTTP Host 提取
**需补充**：
- QUIC SNI 嗅探（QUIC Initial 包 → Client Hello → SNI）
- BitTorrent 协议识别（已有基础）
- SSH 协议识别
- 按嗅探结果做路由决策（不仅覆盖 target，也用于规则匹配）

### A3. Shadowsocks 2022 (SIP022)
**现状**：Shadowsocks 已支持 AEAD，但 2022 协议新特性未确认
**改动**：
- 确认 `2022-blake3-aes-128-gcm` / `2022-blake3-aes-256-gcm` 加密方法
- 基于 identity key 的多用户支持
- UDP 地址类型头

### A4. Hysteria2 完善
**改动**：
- Bandwidth hint（带宽提示，优化拥塞控制）
- 连接迁移（QUIC connection migration）
- 0-RTT

### A5. ECH (Encrypted Client Hello) 实战集成
**现状**：ech.rs 有基础框架
**改动**：
- 自动从 DNS HTTPS 记录获取 ECH 配置
- GREASE ECH 支持（已有）
- 与各出站协议的 TLS 层集成验证

---

## 第六阶段：性能与稳定性（Priority: MEDIUM）

### P1. 零拷贝 relay
**改动**：
- Linux: 使用 `splice()` 系统调用实现零拷贝转发
- 对非 TLS 的 direct 连接使用 sendfile/splice
- Windows: 使用 TransmitFile API（如果适用）
- 回退到 copy_bidirectional

### P2. 内存池
**改动**：
- 为频繁分配的 buffer（relay buffer、DNS 包、mux frame）引入对象池
- 使用 `bytes::BytesMut` 池化分配
- 减少 GC 压力和内存碎片

### P3. 连接数限制与背压
**改动**：
- 全局最大连接数限制（默认 10000）
- 每入站最大连接数限制
- 超限时拒绝新连接并记录日志
- Semaphore 实现（已有但未接入）

### P4. DNS 缓存预取
**改动**：
- TTL 到期前 N 秒自动后台刷新缓存
- 热门域名自动预热
- 减少首次解析延迟

---

## 第七阶段：错误处理与可观测性（Priority: MEDIUM）

### O1. 自定义错误类型体系
**现状**：大量 `anyhow::bail!`，缺少分类
**改动**：
- 新建 `src/common/errors.rs`
- 分类枚举：
  ```rust
  enum ProxyError {
      ConnectionRefused,
      ConnectionTimeout,
      DnsResolutionFailed,
      AuthenticationFailed,
      ProtocolError(String),
      TlsHandshakeFailed,
      CircuitBreakerOpen,
      RateLimited,
      Cancelled,
  }
  ```
- 上层可据此做差异化处理（重试 vs 立即失败 vs 切换节点）

### O2. Prometheus metrics 导出
**改动**：
- `/metrics` 端点，Prometheus 格式
- 指标：活跃连接数、总连接数、流量统计、延迟分布、DNS 缓存命中率、错误计数
- 可对接 Grafana 监控面板

### O3. 结构化访问日志
**改动**：
- 每条连接结束时输出标准格式访问日志
- 包含：时间、源地址、目标、协议、入站、出站、规则、流量、延迟、结果
- 支持输出到文件（可选 JSON 格式）

---

## 第八阶段：生态与兼容（Priority: LOW）

### E1. clash 配置完整导入
**现状**：compat.rs 有基础解析，但协议/规则映射不完整
**改动**：
- 完善 proxy 类型映射（所有 clash.meta 支持的协议）
- rule-provider 远程 URL 导入
- proxy-group 完整映射
- 输出转换 warning（不支持的特性列表）

### E2. sing-box 配置导入
**改动**：
- 新建 `src/config/singbox_compat.rs`
- 解析 sing-box JSON 配置格式
- 映射 inbound / outbound / route / dns 到 OpenWorld 格式

### E3. URI 链接解析
**改动**：
- 解析标准代理 URI 格式：
  - `vless://uuid@host:port?...`
  - `vmess://base64...`
  - `ss://method:password@host:port`
  - `trojan://password@host:port`
  - `hysteria2://password@host:port`
  - `tuic://uuid:password@host:port`
- 用于订阅解析和快速添加节点

### E4. 分享链接生成
**改动**：
- 反向：从 OutboundConfig 生成标准代理 URI
- 用于导出配置、分享节点

---

## 第九阶段：平台能力（Priority: LOW）

### L1. Windows 系统代理设置
**改动**：
- 通过注册表 `HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings` 设置/取消系统代理
- 启动时自动设置，关闭时自动恢复

### L2. Linux nftables/iptables 透明代理自动配置
**改动**：
- 自动生成 iptables/nftables 规则（REDIRECT / TPROXY）
- 启动时应用，关闭时清理
- 支持 cgroup 分流

### L3. 多配置文件合并
**改动**：
- 支持 `include` 指令引入多个配置文件
- 支持配置片段合并（outbound 列表、rule 列表可分文件管理）
- 环境变量替换：`${ENV_VAR}` 语法

---

## 执行优先级总览

```
阶段      优先级      预估工作量     依赖
─────────────────────────────────────────
第一阶段   CRITICAL   ~1500 行      无
第二阶段   HIGH       ~2000 行      第一阶段
第三阶段   HIGH       ~800 行       第一阶段
第四阶段   MEDIUM     ~1200 行      第二/三阶段
第五阶段   MEDIUM     ~1500 行      第二阶段
第六阶段   MEDIUM     ~800 行       第一阶段
第七阶段   MEDIUM     ~600 行       第一阶段
第八阶段   LOW        ~1000 行      第二阶段
第九阶段   LOW        ~500 行       第三阶段
─────────────────────────────────────────
总计                  ~9900 行
```

## 建议执行顺序

```
C1 → C2 → C5 → C3+C4 → H2 → H1 → U1 → U2 → H3 → H4 → H5
→ M1 → M2 → A1 → A2 → P1 → P3 → O1 → O2 → O3
→ H6 → U3 → M3 → A3 → A4 → A5 → P2 → P4
→ E1 → E2 → E3 → E4 → L1 → L2 → L3
```

先把代理内核的核心链路（C1-C5）修到真正能用，
再补齐对标竞品的差异化功能（H1-H6, U1-U3），
最后打磨生态兼容和平台能力。
