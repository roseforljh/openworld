# OpenWorld 补全计划（100% Completion Plan）

> 基线：647 测试通过，Phase 10-20 整体完成度 ~85%
> 目标：将所有 Phase 推至 100%，不遗漏任何计划项
> 约束：不兼容 macOS（跳过所有 macOS 相关项）

---

## 一、Phase 10 DNS 策略引擎（当前 90% → 100%）

### T10.1 DoQ (DNS over QUIC) 客户端
- 在 `src/dns/resolver.rs` 新增 `DoQResolver`
- 复用 quinn QUIC 栈，DNS 消息通过 QUIC stream 发送（RFC 9250）
- 支持配置格式：`quic://dns.example.com:853`
- 在 `build_resolver()` 中识别 `quic://` 前缀

### T10.2 EDNS Client Subnet (ECS) 支持
- 在 DNS 查询构建中附加 OPT RR (type 41) + ECS option (code 8)
- 支持配置 `edns-client-subnet: 1.2.3.0/24`
- 应用于 DoH/DoT/UDP 所有上游

### 测试
- DoQ 地址解析测试
- ECS option 编码/解码测试
- build_resolver 识别 quic:// 前缀测试

---

## 二、Phase 11 TUN 全功能（当前 85% → 100%）

### T11.1 Windows wintun 驱动集成
- 在 `src/proxy/inbound/tun_device.rs` 实现 `WintunDevice: TunDevice`
- 通过 wintun.dll FFI 调用（LoadLibrary 动态加载）
- 创建适配器、读/写 IP 包、设置 MTU
- ring buffer 读写模型

### T11.2 Linux tun 设备创建
- 实现 `LinuxTunDevice: TunDevice`
- 通过 `ioctl(TUNSETIFF)` 创建 tun 设备
- 设置 IFF_TUN | IFF_NO_PI 标志
- 通过 `ip link` / `ip addr` 配置地址

### T11.3 ICMP 透传
- IP 包解析器识别 ICMP (protocol=1) / ICMPv6 (protocol=58)
- 选项：透传到出站 raw socket 或静默丢弃
- 配置开关 `tun.icmp: passthrough | drop`

### 测试
- wintun 设备模拟创建/销毁测试 (cfg(windows))
- Linux tun 设备参数构建测试 (cfg(linux))
- ICMP 包识别与策略测试

---

## 三、Phase 12 协议矩阵（当前 90% → 100%）

### T12.1 VMess AlterID 兼容
- 在 `src/proxy/outbound/vmess/protocol.rs` 支持 legacy 认证头
- AlterID > 0 时使用 MD5+Timestamp 认证（非 AEAD）
- 在 OutboundSettings 增加 `alter_id: Option<u16>` 字段

### T12.2 WireGuard 多 Peer + Keepalive
- 在 `src/proxy/outbound/wireguard/mod.rs` 扩展 `WireGuardPeer` 列表
- 支持 `peers: [{public_key, endpoint, allowed_ips, keepalive}]` 配置
- 实现 persistent keepalive 定时发送
- Peer 选择逻辑：按 allowed_ips 匹配目标地址

### T12.3 Tor 出站（可选）
- 新建 `src/proxy/outbound/tor.rs`
- 通过本地 SOCKS5 代理连接 Tor（依赖外部 tor 进程或 arti crate）
- 配置格式：`protocol: tor, settings: {socks_port: 9050}`
- 标注为 optional feature gate `[features] tor = ["arti-client"]`

### 测试
- AlterID legacy 认证头编码测试
- 多 Peer 配置解析与选择测试
- Keepalive 间隔配置测试
- Tor SOCKS5 地址构建测试

---

## 四、Phase 13 Mux（当前 95% → 100%）

### T13.1 背压与流控
- sing-mux: 实现窗口级流控（per-stream receive window）
- 当 stream 的未读缓冲超过阈值时暂停读取上游帧
- H2Mux: 利用 HTTP/2 原生 WINDOW_UPDATE 实现背压
- 新增 `MuxBackpressure` 结构管理窗口

### 测试
- 窗口满时暂停读取测试
- 窗口恢复后继续读取测试
- H2Mux 流控边界测试

---

## 五、Phase 14 高级路由（当前 90% → 100%）

### T14.1 IP 前缀树加速
- 在 `src/router/trie.rs` 新增 `IpPrefixTrie`
- 使用二进制 trie（按 bit 逐位匹配）存储 CIDR 规则
- 替代当前 `ipnet::IpNet` 的线性遍历匹配
- 支持 IPv4 (32-bit) 和 IPv6 (128-bit)

### T14.2 Sub-Rules 路由完整集成
- 将 `ops.rs` 中的 `SubRule` 集成到 `Router::match_rule()` 流程
- 在 RouterConfig 中支持 `sub-rules:` 配置段
- 当外层规则命中后进入子规则链继续匹配

### T14.3 惰性规则集加载
- rule-set provider 支持 `lazy: true` 配置
- 首次匹配到该 provider 时才触发加载
- 加载前所有引用该 provider 的规则返回 no-match

### 测试
- IpPrefixTrie CIDR 插入与最长前缀匹配测试
- IPv4 / IPv6 前缀树测试
- Sub-Rules 嵌套路由端到端测试
- 惰性加载触发时机测试

---

## 六、Phase 15 代理链与策略（当前 90% → 100%）

### T15.1 代理链健康检查
- `ProxyChain` 增加 `health_check()` 方法
- 逐跳检测：chain[0] → chain[1] → ... → target
- 任意一跳失败则标记整条链为不可用
- 与 url-test/fallback 组集成

### T15.2 策略结果持久化
- 新建 `src/proxy/group/persistence.rs`
- selector 当前选中节点、url-test 最优节点写入文件
- 启动时读取恢复，避免每次重启都重新测速
- 文件格式：JSON `{"selector-group": "node-name", ...}`

### 测试
- 代理链健康检查全通过 / 中间断开测试
- 持久化写入/读取/恢复测试
- 文件不存在时降级为默认行为测试

---

## 七、Phase 16 订阅系统（当前 95% → 100%）

### T16.1 自定义格式适配器接口
- 定义 `trait SubscriptionParser { fn parse(&self, content: &str) -> Result<Vec<ProxyNode>>; }`
- 内置解析器实现该 trait（Base64Parser, ClashYamlParser, SingBoxParser, Sip008Parser）
- 支持注册自定义 parser：`subscription.register_parser("custom", Box::new(...))`

### T16.2 Profile 系统
- 新建 `src/config/profile.rs`
- Profile = 一组预定义的 inbound/outbound/rule 组合
- 支持 `profile: gaming` / `profile: streaming` 快速切换
- 内置 profiles：default, minimal, full

### 测试
- 自定义 parser 注册与调用测试
- Profile 加载/切换测试
- Profile 不存在时报错测试

---

## 八、Phase 17 流量处理（当前 85% → 100%）

### T17.1 MPTCP (Multipath TCP)
- 在 `src/common/traffic.rs` 新增 `MptcpConfig`
- Linux: 设置 `IPPROTO_MPTCP` (protocol 262) socket option
- Windows: 检测系统支持并设置 SIO_ENABLE_MPTCP
- 降级：不支持时回退到普通 TCP

### T17.2 fwmark / routing mark
- 在 `src/common/traffic.rs` 新增 `RoutingMark`
- Linux: `setsockopt(SO_MARK, fwmark)` 设置出站包标记
- Windows: 通过 `bind()` 到特定接口实现等效功能
- 配置：`routing-mark: 233` 或 `fwmark: 0xFF`

### 测试
- MPTCP 配置构建测试
- fwmark socket option 参数测试
- 平台不支持时降级测试

---

## 九、Phase 18 平台适配（当前 60% → 100%，跳过 macOS/iOS）

### T18.1 交叉编译验证
- 在 CI workflow 中添加 armv7 / mips / riscv64 target
- 使用 `cross` 工具进行交叉编译
- 确保 `cargo check --target <target>` 通过

### T18.2 Android JNI 接口
- 新建 `src/app/android.rs`
- 使用 `jni` crate 导出 Java native 方法
- 核心接口：`Java_com_openworld_Core_start(env, config_path)`
- VpnService helper：`configure_tun_fd(fd: i32)`
- feature gate: `[features] android = ["jni"]`

### T18.3 开机自启配置生成
- Windows: 生成注册表 .reg 文件 (HKLM\...\Run)
- Linux: ServiceConfig 已有 systemd unit 生成
- 新增 `ServiceConfig::autostart_registry_command()` 生成 reg add 命令

### 测试
- Android JNI 方法签名正确性测试（无需实际 JVM）
- 自启配置命令生成测试
- CI 交叉编译目标列表完整性测试

---

## 十、Phase 19 运维与生产级（当前 90% → 100%）

### T19.1 配置文件加密存储
- 新建 `src/config/encryption.rs`
- 使用 AES-256-GCM 加密配置文件
- 密钥派生：PBKDF2(password, salt, 100000 iterations)
- 文件格式：`[8B salt][12B nonce][encrypted_data][16B tag]`
- CLI 命令概念：`openworld encrypt-config` / `openworld decrypt-config`

### T19.2 证书管理
- 新建 `src/app/cert.rs`
- 自签证书生成（用于入站 TLS 服务端）
- 证书到期检测与告警
- 支持从 PEM 文件加载证书+私钥
- OCSP stapling 接口预留

### T19.3 连接级 tracing span 闭环
- 在 Dispatcher 中为每个连接创建 `tracing::span!`
- span 包含：conn_id, target, inbound_tag, outbound_tag, matched_rule
- 连接关闭时自动 close span 并记录 duration

### 测试
- AES-256-GCM 加解密往返测试
- PBKDF2 密钥派生确定性测试
- 自签证书生成与解析测试
- 证书到期检测测试
- tracing span 创建与关闭测试

---

## 十一、Phase 20 CI/CD（当前 60% → 100%）

### T20.1 Changelog 自动生成
- 在 release workflow 中使用 `git-cliff` 或 `conventional-changelog`
- 基于 conventional commits 格式自动生成 CHANGELOG.md
- Release 时附带到 GitHub Release notes

### T20.2 Docker 镜像自动推送
- 在 release workflow 中添加 Docker build + push 步骤
- 推送到 GitHub Container Registry (ghcr.io)
- 多架构支持：linux/amd64 + linux/arm64
- Tag: `ghcr.io/owner/openworld:latest` + `ghcr.io/owner/openworld:vX.Y.Z`

### T20.3 质量门禁
- CI 中添加 `cargo test` 失败则阻断合并
- clippy warnings 视为 error (`-D warnings` 已有)
- cargo audit 发现 RUSTSEC 漏洞时阻断
- 覆盖率低于 60% 时 warning（不阻断）
- 在 ci.yml 中添加 benchmark 回归检测 job

### T20.4 性能基准自动对比
- 使用 `criterion` 添加基准测试
- 新建 `benches/` 目录：router_match, dns_resolve, mux_throughput
- CI 中运行 benchmark 并与 main 分支对比
- 回归超过 10% 时输出 warning

### 测试
- CI workflow 语法验证 (actionlint)
- Docker 多阶段构建本地验证
- Changelog 生成格式验证

---

## 执行顺序

```
T10 (DoQ+ECS)           ─┐
T12 (AlterID+WG+Tor)    ─┤
T14 (IP前缀树+SubRule)  ─┼─→ cargo test 验证
T17 (MPTCP+fwmark)      ─┤
T13 (背压流控)           ─┘

T11 (wintun+linux tun)  ─┐
T15 (链健康+持久化)      ─┼─→ cargo test 验证
T16 (适配器+Profile)     ─┘

T19 (加密+证书+tracing) ─┐
T18 (Android+自启+CI)    ─┼─→ cargo test 验证
T20 (Changelog+Docker)   ─┘
```

## 预估新增

| 模块 | 新增代码行 | 新增测试数 |
|------|----------|----------|
| T10 DoQ+ECS | ~300 | ~8 |
| T11 wintun+linux+ICMP | ~400 | ~10 |
| T12 AlterID+WG多Peer+Tor | ~350 | ~12 |
| T13 背压流控 | ~200 | ~6 |
| T14 IP前缀树+SubRule集成+惰性 | ~350 | ~12 |
| T15 链健康+持久化 | ~250 | ~8 |
| T16 适配器+Profile | ~250 | ~8 |
| T17 MPTCP+fwmark | ~200 | ~6 |
| T18 Android+自启+CI | ~300 | ~8 |
| T19 加密+证书+tracing | ~350 | ~12 |
| T20 Changelog+Docker+门禁+benchmark | ~200 | ~6 |
| **总计** | **~3,150** | **~96** |

完成后预期：**~743 测试通过，所有 Phase 100% 完成**
