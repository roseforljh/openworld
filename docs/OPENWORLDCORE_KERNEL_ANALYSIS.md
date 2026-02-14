# OpenWorldCore 内核逻辑与 API 全量分析（Android 集成视角）

## 1. 分析范围与代码基线

本分析基于以下关键文件：

- Android API 声明：`android/app/src/main/java/com/openworld/core/OpenWorldCore.kt`
- JNI 导出层：`src/app/android.rs`
- FFI 实现层：`src/app/ffi.rs`
- 内核装配与主循环：`src/app/mod.rs`
- 数据平面分发：`src/app/dispatcher.rs`
- 入站管理：`src/app/inbound_manager.rs`
- 出站管理：`src/app/outbound_manager.rs`
- 路由核心：`src/router/mod.rs`
- 连接与流量状态：`src/app/tracker.rs`
- 平台状态：`src/app/platform.rs`

---

## 2. 内核总体逻辑（分层）

### 2.1 Android -> JNI -> FFI 调用链

1. Android 调用 `OpenWorldCore` 的 `external fun`。
2. JNI 对应 `Java_com_openworld_core_OpenWorldCore_*`（`src/app/android.rs`）。
3. JNI 再调用 `ffi::openworld_*`（`src/app/ffi.rs`）。
4. FFI 访问/修改全局内核实例 `OpenWorldInstance`，并通过 Tokio runtime 驱动实际逻辑。

### 2.2 内核主装配（`App`）

`App::new`（`src/app/mod.rs`）会构建：

- `Router`（规则匹配）
- `OutboundManager`（出站与代理组）
- `DnsResolver`
- `ConnectionTracker`
- `Dispatcher`（TCP/UDP 数据平面核心）
- `InboundManager`（入站监听器）

`App::run` 会启动：

- 系统代理/透明代理（按配置）
- provider 刷新任务
- DNS prefetch
- API 服务（若配置）
- DERP 服务（若配置）
- 最后阻塞在 `inbound_manager.run()`

### 2.3 运行时数据流

#### TCP 流

`InboundManager` 接受连接 -> `InboundHandler.handle` -> `Dispatcher::dispatch`

在 `dispatch` 内：

- 可选协议嗅探
- FakeIP 反查
- Clash 模式/路由规则决策
- 调用对应 outbound 建连
- `relay_proxy_streams` 转发
- 连接与流量由 `ConnectionTracker` 统计

#### UDP 流

`Dispatcher::dispatch_udp` + `NatTable`（Full Cone NAT）

- 按源流创建/复用 NAT 映射
- 转发到出站 UDP transport
- 回包反向写回 inbound

### 2.4 全局关键状态

`src/app/ffi.rs` 中：

- `INSTANCE: OnceLock<Mutex<Option<OpenWorldInstance>>>`
- `OpenWorldInstance` 关键字段：
  - `runtime`
  - `cancel_token`
  - `tracker`
  - `outbound_manager`
  - `paused`
  - `tun_fd`
  - `profile_manager`
  - `provider_manager`
  - `auto_test_cancel`
  - `custom_rules`
  - `wakelock_held`

---

## 3. 生命周期链路（启动/运行/停止）

### 3.1 启动

`OpenWorldCore.start(config)`
-> `Java_com_openworld_core_OpenWorldCore_start`
-> `openworld_start`
-> 解析配置（JSON/YAML/兼容解析）
-> 创建 runtime
-> spawn `App::new(...).run()`

### 3.2 运行

- 入站持续监听并交由 dispatcher 分发
- 路由规则与代理组持续生效
- 统计/延迟/provider 等接口读写 `OpenWorldInstance` 内状态

### 3.3 停止

`OpenWorldCore.stop()`
-> `Java_com_openworld_core_OpenWorldCore_stop`
-> `openworld_stop`
-> `cancel_token.cancel()` + drop instance/runtime

---

## 4. API 一致性审计结论（重点）

### 4.1 总量

- Kotlin `external fun`：73 个
- JNI `Java_com_openworld_core_OpenWorldCore_*`：73 个

### 4.2 名称映射

- Kotlin 与 JNI 的 API 名称已对齐（无缺失项）

### 4.3 当前重点风险

当前主要风险从“签名不一致”转移到“语义选择”：

1. 部分接口返回 `Int`（数量/错误码）与 `Boolean`（成功/失败）并存，需要调用方统一约定。
2. `notifyNetworkChanged` 与 `notifyMemoryLow` 为 `Unit` 风格调用，业务层应使用统一异常保护策略。
3. 兼容方法与原生方法同时存在时，应优先使用原生方法，避免重复封装漂移。

---

## 5. 全量 API 详细说明（按 Kotlin 声明顺序）

说明格式：

- **功能**：接口作用
- **参数**：关键参数语义
- **返回**：返回值语义
- **实现现状**：在 FFI 中的实际行为

### 5.1 生命周期

1. `start(config: String): Int`
- 功能：启动内核
- 返回：`0` 成功；负值失败
- 实现现状：创建 runtime 并异步运行 `App::run`

2. `stop(): Int`
- 功能：停止内核
- 返回：`0` 成功
- 实现现状：取消 token，释放实例

3. `isRunning(): Boolean`
- 功能：查询是否运行
- 实现现状：检查全局 `INSTANCE` 是否存在

4. `version(): String`
- 功能：获取版本
- 实现现状：返回 `CARGO_PKG_VERSION`

### 5.2 暂停/恢复

5. `pause(): Boolean`
- 功能：标记暂停
- 实现现状：写 `paused=true`

6. `resume(): Boolean`
- 功能：标记恢复
- 实现现状：写 `paused=false`

7. `isPaused(): Boolean`
- 功能：读取暂停状态

### 5.3 出站管理

8. `selectOutbound(tag: String): Boolean`
- 功能：切换到指定出站（在组内选择）
- 实现现状：遍历代理组并执行 `select_proxy`

9. `getSelectedOutbound(): String?`
- 功能：获取当前组选中出站

10. `listOutbounds(): String?`
- 功能：列出出站 tag（换行拼接）

11. `hasSelector(): Boolean`
- 功能：是否存在 selector 组

### 5.4 流量统计

12. `getTrafficTotalUplink(): Long`
13. `getTrafficTotalDownlink(): Long`
14. `resetTrafficStats(): Boolean`
- 功能：总上传/总下载/重置统计
- 实现现状：来自 `ConnectionTracker`

### 5.5 连接管理

15. `getConnectionCount(): Long`
- 功能：活跃连接数

16. `resetAllConnections(sys: Boolean): Boolean`
- 功能：关闭全部连接
- 实现现状：`sys` 参数目前仅透传未区分逻辑

17. `closeAllTrackedConnections(): Int`
- 功能：关闭全部跟踪连接
- 实现现状：**Kotlin 有声明，JNI 缺失（不可用）**

18. `closeIdleConnections(secs: Long): Long`
- 功能：关闭空闲连接

### 5.6 网络恢复/TUN

19. `recoverNetworkAuto(): Boolean`
- 功能：自动网络恢复
- 实现现状：当前主要执行 `close_all` 触发重建

20. `setTunFd(fd: Int): Int`
- 功能：设置 Android TUN fd
- 实现现状：仅写入 `OpenWorldInstance.tun_fd`

### 5.7 热重载与组管理

21. `reloadConfig(config: String): Int`
- 功能：热重载配置
- 实现现状：当前主要关闭连接，未完整重建组件

22. `getProxyGroups(): String?`
- 功能：获取代理组详情 JSON

23. `setGroupSelected(group: String, proxy: String): Boolean`
- 功能：设置组内选中

24. `testGroupDelay(group: String, url: String, timeoutMs: Int): String?`
- 功能：对组成员批量测速，返回 JSON

### 5.8 活跃连接/快照

25. `getActiveConnections(): String?`
- 功能：获取活跃连接 JSON

26. `closeConnectionById(id: Long): Boolean`
- 功能：关闭指定连接

27. `getTrafficSnapshot(): String?`
- 功能：获取总流量+分组流量+连接数 JSON

### 5.9 订阅与 DNS

28. `importSubscription(url: String): String?`
- 功能：拉取并解析订阅
- 实现现状：返回包含 `raw_content` 与节点摘要的 JSON

29. `setSystemDns(dns: String): Boolean`
- 功能：设置系统 DNS
- 实现现状：当前记录设置，实际重建 resolver 逻辑有限

30. `urlTest(tag: String, url: String, timeoutMs: Int): Int`
- 功能：单节点延迟测试
- 返回：毫秒或负值

### 5.10 Clash/DNS/状态

31. `getClashMode(): String?`
32. `setClashMode(mode: String): Boolean`
- 功能：读取/设置 Clash 模式（rule/global/direct）

33. `dnsQuery(name: String, qtype: String): String?`
- 功能：DNS 查询，返回 JSON

34. `dnsFlush(): Boolean`
- 功能：清空 DNS 缓存
- 实现现状：当前返回成功占位

35. `getMemoryUsage(): Long`
- 功能：获取内存使用估算

36. `getStatus(): String?`
- 功能：综合状态 JSON

37. `pollTrafficRate(): String?`
- 功能：轮询速率 JSON，并可触发回调

### 5.11 Profile 管理

38. `listProfiles(): String?`
- 功能：列出 profiles

39. `switchProfile(name: String): Boolean`
- 功能：按名称切换 profile

40. `getCurrentProfile(): String?`
- 功能：当前 profile 名称

41. `importProfile(name: String, content: String): Boolean`
- 功能：导入 profile 内容

42. `exportProfile(name: String): String?`
- 功能：按名称导出 profile

43. `deleteProfile(name: String): Boolean`
- 功能：按名称删除 profile

### 5.12 平台状态

44. `notifyNetworkChanged(networkType: Int, ssid: String, isMetered: Boolean): Unit`
- 功能：上报平台网络变化

45. `getPlatformState(): String?`
- 功能：读取平台状态 JSON

46. `notifyMemoryLow(): Unit`
- 功能：上报低内存事件

47. `isNetworkMetered(): Boolean`
- 功能：查询是否计费网络

### 5.13 Provider 管理

48. `listProviders(): String?`
49. `getProviderNodes(tag: String): String?`
50. `addHttpProvider(tag: String, url: String, interval: Long): Boolean`
51. `updateProvider(tag: String): Int`
52. `removeProvider(tag: String): Boolean`

说明：
- `updateProvider` 返回更新节点数（负值为失败）

### 5.14 延迟历史

53. `getDelayHistory(tagFilter: String): String?`
54. `clearDelayHistory(): Boolean`
55. `getLastDelay(tag: String): Int?`

说明：
- 传空字符串可获取全部延迟历史

### 5.15 自动测速

56. `startAutoTest(tag: String, url: String, intervalSecs: Int, timeoutMs: Int): Boolean`
57. `stopAutoTest(): Boolean`

### 5.16 系统维护

58. `gc(): Int`
- 功能：手动 GC（关闭空闲连接、收缩延迟历史）
- 返回：关闭空闲连接数量（负值为失败）

59. `updateGeoDatabases(geoipPath: String, geoipUrl: String, geositePath: String, geositeUrl: String): Boolean`
- 功能：更新 Geo 数据

### 5.17 规则管理

60. `rulesList(): String?`
61. `rulesAdd(rule: String): Int`
62. `rulesRemove(index: Int): Boolean`

说明：
- `rulesAdd` 返回添加后的规则总数（负值为失败）

### 5.18 WakeLock 与通知

63. `wakelockSet(acquire: Boolean): Boolean`
64. `wakelockHeld(): Boolean`
65. `notificationContent(): String?`

### 5.19 Zenone 与 HTTP

66. `convertSubscriptionToZenone(url: String): String?`
67. `zenoneToConfig(content: String): String?`
68. `isZenoneFormat(content: String): Boolean`
69. `fetchUrl(url: String): String?`

---

## 6. 现状结论

1. **内核主干逻辑完整**：具备生命周期、路由、分发、入站、出站、统计、provider、profile、平台状态等模块。
2. **Android 桥接数量对齐**：73 个 Kotlin API 对应 73 个 JNI 导出。
3. **当前主要问题转为语义一致性治理**：重点是业务层统一使用 Int/Unit 接口语义，减少兼容层漂移。
4. **可用性判定**：
   - 代码层面：功能覆盖广
   - 集成层面：签名已对齐，仍需继续做运行时行为回归验证

---

## 7. 建议的修复优先级（按风险）

P1（语义对齐）：

- `gc` 返回值
- `rulesAdd` / `updateProvider` 返回值
- `notifyMemoryLow` 返回语义
- `getDelayHistory` 过滤参数暴露

P2（实现增强）：

- `reloadConfig` 完整热更新（不仅仅 close_all）
- `setSystemDns` 的即时生效路径
