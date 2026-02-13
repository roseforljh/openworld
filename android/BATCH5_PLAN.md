# Batch 5: 内核集成完善 — 详细计划

## 概述

将 Rust 内核完整集成到 Android 前端，补全所有缺失的桥接代码、优化日志系统、增强 VPN Service 和配置管理。

---

## Task 1: CoreRepository 补全

**文件:** `app/src/main/java/com/openworld/app/repository/CoreRepository.kt`

### 新增数据类

```
ProviderInfo(name: String, url: String, nodeCount: Int, lastUpdated: Long)
ProviderNode(name: String, type: String, server: String, port: Int, delay: Int)
OutboundInfo(tag: String, type: String, alive: Boolean)
RuleInfo(index: Int, type: String, payload: String, outbound: String)
```

### 新增方法

| 分类 | 方法 | 对应 JNI |
|---|---|---|
| 暂停/恢复 | `pause()`, `resume()`, `isPaused()` | 同名 |
| 出站管理 | `selectOutbound(tag): Boolean`, `listOutbounds(): List<OutboundInfo>` | selectOutbound, listOutbounds |
| 连接管理 | `resetAllConnections(system: Boolean)`, `closeIdleConnections(secs): Long`, `resetTrafficStats()` | 同名 |
| 配置 | `reloadConfig(config): Boolean` | reloadConfig |
| Provider | `listProviders(): List<ProviderInfo>` | listProviders |
| Provider | `getProviderNodes(name): List<ProviderNode>` | getProviderNodes |
| Provider | `addHttpProvider(name, url, interval): Boolean` | addHttpProvider |
| Provider | `updateProvider(name): Int` | updateProvider |
| Provider | `removeProvider(name): Boolean` | removeProvider |
| 订阅 | `importSubscription(url): String?` | importSubscription |
| 规则 | `listRules(): List<RuleInfo>` | rulesList (已有 getRoutingRuleCount，补全完整解析) |
| 规则 | `addRule(json): Int` | rulesAdd |
| 规则 | `removeRule(index): Boolean` | rulesRemove |
| GC/Geo | `gc(): Int` | gc |
| GC/Geo | `updateGeoDatabases(geoipPath, geoipUrl, geositePath, geositeUrl): Boolean` | updateGeoDatabases |
| 自动测速 | `startAutoTest(group, url, interval, timeout): Boolean` | startAutoTest |
| 自动测速 | `stopAutoTest(): Boolean` | stopAutoTest |
| 平台 | `notifyNetworkChanged(type, ssid, metered)` | notifyNetworkChanged |
| 平台 | `notifyMemoryLow()` | notifyMemoryLow |

### 实现要点

- 所有方法包裹 try-catch，返回安全默认值
- JSON 反序列化统一用 Gson + TypeToken
- 保持与现有方法一致的代码风格

---

## Task 2: LogRepository 优化

**文件:** `app/src/main/java/com/openworld/app/repository/LogRepository.kt`

### 改动点

1. **MAX_SIZE** 从 500 提升到 1000

2. **去重机制重写：**
   - 移除 `lastDigest: String`（比较整个 status JSON 字符串不合理）
   - 新增 `lastPullTimestamp: Long = 0`，记录上次拉取的最新日志时间戳
   - `pullFromCore()` 中只添加 `timestamp > lastPullTimestamp` 的日志条目
   - 每次拉取后更新 `lastPullTimestamp` 为本批次最大 timestamp
   - 对于无 timestamp 的日志，用 `(level, message)` 组合判断是否已存在

3. **新增方法：**
   - `size(): Int` — 返回当前缓冲区大小
   - `getFiltered(minLevel: Int): List<LogEntry>` — 按级别过滤，减少 UI 层开销

4. **clear() 同时重置 lastPullTimestamp**

---

## Task 3: ConfigManager 增强

**文件:** `app/src/main/java/com/openworld/app/config/ConfigManager.kt`

### 3.1 分应用代理管理

新增 SharedPreferences key：
```
KEY_BYPASS_APPS = "bypass_apps"          // 排除的应用包名，逗号分隔
KEY_PROXY_MODE_APPS = "proxy_mode_apps"  // "bypass"(排除模式) 或 "only"(仅代理模式)
```

新增方法：
```kotlin
fun getBypassApps(context: Context): Set<String>
fun setBypassApps(context: Context, apps: Set<String>)
fun getProxyModeApps(context: Context): String   // 默认 "bypass"
fun setProxyModeApps(context: Context, mode: String)
```

### 3.2 完善 generateConfig()

默认配置增加：
- TUN 入站添加 `"stack": "mixed"`
- TUN 入站添加 `"sniff_timeout": "300ms"`
- route 添加 `"default_interface": ""`

### 3.3 修复 validateConfig()

当前问题：用 `reloadConfig()` 验证会真的重载运行中的配置。

修复方案：
- 内核未运行时：尝试 JSON 解析验证格式，返回解析结果
- 内核运行中时：保持现有行为（reloadConfig 本身就是热重载）
- 添加 `isFormatValid(config): Boolean` 纯格式校验方法

### 3.4 订阅 URL 统一管理

从 ProfilesViewModel 提取到 ConfigManager：
```kotlin
fun getSubscriptionUrl(context: Context, profileName: String): String?
fun setSubscriptionUrl(context: Context, profileName: String, url: String)
fun removeSubscriptionUrl(context: Context, profileName: String)
```

使用独立 SharedPreferences `"profile_subscriptions"` 存储。

---

## Task 4: VPN Service 增强

**文件:** `app/src/main/java/com/openworld/app/service/OpenWorldVpnService.kt`

### 4.1 WakeLock 超时保护

```kotlin
// 改前
wakeLock?.acquire()

// 改后
private val WAKELOCK_TIMEOUT = 10 * 60 * 1000L  // 10分钟
wakeLock?.acquire(WAKELOCK_TIMEOUT)
```

在 notificationLoop 中每次循环检查并续期：
```kotlin
if (wakeLock?.isHeld != true) {
    wakeLock?.acquire(WAKELOCK_TIMEOUT)
}
```

### 4.2 stopVpn 幂等保护

```kotlin
private var stopping = false

private fun stopVpn() {
    if (stopping) return
    stopping = true
    try {
        // ... 现有停止逻辑
    } finally {
        stopping = false
    }
}
```

### 4.3 分应用代理支持

startVpn 中读取 ConfigManager 配置：
```kotlin
val bypassApps = ConfigManager.getBypassApps(this)
val proxyMode = ConfigManager.getProxyModeApps(this)

// 始终排除自身
builder.addDisallowedApplication(packageName)

when (proxyMode) {
    "only" -> bypassApps.forEach { pkg ->
        try { builder.addAllowedApplication(pkg) } catch (_: Exception) {}
    }
    else -> bypassApps.forEach { pkg ->
        if (pkg != packageName) {
            try { builder.addDisallowedApplication(pkg) } catch (_: Exception) {}
        }
    }
}
```

### 4.4 onTrimMemory

```kotlin
override fun onTrimMemory(level: Int) {
    super.onTrimMemory(level)
    if (level >= TRIM_MEMORY_MODERATE) {
        try { OpenWorldCore.notifyMemoryLow() } catch (_: Exception) {}
    }
    if (level >= TRIM_MEMORY_COMPLETE) {
        try { OpenWorldCore.gc() } catch (_: Exception) {}
    }
}
```

---

## Task 5: OpenWorldApp + VpnTileService 修复

### 5.1 OpenWorldApp.kt

添加 onTrimMemory：
```kotlin
override fun onTrimMemory(level: Int) {
    super.onTrimMemory(level)
    if (level >= TRIM_MEMORY_MODERATE) {
        try { OpenWorldCore.notifyMemoryLow() } catch (_: Exception) {}
    }
    if (level >= TRIM_MEMORY_COMPLETE) {
        try { OpenWorldCore.gc() } catch (_: Exception) {}
    }
}
```

### 5.2 VpnTileService.kt

**Bug 修复：** onClick 中状态切换后立即读取 isRunning() 不准确（内核启停需要时间）。

修复方案：
```kotlin
override fun onClick() {
    super.onClick()
    val wasRunning = OpenWorldCore.isRunning()
    if (wasRunning) {
        OpenWorldVpnService.stop(this)
    } else {
        OpenWorldVpnService.start(this)
    }
    // 立即反转状态（乐观更新）
    qsTile?.let {
        it.state = if (wasRunning) Tile.STATE_INACTIVE else Tile.STATE_ACTIVE
        it.updateTile()
    }
}
```

---

## Task 6: strings.xml 补全

**文件:** `app/src/main/res/values/strings.xml`

补全所有 UI 中硬编码的中文字符串：

```xml
<!-- 现有 7 个保留 -->

<!-- 通用 -->
<string name="vpn_status_disconnected">已断开</string>
<string name="vpn_status_error">连接错误</string>

<!-- 导航 -->
<string name="nav_dashboard">仪表盘</string>
<string name="nav_profiles">配置</string>
<string name="nav_nodes">节点</string>
<string name="nav_settings">设置</string>

<!-- Dashboard -->
<string name="dashboard_upload">上传</string>
<string name="dashboard_download">下载</string>
<string name="dashboard_connections">连接数</string>

<!-- Settings -->
<string name="settings_title">设置</string>
<string name="settings_routing">路由设置</string>
<string name="settings_dns">DNS 设置</string>
<string name="settings_connections">活跃连接</string>
<string name="settings_traffic">流量统计</string>
<string name="settings_logs">日志</string>
<string name="settings_about">关于</string>
<string name="settings_proxy_group">代理设置</string>
<string name="settings_monitor_group">监控</string>
<string name="settings_other_group">其他</string>

<!-- DNS -->
<string name="dns_title">DNS 设置</string>
<string name="dns_local_title">本地 DNS</string>
<string name="dns_local_desc">用于解析国内域名，建议使用运营商或公共 DNS</string>
<string name="dns_remote_title">远程 DNS</string>
<string name="dns_remote_desc">用于解析海外域名，支持 DoT/DoH 协议</string>
<string name="dns_saved">DNS 设置已保存</string>
<string name="dns_flush">清除 DNS 缓存</string>
<string name="dns_flush_ok">DNS 缓存已清除</string>
<string name="dns_flush_fail">DNS 缓存清除失败</string>
<string name="dns_protocols_title">支持的协议</string>

<!-- Routing -->
<string name="routing_title">路由设置</string>
<string name="routing_rule">规则模式</string>
<string name="routing_global">全局模式</string>
<string name="routing_direct">直连模式</string>
<string name="routing_rule_desc">根据规则智能分流，推荐日常使用</string>
<string name="routing_global_desc">所有流量走代理</string>
<string name="routing_direct_desc">所有流量直连，不经过代理</string>

<!-- Connections -->
<string name="conn_title">活跃连接</string>
<string name="conn_close_all">全部关闭</string>
<string name="conn_empty">暂无活跃连接</string>

<!-- Logs -->
<string name="logs_title">日志</string>
<string name="logs_filter_all">全部</string>
<string name="logs_empty">暂无日志</string>

<!-- Traffic -->
<string name="traffic_title">流量统计</string>
<string name="traffic_total_up">总上传</string>
<string name="traffic_total_down">总下载</string>
<string name="traffic_empty">暂无流量数据</string>

<!-- About -->
<string name="about_title">关于</string>
<string name="about_subtitle">高性能网络代理内核</string>
<string name="about_app_version">App 版本</string>
<string name="about_core_version">内核版本</string>
<string name="about_memory">内存占用</string>
<string name="about_tech">技术栈</string>

<!-- Profiles -->
<string name="profile_import_url">从 URL 导入</string>
<string name="profile_import_clipboard">从剪贴板导入</string>
<string name="profile_delete">删除</string>
<string name="profile_update">更新订阅</string>
<string name="profile_update_all">全部更新</string>
<string name="profile_empty">暂无配置</string>

<!-- Nodes -->
<string name="nodes_title">节点</string>
<string name="nodes_test">测速</string>
<string name="nodes_test_all">全部测速</string>
<string name="nodes_empty">暂无节点</string>
<string name="nodes_search_hint">搜索节点</string>

<!-- 通用操作 -->
<string name="action_back">返回</string>
<string name="action_save">保存</string>
<string name="action_refresh">刷新</string>
<string name="action_cancel">取消</string>
<string name="action_confirm">确认</string>
<string name="action_close">关闭</string>
```

---

## 执行顺序与依赖

```
Task 1 (CoreRepository)  ──┐
Task 2 (LogRepository)   ──┼── 并行执行，无依赖
Task 6 (strings.xml)     ──┘
            │
Task 3 (ConfigManager)   ── 依赖 Task 1（引用部分方法）
            │
Task 4 (VPN Service)     ── 依赖 Task 3（读取分应用配置）
            │
Task 5 (App + Tile)      ── 无强依赖，最后执行
```

## 涉及文件清单

| 文件 | 操作 |
|---|---|
| `repository/CoreRepository.kt` | 大幅扩展 |
| `repository/LogRepository.kt` | 重写去重逻辑 |
| `config/ConfigManager.kt` | 扩展分应用代理 + 订阅管理 |
| `service/OpenWorldVpnService.kt` | 增强 WakeLock + 分应用 + 幂等 |
| `OpenWorldApp.kt` | 添加 onTrimMemory |
| `service/VpnTileService.kt` | 修复状态切换 |
| `res/values/strings.xml` | 补全 60+ 字符串 |
