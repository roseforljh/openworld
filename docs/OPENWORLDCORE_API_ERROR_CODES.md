# OpenWorldCore API 错误码与返回语义参考

本文档用于 Android 侧统一处理 OpenWorldCore JNI/FFI 的返回语义。

## 1. 通用规则

- `Int` 返回值：通常 `0` 表示成功，负值表示失败。
- `Boolean` 返回值：`true` 成功，`false` 失败。
- `String?` 返回值：
  - 非空：通常是 JSON 或文本结果
  - 空/`null`：通常表示失败或无数据

## 2. 关键接口语义

### 生命周期

- `start(config): Int`
  - `0`: 成功
  - `<0`: 启动失败（参数、配置、运行时等）
- `stop(): Int`
  - `0`: 成功

### 连接与流量

- `closeAllTrackedConnections(): Int`
  - `>=0`: 关闭连接数量
  - `<0`: 失败
- `closeIdleConnections(secs): Long`
  - `>=0`: 关闭连接数量
- `gc(): Int`
  - `>=0`: 本次 GC 关闭的空闲连接数
  - `<0`: 失败

### Provider / Rules

- `updateProvider(tag): Int`
  - `>=0`: 更新成功，值为更新后的节点数量
  - `<0`: 失败
- `rulesAdd(rule): Int`
  - `>=0`: 添加后规则总数
  - `<0`: 失败

### 网络与平台

- `notifyNetworkChanged(networkType, ssid, isMetered): Unit`
  - 无返回值，异常由调用层捕获
- `notifyMemoryLow(): Unit`
  - 无返回值，异常由调用层捕获

## 3. 兼容辅助方法（Kotlin）

`OpenWorldCore.kt` 已提供一组兼容封装，便于老调用方平滑迁移：

- `switchProfileById(profileId: Long)`
- `exportProfileById(profileId: Long)`
- `deleteProfileById(profileId: Long)`
- `notifyNetworkChangedCompat(network: String, ssid: String, isMetered: Boolean)`
- `notifyMemoryLowSafe()`
- `updateProviderSuccess(tag: String)`
- `getDelayHistoryAll()`
- `startAutoTestMs(tag, url, intervalMs, timeoutMs)`
- `gcSuccess()`
- `updateGeoDatabasesByPath(geoipPath, geositePath)`
- `rulesAddSuccess(rule)`

建议：新代码优先调用“强语义”原生接口（`Int`/`Unit` 版本），仅在历史路径上使用兼容方法。
