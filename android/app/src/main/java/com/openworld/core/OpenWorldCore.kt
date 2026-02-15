package com.openworld.core

import android.util.Log

/**
 * OpenWorld Rust 内核的 Java/Kotlin 包装类
 *
 * 对应 Rust JNI 导出: src/app/android.rs
 * 类路径: com.openworld.core.OpenWorldCore
 *
 * 此类的 native 方法由 Rust 内核 (libopenworld.so) 实现
 */
object OpenWorldCore {
    private const val TAG = "OpenWorldCore"

    // ═══════════════════════════════════════════════════════════════════
    // 生命周期
    // ═══════════════════════════════════════════════════════════════════

    /**
     * 启动内核服务
     * @param config OpenWorld JSON 配置
     * @return 0=成功, -1=参数错误, -2=配置无效, -3=其他错误
     */
    external fun start(config: String): Int

    /**
     * 停止内核服务
     * @return 0=成功
     */
    external fun stop(): Int

    /**
     * 检查内核是否正在运行
     */
    external fun isRunning(): Boolean

    /**
     * 获取内核版本
     */
    external fun version(): String

    // ═══════════════════════════════════════════════════════════════════
    // 暂停/恢复
    // ═══════════════════════════════════════════════════════════════════

    /**
     * 暂停服务（设备休眠时调用）
     */
    external fun pause(): Boolean

    /**
     * 恢复服务（设备唤醒时调用）
     */
    external fun resume(): Boolean

    /**
     * 检查是否处于暂停状态
     */
    external fun isPaused(): Boolean

    // ═══════════════════════════════════════════════════════════════════
    // 出站管理
    // ═══════════════════════════════════════════════════════════════════

    /**
     * 切换出站节点
     * @param tag 节点标签
     */
    external fun selectOutbound(tag: String): Boolean

    /**
     * 获取当前选中的出站节点
     */
    external fun getSelectedOutbound(): String?

    /**
     * 获取所有出站节点列表
     * @return 按换行符分隔的标签列表
     */
    external fun listOutbounds(): String?

    /**
     * 检查是否有 selector 类型的出站
     */
    external fun hasSelector(): Boolean

    // ═══════════════════════════════════════════════════════════════════
    // 流量统计
    // ═══════════════════════════════════════════════════════════════════

    /**
     * 获取累计上传字节数
     */
    external fun getTrafficTotalUplink(): Long

    /**
     * 获取累计下载字节数
     */
    external fun getTrafficTotalDownlink(): Long

    /**
     * 重置流量统计
     */
    external fun resetTrafficStats(): Boolean

    // ═══════════════════════════════════════════════════════════════════
    // 连接管理
    // ═══════════════════════════════════════════════════════════════════

    /**
     * 获取当前连接数
     */
    external fun getConnectionCount(): Long

    /**
     * 重置所有连接
     * @param sys true=重置系统级连接表
     */
    external fun resetAllConnections(sys: Boolean): Boolean

    /**
     * 关闭所有跟踪的连接
     */
    external fun closeAllTrackedConnections(): Int

    /**
     * 关闭空闲连接
     * @param secs 空闲秒数
     * @return 关闭的连接数
     */
    external fun closeIdleConnections(secs: Long): Long

    // ═══════════════════════════════════════════════════════════════════
    // 网络恢复 & TUN
    // ═══════════════════════════════════════════════════════════════════

    /**
     * 自动网络恢复
     */
    external fun recoverNetworkAuto(): Boolean

    /**
     * 设置 TUN 文件描述符
     * @param fd VPN TUN 的文件描述符
     * @return 0=成功
     */
    external fun setTunFd(fd: Int): Int

    // ═══════════════════════════════════════════════════════════════════
    // 配置热重载
    // ═══════════════════════════════════════════════════════════════════

    /**
     * 热重载配置
     * @param config 新的 OpenWorld JSON 配置
     * @return 0=成功
     */
    external fun reloadConfig(config: String): Int

    // ═══════════════════════════════════════════════════════════════════
    // 代理组管理
    // ═══════════════════════════════════════════════════════════════════

    /**
     * 获取所有代理组信息
     * @return JSON 格式的代理组列表
     */
    external fun getProxyGroups(): String?

    /**
     * 设置代理组的选中节点
     * @param group 代理组标签
     * @param proxy 节点标签
     */
    external fun setGroupSelected(group: String, proxy: String): Boolean

    /**
     * 测试代理组的延迟
     * @param group 代理组标签
     * @param url 测试 URL
     * @param timeoutMs 超时毫秒数
     * @return JSON 格式的延迟结果
     */
    external fun testGroupDelay(group: String, url: String, timeoutMs: Int): String?

    // ═══════════════════════════════════════════════════════════════════
    // 活跃连接
    // ═══════════════════════════════════════════════════════════════════

    /**
     * 获取活跃连接列表
     * @return JSON 格式的连接列表
     */
    external fun getActiveConnections(): String?

    /**
     * 关闭指定 ID 的连接
     * @param id 连接 ID
     */
    external fun closeConnectionById(id: Long): Boolean

    // ═══════════════════════════════════════════════════════════════════
    // 流量快照
    // ═══════════════════════════════════════════════════════════════════

    /**
     * 获取流量快照
     * @return JSON 格式的流量数据
     */
    external fun getTrafficSnapshot(): String?

    // ═══════════════════════════════════════════════════════════════════
    // 订阅
    // ═══════════════════════════════════════════════════════════════════

    /**
     * 导入订阅
     * @param url 订阅 URL
     * @return JSON 格式的导入结果
     */
    external fun importSubscription(url: String): String?

    // ═══════════════════════════════════════════════════════════════════
    // 系统 DNS
    // ═══════════════════════════════════════════════════════════════════

    /**
     * 设置系统 DNS
     * @param dns DNS 服务器地址
     */
    external fun setSystemDns(dns: String): Boolean

    // ═══════════════════════════════════════════════════════════════════
    // 延迟测试
    // ═══════════════════════════════════════════════════════════════════

    /**
     * 测试单个节点的延迟
     * @param tag 节点标签
     * @param url 测试 URL
     * @param timeoutMs 超时毫秒数
     * @return 延迟毫秒数，-1=失败
     */
    external fun urlTest(tag: String, url: String, timeoutMs: Int): Int

    /**
     * 初始化独立延迟测试器（不依赖核心启动）
     * @param outboundsJson Outbound 配置的 JSON 数组
     * @return 0=成功, -1=参数错误, -2=JSON解析失败, -3=无节点, -4=创建失败, -5=注册失败
     */
    external fun latencyTesterInit(outboundsJson: String): Int

    /**
     * 测试所有已注册节点的延迟（不依赖核心启动）
     * @param url 测试 URL
     * @param timeoutMs 超时毫秒数
     * @return JSON 数组: [{"tag": "node1", "latency_ms": 123, "error": null}, ...]
     */
    external fun latencyTestAll(url: String, timeoutMs: Int): String?

    /**
     * 测试单个节点的延迟（不依赖核心启动）
     * @param tag 节点标签
     * @param url 测试 URL
     * @param timeoutMs 超时毫秒数
     * @return 延迟毫秒数，-1=失败
     */
    external fun latencyTestOne(tag: String, url: String, timeoutMs: Int): Int

    /**
     * 释放独立延迟测试器
     */
    external fun latencyTesterFree(): Unit

    // ═══════════════════════════════════════════════════════════════════
    // Clash 模式
    // ═══════════════════════════════════════════════════════════════════

    /**
     * 获取当前 Clash 模式
     */
    external fun getClashMode(): String?

    /**
     * 设置 Clash 模式
     * @param mode 模式: direct/proxy/global
     */
    external fun setClashMode(mode: String): Boolean

    // ═══════════════════════════════════════════════════════════════════
    // DNS 查询
    // ═══════════════════════════════════════════════════════════════════

    /**
     * DNS 查询
     * @param name 域名
     * @param qtype 查询类型 (A/AAAA/CNAME 等)
     * @return JSON 格式的查询结果
     */
    external fun dnsQuery(name: String, qtype: String): String?

    /**
     * 刷新 DNS 缓存
     */
    external fun dnsFlush(): Boolean

    // ═══════════════════════════════════════════════════════════════════
    // 内存 / 状态
    // ═══════════════════════════════════════════════════════════════════

    /**
     * 获取内存使用量（字节）
     */
    external fun getMemoryUsage(): Long

    /**
     * 获取内核状态
     * @return JSON 格式的状态信息
     */
    external fun getStatus(): String?

    // ═══════════════════════════════════════════════════════════════════
    // 流量速率
    // ═══════════════════════════════════════════════════════════════════

    /**
     * 轮询流量速率
     * @return JSON 格式的流量速率数据
     */
    external fun pollTrafficRate(): String?

    // ═══════════════════════════════════════════════════════════════════
    // Profile 管理
    // ═══════════════════════════════════════════════════════════════════

    /**
     * 列出所有 Profile
     */
    external fun listProfiles(): String?

    external fun switchProfile(name: String): Boolean

    /**
     * 获取当前 Profile
     */
    external fun getCurrentProfile(): String?

    external fun importProfile(name: String, content: String): Boolean

    external fun exportProfile(name: String): String?

    external fun deleteProfile(name: String): Boolean

    // ═══════════════════════════════════════════════════════════════════
    // 网络状态
    // ═══════════════════════════════════════════════════════════════════

    external fun notifyNetworkChanged(networkType: Int, ssid: String, isMetered: Boolean)

    /**
     * 获取平台状态
     */
    external fun getPlatformState(): String?

    external fun notifyMemoryLow()

    /**
     * 检查网络是否计费
     */
    external fun isNetworkMetered(): Boolean

    // ═══════════════════════════════════════════════════════════════════
    // Provider 管理
    // ═══════════════════════════════════════════════════════════════════

    /**
     * 列出所有 Provider
     */
    external fun listProviders(): String?

    /**
     * 获取 Provider 的节点
     * @param tag Provider 标签
     */
    external fun getProviderNodes(tag: String): String?

    /**
     * 添加 HTTP Provider
     * @param tag Provider 标签
     * @param url URL
     * @param interval 间隔（秒）
     */
    external fun addHttpProvider(tag: String, url: String, interval: Long): Boolean

    /**
     * 更新 Provider
     * @param tag Provider 标签
     */
    external fun updateProvider(tag: String): Int

    /**
     * 删除 Provider
     * @param tag Provider 标签
     */
    external fun removeProvider(tag: String): Boolean

    // ═══════════════════════════════════════════════════════════════════
    // 延迟历史
    // ═══════════════════════════════════════════════════════════════════

    external fun getDelayHistory(tagFilter: String): String?

    /**
     * 清除延迟历史
     */
    external fun clearDelayHistory(): Boolean

    /**
     * 获取上次延迟
     * @param tag 节点标签
     */
    external fun getLastDelay(tag: String): Int?

    // ═══════════════════════════════════════════════════════════════════
    // 自动测速
    // ═══════════════════════════════════════════════════════════════════

    external fun startAutoTest(tag: String, url: String, intervalSecs: Int, timeoutMs: Int): Boolean

    /**
     * 停止自动测速
     */
    external fun stopAutoTest(): Boolean

    // ═══════════════════════════════════════════════════════════════════
    // 系统
    // ═══════════════════════════════════════════════════════════════════

    external fun gc(): Int

    external fun updateGeoDatabases(
        geoipPath: String,
        geoipUrl: String,
        geositePath: String,
        geositeUrl: String
    ): Boolean

    // ═══════════════════════════════════════════════════════════════════
    // 规则管理
    // ═══════════════════════════════════════════════════════════════════

    /**
     * 列出规则
     */
    external fun rulesList(): String?

    external fun rulesAdd(rule: String): Int

    /**
     * 删除规则
     * @param index 规则索引
     */
    external fun rulesRemove(index: Int): Boolean

    // ═══════════════════════════════════════════════════════════════════
    // Wake Lock
    // ═══════════════════════════════════════════════════════════════════

    /**
     * 设置 Wake Lock
     * @param acquire true=获取, false=释放
     */
    external fun wakelockSet(acquire: Boolean): Boolean

    /**
     * 检查 Wake Lock 是否持有
     */
    external fun wakelockHeld(): Boolean

    // ═══════════════════════════════════════════════════════════════════
    // 通知
    // ═══════════════════════════════════════════════════════════════════

    /**
     * 获取通知内容
     */
    external fun notificationContent(): String?

    // ═══════════════════════════════════════════════════════════════════
    // Zenone 格式转换
    // ═══════════════════════════════════════════════════════════════════

    /**
     * 转换订阅为 Zenone 格式
     */
    external fun convertSubscriptionToZenone(url: String): String?

    /**
     * Zenone 转换为配置
     */
    external fun zenoneToConfig(content: String): String?

    /**
     * 检查是否为 Zenone 格式
     */
    external fun isZenoneFormat(content: String): Boolean

    /**
     * 导出配置为指定格式
     * @param content Zenone 格式的配置内容
     * @param format 目标格式: clash, singbox, zenone, json
     * @return JSON 格式的导出结果: {"success": true, "content": "...", "format": "..."}
     */
    external fun exportConfig(content: String, format: String): String?

    /**
     * 导出节点为 URI 链接
     * @param nodeJson 节点配置的 JSON
     * @return JSON 格式的导出结果: {"success": true, "uri": "vmess://..."}
     */
    external fun exportNodeAsUri(nodeJson: String): String?

    // ═══════════════════════════════════════════════════════════════════
    // HTTP 请求
    // ═══════════════════════════════════════════════════════════════════

    /**
     * 获取 URL 内容
     */
    external fun fetchUrl(url: String): String?

    fun switchProfileById(profileId: Long): Boolean = switchProfile(profileId.toString())

    fun exportProfileById(profileId: Long): String? = exportProfile(profileId.toString())

    fun deleteProfileById(profileId: Long): Boolean = deleteProfile(profileId.toString())

    fun notifyNetworkChangedCompat(network: String, ssid: String = "", isMetered: Boolean = false): Boolean {
        val networkType = when (network.lowercase()) {
            "none" -> 0
            "wifi" -> 1
            "cellular", "mobile" -> 2
            "ethernet" -> 3
            else -> 4
        }
        return runCatching {
            notifyNetworkChanged(networkType, ssid, isMetered)
            true
        }.getOrDefault(false)
    }

    fun notifyMemoryLowSafe(): Boolean {
        return runCatching {
            notifyMemoryLow()
            true
        }.getOrDefault(false)
    }

    fun updateProviderSuccess(tag: String): Boolean = updateProvider(tag) >= 0

    fun getDelayHistoryAll(): String? = getDelayHistory("")

    fun startAutoTestMs(
        tag: String,
        url: String,
        intervalMs: Int,
        timeoutMs: Int = 5000
    ): Boolean {
        val intervalSecs = (intervalMs / 1000).coerceAtLeast(30)
        return startAutoTest(tag, url, intervalSecs, timeoutMs)
    }

    fun gcSuccess(): Boolean = gc() >= 0

    fun updateGeoDatabasesByPath(geoipPath: String, geositePath: String): Boolean {
        return updateGeoDatabases(geoipPath, "", geositePath, "")
    }

    fun rulesAddSuccess(rule: String): Boolean = rulesAdd(rule) >= 0

    // ═══════════════════════════════════════════════════════════════════
    // 初始化静态块
    // ═══════════════════════════════════════════════════════════════════

    init {
        try {
            System.loadLibrary("openworld")
            Log.i(TAG, "OpenWorldCore library loaded")
        } catch (e: UnsatisfiedLinkError) {
            Log.e(TAG, "Failed to load OpenWorldCore library", e)
        }
    }
}
