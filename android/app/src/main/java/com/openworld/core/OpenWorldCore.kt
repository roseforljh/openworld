package com.openworld.core

/**
 * OpenWorld 内核 JNI 桥接层
 * 对应 Rust 侧: src/app/android.rs -> com.openworld.core.OpenWorldCore
 */
object OpenWorldCore {

    init {
        System.loadLibrary("openworld")
    }

    // ── 生命周期 ──
    @JvmStatic external fun start(config: String): Int
    @JvmStatic external fun stop(): Int
    @JvmStatic external fun isRunning(): Boolean
    @JvmStatic external fun version(): String

    // ── 暂停/恢复 ──
    @JvmStatic external fun pause(): Boolean
    @JvmStatic external fun resume(): Boolean
    @JvmStatic external fun isPaused(): Boolean

    // ── 出站管理 ──
    @JvmStatic external fun selectOutbound(tag: String): Boolean
    @JvmStatic external fun getSelectedOutbound(): String?
    @JvmStatic external fun listOutbounds(): String?
    @JvmStatic external fun hasSelector(): Boolean

    // ── 流量统计 ──
    @JvmStatic external fun getTrafficTotalUplink(): Long
    @JvmStatic external fun getTrafficTotalDownlink(): Long
    @JvmStatic external fun resetTrafficStats(): Boolean
    @JvmStatic external fun getConnectionCount(): Long
    @JvmStatic external fun resetAllConnections(system: Boolean): Boolean
    @JvmStatic external fun closeIdleConnections(seconds: Long): Long

    // ── 网络恢复 & TUN ──
    @JvmStatic external fun recoverNetworkAuto(): Boolean
    @JvmStatic external fun setTunFd(fd: Int): Int

    // ── 配置热重载 ──
    @JvmStatic external fun reloadConfig(config: String): Int

    // ── 代理组 ──
    @JvmStatic external fun getProxyGroups(): String?
    @JvmStatic external fun setGroupSelected(group: String, proxy: String): Boolean
    @JvmStatic external fun testGroupDelay(group: String, url: String, timeoutMs: Int): String?

    // ── 活跃连接 ──
    @JvmStatic external fun getActiveConnections(): String?
    @JvmStatic external fun closeConnectionById(id: Long): Boolean

    // ── 流量快照 ──
    @JvmStatic external fun getTrafficSnapshot(): String?

    // ── 订阅 ──
    @JvmStatic external fun importSubscription(url: String): String?

    // ── DNS ──
    @JvmStatic external fun setSystemDns(dns: String): Boolean
    @JvmStatic external fun dnsQuery(name: String, qtype: String): String?
    @JvmStatic external fun dnsFlush(): Boolean

    // ── 延迟测试 ──
    @JvmStatic external fun urlTest(tag: String, url: String, timeoutMs: Int): Int

    // ── Clash 模式 ──
    @JvmStatic external fun getClashMode(): String?
    @JvmStatic external fun setClashMode(mode: String): Boolean

    // ── 状态 ──
    @JvmStatic external fun getMemoryUsage(): Long
    @JvmStatic external fun getStatus(): String?
    @JvmStatic external fun pollTrafficRate(): String?

    // ── Profile 管理 ──
    @JvmStatic external fun listProfiles(): String?
    @JvmStatic external fun switchProfile(name: String): Boolean
    @JvmStatic external fun getCurrentProfile(): String?
    @JvmStatic external fun importProfile(name: String, yaml: String): Boolean
    @JvmStatic external fun exportProfile(name: String): String?
    @JvmStatic external fun deleteProfile(name: String): Boolean

    // ── 平台接口 ──
    @JvmStatic external fun notifyNetworkChanged(networkType: Int, ssid: String, isMetered: Boolean)
    @JvmStatic external fun getPlatformState(): String?
    @JvmStatic external fun notifyMemoryLow()
    @JvmStatic external fun isNetworkMetered(): Boolean

    // ── Provider 管理 ──
    @JvmStatic external fun listProviders(): String?
    @JvmStatic external fun getProviderNodes(name: String): String?
    @JvmStatic external fun addHttpProvider(name: String, url: String, intervalSecs: Long): Boolean
    @JvmStatic external fun updateProvider(name: String): Int
    @JvmStatic external fun removeProvider(name: String): Boolean

    // ── 延迟历史 ──
    @JvmStatic external fun getDelayHistory(tagFilter: String): String?
    @JvmStatic external fun clearDelayHistory(): Boolean
    @JvmStatic external fun getLastDelay(tag: String): Int

    // ── 自动测速 ──
    @JvmStatic external fun startAutoTest(groupTag: String, testUrl: String, intervalSecs: Int, timeoutMs: Int): Boolean
    @JvmStatic external fun stopAutoTest(): Boolean

    // ── GC / Geo ──
    @JvmStatic external fun gc(): Int
    @JvmStatic external fun updateGeoDatabases(geoipPath: String, geoipUrl: String, geositePath: String, geositeUrl: String): Boolean

    // ── 规则 CRUD ──
    @JvmStatic external fun rulesList(): String?
    @JvmStatic external fun rulesAdd(ruleJson: String): Int
    @JvmStatic external fun rulesRemove(index: Int): Boolean

    // ── WakeLock / 通知 ──
    @JvmStatic external fun wakelockSet(acquire: Boolean): Boolean
    @JvmStatic external fun wakelockHeld(): Boolean
    @JvmStatic external fun notificationContent(): String?

    // ── ZenOne 统一配置 API ──
    @JvmStatic external fun convertSubscriptionToZenone(content: String): String?
    @JvmStatic external fun zenoneToConfig(zenoneContent: String): String?
    @JvmStatic external fun isZenoneFormat(content: String): Boolean

    // ── 独立 HTTP 下载（不依赖内核运行） ──
    @JvmStatic external fun fetchUrl(url: String): String?
}
