package com.openworld.app.repository

import com.google.gson.Gson
import com.google.gson.JsonArray
import com.google.gson.JsonObject
import com.google.gson.JsonParser
import com.google.gson.reflect.TypeToken
import com.openworld.core.OpenWorldCore
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * 内核交互封装层，将 JNI 的 JSON 字符串转为 Kotlin 数据类
 */
object CoreRepository {

    private val gson = Gson()

    // ── 已有数据类 ──

    data class CoreStatus(
        val running: Boolean = false,
        val mode: String = "rule",
        val upload: Long = 0,
        val download: Long = 0,
        val connections: Int = 0
    )

    data class TrafficRate(
        val up_rate: Long = 0,
        val down_rate: Long = 0,
        val total_up: Long = 0,
        val total_down: Long = 0
    )

    data class ProxyGroup(
        val name: String = "",
        val type: String = "",
        val selected: String? = null,
        val members: List<String> = emptyList()
    )

    data class ActiveConnection(
        val id: Long = 0,
        val destination: String = "",
        val outbound: String = "",
        val network: String = "",
        val start_time: Long = 0,
        val upload: Long = 0,
        val download: Long = 0
    )

    data class DelayResult(val name: String = "", val delay: Long = -1)

    data class DelayEntry(
        val tag: String = "",
        val delay: Int = -1,
        val timestamp: Long = 0
    )

    data class NotificationInfo(
        val status: String = "stopped",
        val active_connections: Int = 0,
        val upload: Long = 0,
        val download: Long = 0
    )

    // ── 新增数据类 ──

    data class ProviderInfo(
        val name: String = "",
        val url: String = "",
        val nodeCount: Int = 0,
        val lastUpdated: Long = 0
    )

    data class ProviderNode(
        val name: String = "",
        val type: String = "",
        val server: String = "",
        val port: Int = 0,
        val delay: Int = -1
    )

    data class OutboundInfo(
        val tag: String = "",
        val type: String = "",
        val alive: Boolean = true
    )

    data class RuleInfo(
        val index: Int = 0,
        val type: String = "",
        val payload: String = "",
        val outbound: String = ""
    )

    // ── 状态 ──

    fun getStatus(): CoreStatus {
        val json = OpenWorldCore.getStatus() ?: return CoreStatus()
        return try { gson.fromJson(json, CoreStatus::class.java) } catch (_: Exception) { CoreStatus() }
    }

    fun pollTrafficRate(): TrafficRate {
        val json = OpenWorldCore.pollTrafficRate() ?: return TrafficRate()
        return try { gson.fromJson(json, TrafficRate::class.java) } catch (_: Exception) { TrafficRate() }
    }

    fun getNotificationInfo(): NotificationInfo {
        val json = OpenWorldCore.notificationContent() ?: return NotificationInfo()
        return try { gson.fromJson(json, NotificationInfo::class.java) } catch (_: Exception) { NotificationInfo() }
    }

    // ── 暂停/恢复 ──

    fun pause(): Boolean = try { OpenWorldCore.pause() } catch (_: Exception) { false }

    fun resume(): Boolean = try { OpenWorldCore.resume() } catch (_: Exception) { false }

    fun isPaused(): Boolean = try { OpenWorldCore.isPaused() } catch (_: Exception) { false }

    // ── 出站管理 ──

    fun selectOutbound(tag: String): Boolean = try { OpenWorldCore.selectOutbound(tag) } catch (_: Exception) { false }

    fun getSelectedOutbound(): String = try { OpenWorldCore.getSelectedOutbound().orEmpty() } catch (_: Exception) { "" }

    fun hasSelector(): Boolean = try { OpenWorldCore.hasSelector() } catch (_: Exception) { false }

    fun listOutbounds(): List<OutboundInfo> {
        val json = try { OpenWorldCore.listOutbounds() } catch (_: Exception) { null } ?: return emptyList()
        return try {
            val type = object : TypeToken<List<OutboundInfo>>() {}.type
            gson.fromJson(json, type)
        } catch (_: Exception) { emptyList() }
    }

    // ── 连接管理 ──

    fun resetAllConnections(system: Boolean = false): Boolean =
        try { OpenWorldCore.resetAllConnections(system) } catch (_: Exception) { false }

    fun closeIdleConnections(seconds: Long): Long =
        try { OpenWorldCore.closeIdleConnections(seconds) } catch (_: Exception) { 0L }

    fun resetTrafficStats(): Boolean =
        try { OpenWorldCore.resetTrafficStats() } catch (_: Exception) { false }

    // ── 配置热重载 ──

    fun reloadConfig(config: String): Boolean =
        try { OpenWorldCore.reloadConfig(config) == 0 } catch (_: Exception) { false }

    // ── 代理组 ──

    fun getProxyGroups(): List<ProxyGroup> {
        val json = OpenWorldCore.getProxyGroups() ?: return emptyList()
        return try {
            val type = object : TypeToken<List<ProxyGroup>>() {}.type
            gson.fromJson(json, type)
        } catch (_: Exception) { emptyList() }
    }

    fun getActiveConnections(): List<ActiveConnection> {
        val json = OpenWorldCore.getActiveConnections() ?: return emptyList()
        return try {
            val type = object : TypeToken<List<ActiveConnection>>() {}.type
            gson.fromJson(json, type)
        } catch (_: Exception) { emptyList() }
    }

    suspend fun testGroupDelay(group: String, url: String, timeoutMs: Int): List<DelayResult> =
        withContext(Dispatchers.IO) {
            val json = OpenWorldCore.testGroupDelay(group, url, timeoutMs) ?: return@withContext emptyList()
            try {
                val type = object : TypeToken<List<DelayResult>>() {}.type
                gson.fromJson(json, type)
            } catch (_: Exception) { emptyList() }
        }

    // ── Provider 管理 ──

    fun listProviders(): List<ProviderInfo> {
        val json = try { OpenWorldCore.listProviders() } catch (_: Exception) { null } ?: return emptyList()
        return try {
            val type = object : TypeToken<List<ProviderInfo>>() {}.type
            gson.fromJson(json, type)
        } catch (_: Exception) { emptyList() }
    }

    fun getProviderNodes(name: String): List<ProviderNode> {
        val json = try { OpenWorldCore.getProviderNodes(name) } catch (_: Exception) { null } ?: return emptyList()
        return try {
            val type = object : TypeToken<List<ProviderNode>>() {}.type
            gson.fromJson(json, type)
        } catch (_: Exception) { emptyList() }
    }

    fun addHttpProvider(name: String, url: String, intervalSecs: Long): Boolean =
        try { OpenWorldCore.addHttpProvider(name, url, intervalSecs) } catch (_: Exception) { false }

    fun updateProvider(name: String): Int =
        try { OpenWorldCore.updateProvider(name) } catch (_: Exception) { -1 }

    fun removeProvider(name: String): Boolean =
        try { OpenWorldCore.removeProvider(name) } catch (_: Exception) { false }

    // ── 订阅 ──

    fun importSubscription(url: String): String? =
        try { OpenWorldCore.importSubscription(url) } catch (_: Exception) { null }

    // ── 规则 ──

    fun getRoutingRuleCount(): Int {
        val json = try { OpenWorldCore.rulesList().orEmpty() } catch (_: Exception) { "" }
        if (json.isEmpty()) return 0
        return try {
            val parsed = JsonParser.parseString(json)
            when {
                parsed.isJsonArray -> parsed.asJsonArray.size()
                parsed.isJsonObject -> {
                    val obj = parsed.asJsonObject
                    when {
                        obj.has("rules") && obj.get("rules").isJsonArray -> obj.getAsJsonArray("rules").size()
                        else -> obj.entrySet().size
                    }
                }
                else -> 0
            }
        } catch (_: Exception) { 0 }
    }

    fun listRules(): List<RuleInfo> {
        val json = try { OpenWorldCore.rulesList().orEmpty() } catch (_: Exception) { "" }
        if (json.isEmpty()) return emptyList()
        return try {
            val parsed = JsonParser.parseString(json)
            val arr = when {
                parsed.isJsonArray -> parsed.asJsonArray
                parsed.isJsonObject -> {
                    val obj = parsed.asJsonObject
                    if (obj.has("rules") && obj.get("rules").isJsonArray) obj.getAsJsonArray("rules")
                    else return emptyList()
                }
                else -> return emptyList()
            }
            arr.mapIndexedNotNull { index, element ->
                if (!element.isJsonObject) return@mapIndexedNotNull null
                val obj = element.asJsonObject
                RuleInfo(
                    index = index,
                    type = obj.get("type")?.asString ?: "",
                    payload = obj.get("payload")?.asString ?: "",
                    outbound = obj.get("outbound")?.asString ?: obj.get("action")?.asString ?: ""
                )
            }
        } catch (_: Exception) { emptyList() }
    }

    fun addRule(ruleJson: String): Int =
        try { OpenWorldCore.rulesAdd(ruleJson) } catch (_: Exception) { -1 }

    fun removeRule(index: Int): Boolean =
        try { OpenWorldCore.rulesRemove(index) } catch (_: Exception) { false }

    // ── GC / Geo ──

    fun gc(): Int = try { OpenWorldCore.gc() } catch (_: Exception) { -1 }

    fun updateGeoDatabases(geoipPath: String, geoipUrl: String, geositePath: String, geositeUrl: String): Boolean =
        try { OpenWorldCore.updateGeoDatabases(geoipPath, geoipUrl, geositePath, geositeUrl) } catch (_: Exception) { false }

    // ── 自动测速 ──

    fun startAutoTest(groupTag: String, testUrl: String, intervalSecs: Int, timeoutMs: Int): Boolean =
        try { OpenWorldCore.startAutoTest(groupTag, testUrl, intervalSecs, timeoutMs) } catch (_: Exception) { false }

    fun stopAutoTest(): Boolean =
        try { OpenWorldCore.stopAutoTest() } catch (_: Exception) { false }

    // ── 平台接口 ──

    fun notifyNetworkChanged(networkType: Int, ssid: String, isMetered: Boolean) {
        try { OpenWorldCore.notifyNetworkChanged(networkType, ssid, isMetered) } catch (_: Exception) {}
    }

    fun notifyMemoryLow() {
        try { OpenWorldCore.notifyMemoryLow() } catch (_: Exception) {}
    }

    // ── 通知 / WakeLock ──

    fun getNotificationContent(): String = OpenWorldCore.notificationContent().orEmpty()

    // ── Profile 管理 ──

    fun listProfiles(): List<String> {
        val json = OpenWorldCore.listProfiles() ?: return emptyList()
        return try {
            val type = object : TypeToken<List<String>>() {}.type
            gson.fromJson(json, type)
        } catch (_: Exception) { emptyList() }
    }

    fun switchProfile(name: String): Boolean = OpenWorldCore.switchProfile(name)

    fun getCurrentProfile(): String = OpenWorldCore.getCurrentProfile().orEmpty()

    fun importProfile(name: String, yaml: String): Boolean = OpenWorldCore.importProfile(name, yaml)

    fun deleteProfile(name: String): Boolean = OpenWorldCore.deleteProfile(name)

    // ── DNS ──

    fun dnsQuery(name: String, qtype: String): String = OpenWorldCore.dnsQuery(name, qtype).orEmpty()

    fun dnsFlush(): Boolean = OpenWorldCore.dnsFlush()

    // ── 延迟 ──

    fun getLastDelay(tag: String): Int = try { OpenWorldCore.getLastDelay(tag) } catch (_: Exception) { -1 }

    fun getDelayHistory(tagFilter: String = ""): List<DelayEntry> {
        val json = OpenWorldCore.getDelayHistory(tagFilter) ?: return emptyList()
        return try {
            val type = object : TypeToken<List<DelayEntry>>() {}.type
            gson.fromJson(json, type)
        } catch (_: Exception) { emptyList() }
    }

    fun clearDelayHistory(): Boolean = OpenWorldCore.clearDelayHistory()
}

