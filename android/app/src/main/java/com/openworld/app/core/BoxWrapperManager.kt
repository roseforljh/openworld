package com.openworld.app.core

import android.util.Log
import com.openworld.core.OpenWorldCore
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

/**
 * OpenWorld 内核管理�?- 管理 OpenWorld Rust 内核的生命周�? *
 * 功能:
 * - 节点切换: selectOutbound()
 * - 电源管理: pause() / resume()
 * - 流量统计: getUploadTotal() / getDownloadTotal()
 * - 连接管理: resetAllConnections(), closeIdleConnections()
 *
 * 完全基于 OpenWorldCore (libopenworld.so) 实现
 */
object BoxWrapperManager {
    private const val TAG = "BoxWrapperManager"

    /**
     * OpenWorld 内核是否可用
     */
    @Volatile
    var useOpenWorldKernel: Boolean = false
        private set

    /**
     * OpenWorld 内核是否可用（别名）
     */
    val isOpenWorldAvailable: Boolean
        get() = useOpenWorldKernel

    /**
     * 检测并初始�?OpenWorld 内核
     * 在应用启动时调用
     */
    fun detectOpenWorldKernel(): Boolean {
        return try {
            val version = OpenWorldCore.version()
            if (version.isNotBlank()) {
                useOpenWorldKernel = true
                Log.i(TAG, "OpenWorld kernel detected: $version")
                true
            } else {
                useOpenWorldKernel = false
                Log.w(TAG, "OpenWorld kernel version is blank")
                false
            }
        } catch (e: UnsatisfiedLinkError) {
            useOpenWorldKernel = false
            Log.e(TAG, "OpenWorld kernel not available: ${e.message}")
            false
        } catch (e: Exception) {
            useOpenWorldKernel = false
            Log.w(TAG, "OpenWorld kernel detection failed: ${e.message}")
            false
        }
    }

    enum class RecoveryMode {
        SOFT,
        HARD
    }

    // 服务运行状�?    @Volatile
    private var isRunning: Boolean = false

    private val _isPaused = MutableStateFlow(false)
    val isPaused: StateFlow<Boolean> = _isPaused.asStateFlow()

    private val _hasSelector = MutableStateFlow(false)
    val hasSelector: StateFlow<Boolean> = _hasSelector.asStateFlow()

    // 暂停历史跟踪
    @Volatile
    private var lastResumeTimestamp: Long = 0L

    // resetNetwork 防抖
    @Volatile
    private var lastResetNetworkTimestamp: Long = 0L
    private const val RESET_NETWORK_DEBOUNCE_MS = 500L

    /**
     * 初始�?- 在服务启动后调用
     * @param server 兼容参数（忽略）
     */
    fun init(server: Any? = null): Boolean {
        return try {
            isRunning = true
            _isPaused.value = false
            _hasSelector.value = runCatching { OpenWorldCore.hasSelector() }.getOrDefault(false)
            Log.i(TAG, "BoxWrapperManager initialized, hasSelector=${_hasSelector.value}")
            true
        } catch (e: Exception) {
            Log.e(TAG, "Failed to init BoxWrapperManager", e)
            isRunning = false
            false
        }
    }

    /**
     * 释放 - 在服务关闭时调用
     */
    fun release() {
        isRunning = false
        _isPaused.value = false
        _hasSelector.value = false
        Log.i(TAG, "BoxWrapperManager released")
    }

    /**
     * 检查服务是否可�?     */
    fun isAvailable(): Boolean {
        return isRunning && useOpenWorldKernel
    }

    // ==================== 节点切换 ====================

    /**
     * 切换出站节点
     */
    fun selectOutbound(nodeTag: String): Boolean {
        return try {
            val result = OpenWorldCore.selectOutbound(nodeTag)
            if (result) {
                Log.i(TAG, "selectOutbound($nodeTag) success")
            } else {
                Log.w(TAG, "selectOutbound($nodeTag) failed")
            }
            result
        } catch (e: Exception) {
            Log.w(TAG, "selectOutbound($nodeTag) failed: ${e.message}")
            false
        }
    }

    /**
     * 获取当前选中的出站节�?     */
    fun getSelectedOutbound(): String? {
        return try {
            OpenWorldCore.getSelectedOutbound()?.takeIf { it.isNotBlank() }
        } catch (e: Exception) {
            Log.w(TAG, "getSelectedOutbound failed: ${e.message}")
            null
        }
    }

    /**
     * 获取所有出站节点列�?     */
    fun listOutbounds(): List<String> {
        return try {
            OpenWorldCore.listOutbounds()
                ?.split("\n")
                ?.filter { it.isNotBlank() }
                ?: emptyList()
        } catch (e: Exception) {
            Log.w(TAG, "listOutbounds failed: ${e.message}")
            emptyList()
        }
    }

    /**
     * 检查是否有 selector 类型的出�?     */
    fun hasSelector(): Boolean {
        return try {
            OpenWorldCore.hasSelector()
        } catch (e: Exception) {
            false
        }
    }

    // ==================== 电源管理 ====================

    /**
     * 暂停 - 设备休眠时调�?     */
    fun pause(): Boolean {
        return try {
            val result = OpenWorldCore.pause()
            _isPaused.value = true
            Log.i(TAG, "pause() success")
            result
        } catch (e: Exception) {
            Log.w(TAG, "pause() failed: ${e.message}")
            false
        }
    }

    /**
     * 恢复 - 设备唤醒时调�?     */
    fun resume(): Boolean {
        return try {
            val result = OpenWorldCore.resume()
            _isPaused.value = false
            lastResumeTimestamp = System.currentTimeMillis()
            Log.i(TAG, "resume() success")
            result
        } catch (e: Exception) {
            Log.w(TAG, "resume() failed: ${e.message}")
            false
        }
    }

    /**
     * 检查是否处于暂停状�?     */
    fun isPausedNow(): Boolean {
        return try {
            OpenWorldCore.isPaused()
        } catch (e: Exception) {
            _isPaused.value
        }
    }

    /**
     * 检查是否最近从暂停状态恢�?     */
    fun wasPausedRecently(thresholdMs: Long = 30_000L): Boolean {
        val timestamp = lastResumeTimestamp
        if (timestamp == 0L) return false
        return (System.currentTimeMillis() - timestamp) < thresholdMs
    }

    /**
     * 进入睡眠模式
     */
    fun sleep(): Boolean = pause()

    /**
     * 从睡眠中唤醒
     */
    fun wake(): Boolean = resume()

    // ==================== 网络恢复 ====================

    fun wakeAndResetNetwork(source: String, force: Boolean = false): Boolean {
        return recoverNetwork(source = source, mode = RecoveryMode.SOFT, force = force)
    }

    fun recoverNetwork(source: String, mode: RecoveryMode, force: Boolean = false): Boolean {
        if (!isAvailable()) {
            Log.d(TAG, "[$source] recoverNetwork skipped (service not available)")
            return false
        }

        val now = System.currentTimeMillis()
        val elapsed = now - lastResetNetworkTimestamp

        if (!force && elapsed < RESET_NETWORK_DEBOUNCE_MS) {
            Log.d(TAG, "[$source] recoverNetwork skipped (debounce: ${elapsed}ms)")
            return true
        }

        val connCount = runCatching { getConnectionCount() }.getOrDefault(0)
        val needRecovery = runCatching { isNetworkRecoveryNeeded() }.getOrDefault(false)
        val hasActiveState = connCount > 0 || needRecovery || isPausedNow()
        val bypassIdleGuard = shouldBypassIdleGuard(source)
        if (!force && !hasActiveState && !bypassIdleGuard) {
            Log.d(TAG, "[$source] recoverNetwork skipped (no connections, recovery not needed, bypass=$bypassIdleGuard)")
            return true
        }

        Log.d(TAG, "[$source] recoverNetwork proceed (mode=$mode force=$force hasActiveState=$hasActiveState bypass=$bypassIdleGuard)")

        lastResetNetworkTimestamp = now
        _isPaused.value = false
        lastResumeTimestamp = now

        return when (mode) {
            RecoveryMode.SOFT -> recoverNetworkSoft(source)
            RecoveryMode.HARD -> recoverNetworkHard(source)
        }
    }

    // ==================== 智能恢复 ====================

    suspend fun smartRecover(
        context: android.content.Context,
        source: String,
        skipProbe: Boolean = false
    ): SmartRecoveryResult {
        if (!isAvailable()) {
            Log.d(TAG, "[$source] smartRecover skipped (service not available)")
            return SmartRecoveryResult(RecoveryLevel.NONE, false, "service not available")
        }

        val startTime = System.currentTimeMillis()

        if (!skipProbe) {
            val probeResult = executeProbeLevel(context, source, startTime)
            if (probeResult != null) return probeResult
        }

        val selectiveResult = executeSelectiveLevel(context, source, startTime)
        if (selectiveResult.success && selectiveResult.level == RecoveryLevel.SELECTIVE) {
            return selectiveResult
        }

        return executeNuclearLevel(source, startTime, selectiveResult.closedConnections)
    }

    private suspend fun executeProbeLevel(
        context: android.content.Context,
        source: String,
        startTime: Long
    ): SmartRecoveryResult? {
        Log.i(TAG, "[$source] smartRecover: Level 1 (PROBE)")
        val probeResult = ProbeManager.probeFirstSuccessViaVpn(context, timeoutMs = 1500L)

        if (probeResult != null) {
            val elapsed = System.currentTimeMillis() - startTime
            Log.i(TAG, "[$source] PROBE success (${probeResult.latencyMs}ms), total: ${elapsed}ms")
            return SmartRecoveryResult(
                RecoveryLevel.PROBE, true, "VPN link healthy",
                probeLatencyMs = probeResult.latencyMs
            )
        }
        Log.w(TAG, "[$source] PROBE failed, escalating to SELECTIVE")
        return null
    }

    private suspend fun executeSelectiveLevel(
        context: android.content.Context,
        source: String,
        startTime: Long
    ): SmartRecoveryResult {
        Log.i(TAG, "[$source] smartRecover: Level 2 (SELECTIVE)")
        wake()
        val closedCount = closeIdleConnections(maxIdleSeconds = 30)
        resetNetwork()
        Log.i(TAG, "[$source] SELECTIVE closed=$closedCount")

        kotlinx.coroutines.delay(300)
        val verifyResult = ProbeManager.probeFirstSuccessViaVpn(context, timeoutMs = 1500L)

        if (verifyResult != null) {
            val elapsed = System.currentTimeMillis() - startTime
            Log.i(TAG, "[$source] SELECTIVE success, verify=${verifyResult.latencyMs}ms, total: ${elapsed}ms")
            return SmartRecoveryResult(
                RecoveryLevel.SELECTIVE, true, "SELECTIVE succeeded",
                closedConnections = closedCount, probeLatencyMs = verifyResult.latencyMs
            )
        }
        Log.w(TAG, "[$source] SELECTIVE verify failed, escalating to NUCLEAR")
        return SmartRecoveryResult(RecoveryLevel.SELECTIVE, false, "verify failed", closedCount)
    }

    private fun executeNuclearLevel(source: String, startTime: Long, closedCount: Int): SmartRecoveryResult {
        Log.i(TAG, "[$source] smartRecover: Level 3 (NUCLEAR)")
        resetAllConnections(true)
        resetNetwork()
        val elapsed = System.currentTimeMillis() - startTime
        Log.i(TAG, "[$source] NUCLEAR completed, total: ${elapsed}ms")
        return SmartRecoveryResult(RecoveryLevel.NUCLEAR, true, "NUCLEAR completed", closedCount)
    }

    enum class RecoveryLevel { NONE, PROBE, SELECTIVE, NUCLEAR }

    data class SmartRecoveryResult(
        val level: RecoveryLevel,
        val success: Boolean,
        val reason: String,
        val closedConnections: Int = 0,
        val probeLatencyMs: Long? = null
    )

    // ==================== 流量统计 ====================

    fun getUploadTotal(): Long {
        return try {
            OpenWorldCore.getTrafficTotalUplink()
        } catch (e: Exception) {
            Log.w(TAG, "getUploadTotal failed: ${e.message}")
            -1L
        }
    }

    fun getDownloadTotal(): Long {
        return try {
            OpenWorldCore.getTrafficTotalDownlink()
        } catch (e: Exception) {
            Log.w(TAG, "getDownloadTotal failed: ${e.message}")
            -1L
        }
    }

    fun resetTraffic(): Boolean {
        return try {
            val result = OpenWorldCore.resetTrafficStats()
            Log.i(TAG, "resetTraffic() result=$result")
            result
        } catch (e: Exception) {
            Log.w(TAG, "resetTraffic() failed: ${e.message}")
            false
        }
    }

    fun getConnectionCount(): Int {
        return try {
            OpenWorldCore.getConnectionCount().toInt()
        } catch (e: Exception) {
            0
        }
    }

    // ==================== 连接管理 ====================

    fun resetAllConnections(system: Boolean = true): Boolean {
        return try {
            val result = OpenWorldCore.resetAllConnections(system)
            Log.i(TAG, "resetAllConnections($system) success: $result")
            result
        } catch (e: Exception) {
            Log.w(TAG, "resetAllConnections failed: ${e.message}")
            false
        }
    }

    fun resetNetwork(): Boolean {
        return try {
            val result = OpenWorldCore.resetAllConnections(false)
            Log.i(TAG, "resetNetwork() success")
            result
        } catch (e: Exception) {
            Log.w(TAG, "resetNetwork() failed: ${e.message}")
            false
        }
    }

    fun closeAllTrackedConnections(): Int {
        return try {
            val count = OpenWorldCore.closeAllTrackedConnections()
            if (count > 0) {
                Log.i(TAG, "closeAllTrackedConnections: closed $count connections")
            }
            count
        } catch (e: Exception) {
            Log.w(TAG, "closeAllTrackedConnections failed: ${e.message}")
            0
        }
    }

    fun closeIdleConnections(maxIdleSeconds: Int = 30): Int {
        return try {
            val count = OpenWorldCore.closeIdleConnections(maxIdleSeconds.toLong()).toInt()
            if (count > 0) {
                Log.i(TAG, "closeIdleConnections($maxIdleSeconds): closed $count connections")
            }
            count
        } catch (e: Exception) {
            Log.w(TAG, "closeIdleConnections failed: ${e.message}, fallback to closeAllTrackedConnections")
            closeAllTrackedConnections()
        }
    }

    fun getExtensionVersion(): String {
        return try {
            OpenWorldCore.version()
        } catch (e: Exception) {
            "unknown"
        }
    }

    // ==================== 网络恢复 (Network Recovery) ====================

    fun recoverNetworkAuto(): Boolean {
        return try {
            OpenWorldCore.recoverNetworkAuto()
        } catch (e: Exception) {
            Log.w(TAG, "recoverNetworkAuto failed, fallback to SOFT", e)
            recoverNetwork(source = "recoverNetworkAuto-fallback", mode = RecoveryMode.SOFT, force = true)
        }
    }

    fun isNetworkRecoveryNeeded(): Boolean {
        return isPausedNow()
    }

    private fun shouldBypassIdleGuard(source: String): Boolean {
        return when (source) {
            "app_foreground", "screen_on", "doze_exit", "network_type_changed" -> true
            else -> false
        }
    }

    private fun recoverNetworkSoft(source: String): Boolean {
        val wakeOk = wake()
        val resetOk = resetNetwork()
        val ok = wakeOk && resetOk
        Log.i(TAG, "[SOFT][$source] wake=$wakeOk resetNetwork=$resetOk")
        return ok
    }

    private fun recoverNetworkHard(source: String): Boolean {
        val wakeOk = wake()
        val closed = closeAllTrackedConnections()
        val resetConnOk = resetAllConnections(true)
        val resetOk = resetNetwork()
        val ok = wakeOk && resetConnOk && resetOk
        Log.i(TAG, "[HARD][$source] wake=$wakeOk closed=$closed resetAllConnections=$resetConnOk resetNetwork=$resetOk")
        return ok
    }

    // ==================== URL 测试 ====================

    fun urlTestOutbound(outboundTag: String, url: String, timeoutMs: Int): Int {
        Log.d(TAG, "urlTestOutbound: using OpenWorld kernel")
        return try {
            OpenWorldCore.urlTest(outboundTag, url, timeoutMs).toInt()
        } catch (e: Exception) {
            Log.w(TAG, "urlTestOutbound failed: ${e.message}")
            -1
        }
    }

    fun urlTestBatch(
        outboundTags: List<String>,
        url: String,
        timeoutMs: Int,
        concurrency: Int
    ): Map<String, Int> {
        // 使用 OpenWorld 内置�?group 测试
        Log.d(TAG, "urlTestBatch: returning empty map")
        return emptyMap()
    }

    suspend fun urlTestGroupAsync(groupTag: String, timeoutMs: Long = 10000L): Map<String, Int> {
        val service = com.openworld.app.service.OpenWorldService.instance
        if (service == null) {
            Log.w(TAG, "urlTestGroupAsync: service not available")
            return emptyMap()
        }
        return try {
            service.urlTestGroup(groupTag, timeoutMs)
        } catch (e: Exception) {
            Log.e(TAG, "urlTestGroupAsync failed: ${e.message}")
            emptyMap()
        }
    }

    fun getCachedUrlTestDelay(tag: String): Int? {
        val service = com.openworld.app.service.OpenWorldService.instance
        return service?.getCachedUrlTestDelay(tag)
    }

    // ==================== 主流量保�?====================

    fun notifyMainTrafficActive() {
        Log.d(TAG, "notifyMainTrafficActive")
    }

    // ==================== 按出站流量统�?====================

    fun getTrafficByOutbound(): Map<String, Pair<Long, Long>> {
        return try {
            val json = OpenWorldCore.getTrafficSnapshot() ?: return emptyMap()
            // 解析 JSON 格式的流量快�?            parseTrafficSnapshot(json)
        } catch (e: Exception) {
            Log.w(TAG, "getTrafficByOutbound failed: ${e.message}")
            emptyMap()
        }
    }

    private fun parseTrafficSnapshot(json: String): Map<String, Pair<Long, Long>> {
        // 简单解�?- 实际应该�?Gson
        return try {
            val result = mutableMapOf<String, Pair<Long, Long>>()
            // TODO: 完善 JSON 解析
            result
        } catch (e: Exception) {
            emptyMap()
        }
    }

    fun closeConnectionsForApp(packageName: String): Int {
        Log.d(TAG, "closeConnectionsForApp not available")
        return 0
    }
}







