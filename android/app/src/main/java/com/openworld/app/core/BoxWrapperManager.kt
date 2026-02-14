package com.openworld.app.core

import android.util.Log
import com.openworld.app.core.bridge.CommandServer
import com.openworld.app.core.bridge.Libbox
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

/**
 * BoxWrapper 管理器 - 统一管理 libbox 的生命周期
 *
 * 功能:
 * - 节点切换: selectOutbound()
 * - 电源管理: pause() / resume()
 * - 流量统计: getUploadTotal() / getDownloadTotal()
 * - 全局访问: 通过 Libbox 静态方法跨组件共享
 *
 * 新版 libbox API (基于 CommandServer):
 * - 不再使用 BoxService 和 BoxWrapper
 * - 使用 Libbox.xxxxx() 静态方法
 * - CommandServer 作为主入口点管理服务生命周期
 */
object BoxWrapperManager {
    private const val TAG = "BoxWrapperManager"

    enum class RecoveryMode {
        SOFT,
        HARD
    }

    @Volatile
    private var commandServer: CommandServer? = null

    private val _isPaused = MutableStateFlow(false)
    val isPaused: StateFlow<Boolean> = _isPaused.asStateFlow()

    private val _hasSelector = MutableStateFlow(false)
    val hasSelector: StateFlow<Boolean> = _hasSelector.asStateFlow()

    // 2025-fix-v22: 暂停历史跟踪，用于判断是否需要强制关闭连接
    @Volatile
    private var lastResumeTimestamp: Long = 0L

    // 2025-fix-v18: resetNetwork 防抖，防止多个恢复触发点同时调用
    // 2025-fix-v26: 降低防抖时间从 2 秒到 500 毫秒，避免正常恢复被跳过
    @Volatile
    private var lastResetNetworkTimestamp: Long = 0L
    private const val RESET_NETWORK_DEBOUNCE_MS = 500L

    fun detectCoreType() {
        Log.i(TAG, "OpenWorld core mode active")
    }

    /**
     * 初始化 - 绑定 CommandServer
     * 在 CommandServer 创建后调用
     */
    fun init(server: CommandServer): Boolean {
        return try {
            commandServer = server
            _isPaused.value = false
            _hasSelector.value = runCatching { Libbox.hasSelector() }.getOrDefault(false)
            Log.i(TAG, "BoxWrapperManager initialized, hasSelector=${_hasSelector.value}")
            true
        } catch (e: Exception) {
            Log.e(TAG, "Failed to init BoxWrapperManager", e)
            commandServer = null
            false
        }
    }

    /**
     * 释放 - 清理状态
     * 在 CommandServer 关闭时调用
     */
    fun release() {
        commandServer = null
        _isPaused.value = false
        _hasSelector.value = false
        Log.i(TAG, "BoxWrapperManager released")
    }

    /**
     * 检查服务是否可用
     * v1.12.20: Libbox.isRunning() 已移除，改为检查 commandServer 是否存在
     */
    fun isAvailable(): Boolean {
        return commandServer != null
    }

    // ==================== 节点切换 ====================

    /**
     * 切换出站节点
     * @param nodeTag 节点标签
     * @return true 如果切换成功
     */
    fun selectOutbound(nodeTag: String): Boolean {
        return try {
            val result = Libbox.selectOutboundByTag(nodeTag)
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
     * 获取当前选中的出站节点
     */
    fun getSelectedOutbound(): String? {
        return try {
            Libbox.getSelectedOutbound().takeIf { it.isNotBlank() }
        } catch (e: Exception) {
            Log.w(TAG, "getSelectedOutbound failed: ${e.message}")
            null
        }
    }

    /**
     * 获取所有出站节点列表
     * @return 节点标签列表
     */
    fun listOutbounds(): List<String> {
        return try {
            Libbox.listOutboundsString()
                ?.split("\n")
                ?.filter { it.isNotBlank() }
                ?: emptyList()
        } catch (e: Exception) {
            Log.w(TAG, "listOutbounds failed: ${e.message}")
            emptyList()
        }
    }

    /**
     * 检查是否有 selector 类型的出站
     */
    fun hasSelector(): Boolean {
        return try {
            Libbox.hasSelector()
        } catch (e: Exception) {
            false
        }
    }

    // ==================== 电源管理 ====================

    /**
     * 暂停 - 设备休眠时调用
     * 通知 sing-box 内核进入省电模式
     */
    fun pause(): Boolean {
        return try {
            Libbox.pauseService()
            _isPaused.value = true
            Log.i(TAG, "pause() success")
            true
        } catch (e: Exception) {
            Log.w(TAG, "pause() failed: ${e.message}")
            false
        }
    }

    /**
     * 恢复 - 设备唤醒时调用
     * 通知 sing-box 内核恢复正常模式
     */
    fun resume(): Boolean {
        return try {
            Libbox.resumeService()
            _isPaused.value = false
            lastResumeTimestamp = System.currentTimeMillis()
            Log.i(TAG, "resume() success")
            true
        } catch (e: Exception) {
            Log.w(TAG, "resume() failed: ${e.message}")
            false
        }
    }

    /**
     * 检查是否处于暂停状态
     */
    fun isPausedNow(): Boolean {
        return try {
            Libbox.isPaused()
        } catch (e: Exception) {
            _isPaused.value
        }
    }

    /**
     * 检查是否最近从暂停状态恢复
     * 用于判断是否需要在 NetworkBump 时强制关闭连接 (发送 RST)
     *
     * @param thresholdMs 阈值毫秒数，默认 30 秒
     * @return true 如果在阈值时间内从暂停状态恢复过
     */
    fun wasPausedRecently(thresholdMs: Long = 30_000L): Boolean {
        val timestamp = lastResumeTimestamp
        if (timestamp == 0L) return false
        return (System.currentTimeMillis() - timestamp) < thresholdMs
    }

    /**
     * 进入睡眠模式 - 设备空闲 (Doze) 时调用
     * 比 pause() 更激进
     *
     * @return true 如果成功
     */
    fun sleep(): Boolean {
        return pause()
    }

    /**
     * 从睡眠中唤醒 - 设备退出空闲 (Doze) 模式时调用
     * v1.12.20: CommandServer.wake() 已移除，使用 Libbox.resumeService() 替代
     *
     * @return true 如果成功
     */
    fun wake(): Boolean {
        // v1.12.20: 直接使用 resume() 实现唤醒功能
        return resume()
    }

    /**
     * 2025-fix-v19: 完整网络恢复 - 统一入口点
     * 2025-fix-v26: 添加 force 参数，允许绕过防抖强制执行
     *
     * @param source 调用来源，用于日志追踪
     * @param force 是否强制执行（绕过防抖），用于关键恢复场景如 Activity Resume
     * @return true 如果成功执行
     */
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
            Log.d(
                TAG,
                "[$source] recoverNetwork skipped (no connections, " +
                    "recovery not needed, bypass=$bypassIdleGuard)"
            )
            return true
        }

        Log.d(
            TAG,
            "[$source] recoverNetwork proceed (mode=$mode force=$force " +
                "hasActiveState=$hasActiveState bypass=$bypassIdleGuard)"
        )

        lastResetNetworkTimestamp = now
        _isPaused.value = false
        lastResumeTimestamp = now

        return when (mode) {
            RecoveryMode.SOFT -> recoverNetworkSoft(source)
            RecoveryMode.HARD -> recoverNetworkHard(source)
        }
    }

    // ==================== 智能恢复 (Phase 1) ====================

    /**
     * 智能恢复 - 三级渐进式恢复策略
     *
     * Level 1 (PROBE): 探测 VPN 链路，如果正常则无需恢复
     * Level 2 (SELECTIVE): 关闭所有连接 + resetNetwork
     * Level 3 (NUCLEAR): 完整重置 (resetAllConnections + resetNetwork)
     *
     * @param context Android Context，用于探测
     * @param source 调用来源，用于日志追踪
     * @param skipProbe 是否跳过探测直接恢复（用于已知链路异常的场景）
     * @return SmartRecoveryResult 恢复结果
     */
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

        // Level 1: PROBE
        if (!skipProbe) {
            val probeResult = executeProbeLevel(context, source, startTime)
            if (probeResult != null) return probeResult
        }

        // Level 2: SELECTIVE
        val selectiveResult = executeSelectiveLevel(context, source, startTime)
        if (selectiveResult.success && selectiveResult.level == RecoveryLevel.SELECTIVE) {
            return selectiveResult
        }

        // Level 3: NUCLEAR
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
        // Phase 2: 优先关闭空闲连接，保留活跃连接
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

    /** 恢复级别 */
    enum class RecoveryLevel { NONE, PROBE, SELECTIVE, NUCLEAR }

    /** 智能恢复结果 */
    data class SmartRecoveryResult(
        val level: RecoveryLevel,
        val success: Boolean,
        val reason: String,
        val closedConnections: Int = 0,
        val probeLatencyMs: Long? = null
    )

    // ==================== 流量统计 ====================

    /**
     * 获取累计上传字节数
     */
    fun getUploadTotal(): Long {
        return try {
            Libbox.getTrafficTotalUplink()
        } catch (e: Exception) {
            Log.w(TAG, "getUploadTotal failed: ${e.message}")
            -1L
        }
    }

    /**
     * 获取累计下载字节数
     */
    fun getDownloadTotal(): Long {
        return try {
            Libbox.getTrafficTotalDownlink()
        } catch (e: Exception) {
            Log.w(TAG, "getDownloadTotal failed: ${e.message}")
            -1L
        }
    }

    /**
     * 重置流量统计
     */
    fun resetTraffic(): Boolean {
        return try {
            val result = Libbox.resetTrafficStats()
            Log.i(TAG, "resetTraffic() result=$result")
            result
        } catch (e: Exception) {
            Log.w(TAG, "resetTraffic() failed: ${e.message}")
            false
        }
    }

    /**
     * 获取连接数
     */
    fun getConnectionCount(): Int {
        return try {
            Libbox.getConnectionCount().toInt()
        } catch (e: Exception) {
            0
        }
    }

    // ==================== 工具函数 ====================

    /**
     * 重置所有连接
     * @param system true=重置系统级连接表
     */
    fun resetAllConnections(system: Boolean = true): Boolean {
        return try {
            Libbox.resetAllConnections(system)
            Log.i(TAG, "resetAllConnections($system) success")
            true
        } catch (e: Exception) {
            Log.w(TAG, "resetAllConnections failed: ${e.message}")
            // 回退到 LibboxCompat
            LibboxCompat.resetAllConnections(system)
        }
    }

    /**
     * 重置网络
     * v1.12.20: CommandServer.resetNetwork() 已移除，使用 Libbox.resetAllConnections() 替代
     */
    fun resetNetwork(): Boolean {
        // v1.12.20: 使用 resetAllConnections 作为替代方案
        return try {
            Libbox.resetAllConnections(false)
            Log.i(TAG, "resetNetwork() success (via resetAllConnections)")
            true
        } catch (e: Exception) {
            Log.w(TAG, "resetNetwork() failed: ${e.message}")
            false
        }
    }

    /**
     * 关闭所有跟踪连接
     */
    fun closeAllTrackedConnections(): Int {
        return try {
            val count = Libbox.closeAllTrackedConnections().toInt()
            if (count > 0) {
                Log.i(TAG, "closeAllTrackedConnections: closed $count connections")
            }
            count
        } catch (e: Exception) {
            Log.w(TAG, "closeAllTrackedConnections failed: ${e.message}")
            0
        }
    }

    /**
     * 关闭空闲连接 (Phase 2)
     * 关闭空闲超过指定时间的连接
     *
     * @param maxIdleSeconds 最大空闲时间(秒)
     * @return 关闭的连接数
     */
    fun closeIdleConnections(maxIdleSeconds: Int = 30): Int {
        // 尝试通过反射调用内核扩展 API (避免编译时依赖)
        return try {
            val method = Libbox::class.java.getMethod("closeIdleConnections", Long::class.javaPrimitiveType)
            val count = (method.invoke(null, maxIdleSeconds.toLong()) as Number).toInt()
            if (count > 0) {
                Log.i(TAG, "closeIdleConnections($maxIdleSeconds): closed $count connections")
            }
            count
        } catch (e: NoSuchMethodException) {
            // 内核不支持此 API，回退到关闭所有连接
            Log.w(TAG, "closeIdleConnections not available in kernel: ${e.message}, fallback")
            closeAllTrackedConnections()
        } catch (e: Exception) {
            Log.w(TAG, "closeIdleConnections failed: ${e.message}, fallback to closeAllTrackedConnections")
            closeAllTrackedConnections()
        }
    }

    /**
     * 获取扩展版本
     */
    fun getExtensionVersion(): String {
        return try {
            Libbox.getOpenWorldVersion()
        } catch (e: Exception) {
            "unknown"
        }
    }

    /**
     * 获取 CommandServer 实例
     * 仅在 VPN 运行时可用
     */
    fun getCommandServer(): CommandServer? {
        return commandServer
    }

    // ==================== Network Recovery (Fix loading issue after background resume) ====================

    /**
     * Auto network recovery - Recommended entry point
     * Automatically selects recovery strategy based on current state
     * @return true if recovery succeeded
     */
    fun recoverNetworkAuto(): Boolean {
        return try {
            Libbox.recoverNetworkAuto()
        } catch (e: Exception) {
            Log.w(TAG, "recoverNetworkAuto kernel call failed, fallback to SOFT", e)
            recoverNetwork(source = "recoverNetworkAuto-fallback", mode = RecoveryMode.SOFT, force = true)
        }
    }

    /**
     * Check if network recovery is needed
     */
    fun isNetworkRecoveryNeeded(): Boolean {
        return try {
            Libbox.checkNetworkRecoveryNeeded()
        } catch (e: Exception) {
            isPausedNow()
        }
    }

    private fun shouldBypassIdleGuard(source: String): Boolean {
        return when (source) {
            "app_foreground",
            "screen_on",
            "doze_exit",
            "network_type_changed" -> true

            else -> false
        }
    }

    private fun recoverNetworkSoft(source: String): Boolean {
        val forceTag = "[SOFT][$source]"
        return try {
            val wakeOk = wake()
            val resetOk = resetNetwork()
            val ok = wakeOk && resetOk
            Log.i(TAG, "$forceTag wake=$wakeOk resetNetwork=$resetOk")
            ok
        } catch (e: Exception) {
            Log.w(TAG, "$forceTag failed", e)
            false
        }
    }

    private fun recoverNetworkHard(source: String): Boolean {
        val forceTag = "[HARD][$source]"
        return try {
            val wakeOk = wake()
            val closed = closeAllTrackedConnections()
            val resetConnOk = resetAllConnections(true)
            val resetOk = resetNetwork()
            val ok = wakeOk && resetConnOk && resetOk
            Log.i(
                TAG,
                "$forceTag wake=$wakeOk closed=$closed resetAllConnections=$resetConnOk resetNetwork=$resetOk"
            )
            ok
        } catch (e: Exception) {
            Log.e(TAG, "$forceTag failed", e)
            false
        }
    }

    /**
     * URL 测试单个节点
     * v1.12.20: Libbox.urlTestOutbound() 已移除，返回 -1 表示不支持
     * 注意: 单节点测试需要使用 OkHttp 回退方案，因为 CommandClient.urlTest() 是针对整个 group 的
     */
    @Suppress("UNUSED_PARAMETER")
    fun urlTestOutbound(outboundTag: String, url: String, timeoutMs: Int): Int {
        // v1.12.20: urlTestOutbound API 已移除，返回 -1 触发回退到本地测试
        // CommandClient.urlTest() 是针对整个 group 的，不支持单节点测试
        Log.d(TAG, "urlTestOutbound: using fallback for single node test")
        return -1
    }

    /**
     * 批量 URL 测试 (同步版本)
     * v1.12.20: 使用 CommandClient.urlTest(groupTag) 实现
     * 注意: 这是同步方法，如果需要异步测试请使用 urlTestGroupAsync()
     */
    @Suppress("UNUSED_PARAMETER")
    fun urlTestBatch(
        outboundTags: List<String>,
        url: String,
        timeoutMs: Int,
        concurrency: Int
    ): Map<String, Int> {
        // v1.12.20: 同步方法无法使用异步的 CommandClient.urlTest()
        // 返回空 Map 触发回退到 OkHttp 方案
        Log.d(TAG, "urlTestBatch: sync method, returning empty map to trigger fallback")
        return emptyMap()
    }

    /**
     * 异步 URL 测试整个 group
     * v1.12.20: 使用 CommandClient.urlTest(groupTag) API
     *
     * @param groupTag 要测试的 group 标签 (如 "PROXY")
     * @param timeoutMs 等待结果的超时时间
     * @return 节点延迟映射 (tag -> delay ms)，失败返回空 Map
     */
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

    /**
     * 获取缓存的 URL 测试延迟
     * @param tag 节点标签
     * @return 延迟值 (ms)，未测试返回 null
     */
    fun getCachedUrlTestDelay(tag: String): Int? {
        val service = com.openworld.app.service.OpenWorldService.instance
        return service?.getCachedUrlTestDelay(tag)
    }

    // ==================== Main Traffic Protection ====================

    /**
     * 通知内核主流量正在活跃
     * v1.12.20: Libbox.notifyMainTrafficActive() 已移除，空实现
     */
    fun notifyMainTrafficActive() {
        // v1.12.20: notifyMainTrafficActive API 已移除，空实现
        Log.d(TAG, "notifyMainTrafficActive not available in v1.12.20")
    }

    // ==================== Per-Outbound Traffic ====================

    /**
     * 获取按出站分组的流量统计
     * 用于准确记录分流场景下各节点的流量
     *
     * @return Map<节点标签, Pair<上传字节, 下载字节>>
     */
    fun getTrafficByOutbound(): Map<String, Pair<Long, Long>> {
        return try {
            val iterator = Libbox.getTrafficByOutbound() ?: return emptyMap()
            val result = mutableMapOf<String, Pair<Long, Long>>()
            while (iterator.hasNext()) {
                val item = iterator.next() ?: continue
                val tag = item.tag
                if (!tag.isNullOrBlank()) {
                    result[tag] = Pair(item.upload, item.download)
                }
            }
            result
        } catch (e: Exception) {
            Log.w(TAG, "getTrafficByOutbound failed: ${e.message}")
            emptyMap()
        }
    }

    /**
     * 关闭指定应用的连接
     * v1.12.20: Libbox.closeConnectionsForApp() 已移除，返回 0
     */
    @Suppress("UNUSED_PARAMETER")
    fun closeConnectionsForApp(packageName: String): Int {
        // v1.12.20: closeConnectionsForApp API 已移除
        Log.d(TAG, "closeConnectionsForApp not available in v1.12.20")
        return 0
    }
}
