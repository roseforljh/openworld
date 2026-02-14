package com.openworld.app.service.manager

import android.app.Notification
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.net.Network
import android.net.VpnService
import android.os.SystemClock
import android.util.Log
import com.google.gson.Gson
import com.openworld.app.model.AppSettings
import com.openworld.app.model.OpenWorldConfig
import com.openworld.app.repository.LogRepository
import com.openworld.app.repository.RuleSetRepository
import com.openworld.app.repository.SettingsRepository
import com.openworld.app.service.notification.VpnNotificationManager
import com.openworld.app.utils.perf.DnsPrewarmer
import com.openworld.app.utils.perf.PerfTracer
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.first
import java.io.File
import java.net.InetSocketAddress
import java.net.ServerSocket

/**
 * VPN 启动管理�? * 负责完整�?VPN 启动流程，包括：
 * - 前台通知
 * - 权限检�? * - 并行初始�? * - 配置加载和修�? * - Libbox 启动
 */
class StartupManager(
    private val context: Context,
    private val vpnService: VpnService,
    private val serviceScope: CoroutineScope
) {
    companion object {
        private const val TAG = "StartupManager"
    }

    private val gson = Gson()
    private val logRepo by lazy { LogRepository.getInstance() }

    private fun log(msg: String) {
        Log.i(TAG, msg)
        logRepo.addLog("INFO [Startup] $msg")
    }

    /**
     * 检测端口是否可�?     */
    private fun isPortAvailable(port: Int): Boolean {
        if (port <= 0) return true
        return try {
            ServerSocket().use { socket ->
                socket.reuseAddress = true
                socket.bind(InetSocketAddress("127.0.0.1", port))
                true
            }
        } catch (@Suppress("SwallowedException") e: Exception) {
            // 端口被占用时会抛出异常，这是预期行为
            false
        }
    }

    /**
     * 启动回调接口
     */
    interface Callbacks {
        // 状态回�?        fun onStarting()
        fun onStarted(configContent: String)
        fun onFailed(error: String)
        fun onCancelled()

        // 通知管理
        fun createNotification(): Notification
        fun markForegroundStarted()

        // 生命周期管理
        fun registerScreenStateReceiver()
        fun startForeignVpnMonitor()
        fun stopForeignVpnMonitor()

        /**
         * 检测外�?VPN 并记录，返回是否存在外部 VPN
         */
        fun detectExistingVpns(): Boolean

        // 组件初始�?        fun initSelectorManager(configContent: String)
        fun createAndStartCommandServer(): Result<Unit>
        fun startCommandClients()
        fun startRouteGroupAutoSelect(configContent: String)
        fun scheduleAsyncRuleSetUpdate()
        fun startHealthMonitor()
        fun scheduleKeepaliveWorker()
        fun startTrafficMonitor()

        // 状态管�?        fun updateTileState()
        fun setIsRunning(running: Boolean)
        fun setIsStarting(starting: Boolean)
        fun setLastError(error: String?)
        fun persistVpnState(isRunning: Boolean)
        fun persistVpnPending(pending: String)

        // 网络管理
        suspend fun waitForUsablePhysicalNetwork(timeoutMs: Long): Network?
        suspend fun ensureNetworkCallbackReady(timeoutMs: Long)
        fun setLastKnownNetwork(network: Network?)
        fun setNetworkCallbackReady(ready: Boolean)
        /**
         * �?libbox 启动前恢复底层网�?         * 修复 PREPARE_RESTART -> setUnderlyingNetworks(null) �?         * libbox 在无底层网络状态下启动导致网络请求失败进入退避的问题
         */
        fun restoreUnderlyingNetwork(network: Network)

        // 清理
        suspend fun waitForCleanupJob()
        fun stopSelf()
    }

    /**
     * 启动结果
     */
    sealed class StartResult {
        data class Success(val configContent: String, val durationMs: Long) : StartResult()
        data class Failed(val error: String, val exception: Exception? = null) : StartResult()
        data object Cancelled : StartResult()
        data object NeedPermission : StartResult()
    }

    /**
     * 并行初始化结�?     */
    private data class ParallelInitResult(
        val network: Network?,
        val ruleSetReady: Boolean,
        val settings: AppSettings,
        val configContent: String,
        val dnsPrewarmResult: DnsPrewarmer.PrewarmResult?
    )

    /**
     * 执行完整�?VPN 启动流程
     */
    @Suppress("CognitiveComplexMethod", "CyclomaticComplexMethod", "LongMethod")
    suspend fun startVpn(
        configPath: String,
        cleanCache: Boolean,
        coreManager: CoreManager,
        connectManager: ConnectManager,
        callbacks: Callbacks
    ): StartResult = withContext(Dispatchers.IO) {
        val startupBeginMs = SystemClock.elapsedRealtime()
        PerfTracer.begin(PerfTracer.Phases.VPN_STARTUP)
        log("========== VPN STARTUP BEGIN ==========")

        try {
            // 等待前一个清理任务完�?            var stepStart = SystemClock.elapsedRealtime()
            callbacks.waitForCleanupJob()
            log("[STEP] waitForCleanupJob: ${SystemClock.elapsedRealtime() - stepStart}ms")

            callbacks.onStarting()

            // 1. 获取锁和注册监听�?            stepStart = SystemClock.elapsedRealtime()
            coreManager.acquireLocks()
            callbacks.registerScreenStateReceiver()
            log("[STEP] acquireLocks+registerReceiver: ${SystemClock.elapsedRealtime() - stepStart}ms")

            // 1.5 检测外�?VPN（在 prepare 之前�?            stepStart = SystemClock.elapsedRealtime()
            val hasExistingVpn = callbacks.detectExistingVpns()
            log("[STEP] detectExistingVpns: ${SystemClock.elapsedRealtime() - stepStart}ms, found=$hasExistingVpn")

            // 如果检测到外部 VPN，等待一小段时间�?prepare() 能正确处�?VPN 切换
            if (hasExistingVpn) {
                log("[STEP] External VPN detected, waiting for system to prepare takeover...")
                delay(100)
            }

            // 2. 检�?VPN 权限
            stepStart = SystemClock.elapsedRealtime()
            val prepareIntent = VpnService.prepare(context)
            log("[STEP] VpnService.prepare: ${SystemClock.elapsedRealtime() - stepStart}ms")
            if (prepareIntent != null) {
                handlePermissionRequired(prepareIntent, callbacks)
                return@withContext StartResult.NeedPermission
            }

            callbacks.startForeignVpnMonitor()

            // 3. 并行初始化（包括配置读取�?DNS 预热�?            stepStart = SystemClock.elapsedRealtime()
            PerfTracer.begin(PerfTracer.Phases.PARALLEL_INIT)
            val initResult = parallelInit(configPath, callbacks)
            PerfTracer.end(PerfTracer.Phases.PARALLEL_INIT)
            log("[STEP] parallelInit: ${SystemClock.elapsedRealtime() - stepStart}ms")

            // 记录 DNS 预热结果
            initResult.dnsPrewarmResult?.let { result ->
                log(
                    "[STEP] DNS prewarm: ${result.resolvedDomains} resolved, " +
                        "${result.cachedDomains} cached, ${result.failedDomains} failed " +
                        "of ${result.totalDomains} total in ${result.durationMs}ms"
                )
            } ?: log("[STEP] DNS prewarm: skipped")

            if (initResult.network == null) {
                throw IllegalStateException("No usable physical network before VPN start")
            }
            log("[STEP] network ready: ${initResult.network}")

            // 更新网络状�?            callbacks.setLastKnownNetwork(initResult.network)
            callbacks.setNetworkCallbackReady(true)

            // 设置 CoreManager 的当前设�?(用于 TUN 配置中的分应用代理等)
            coreManager.setCurrentSettings(initResult.settings)

            val configContent = initResult.configContent

            // 4. 清理缓存（如果需要）
            if (cleanCache) {
                stepStart = SystemClock.elapsedRealtime()
                coreManager.cleanCacheDb()
                log("[STEP] cleanCacheDb: ${SystemClock.elapsedRealtime() - stepStart}ms")
            }

            // 4.5 检查代理端口是否可�?            // 正常情况下关闭时已确保端口释放，这里只是防御性检�?            val proxyPort = initResult.settings.proxyPort
            if (proxyPort > 0 && !isPortAvailable(proxyPort)) {
                log("[STEP] Port $proxyPort unexpectedly in use, this should not happen")
                throw IllegalStateException("Port $proxyPort is still in use")
            }

            // 5. 创建并启�?CommandServer (必须�?startLibbox 之前)
            stepStart = SystemClock.elapsedRealtime()
            callbacks.createAndStartCommandServer().getOrThrow()
            log("[STEP] createAndStartCommandServer: ${SystemClock.elapsedRealtime() - stepStart}ms")

            // 5.5 �?libbox 启动前恢复底层网络（修复 PREPARE_RESTART 时序问题�?            callbacks.restoreUnderlyingNetwork(initResult.network)

            // 6. 启动 Libbox
            stepStart = SystemClock.elapsedRealtime()
            when (val result = coreManager.startLibbox(configContent)) {
                is CoreManager.StartResult.Success -> {
                    log(
                        "[STEP] startLibbox: ${SystemClock.elapsedRealtime() - stepStart}ms " +
                            "(internal: ${result.durationMs}ms)"
                    )
                }
                is CoreManager.StartResult.Failed -> {
                    throw Exception("Libbox start failed: ${result.error}", result.exception)
                }
                is CoreManager.StartResult.Cancelled -> {
                    return@withContext StartResult.Cancelled
                }
            }

            // 8. 初始化后续组�?            stepStart = SystemClock.elapsedRealtime()
            if (!coreManager.isServiceRunning()) {
                throw IllegalStateException("Service is not running after successful start")
            }

            callbacks.startCommandClients()
            callbacks.initSelectorManager(configContent)
            log("[STEP] postInit (clients+selector): ${SystemClock.elapsedRealtime() - stepStart}ms")

            // 9. 标记运行状�?            stepStart = SystemClock.elapsedRealtime()
            callbacks.setIsRunning(true)
            callbacks.setLastError(null)
            callbacks.persistVpnState(true)
            callbacks.stopForeignVpnMonitor()
            log("[STEP] markRunning: ${SystemClock.elapsedRealtime() - stepStart}ms")

            // 10. 启动监控和辅助组�?            stepStart = SystemClock.elapsedRealtime()
            callbacks.startTrafficMonitor()
            callbacks.startHealthMonitor()
            callbacks.scheduleKeepaliveWorker()
            callbacks.startRouteGroupAutoSelect(configContent)
            callbacks.scheduleAsyncRuleSetUpdate()
            log("[STEP] startMonitors: ${SystemClock.elapsedRealtime() - stepStart}ms")

            // 11. 更新 UI 状�?            stepStart = SystemClock.elapsedRealtime()
            callbacks.persistVpnPending("")
            callbacks.updateTileState()
            log("[STEP] updateUI: ${SystemClock.elapsedRealtime() - stepStart}ms")

            callbacks.onStarted(configContent)

            val totalMs = PerfTracer.end(PerfTracer.Phases.VPN_STARTUP)
            val actualTotal = SystemClock.elapsedRealtime() - startupBeginMs
            log("========== VPN STARTUP COMPLETE: ${actualTotal}ms ==========")

            StartResult.Success(configContent, totalMs)
        } catch (e: CancellationException) {
            PerfTracer.end(PerfTracer.Phases.VPN_STARTUP)
            callbacks.onCancelled()
            StartResult.Cancelled
        } catch (e: Exception) {
            PerfTracer.end(PerfTracer.Phases.VPN_STARTUP)
            val error = parseStartError(e)
            callbacks.onFailed(error)
            StartResult.Failed(error, e)
        } finally {
            callbacks.setIsStarting(false)
        }
    }

    private suspend fun parallelInit(
        configPath: String,
        callbacks: Callbacks
    ): ParallelInitResult = coroutineScope {
        val parallelStart = SystemClock.elapsedRealtime()
        log("[parallelInit] BEGIN")

        // 1. 读取配置文件（同步，因为后续任务依赖它）
        var stepStart = SystemClock.elapsedRealtime()
        val configFile = File(configPath)
        if (!configFile.exists()) {
            throw IllegalStateException("Config file not found: $configPath")
        }
        val rawConfigContent = configFile.readText()
        log(
            "[parallelInit] readConfig: ${SystemClock.elapsedRealtime() - stepStart}ms, size=${rawConfigContent.length}"
        )

        // 2. 启动并行任务
        val networkDeferred = async { ensureNetworkCallbackReady(callbacks) }
        val ruleSetDeferred = async { ensureRuleSetReady() }
        val settingsDeferred = async {
            val t = SystemClock.elapsedRealtime()
            val settingsRepository = SettingsRepository.getInstance(context)
            settingsRepository.reloadFromStorage()
            val settings = settingsRepository.settings.first()
            log("[parallelInit] loadSettings: ${SystemClock.elapsedRealtime() - t}ms")
            settings
        }
        val dnsPrewarmDeferred = async { prewarmDns(rawConfigContent) }

        // 4. 等待设置加载完成，然后修补配�?        stepStart = SystemClock.elapsedRealtime()
        val settings = settingsDeferred.await()
        val configContent = patchConfig(rawConfigContent, settings)
        log("[parallelInit] patchConfig: ${SystemClock.elapsedRealtime() - stepStart}ms")

        // 等待所有并行任务完�?        val network = networkDeferred.await()
        val ruleSetReady = ruleSetDeferred.await()
        val dnsResult = dnsPrewarmDeferred.await()

        log("[parallelInit] END: ${SystemClock.elapsedRealtime() - parallelStart}ms total")

        ParallelInitResult(
            network = network,
            ruleSetReady = ruleSetReady,
            settings = settings,
            configContent = configContent,
            dnsPrewarmResult = dnsResult
        )
    }

    private suspend fun ensureNetworkCallbackReady(callbacks: Callbacks): Network? {
        val t = SystemClock.elapsedRealtime()
        callbacks.ensureNetworkCallbackReady(1500L)
        val afterCallback = SystemClock.elapsedRealtime()
        log("[parallelInit] ensureNetworkCallbackReady: ${afterCallback - t}ms")
        val network = callbacks.waitForUsablePhysicalNetwork(3000L)
        log(
            "[parallelInit] waitForUsablePhysicalNetwork: " +
                "${SystemClock.elapsedRealtime() - afterCallback}ms, network=$network"
        )
        return network
    }

    private suspend fun ensureRuleSetReady(): Boolean {
        val t = SystemClock.elapsedRealtime()
        val result = runCatching {
            RuleSetRepository.getInstance(context).ensureRuleSetsReady(
                forceUpdate = false,
                allowNetwork = false
            ) { }
        }.getOrDefault(false)
        log("[parallelInit] ruleSetReady: ${SystemClock.elapsedRealtime() - t}ms, ready=$result")
        return result
    }

    private suspend fun prewarmDns(rawConfigContent: String): DnsPrewarmer.PrewarmResult? {
        val t = SystemClock.elapsedRealtime()
        val result = runCatching {
            DnsPrewarmer.prewarm(rawConfigContent)
        }.getOrNull()
        log(
            "[parallelInit] dnsPrewarm: ${SystemClock.elapsedRealtime() - t}ms, domains=${result?.totalDomains ?: 0}"
        )
        return result
    }

    private fun patchConfig(rawConfigContent: String, settings: AppSettings): String {
        var configContent = rawConfigContent
        val logLevel = if (settings.debugLoggingEnabled) "debug" else "info"

        try {
            val configObj = gson.fromJson(configContent, OpenWorldConfig::class.java)

            val logConfig = configObj.log?.copy(level = logLevel)
                ?: com.openworld.app.model.LogConfig(level = logLevel, timestamp = true, output = "box.log")

            var newConfig = configObj.copy(log = logConfig)

            if (newConfig.inbounds != null) {
                val newInbounds = newConfig.inbounds.orEmpty().map { inbound ->
                    if (inbound.type == "tun") {
                        inbound.copy(autoRoute = settings.autoRoute)
                    } else {
                        inbound
                    }
                }
                newConfig = newConfig.copy(inbounds = newInbounds)
            }

            // 为代理节点设置较短的连接超时，减少启动延�?            // 非代理类型（direct, block, dns, selector, urltest）不需要设�?            val proxyTypes = setOf(
                "shadowsocks", "vmess", "vless", "trojan",
                "hysteria", "hysteria2", "tuic", "wireguard",
                "ssh", "shadowtls", "socks", "http", "anytls"
            )
            val defaultConnectTimeout = "5s"

            if (newConfig.outbounds != null) {
                val newOutbounds = newConfig.outbounds.orEmpty().map { outbound ->
                    if (outbound.type in proxyTypes && outbound.connectTimeout == null) {
                        outbound.copy(connectTimeout = defaultConnectTimeout)
                    } else {
                        outbound
                    }
                }
                newConfig = newConfig.copy(outbounds = newOutbounds)
            }

            configContent = gson.toJson(newConfig)
            Log.i(
                TAG,
                "Patched config: auto_route=${settings.autoRoute}, " +
                    "log_level=$logLevel, connect_timeout=$defaultConnectTimeout"
            )
        } catch (e: Exception) {
            Log.w(TAG, "Failed to patch config: ${e.message}")
        }

        return configContent
    }

    private fun handlePermissionRequired(prepareIntent: Intent, callbacks: Callbacks) {
        Log.w(TAG, "VPN permission required")
        callbacks.persistVpnState(false)
        callbacks.persistVpnPending("")

        runCatching {
            prepareIntent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            context.startActivity(prepareIntent)
        }.onFailure {
            runCatching {
                val manager = context.getSystemService(NotificationManager::class.java)
                val pi = PendingIntent.getActivity(
                    context, 2002,
                    prepareIntent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK),
                    PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
                )
                val notification = Notification.Builder(context, VpnNotificationManager.CHANNEL_ID)
                    .setContentTitle("VPN Permission Required")
                    .setContentText("Tap to grant VPN permission")
                    .setSmallIcon(android.R.drawable.ic_dialog_info)
                    .setContentIntent(pi)
                    .setAutoCancel(true)
                    .build()
                manager.notify(VpnNotificationManager.NOTIFICATION_ID + 3, notification)
            }
        }
    }

    private fun parseStartError(e: Exception): String {
        val msg = e.message.orEmpty()
        return when {
            msg.contains("VPN lockdown enabled by", ignoreCase = true) -> {
                val lockedBy = msg.substringAfter("VPN lockdown enabled by ").trim().ifBlank { "unknown" }
                "Start failed: system lockdown VPN enabled ($lockedBy)"
            }
            msg.contains("VPN interface establish failed", ignoreCase = true) ||
                msg.contains("configure tun interface", ignoreCase = true) ||
                msg.contains("fd=-1", ignoreCase = true) -> {
                "Start failed: could not establish VPN interface"
            }
            else -> "Failed to start VPN: ${e.javaClass.simpleName}: ${e.message}"
        }
    }
}







