package com.openworld.app.service.manager

import android.content.Context
import android.net.Network
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.os.PowerManager
import android.net.wifi.WifiManager
import android.util.Log
import com.openworld.app.core.SingBoxCore
import com.openworld.app.core.BoxWrapperManager
import com.openworld.app.core.SelectorManager
import com.openworld.app.model.AppSettings
import com.openworld.app.repository.SettingsRepository
import com.openworld.app.service.tun.VpnTunManager
import com.openworld.app.utils.perf.PerfTracer
import io.nekohasekai.libbox.CommandClient
import io.nekohasekai.libbox.CommandServer
import io.nekohasekai.libbox.Libbox
import io.nekohasekai.libbox.BoxService
import io.nekohasekai.libbox.PlatformInterface
import io.nekohasekai.libbox.TunOptions
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.first
import java.io.File

/**
 * 核心管理器 (重构版)
 * 负责完整的 VPN 生命周期管理
 * 使用 Result<T> 返回值模式
 *
 * v1.12.20 libbox API:
 * - BoxService 通过 Libbox.newService(configContent, platformInterface) 创建
 * - BoxService.start() 启动服务
 * - BoxService.close() 关闭服务
 * - CommandServer.setService(boxService) 关联服务
 */
class CoreManager(
    private val context: Context,
    private val vpnService: VpnService,
    private val serviceScope: CoroutineScope
) {
    companion object {
        private const val TAG = "CoreManager"
    }

    private val tunManager = VpnTunManager(context, vpnService)
    private val settingsRepository by lazy { SettingsRepository.getInstance(context) }

    // ===== 核心状态 =====
    @Volatile var commandServer: CommandServer? = null
        private set

    // v1.12.20: 添加 BoxService 字段
    @Volatile var boxService: BoxService? = null
        private set

    @Volatile var vpnInterface: ParcelFileDescriptor? = null
        private set

    @Volatile var currentSettings: AppSettings? = null
        private set

    @Volatile var isStarting = false
        private set

    @Volatile var isStopping = false
        private set

    @Volatile var currentConfigContent: String? = null
        private set

    // ===== Command Client =====
    var commandClient: CommandClient? = null
        private set

    // ===== Locks =====
    private var wakeLock: PowerManager.WakeLock? = null
    private var wifiLock: WifiManager.WifiLock? = null

    @Volatile
    private var wifiLockSuppressed: Boolean = false

    // 回调接口
    private var platformInterface: PlatformInterface? = null

    /**
     * 启动结果
     */
    sealed class StartResult {
        data class Success(val durationMs: Long, val configContent: String) : StartResult()
        data class Failed(val error: String, val exception: Exception? = null) : StartResult()
        object Cancelled : StartResult()
    }

    /**
     * 停止结果
     */
    sealed class StopResult {
        object Success : StopResult()
        data class Failed(val error: String) : StopResult()
    }

    /**
     * 初始化管理器
     */
    fun init(platformInterface: PlatformInterface): Result<Unit> {
        return runCatching {
            this.platformInterface = platformInterface
            Log.i(TAG, "CoreManager initialized")
        }
    }

    /**
     * 预分配 TUN Builder
     */
    fun preallocateTunBuilder(): Result<Unit> {
        return runCatching {
            tunManager.preallocateBuilder()
            Log.d(TAG, "TUN builder preallocated")
        }
    }

    /**
     * 加载设置
     */
    suspend fun loadSettings(): Result<AppSettings> {
        return runCatching {
            PerfTracer.begin(PerfTracer.Phases.SETTINGS_LOAD)
            val settings = settingsRepository.settings.first()
            currentSettings = settings
            PerfTracer.end(PerfTracer.Phases.SETTINGS_LOAD)
            settings
        }
    }

    /**
     * 设置当前设置 (用于外部已加载的设置)
     */
    fun setCurrentSettings(settings: AppSettings) {
        currentSettings = settings
    }

    /**
     * 获取 WakeLock 和 WifiLock
     */
    fun acquireLocks(): Result<Unit> {
        return runCatching {
            acquireWakeLock()
            acquireWifiLockIfAllowed()
            Log.i(TAG, "WakeLock and WifiLock acquired")
        }
    }

    private fun acquireWakeLock() {
        if (wakeLock?.isHeld == true) return

        val pm = context.getSystemService(Context.POWER_SERVICE) as PowerManager
        wakeLock = pm.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "OpenWorld:VpnService")
        wakeLock?.setReferenceCounted(false)
        // Keep a long timeout as a safety net. We rely on explicit release in stopFully().
        wakeLock?.acquire(24 * 60 * 60 * 1000L)
    }

    private fun acquireWifiLockIfAllowed() {
        if (wifiLockSuppressed) {
            Log.i(TAG, "WifiLock suppressed (power saving), skip acquire")
            return
        }
        if (wifiLock?.isHeld == true) return

        val wm = context.getSystemService(Context.WIFI_SERVICE) as WifiManager
        @Suppress("DEPRECATION")
        wifiLock = wm.createWifiLock(WifiManager.WIFI_MODE_FULL_HIGH_PERF, "OpenWorld:VpnService")
        wifiLock?.setReferenceCounted(false)
        wifiLock?.acquire()
    }

    /**
     * 释放 WakeLock 和 WifiLock
     */
    fun releaseLocks(): Result<Unit> {
        return runCatching {
            if (wakeLock?.isHeld == true) wakeLock?.release()
            wakeLock = null
            releaseWifiLockInternal()
            Log.i(TAG, "WakeLock and WifiLock released")
        }
    }

    /**
     * Reduce battery usage in background power-saving mode.
     * Stability-first: we only suppress WifiLock here (WakeLock kept as before).
     */
    fun enterPowerSavingMode(): Result<Unit> {
        return runCatching {
            wifiLockSuppressed = true
            releaseWifiLockInternal()
            Log.i(TAG, "Entered power saving mode: WifiLock suppressed")
        }
    }

    /**
     * Resume normal mode. WifiLock will be re-acquired when VPN is running.
     */
    fun exitPowerSavingMode(): Result<Unit> {
        return runCatching {
            wifiLockSuppressed = false
            acquireWifiLockIfAllowed()
            Log.i(TAG, "Exited power saving mode: WifiLock allowed")
        }
    }

    private fun releaseWifiLockInternal() {
        if (wifiLock?.isHeld == true) wifiLock?.release()
        wifiLock = null
    }

    /**
     * 清理 cache.db (跨配置切换)
     */
    fun cleanCacheDb(): Result<Boolean> {
        return runCatching {
            val cacheDir = File(context.filesDir, "singbox_data")
            val cacheDb = File(cacheDir, "cache.db")
            if (cacheDb.exists()) {
                val deleted = cacheDb.delete()
                Log.i(TAG, "Deleted cache.db: $deleted")
                deleted
            } else {
                false
            }
        }
    }

    /**
     * 设置 CommandServer (从 CommandManager 传入)
     */
    fun setCommandServer(server: CommandServer?) {
        commandServer = server
    }

    /**
     * 启动 Libbox 服务 (v1.12.20: 使用 BoxService 模式)
     */
    suspend fun startLibbox(configContent: String): StartResult {
        if (isStarting) {
            return StartResult.Failed("Already starting")
        }

        isStarting = true
        PerfTracer.begin(PerfTracer.Phases.LIBBOX_START)

        val logRepo = com.openworld.app.repository.LogRepository.getInstance()

        return try {
            val server = commandServer
                ?: throw IllegalStateException("CommandServer not initialized")
            val pi = platformInterface
                ?: throw IllegalStateException("PlatformInterface not initialized")

            logRepo.addLog("INFO [Startup] [STEP] startLibbox: ensureLibboxSetup...")
            SingBoxCore.ensureLibboxSetup(context)

            logRepo.addLog("INFO [Startup] [STEP] startLibbox: creating BoxService...")
            val serviceStartTime = android.os.SystemClock.elapsedRealtime()

            withContext(Dispatchers.IO) {
                // v1.12.20: 使用 BoxService 模式
                val service = Libbox.newService(configContent, pi)
                service.start()
                boxService = service
                server.setService(service)
            }

            val serviceStartDuration = android.os.SystemClock.elapsedRealtime() - serviceStartTime
            logRepo.addLog(
                "INFO [Startup] [STEP] startLibbox: BoxService started in ${serviceStartDuration}ms"
            )

            currentConfigContent = configContent

            val durationMs = PerfTracer.end(PerfTracer.Phases.LIBBOX_START)
            Log.i(TAG, "Libbox started in ${durationMs}ms")

            StartResult.Success(durationMs, configContent)
        } catch (e: CancellationException) {
            PerfTracer.end(PerfTracer.Phases.LIBBOX_START)
            Log.i(TAG, "Libbox start cancelled")
            StartResult.Cancelled
        } catch (e: Exception) {
            PerfTracer.end(PerfTracer.Phases.LIBBOX_START)
            Log.e(TAG, "Libbox start failed: ${e.message}", e)
            logRepo.addLog("ERR [Startup] startLibbox failed: ${e.message}")
            StartResult.Failed(e.message ?: "Unknown error", e)
        } finally {
            isStarting = false
        }
    }

    /**
     * 停止服务 (保留 TUN 用于跨配置切换)
     * v1.12.20: 使用 BoxService.close() 替代 CommandServer.closeService()
     */
    suspend fun stopService(): Result<Unit> {
        return runCatching {
            withContext(Dispatchers.IO) {
                // 释放 BoxWrapperManager
                BoxWrapperManager.release()

                // 清除 SelectorManager 状态
                SelectorManager.clear()

                // v1.12.20: 关闭 BoxService
                boxService?.close()
                boxService = null

                currentConfigContent = null
                Log.i(TAG, "Service stopped")
                Unit
            }
        }
    }

    /**
     * 完全停止 VPN (关闭 TUN)
     */
    suspend fun stopFully(): Result<Unit> {
        if (isStopping) {
            return Result.failure(IllegalStateException("Already stopping"))
        }

        isStopping = true

        return runCatching {
            withContext(Dispatchers.IO) {
                // 1. 停止服务
                stopService()

                // 2. 关闭 TUN 接口
                vpnInterface?.let { pfd ->
                    runCatching { pfd.close() }
                    vpnInterface = null
                }

                // 3. 清理 TUN 管理器
                tunManager.cleanup()

                // 4. 释放锁
                releaseLocks()

                currentSettings = null
                Log.i(TAG, "VPN fully stopped")
                Unit
            }
        }.also {
            isStopping = false
        }
    }

    /**
     * 停止 (兼容旧 API)
     */
    suspend fun stop(): Result<Unit> = stopFully()

    /**
     * 设置底层网络（统一方法）
     * 修复：复用 TUN 时也必须刷新 underlying networks
     * 解决 ACTION_PREPARE_RESTART -> setUnderlyingNetworks(null) 后无法自动恢复的问题
     */
    private fun applyUnderlyingNetworkIfPossible(underlyingNetwork: Network?, reason: String) {
        if (underlyingNetwork == null) return
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.LOLLIPOP_MR1) return

        runCatching {
            vpnService.setUnderlyingNetworks(arrayOf(underlyingNetwork))
            Log.i(TAG, "Underlying network set ($reason): $underlyingNetwork")
        }.onFailure { e ->
            Log.w(TAG, "Failed to set underlying network ($reason)", e)
        }
    }

    /**
     * 打开 TUN 接口
     */
    fun openTun(
        options: TunOptions?,
        underlyingNetwork: Network? = null,
        reuseExisting: Boolean = true
    ): Result<Int> {
        if (options == null) {
            return Result.failure(IllegalArgumentException("TunOptions cannot be null"))
        }

        return runCatching {
            // 1. 尝试复用现有 TUN 接口
            if (reuseExisting) {
                vpnInterface?.let { existing ->
                    val existingFd = existing.fd
                    if (existingFd >= 0) {
                        // FIX: 即使复用 TUN，也必须刷新 underlying networks
                        // 修复跨配置切换时 underlying networks 停留在 null 导致网络丢失的问题
                        applyUnderlyingNetworkIfPossible(underlyingNetwork, reason = "reuse_tun")

                        Log.i(TAG, "Reusing existing TUN interface (fd=$existingFd)")
                        return@runCatching existingFd
                    }
                    Log.w(TAG, "Existing TUN interface has invalid fd, recreating")
                    runCatching { existing.close() }
                    vpnInterface = null
                }
            }

            // 2. 创建新 TUN 接口
            PerfTracer.begin(PerfTracer.Phases.TUN_CREATE)

            val builder = tunManager.consumePreallocatedBuilder()
                ?: vpnService.Builder()

            tunManager.configureBuilder(builder, options, currentSettings)

            // 3. 建立 TUN 接口 (带重试)
            val pfd = tunManager.establishWithRetry(builder) { isStopping }
                ?: throw IllegalStateException("Failed to establish TUN interface")

            vpnInterface = pfd
            val fd = pfd.fd

            // 4. 设置底层网络
            applyUnderlyingNetworkIfPossible(underlyingNetwork, reason = "new_tun")

            PerfTracer.end(PerfTracer.Phases.TUN_CREATE)
            Log.i(TAG, "TUN interface opened, fd=$fd")

            fd
        }
    }

    /**
     * 关闭 TUN 接口
     */
    fun closeTunInterface(): Result<Unit> {
        return runCatching {
            vpnInterface?.let { pfd ->
                runCatching { pfd.close() }
                vpnInterface = null
                Log.i(TAG, "TUN interface closed")
            }
            Unit
        }
    }

    /**
     * 保留 TUN 接口
     */
    fun preserveTunInterface(): ParcelFileDescriptor? = vpnInterface

    fun setVpnInterface(pfd: ParcelFileDescriptor?) { vpnInterface = pfd }

    // v1.12.20: 检查 boxService 是否存在
    fun isServiceRunning(): Boolean = boxService != null

    fun isVpnInterfaceValid(): Boolean = vpnInterface?.fileDescriptor?.valid() == true

    // v1.12.20: 使用 BoxWrapperManager.resume() 替代 CommandServer.wake()
    suspend fun wakeService(): Result<Unit> {
        return runCatching {
            withContext(Dispatchers.IO) {
                BoxWrapperManager.resume()
                Unit
            }
        }
    }

    // v1.12.20: 使用 BoxWrapperManager.resetNetwork() 替代 CommandServer.resetNetwork()
    suspend fun resetNetwork(): Result<Unit> {
        return runCatching {
            withContext(Dispatchers.IO) {
                BoxWrapperManager.resetNetwork()
                Unit
            }
        }
    }

    /**
     * Hot reload config without destroying VPN service
     * v1.12.20: 需要关闭旧 BoxService 并创建新的
     * Returns true if hot reload succeeded, false if fallback to full restart is needed
     */
    @Suppress("UNUSED_PARAMETER")
    suspend fun hotReloadConfig(configContent: String, preserveSelector: Boolean = true): Result<Boolean> {
        return runCatching {
            withContext(Dispatchers.IO) {
                val server = commandServer ?: return@withContext false
                val pi = platformInterface ?: return@withContext false

                Log.i(TAG, "Attempting hot reload...")

                // v1.12.20: 关闭旧服务，创建新服务
                boxService?.close()

                val newService = Libbox.newService(configContent, pi)
                newService.start()
                boxService = newService
                server.setService(newService)

                // Update current config content
                currentConfigContent = configContent

                Log.i(TAG, "Hot reload completed successfully")
                true
            }
        }
    }

    fun cleanup(): Result<Unit> {
        return runCatching {
            serviceScope.launch { stopFully() }
            platformInterface = null
            Log.i(TAG, "CoreManager cleaned up")
        }
    }
}
