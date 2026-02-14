package com.openworld.app.service

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.app.Service
import android.content.Intent
import android.net.ConnectivityManager
import android.os.Build
import android.os.IBinder
import android.os.SystemClock
import android.util.Log
import com.openworld.app.MainActivity
import com.openworld.app.core.BoxWrapperManager
import com.openworld.app.ipc.OpenWorldIpcHub
import com.openworld.app.ipc.VpnStateStore
import com.openworld.app.repository.ConfigRepository
import com.openworld.app.repository.LogRepository
import com.openworld.app.repository.SettingsRepository
import com.openworld.app.repository.RuleSetRepository
import com.openworld.app.utils.NetworkClient
import com.openworld.app.utils.KernelHttpClient
import com.openworld.core.OpenWorldCore
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.collect
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File
import java.net.InetSocketAddress
import java.net.ServerSocket

class ProxyOnlyService : Service() {

    companion object {
        private const val TAG = "ProxyOnlyService"
        private const val NOTIFICATION_ID = 11
        private const val CHANNEL_ID = "openworld_proxy_silent"
        private const val LEGACY_CHANNEL_ID = "singbox_proxy"
        // 启动时的端口等待作为兜底，主要等待在关闭流程中完�?        private const val PORT_WAIT_TIMEOUT_MS = 5000L
        private const val PORT_CHECK_INTERVAL_MS = 100L

        const val ACTION_START = OpenWorldService.ACTION_START
        const val ACTION_STOP = OpenWorldService.ACTION_STOP
        const val ACTION_SWITCH_NODE = OpenWorldService.ACTION_SWITCH_NODE
        const val ACTION_PREPARE_RESTART = OpenWorldService.ACTION_PREPARE_RESTART
        const val EXTRA_CONFIG_PATH = OpenWorldService.EXTRA_CONFIG_PATH

        @Volatile
        var isRunning = false
            private set

        @Volatile
        var isStarting = false
            private set

        private val _lastErrorFlow = kotlinx.coroutines.flow.MutableStateFlow<String?>(null)
        val lastErrorFlow = _lastErrorFlow.asStateFlow()

        private fun setLastError(message: String?) {
            _lastErrorFlow.value = message
            if (!message.isNullOrBlank()) {
                runCatching {
                    LogRepository.getInstance().addLog("ERROR ProxyOnlyService: $message")
                }
            }
        }
    }

    private val notificationUpdateDebounceMs: Long = 900L
    private val lastNotificationUpdateAtMs = java.util.concurrent.atomic.AtomicLong(0L)
    @Volatile private var notificationUpdateJob: Job? = null
    @Volatile private var suppressNotificationUpdates = false

    // ACTION_PREPARE_RESTART 防抖：避免短时间内重�?resetAllConnections()
    private val lastPrepareRestartAtMs = java.util.concurrent.atomic.AtomicLong(0L)
    private val prepareRestartDebounceMs: Long = 1500L

    // 华为设备修复: 追踪是否已经调用�?startForeground(),避免重复调用触发提示�?    private val hasForegroundStarted = java.util.concurrent.atomic.AtomicBoolean(false)

    private val serviceSupervisorJob = SupervisorJob()
    private val serviceScope = CoroutineScope(Dispatchers.IO + serviceSupervisorJob)
    private val cleanupSupervisorJob = SupervisorJob()
    private val cleanupScope = CoroutineScope(Dispatchers.IO + cleanupSupervisorJob)

    @Volatile private var isStopping: Boolean = false
    @Volatile private var stopSelfRequested: Boolean = false
    @Volatile private var startJob: Job? = null
    @Volatile private var cleanupJob: Job? = null

    private var connectivityManager: ConnectivityManager? = null

    override fun onBind(intent: Intent?): IBinder? = null

    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()
        connectivityManager = getSystemService(ConnectivityManager::class.java)

        serviceScope.launch {
            lastErrorFlow.collect {
                notifyRemoteState()
            }
        }

        serviceScope.launch {
            ConfigRepository.getInstance(this@ProxyOnlyService).activeNodeId.collect {
                if (isRunning) {
                    requestNotificationUpdate(force = false)
                    notifyRemoteState()
                }
            }
        }
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        Log.i(TAG, "onStartCommand action=${intent?.action}")
        runCatching {
            LogRepository.getInstance().addLog("INFO ProxyOnlyService: onStartCommand action=${intent?.action}")
        }

        when (intent?.action) {
            ACTION_START -> {
                VpnTileService.persistVpnPending(applicationContext, "starting")
                var configPath = intent.getStringExtra(EXTRA_CONFIG_PATH)

                // P0 Optimization: If config path is missing, generate it inside Service
                if (configPath == null) {
                    Log.i(TAG, "ACTION_START received without config path, generating config...")
                    serviceScope.launch {
                        try {
                            val repo = ConfigRepository.getInstance(applicationContext)
                            val result = repo.generateConfigFile()
                            if (result != null) {
                                Log.i(TAG, "Config generated successfully: ${result.path}")
                                // Recursively call start command with the generated path
                                val newIntent = Intent(applicationContext, ProxyOnlyService::class.java).apply {
                                    action = ACTION_START
                                    putExtra(EXTRA_CONFIG_PATH, result.path)
                                }
                                startService(newIntent)
                            } else {
                                Log.e(TAG, "Failed to generate config file")
                                setLastError("Failed to generate config file")
                                withContext(Dispatchers.Main) { stopSelf() }
                            }
                        } catch (e: Exception) {
                            Log.e(TAG, "Error generating config in Service", e)
                            setLastError("Error generating config: ${e.message}")
                            withContext(Dispatchers.Main) { stopSelf() }
                        }
                    }
                    return START_NOT_STICKY
                }

                if (!configPath.isNullOrBlank()) {
                    startCore(configPath)
                }
            }
            ACTION_STOP -> {
                VpnTileService.persistVpnPending(applicationContext, "stopping")
                stopCore(stopService = true)
            }
            ACTION_SWITCH_NODE -> {
                val configPath = intent.getStringExtra(EXTRA_CONFIG_PATH)
                if (!configPath.isNullOrBlank()) {
                    serviceScope.launch {
                        stopCore(stopService = false)
                        waitForCleanupJob()
                        startCore(configPath)
                    }
                } else {
                    serviceScope.launch {
                        val repo = ConfigRepository.getInstance(this@ProxyOnlyService)
                        val generationResult = repo.generateConfigFile()
                        if (generationResult?.path.isNullOrBlank()) return@launch
                        stopCore(stopService = false)
                        waitForCleanupJob()
                        startCore(generationResult!!.path)
                    }
                }
            }
            ACTION_PREPARE_RESTART -> {
                // 跨配置切换预清理机制
                // ProxyOnlyService 模式下：唤醒核心 + 重置网络 + 关闭连接
                // 2025-fix: 简化流程，减少过度的重置次�?                val reason = intent.getStringExtra(OpenWorldService.EXTRA_PREPARE_RESTART_REASON).orEmpty()
                Log.i(TAG, "Received ACTION_PREPARE_RESTART (reason='$reason') -> preparing for restart")

                val now = SystemClock.elapsedRealtime()
                val last = lastPrepareRestartAtMs.get()
                val elapsed = now - last
                if (elapsed < prepareRestartDebounceMs) {
                    Log.d(TAG, "ACTION_PREPARE_RESTART skipped (debounce, elapsed=${elapsed}ms)")
                    return START_NOT_STICKY
                }
                lastPrepareRestartAtMs.set(now)

                serviceScope.launch {
                    try {
                        // Step 1: 唤醒核心 (如果已暂�?
                        if (OpenWorldCore.isPaused()) {
                            OpenWorldCore.resume()
                        }
                        Log.i(TAG, "[PrepareRestart] Step 1/2: Ensured core is awake")

                        // Step 2: 关闭所有连�?                        Log.i(TAG, "[PrepareRestart] Step 2/2: Close connections")
                        delay(50)
                        try {
                            OpenWorldCore.resetAllConnections(false)
                        } catch (e: Exception) {
                            Log.w(TAG, "resetAllConnections failed: ${e.message}")
                        }

                        Log.i(TAG, "[PrepareRestart] Complete")
                    } catch (e: Exception) {
                        Log.e(TAG, "PrepareRestart error", e)
                    }
                }
            }
        }

        return START_NOT_STICKY
    }

    @Suppress("CognitiveComplexMethod", "LongMethod")
    private fun startCore(configPath: String) {
        synchronized(this) {
            if (isRunning || isStarting) return
            if (isStopping) return
            isStarting = true
        }

        setLastError(null)

        notifyRemoteState(state = ServiceState.STARTING)
        updateTileState()

        try {
            startForeground(NOTIFICATION_ID, createNotification())
            hasForegroundStarted.set(true)
        } catch (e: Exception) {
            Log.e(TAG, "Failed to call startForeground", e)
        }

        startJob?.cancel()
        startJob = serviceScope.launch {
            try {
                val ruleSetRepo = RuleSetRepository.getInstance(this@ProxyOnlyService)
                runCatching {
                    ruleSetRepo.ensureRuleSetsReady(
                        forceUpdate = false,
                        allowNetwork = false
                    ) {}
                }

                val configFile = File(configPath)
                if (!configFile.exists()) {
                    setLastError("Config file not found: $configPath")
                    withContext(Dispatchers.Main) { stopSelf() }
                    return@launch
                }

                val configContent = configFile.readText()

                // 等待代理端口可用（解决跨服务切换时端口未释放的问题）
                val proxyPort = runCatching {
                    SettingsRepository
                        .getInstance(this@ProxyOnlyService)
                        .settings.first().proxyPort
                }.getOrDefault(2080)
                if (proxyPort > 0 && !isPortAvailable(proxyPort)) {
                    Log.i(TAG, "Port $proxyPort in use, waiting for release...")
                    val waitStart = SystemClock.elapsedRealtime()
                    val portAvailable = waitForPortAvailable(proxyPort)
                    val waitTime = SystemClock.elapsedRealtime() - waitStart
                    if (portAvailable) {
                        Log.i(TAG, "Port $proxyPort available after ${waitTime}ms")
                    } else {
                        // 端口超时未释放，强制杀死进程让系统回收端口
                        Log.e(TAG, "Port $proxyPort NOT released after ${waitTime}ms, killing process to force release")
                        // 在杀死进程前先清除通知，防止通知残留
                        runCatching {
                            val nm = getSystemService(android.app.NotificationManager::class.java)
                            nm?.cancel(NOTIFICATION_ID)
                        }
                        Thread.sleep(50)
                        android.os.Process.killProcess(android.os.Process.myPid())
                    }
                }

                // 使用 OpenWorldCore 启动代理服务
                val startResult = OpenWorldCore.start(configContent)
                if (startResult != 0) {
                    throw IllegalStateException("OpenWorldCore.start failed with code: $startResult")
                }

                // 初始�?BoxWrapperManager
                BoxWrapperManager.init()

                isRunning = true
                NetworkClient.onVpnStateChanged(true)

                // 初始�?KernelHttpClient 的代理端�?                KernelHttpClient.updateProxyPortFromSettings(this@ProxyOnlyService)

                VpnTileService.persistVpnState(applicationContext, true)
                VpnStateStore.setMode(VpnStateStore.CoreMode.PROXY)
                VpnTileService.persistVpnPending(applicationContext, "")
                setLastError(null)
                notifyRemoteState(state = ServiceState.RUNNING)
                updateTileState()
                requestNotificationUpdate(force = true)
            } catch (e: CancellationException) {
                return@launch
            } catch (e: Exception) {
                val reason = "Failed to start proxy-only: ${e.javaClass.simpleName}: ${e.message}"
                Log.e(TAG, reason, e)
                setLastError(reason)
                withContext(Dispatchers.Main) {
                    isRunning = false
                    notifyRemoteState(state = ServiceState.STOPPED)
                    stopCore(stopService = true)
                }
            } finally {
                isStarting = false
                startJob = null
            }
        }
    }

    /**
     * 停止核心服务，返�?Job 以便调用方等待关闭完�?     * @param stopService 是否同时停止 Service 本身
     * @return 清理任务�?Job，调用方可通过 job.join() 等待关闭完成
     */
    @Suppress("CognitiveComplexMethod", "LongMethod")
    private fun stopCore(stopService: Boolean): Job? {
        synchronized(this) {
            stopSelfRequested = stopSelfRequested || stopService
            if (isStopping) return cleanupJob
            isStopping = true
        }

        notifyRemoteState(state = ServiceState.STOPPING)
        updateTileState()
        isRunning = false
        NetworkClient.onVpnStateChanged(false)

        val jobToJoin = startJob
        startJob = null
        jobToJoin?.cancel()

        // 释放 BoxWrapperManager
        BoxWrapperManager.release()

        notificationUpdateJob?.cancel()
        notificationUpdateJob = null
        hasForegroundStarted.set(false)

        // 获取代理端口用于等待释放
        val proxyPort = runCatching {
            SettingsRepository
                .getInstance(this@ProxyOnlyService)
                .settings.value.proxyPort
        }.getOrDefault(2080)

        val job = cleanupScope.launch(NonCancellable) {
            try {
                jobToJoin?.join()
            } catch (e: Exception) {
                Log.w(TAG, "Failed to join start job", e)
            }

            // 停止 OpenWorldCore
            if (OpenWorldCore.isRunning()) {
                Log.i(TAG, "Stopping OpenWorldCore...")
                val closeStart = SystemClock.elapsedRealtime()
                try {
                    val stopResult = OpenWorldCore.stop()
                    if (stopResult != 0) {
                        Log.w(TAG, "OpenWorldCore.stop returned: $stopResult")
                    }

                    // 关键修复：主动等待端口释�?                    if (proxyPort > 0) {
                        val portReleased = waitForPortAvailable(proxyPort, PORT_WAIT_TIMEOUT_MS)
                        val elapsed = SystemClock.elapsedRealtime() - closeStart
                        if (portReleased) {
                            Log.i(TAG, "OpenWorldCore stopped, port $proxyPort released in ${elapsed}ms")
                        } else {
                            // 端口释放失败，强制杀死进程让系统回收端口
                            Log.e(TAG, "Port $proxyPort NOT released after ${elapsed}ms, " +
                                "killing process to force release")
                            // 在杀死进程前先清除通知，防止通知残留
                            runCatching {
                                val nm = getSystemService(android.app.NotificationManager::class.java)
                                nm?.cancel(NOTIFICATION_ID)
                            }
                            Thread.sleep(50)
                            android.os.Process.killProcess(android.os.Process.myPid())
                        }
                    } else {
                        Log.i(TAG, "OpenWorldCore stopped in ${SystemClock.elapsedRealtime() - closeStart}ms")
                    }
                } catch (e: Exception) {
                    Log.w(TAG, "Failed to stop OpenWorldCore: ${e.message}", e)
                }
            }

            withContext(Dispatchers.Main) {
                runCatching { stopForeground(STOP_FOREGROUND_REMOVE) }
                if (stopSelfRequested) {
                    stopSelf()
                }
                VpnTileService.persistVpnState(applicationContext, false)
                VpnStateStore.setMode(VpnStateStore.CoreMode.NONE)
                VpnTileService.persistVpnPending(applicationContext, "")
                notifyRemoteState(state = ServiceState.STOPPED)
                updateTileState()
            }

            synchronized(this@ProxyOnlyService) {
                isStopping = false
                stopSelfRequested = false
                cleanupJob = null
            }
        }
        cleanupJob = job
        return job
    }

    /**
     * 等待上一次清理任务完�?     */
    private suspend fun waitForCleanupJob() {
        val job = cleanupJob
        if (job != null && job.isActive) {
            Log.i(TAG, "Waiting for previous cleanup to complete...")
            val waitStart = SystemClock.elapsedRealtime()
            job.join()
            Log.i(TAG, "Previous cleanup completed in ${SystemClock.elapsedRealtime() - waitStart}ms")
        }
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
     * 等待端口可用，带超时
     */
    private suspend fun waitForPortAvailable(port: Int, timeoutMs: Long = PORT_WAIT_TIMEOUT_MS): Boolean {
        if (port <= 0) return true
        val startTime = SystemClock.elapsedRealtime()
        while (SystemClock.elapsedRealtime() - startTime < timeoutMs) {
            if (isPortAvailable(port)) {
                return true
            }
            delay(PORT_CHECK_INTERVAL_MS)
        }
        return false
    }

    private fun notifyRemoteState(state: ServiceState? = null) {
        val st = state ?: if (isRunning) ServiceState.RUNNING else ServiceState.STOPPED
        val repo = runCatching { ConfigRepository.getInstance(applicationContext) }.getOrNull()
        val activeId = repo?.activeNodeId?.value
        // 2025-fix: 优先使用 VpnStateStore.getActiveLabel()，然后回退�?configRepository
        val activeLabel = runCatching {
            VpnStateStore.getActiveLabel().takeIf { it.isNotBlank() }
                ?: if (repo != null && activeId != null) repo.nodes.value.find { it.id == activeId }?.name else ""
        }.getOrNull().orEmpty()

        OpenWorldIpcHub.update(
            state = st,
            activeLabel = activeLabel,
            lastError = lastErrorFlow.value.orEmpty(),
            manuallyStopped = false
        )
    }

    private fun updateTileState() {
        runCatching {
            val intent = Intent(VpnTileService.ACTION_REFRESH_TILE)
            intent.setClass(applicationContext, VpnTileService::class.java)
            startService(intent)
        }
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val manager = getSystemService(NotificationManager::class.java)
            try {
                manager.deleteNotificationChannel(LEGACY_CHANNEL_ID)
            } catch (e: Exception) {
                Log.w(TAG, "Failed to delete legacy notification channel", e)
            }

            val channel = NotificationChannel(
                CHANNEL_ID,
                "OpenWorld Proxy",
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                setShowBadge(false)
                enableVibration(false)
                enableLights(false)
                setSound(null, null)
                lockscreenVisibility = Notification.VISIBILITY_PUBLIC
            }
            manager.createNotificationChannel(channel)
        }
    }

    private fun createNotification(): Notification {
        val intent = Intent(this, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_CLEAR_TOP or Intent.FLAG_ACTIVITY_SINGLE_TOP
        }
        val pendingIntent = PendingIntent.getActivity(
            this,
            0,
            intent,
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )

        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            Notification.Builder(this, CHANNEL_ID)
                .setContentTitle("OpenWorld")
                .setContentText("Proxy-only running")
                .setSmallIcon(android.R.drawable.stat_sys_upload)
                .setContentIntent(pendingIntent)
                .setOngoing(true)
                .build()
        } else {
            @Suppress("DEPRECATION")
            Notification.Builder(this)
                .setContentTitle("OpenWorld")
                .setContentText("Proxy-only running")
                .setSmallIcon(android.R.drawable.stat_sys_upload)
                .setContentIntent(pendingIntent)
                .setOngoing(true)
                .build()
        }
    }

    private fun updateNotification() {
        val notification = createNotification()
        val manager = getSystemService(NotificationManager::class.java)
        if (!hasForegroundStarted.get()) {
            runCatching {
                startForeground(NOTIFICATION_ID, notification)
                hasForegroundStarted.set(true)
            }.onFailure { e ->
                Log.w(TAG, "Failed to call startForeground, fallback to notify()", e)
                manager.notify(NOTIFICATION_ID, notification)
            }
        } else {
            runCatching {
                manager.notify(NOTIFICATION_ID, notification)
            }.onFailure { e ->
                Log.w(TAG, "Failed to update notification via notify()", e)
            }
        }
    }

    private fun requestNotificationUpdate(force: Boolean = false) {
        if (suppressNotificationUpdates) return
        if (isStopping) return
        val now = SystemClock.elapsedRealtime()
        val last = lastNotificationUpdateAtMs.get()

        if (force) {
            lastNotificationUpdateAtMs.set(now)
            notificationUpdateJob?.cancel()
            notificationUpdateJob = null
            updateNotification()
            return
        }

        val delayMs = (notificationUpdateDebounceMs - (now - last)).coerceAtLeast(0L)
        if (delayMs <= 0L) {
            lastNotificationUpdateAtMs.set(now)
            notificationUpdateJob?.cancel()
            notificationUpdateJob = null
            updateNotification()
            return
        }

        if (notificationUpdateJob?.isActive == true) return
        notificationUpdateJob = serviceScope.launch {
            delay(delayMs)
            lastNotificationUpdateAtMs.set(SystemClock.elapsedRealtime())
            updateNotification()
        }
    }

    override fun onDestroy() {
        super.onDestroy()
        runCatching { serviceSupervisorJob.cancel() }
        runCatching { cleanupSupervisorJob.cancel() }
        notificationUpdateJob?.cancel()
        notificationUpdateJob = null
        hasForegroundStarted.set(false)
        // 确保通知被清除，防止进程异常终止时通知残留
        runCatching {
            val nm = getSystemService(android.app.NotificationManager::class.java)
            nm.cancel(NOTIFICATION_ID)
            stopForeground(STOP_FOREGROUND_REMOVE)
        }
    }
}







