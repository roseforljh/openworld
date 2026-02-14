package com.openworld.app.service

import android.app.Notification
import android.app.NotificationManager
import android.content.Intent
import android.net.ConnectivityManager
import android.net.Network
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.os.Process
import android.os.SystemClock
import android.util.Log
import android.service.quicksettings.TileService
import android.content.ComponentName
import com.google.gson.Gson
import com.openworld.app.R
import com.openworld.app.ipc.OpenWorldIpcHub
import com.openworld.app.ipc.VpnStateStore
import com.openworld.app.model.AppSettings
import com.openworld.app.model.OpenWorldConfig
import com.openworld.app.repository.ConfigRepository
import com.openworld.app.repository.LogRepository
import com.openworld.app.repository.RuleSetRepository
import com.openworld.app.repository.SettingsRepository
import com.openworld.app.repository.TrafficRepository
import com.openworld.app.core.BoxWrapperManager
import com.openworld.app.core.ProbeManager
import com.openworld.app.core.SelectorManager
import com.openworld.app.service.network.NetworkManager
import com.openworld.app.service.network.TrafficMonitor
import com.openworld.app.service.notification.VpnNotificationManager
import com.openworld.app.service.manager.ConnectManager
import com.openworld.app.service.manager.SelectorManager as ServiceSelectorManager
import com.openworld.app.service.manager.CommandManager
import com.openworld.app.service.manager.CoreManager
import com.openworld.app.service.manager.NetworkHelper
import com.openworld.app.service.manager.PlatformInterfaceImpl
import com.openworld.app.service.manager.ShutdownManager
import com.openworld.app.service.manager.ScreenStateManager
import com.openworld.app.service.manager.RouteGroupSelector
import com.openworld.app.service.manager.ForeignVpnMonitor
import com.openworld.app.service.manager.NodeSwitchManager
import com.openworld.app.service.manager.BackgroundPowerManager
import com.openworld.app.service.manager.ServiceStateHolder
import com.openworld.app.model.BackgroundPowerSavingDelay
import com.openworld.app.core.bridge.*
import com.openworld.app.utils.L
import com.openworld.app.utils.KernelHttpClient
import com.openworld.app.utils.NetworkClient
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.collect
import kotlinx.coroutines.flow.distinctUntilChanged
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.map
import java.io.File
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong

class OpenWorldService : VpnService() {

    private val gson = Gson()

    // ===== 新架�?Managers =====
    // 核心管理�?(VPN 启动/停止)
    private val coreManager: CoreManager by lazy {
        CoreManager(this, this, serviceScope)
    }

    // 连接管理器
    private val connectManager: ConnectManager by lazy {
        ConnectManager(this, serviceScope)
    }

    // 节点选择管理器
    private val serviceSelectorManager: ServiceSelectorManager by lazy {
        ServiceSelectorManager()
    }

    // 路由组自动选择管理器
    private val routeGroupSelector: RouteGroupSelector by lazy {
        RouteGroupSelector(this, serviceScope)
    }

    // Command 管理�?(Server/Client 交互)
    private val commandManager: CommandManager by lazy {
        CommandManager(this, serviceScope)
    }

    // Platform Interface 实现 (提取自原内联实现)
    private val platformInterfaceImpl: PlatformInterfaceImpl by lazy {
        PlatformInterfaceImpl(
            context = this,
            serviceScope = serviceScope,
            mainHandler = mainHandler,
            callbacks = platformCallbacks
        )
    }

    // 网络辅助工具
    private val networkHelper: NetworkHelper by lazy {
        NetworkHelper(this, serviceScope)
    }

    // 启动管理器
    private val startupManager: com.openworld.app.service.manager.StartupManager by lazy {
        com.openworld.app.service.manager.StartupManager(this, this, serviceScope)
    }

    // 关闭管理器
    private val shutdownManager: com.openworld.app.service.manager.ShutdownManager by lazy {
        com.openworld.app.service.manager.ShutdownManager(this, cleanupScope)
    }

    // 屏幕状态管理器
    private val screenStateManager: ScreenStateManager by lazy {
        ScreenStateManager(this, serviceScope)
    }

    // 外部 VPN 监控器
    private val foreignVpnMonitor: ForeignVpnMonitor by lazy {
        ForeignVpnMonitor(this)
    }

    // 节点切换管理器
    private val nodeSwitchManager: NodeSwitchManager by lazy {
        NodeSwitchManager(this, serviceScope)
    }

    private val backgroundPowerManager: BackgroundPowerManager by lazy {
        BackgroundPowerManager(serviceScope)
    }

    @Volatile
    private var backgroundPowerSavingThresholdMs: Long = BackgroundPowerSavingDelay.MINUTES_30.delayMs

    // PlatformInterfaceImpl 回调实现
    private val platformCallbacks = object : PlatformInterfaceImpl.Callbacks {
        override fun protect(fd: Int): Boolean = this@OpenWorldService.protect(fd)

        override fun openTun(options: TunOptions): Result<Int> {
            isConnectingTun.set(true)
            return try {
                val network = connectManager.getCurrentNetwork()
                val result = coreManager.openTun(options, network, reuseExisting = true)
                result.onSuccess { _ ->
                    vpnInterface = coreManager.vpnInterface
                    if (network != null) {
                        lastKnownNetwork = network
                        vpnStartedAtMs.set(SystemClock.elapsedRealtime())
                        connectManager.markVpnStarted()
                    }
                }
                result
            } finally {
                isConnectingTun.set(false)
            }
        }

        override fun getConnectivityManager(): ConnectivityManager? = connectivityManager
        override fun getCurrentNetwork(): Network? = connectManager.getCurrentNetwork()
        override fun getLastKnownNetwork(): Network? = lastKnownNetwork
        override fun setLastKnownNetwork(network: Network?) { lastKnownNetwork = network }
        override fun markVpnStarted() { connectManager.markVpnStarted() }

        override fun requestCoreNetworkReset(reason: String, force: Boolean) {
            this@OpenWorldService.requestCoreNetworkReset(reason, force)
        }
        override fun resetConnectionsOptimal(reason: String, skipDebounce: Boolean) {
            serviceScope.launch {
                BoxWrapperManager.resetAllConnections(true)
                Log.i(TAG, "resetConnectionsOptimal: $reason")
            }
        }
        override fun setUnderlyingNetworks(networks: Array<Network>?) {
            this@OpenWorldService.setUnderlyingNetworks(networks)
        }

        override fun isRunning(): Boolean = ServiceStateHolder.isRunning
        override fun isStarting(): Boolean = ServiceStateHolder.isStarting
        override fun isManuallyStopped(): Boolean = ServiceStateHolder.isManuallyStopped
        override fun getLastConfigPath(): String? = ServiceStateHolder.lastConfigPath
        override fun getCurrentSettings(): AppSettings? = currentSettings

        override fun incrementConnectionOwnerCalls() { ServiceStateHolder.incrementConnectionOwnerCalls() }
        override fun incrementConnectionOwnerInvalidArgs() { ServiceStateHolder.incrementConnectionOwnerInvalidArgs() }
        override fun incrementConnectionOwnerUidResolved() { ServiceStateHolder.incrementConnectionOwnerUidResolved() }
        override fun incrementConnectionOwnerSecurityDenied() {
            ServiceStateHolder.incrementConnectionOwnerSecurityDenied()
        }
        override fun incrementConnectionOwnerOtherException() {
            ServiceStateHolder.incrementConnectionOwnerOtherException()
        }
        override fun setConnectionOwnerLastEvent(event: String) {
            ServiceStateHolder.setConnectionOwnerLastEvent(event)
        }
        override fun setConnectionOwnerLastUid(uid: Int) {
            ServiceStateHolder.setConnectionOwnerLastUid(uid)
        }
        override fun isConnectionOwnerPermissionDeniedLogged(): Boolean =
            ServiceStateHolder.connectionOwnerPermissionDeniedLogged
        override fun setConnectionOwnerPermissionDeniedLogged(logged: Boolean) {
            ServiceStateHolder.connectionOwnerPermissionDeniedLogged = logged
        }

        override fun cacheUidToPackage(uid: Int, packageName: String) {
            this@OpenWorldService.cacheUidToPackage(uid, packageName)
        }
        override fun getUidFromCache(uid: Int): String? = uidToPackageCache[uid]

        override fun findBestPhysicalNetwork(): Network? = this@OpenWorldService.findBestPhysicalNetwork()
    }

    // 通知管理�?(原有)
    private val notificationManager: VpnNotificationManager by lazy {
        VpnNotificationManager(this, serviceScope)
    }

    private val remoteStateUpdateDebounceMs: Long = 250L
    private val lastRemoteStateUpdateAtMs = AtomicLong(0L)
    @Volatile private var remoteStateUpdateJob: Job? = null

    companion object {
        private const val TAG = "OpenWorldService"

        const val ACTION_START = ServiceStateHolder.ACTION_START
        const val ACTION_STOP = ServiceStateHolder.ACTION_STOP
        const val ACTION_SWITCH_NODE = ServiceStateHolder.ACTION_SWITCH_NODE
        const val ACTION_SERVICE = ServiceStateHolder.ACTION_SERVICE
        const val ACTION_UPDATE_SETTING = ServiceStateHolder.ACTION_UPDATE_SETTING
        const val ACTION_RESET_CONNECTIONS = ServiceStateHolder.ACTION_RESET_CONNECTIONS
        const val ACTION_PREPARE_RESTART = ServiceStateHolder.ACTION_PREPARE_RESTART
        const val ACTION_HOT_RELOAD = ServiceStateHolder.ACTION_HOT_RELOAD
        const val ACTION_FULL_RESTART = ServiceStateHolder.ACTION_FULL_RESTART
        const val ACTION_NETWORK_BUMP = "com.openworld.app.action.NETWORK_BUMP"
        const val EXTRA_CONFIG_PATH = ServiceStateHolder.EXTRA_CONFIG_PATH
        const val EXTRA_CONFIG_CONTENT = ServiceStateHolder.EXTRA_CONFIG_CONTENT
        const val EXTRA_CLEAN_CACHE = ServiceStateHolder.EXTRA_CLEAN_CACHE
        const val EXTRA_SETTING_KEY = ServiceStateHolder.EXTRA_SETTING_KEY
        const val EXTRA_SETTING_VALUE_BOOL = ServiceStateHolder.EXTRA_SETTING_VALUE_BOOL
        const val EXTRA_PREPARE_RESTART_REASON = ServiceStateHolder.EXTRA_PREPARE_RESTART_REASON

        var instance: OpenWorldService?
            get() = ServiceStateHolder.instance
            private set(value) { ServiceStateHolder.instance = value }

        var isRunning: Boolean
            get() = ServiceStateHolder.isRunning
            private set(value) { ServiceStateHolder.isRunning = value }

        val isRunningFlow get() = ServiceStateHolder.isRunningFlow

        var isStarting: Boolean
            get() = ServiceStateHolder.isStarting
            private set(value) { ServiceStateHolder.isStarting = value }

        val isStartingFlow get() = ServiceStateHolder.isStartingFlow

        val lastErrorFlow get() = ServiceStateHolder.lastErrorFlow

        var isManuallyStopped: Boolean
            get() = ServiceStateHolder.isManuallyStopped
            private set(value) { ServiceStateHolder.isManuallyStopped = value }

        private var lastConfigPath: String?
            get() = ServiceStateHolder.lastConfigPath
            set(value) { ServiceStateHolder.lastConfigPath = value }

        private fun setLastError(message: String?) = ServiceStateHolder.setLastError(message)

        fun getConnectionOwnerStatsSnapshot() = ServiceStateHolder.getConnectionOwnerStatsSnapshot()
        fun resetConnectionOwnerStats() = ServiceStateHolder.resetConnectionOwnerStats()
    }

    private fun tryRegisterRunningServiceForLibbox() {
        // No longer needed with new CommandServer API
    }

    private fun tryClearRunningServiceForLibbox() {
        // No longer needed with new CommandServer API
    }

    /**
     * 初始化新架构 Managers (7个核心模�?
     */
    @Suppress("CognitiveComplexMethod")
    private fun initManagers() {
        // 1. 初始化核心管理器
        coreManager.init(platformInterfaceImpl)
        Log.i(TAG, "CoreManager initialized")

        initConnectManager()
        initServiceSelectorManager()
        initCommandManager()
        initSecondaryManagers()

        Log.i(TAG, "All managers initialized")
    }

    private fun initConnectManager() {
        connectManager.init(
            onNetworkChanged = { network ->
                if (network != null) {
                    Log.d(TAG, "Network changed: $network")
                }
            },
            onNetworkLost = {
                Log.i(TAG, "Network lost")
            },
            setUnderlyingNetworksFn = { nets ->
                setUnderlyingNetworks(nets)
            }
        )
        Log.i(TAG, "ConnectManager initialized")
    }

    private fun initServiceSelectorManager() {
        // 3. 初始化节点选择管理�?
        serviceSelectorManager.init(commandManager.getCommandClient())
        Log.i(TAG, "ServiceSelectorManager initialized")
    }

    private fun initCommandManager() {
        // 4. 初始�?Command 管理�?
        commandManager.init(object : CommandManager.Callbacks {
            override fun requestNotificationUpdate(force: Boolean) {
                this@OpenWorldService.requestNotificationUpdate(force)
            }
            override fun resolveEgressNodeName(tagOrSelector: String?): String? {
                return this@OpenWorldService.resolveEgressNodeName(
                    ConfigRepository.getInstance(this@OpenWorldService),
                    tagOrSelector
                )
            }
            override fun onServiceStop() {
                Log.i(TAG, "CommandManager: onServiceStop requested")
                serviceScope.launch {
                    stopVpn(stopService = true)
                }
            }
            override fun onServiceReload() {
                Log.i(TAG, "CommandManager: onServiceReload requested")
            }
        })
        Log.i(TAG, "CommandManager initialized")
    }

    private fun initSecondaryManagers() {
        // 初始化屏幕状态管理器
        screenStateManager.init(object : ScreenStateManager.Callbacks {
            override val isRunning: Boolean
                get() = OpenWorldService.isRunning

            override fun notifyRemoteStateUpdate(force: Boolean) {
                this@OpenWorldService.requestRemoteStateUpdate(force)
            }

            override fun requestCoreNetworkRecovery(reason: String, force: Boolean) {
                this@OpenWorldService.requestCoreNetworkReset(reason, force)
            }
        })
        Log.i(TAG, "ScreenStateManager initialized")

        // 初始化路由组自动选择管理�?
        routeGroupSelector.init(object : RouteGroupSelector.Callbacks {
            override val isRunning: Boolean
                get() = OpenWorldService.isRunning
            override val isStopping: Boolean
                get() = coreManager.isStopping
            override fun getCommandClient() = commandManager.getCommandClient()
            override fun getSelectedOutbound(groupTag: String) = commandManager.getSelectedOutbound(groupTag)
        })
        Log.i(TAG, "RouteGroupSelector initialized")

        // 9. 初始化外�?VPN 监控�?
        foreignVpnMonitor.init(object : ForeignVpnMonitor.Callbacks {
            override val isStarting: Boolean
                get() = OpenWorldService.isStarting
            override val isRunning: Boolean
                get() = OpenWorldService.isRunning
            override val isConnectingTun: Boolean
                get() = this@OpenWorldService.isConnectingTun.get()
        })
        Log.i(TAG, "ForeignVpnMonitor initialized")

        // 10. 初始化节点切换管理器
        nodeSwitchManager.init(object : NodeSwitchManager.Callbacks {
            override val isRunning: Boolean
                get() = OpenWorldService.isRunning
            override suspend fun hotSwitchNode(nodeTag: String): Boolean = this@OpenWorldService.hotSwitchNode(nodeTag)
            override fun getConfigPath(): String = pendingHotSwitchFallbackConfigPath
                ?: File(filesDir, "running_config.json").absolutePath
            override fun setRealTimeNodeName(name: String?) { realTimeNodeName = name }
            override fun requestNotificationUpdate(force: Boolean) {
                this@OpenWorldService.requestNotificationUpdate(force)
            }
            override fun notifyRemoteStateUpdate(force: Boolean) {
                this@OpenWorldService.requestRemoteStateUpdate(force)
            }
            override fun startServiceIntent(intent: Intent) {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                    startForegroundService(intent)
                } else {
                    startService(intent)
                }
            }
        })
        Log.i(TAG, "NodeSwitchManager initialized")

        initBackgroundPowerManager()
        Log.i(TAG, "BackgroundPowerManager initialized")

        Log.i(TAG, "OpenWorld VPN started successfully")
        notificationManager.setSuppressUpdates(false)
    }

    private fun initBackgroundPowerManager() {
        val initialThresholdMs = backgroundPowerSavingThresholdMs

        backgroundPowerManager.init(
            callbacks = object : BackgroundPowerManager.Callbacks {
                override val isVpnRunning: Boolean
                    get() = isRunning

                override fun requestCoreNetworkRecovery(reason: String, force: Boolean) {
                    this@OpenWorldService.requestCoreNetworkReset(reason, force)
                }

                override fun suspendNonEssentialProcesses() {
                    Log.d(TAG, "[PowerSaving] suspendNonEssentialProcesses ignored")
                }

                override fun resumeNonEssentialProcesses() {
                    Log.d(TAG, "[PowerSaving] resumeNonEssentialProcesses ignored")
                }
            },
            thresholdMs = initialThresholdMs
        )

        // Load user setting asynchronously to avoid blocking service initialization.
        serviceScope.launch {
            val thresholdMs = runCatching {
                val settings = SettingsRepository.getInstance(this@OpenWorldService).settings.first()
                settings.backgroundPowerSavingDelay.delayMs
            }.getOrElse { e ->
                Log.w(TAG, "Failed to read power saving delay setting, using default", e)
                BackgroundPowerSavingDelay.MINUTES_30.delayMs
            }
            backgroundPowerSavingThresholdMs = thresholdMs
            backgroundPowerManager.setThreshold(thresholdMs)
        }

        // 设置 IPC Hub �?PowerManager 引用，用于接收主进程的生命周期通知
        OpenWorldIpcHub.setPowerManager(backgroundPowerManager)
        // 设置 ScreenStateManager �?PowerManager 引用，用于接收屏幕状态通知
        screenStateManager.setPowerManager(backgroundPowerManager)
    }

    /**
     * StartupManager 回调实现
     */
    private val startupCallbacks = object : com.openworld.app.service.manager.StartupManager.Callbacks {
        // 状态回调
        override fun onStarting() {
            updateServiceState(ServiceState.STARTING)
            realTimeNodeName = null
            vpnLinkValidated = false
        }

        override fun onStarted(configContent: String) {
            Log.i(TAG, "OpenWorld VPN started successfully")
            notificationManager.setSuppressUpdates(false)

            // 初始�?KernelHttpClient 的代理端�?
            serviceScope.launch {
                KernelHttpClient.updateProxyPortFromSettings(this@OpenWorldService)
            }
        }

        override fun onFailed(error: String) {
            Log.e(TAG, error)
            setLastError(error)
            notificationManager.setSuppressUpdates(true)
            notificationManager.cancelNotification()
            updateServiceState(ServiceState.STOPPED)
        }

        override fun onCancelled() {
            Log.i(TAG, "startVpn cancelled")
            if (!isStopping) {
                Log.w(TAG, "startVpn cancelled but not by stopVpn, resetting state to STOPPED")
                isRunning = false
                updateServiceState(ServiceState.STOPPED)
            }
        }

        // 通知管理
        override fun createNotification(): Notification = this@OpenWorldService.createNotification()
        override fun markForegroundStarted() { notificationManager.markForegroundStarted() }

        // 生命周期管理
        override fun registerScreenStateReceiver() { screenStateManager.registerScreenStateReceiver() }
        override fun startForeignVpnMonitor() { foreignVpnMonitor.start() }
        override fun stopForeignVpnMonitor() { foreignVpnMonitor.stop() }
        override fun detectExistingVpns(): Boolean = foreignVpnMonitor.hasExistingVpn()

        // 组件初始化
        override fun initSelectorManager(configContent: String) {
            this@OpenWorldService.initSelectorManager(configContent)
        }

        override fun createAndStartCommandServer(): Result<Unit> {
            return runCatching {
                // 1. 创建 CommandServer
                val server = commandManager.createServer(platformInterfaceImpl).getOrThrow()
                // 2. 设置�?CoreManager
                coreManager.setCommandServer(server)
                // 3. 启动 CommandServer
                commandManager.startServer().getOrThrow()
                Log.i(TAG, "CommandServer created and started")
            }
        }

        override fun startCommandClients() {
            commandManager.startClients().onFailure { e ->
                Log.e(TAG, "Failed to start Command Clients", e)
            }
            // 更新 serviceSelectorManager �?commandClient (修复热切换不生效的问�?
            serviceSelectorManager.updateCommandClient(commandManager.getCommandClient())
        }

        override fun startRouteGroupAutoSelect(configContent: String) {
            routeGroupSelector.start(configContent)
        }

        override fun scheduleAsyncRuleSetUpdate() {
            this@OpenWorldService.scheduleAsyncRuleSetUpdate()
        }

        override fun startHealthMonitor() {
            // 健康监控已移除，保留空实�?
            Log.i(TAG, "Health monitor disabled (simplified mode)")
        }

        override fun scheduleKeepaliveWorker() {
            VpnKeepaliveWorker.schedule(applicationContext)
            Log.i(TAG, "VPN keepalive worker scheduled")
        }

        override fun startTrafficMonitor() {
            trafficMonitor.start(Process.myUid(), trafficListener)
            networkManager = NetworkManager(this@OpenWorldService, this@OpenWorldService)
        }

        // 状态管理
        override fun updateTileState() { this@OpenWorldService.updateTileState() }
        override fun setIsRunning(running: Boolean) { isRunning = running; NetworkClient.onVpnStateChanged(running) }
        override fun setIsStarting(starting: Boolean) { isStarting = starting }
        override fun setLastError(error: String?) { OpenWorldService.setLastError(error) }
        override fun persistVpnState(isRunning: Boolean) {
            VpnTileService.persistVpnState(applicationContext, isRunning)
            if (isRunning) {
                VpnStateStore.setMode(VpnStateStore.CoreMode.VPN)
            }
        }
        override fun persistVpnPending(pending: String) {
            VpnTileService.persistVpnPending(applicationContext, pending)
        }

        // 网络管理
        override suspend fun waitForUsablePhysicalNetwork(timeoutMs: Long): Network? {
            return this@OpenWorldService.waitForUsablePhysicalNetwork(timeoutMs)
        }

        override suspend fun ensureNetworkCallbackReady(timeoutMs: Long) {
            this@OpenWorldService.ensureNetworkCallbackReadyWithTimeout(timeoutMs)
        }

        override fun setLastKnownNetwork(network: Network?) { lastKnownNetwork = network }
        override fun setNetworkCallbackReady(ready: Boolean) { networkCallbackReady = ready }

        override fun restoreUnderlyingNetwork(network: Network) {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP_MR1) {
                setUnderlyingNetworks(arrayOf(network))
            Log.i(TAG, "Underlying network restored before core start: $network")
            }
        }

        // 清理
        override suspend fun waitForCleanupJob() {
            val cleanup = cleanupJob
            if (cleanup != null && cleanup.isActive) {
                Log.i(TAG, "Waiting for previous service cleanup...")
                cleanup.join()
                Log.i(TAG, "Previous cleanup finished")
            }
        }

        override fun stopSelf() { this@OpenWorldService.stopSelf() }
    }

    // ShutdownManager 回调实现
    private val shutdownCallbacks = object : ShutdownManager.Callbacks {
        // 状态管理
        override fun updateServiceState(state: ServiceState) {
            this@OpenWorldService.updateServiceState(state)
        }
        override fun updateTileState() { this@OpenWorldService.updateTileState() }
        override fun stopForegroundService() {
            try {
                stopForeground(STOP_FOREGROUND_REMOVE)
            } catch (e: Exception) {
                Log.e(TAG, "Error stopping foreground", e)
            }
        }
        override fun stopSelf() {
            if (stopSelfRequested) {
                this@OpenWorldService.stopSelf()
            }
        }

        // 组件管理
        override fun cancelStartVpnJob(): Job? {
            val job = startVpnJob
            startVpnJob = null
            job?.cancel()
            return job
        }
        override fun cancelVpnHealthJob() {
            vpnHealthJob?.cancel()
            vpnHealthJob = null
        }
        override fun cancelRemoteStateUpdateJob() {
            remoteStateUpdateJob?.cancel()
            remoteStateUpdateJob = null
        }
        override fun cancelRouteGroupAutoSelectJob() {
            routeGroupSelector.stop()
        }

        // 资源清理
        override fun stopForeignVpnMonitor() { foreignVpnMonitor.stop() }
        override fun tryClearRunningServiceForLibbox() {
            this@OpenWorldService.tryClearRunningServiceForLibbox()
        }
        override fun unregisterScreenStateReceiver() {
            screenStateManager.unregisterScreenStateReceiver()
        }
        override fun closeDefaultInterfaceMonitor(listener: InterfaceUpdateListener?) {
            platformInterfaceImpl.closeDefaultInterfaceMonitor(listener)
        }

        // 获取状态
        override fun isServiceRunning(): Boolean = coreManager.isServiceRunning()
        override fun getVpnInterface(): ParcelFileDescriptor? = vpnInterface
        override fun getCurrentInterfaceListener(): InterfaceUpdateListener? = currentInterfaceListener
        override fun getConnectivityManager(): ConnectivityManager? = connectivityManager

        // 设置状态
        override fun setVpnInterface(fd: ParcelFileDescriptor?) { vpnInterface = fd }
        override fun setIsRunning(running: Boolean) { isRunning = running }
        override fun setRealTimeNodeName(name: String?) { realTimeNodeName = name }
        override fun setVpnLinkValidated(validated: Boolean) { vpnLinkValidated = validated }
        override fun setNoPhysicalNetworkWarningLogged(logged: Boolean) {
            noPhysicalNetworkWarningLogged = logged
        }
        override fun setDefaultInterfaceName(name: String) { defaultInterfaceName = name }
        override fun setNetworkCallbackReady(ready: Boolean) { networkCallbackReady = ready }
        override fun setLastKnownNetwork(network: Network?) { lastKnownNetwork = network }
        override fun clearUnderlyingNetworks() {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP_MR1) {
                runCatching { setUnderlyingNetworks(null) }
            }
        }

        // 获取配置路径用于重启
        override fun getPendingStartConfigPath(): String? = synchronized(this@OpenWorldService) {
            val pending = pendingStartConfigPath
            stopSelfRequested = false
            pending
        }
        override fun clearPendingStartConfigPath() = synchronized(this@OpenWorldService) {
            pendingStartConfigPath = null
            isStopping = false
        }
        override fun startVpn(configPath: String) {
            this@OpenWorldService.startVpn(configPath)
        }

        // 检查 VPN 接口是否可复用
        override fun hasExistingTunInterface(): Boolean = vpnInterface != null
    }

    /**
     * 初始�?SelectorManager - 记录 PROXY selector �?outbound 列表
     * 用于后续热切换时判断是否在同一 selector group �?     */
    private fun initSelectorManager(configContent: String) {
        try {
            val config = gson.fromJson(configContent, OpenWorldConfig::class.java) ?: return
            val proxySelector = config.outbounds?.find {
                it.type == "selector" && it.tag.equals("PROXY", ignoreCase = true)
            }

            if (proxySelector == null) {
                Log.w(TAG, "No PROXY selector found in config")
                return
            }

            val outboundTags = proxySelector.outbounds?.filter { it.isNotBlank() } ?: emptyList()
            val selectedTag = proxySelector.default ?: outboundTags.firstOrNull()

            SelectorManager.recordSelectorSignature(outboundTags, selectedTag)
            Log.i(TAG, "SelectorManager initialized: ${outboundTags.size} outbounds, selected=$selectedTag")
        } catch (e: Exception) {
            Log.e(TAG, "Failed to init SelectorManager", e)
        }
    }

    /**
     * 触发 URL 测试并返回结�?     * 使用 CommandClient.urlTest(groupTag) API
     *
     * @param groupTag 要测试的 group 标签 (�?"PROXY")
     * @param timeoutMs 等待结果的超时时�?     * @return 节点延迟映射 (tag -> delay ms)，失败返回空 Map
     */
    suspend fun urlTestGroup(groupTag: String, timeoutMs: Long = 10000L): Map<String, Int> {
        return commandManager.urlTestGroup(groupTag, timeoutMs)
    }

    /**
     * 获取缓存�?URL 测试延迟
     * @param tag 节点标签
     * @return 延迟�?(ms)，未测试返回 null
     */
    fun getCachedUrlTestDelay(tag: String): Int? {
        return commandManager.getCachedUrlTestDelay(tag)
    }

    private fun closeRecentConnectionsBestEffort(reason: String) {
        val ids = recentConnectionIds
        if (ids.isEmpty()) return
        var closed = 0
        for (id in ids) {
            if (id.isBlank()) continue
            if (commandManager.closeConnection(id)) closed++
        }
        if (closed > 0) {
            LogRepository.getInstance().addLog("INFO: closeConnection($reason) closed=$closed")
        }
    }

    /**
     * 重置所有连�?- 渐进式降级策�?     */
    private suspend fun resetConnectionsOptimal(reason: String, skipDebounce: Boolean = false) {
        networkHelper.resetConnectionsOptimal(
            reason = reason,
            skipDebounce = skipDebounce,
            lastResetAtMs = lastConnectionsResetAtMs,
            debounceMs = connectionsResetDebounceMs,
            commandManager = commandManager,
            closeRecentFn = { r -> closeRecentConnectionsBestEffort(r) },
            updateLastReset = { ms -> lastConnectionsResetAtMs = ms }
        )
    }

    @Volatile private var serviceState: ServiceState = ServiceState.STOPPED

    private fun resolveEgressNodeName(repo: ConfigRepository, tagOrSelector: String?): String? {
        if (tagOrSelector.isNullOrBlank()) return null

        // 1) Direct outbound tag -> node name
        repo.resolveNodeNameFromOutboundTag(tagOrSelector)?.let { return it }

        // 2) Selector/group tag -> selected outbound -> resolve again (depth-limited)
        var current: String? = tagOrSelector
        repeat(4) {
            val next = current?.let { commandManager.getSelectedOutbound(it) }
            if (next.isNullOrBlank() || next == current) return@repeat
            repo.resolveNodeNameFromOutboundTag(next)?.let { return it }
            current = next
        }

        return null
    }

    private fun notifyRemoteStateNow() {
        val activeLabel = runCatching {
            val repo = ConfigRepository.getInstance(applicationContext)
            val activeNodeId = repo.activeNodeId.value
            // 2025-fix: 与 buildNotificationState 保持一致优先级
            val resolvedNodeName = realTimeNodeName
                ?: VpnStateStore.getActiveLabel().takeIf { it.isNotBlank() }
                ?: repo.nodes.value.find { it.id == activeNodeId }?.name
                ?: ""
            resolvedNodeName
        }.getOrDefault("")

        OpenWorldIpcHub.update(
            state = serviceState,
            activeLabel = activeLabel,
            lastError = lastErrorFlow.value.orEmpty(),
            manuallyStopped = isManuallyStopped
        )
    }

    private fun requestRemoteStateUpdate(force: Boolean = false) {
        val now = SystemClock.elapsedRealtime()
        val last = lastRemoteStateUpdateAtMs.get()

        if (force) {
            lastRemoteStateUpdateAtMs.set(now)
            remoteStateUpdateJob?.cancel()
            remoteStateUpdateJob = null
            notifyRemoteStateNow()
            return
        }

        val delayMs = (remoteStateUpdateDebounceMs - (now - last)).coerceAtLeast(0L)
        if (delayMs <= 0L) {
            lastRemoteStateUpdateAtMs.set(now)
            remoteStateUpdateJob?.cancel()
            remoteStateUpdateJob = null
            notifyRemoteStateNow()
            return
        }

        if (remoteStateUpdateJob?.isActive == true) return
        remoteStateUpdateJob = serviceScope.launch {
            delay(delayMs)
            lastRemoteStateUpdateAtMs.set(SystemClock.elapsedRealtime())
            notifyRemoteStateNow()
        }
    }

    private fun updateServiceState(state: ServiceState) {
        if (serviceState == state) return
        serviceState = state
        requestRemoteStateUpdate(force = true)
    }

    /**
     * 暴露�?ConfigRepository 调用，尝试热切换节点
     * @return true if hot switch triggered successfully, false if restart is needed
     *
     * 核心原理:
     * OpenWorld Selector.SelectOutbound() 内部会调用 interruptGroup.Interrupt(interruptExternalConnections)
     * �?PROXY selector 配置�?interrupt_exist_connections=true �?
     * selectOutbound 会自动中断所有外部连�?入站连接)
     */
    suspend fun hotSwitchNode(nodeTag: String): Boolean {
        if (!coreManager.isServiceRunning() || !isRunning) return false

        try {
            L.connection("HotSwitch", "Starting switch to: $nodeTag")

            // Step 1: 唤醒核心
            coreManager.wakeService()
            L.step("HotSwitch", 1, 2, "Called wakeService()")

            // Step 2: 使用 SelectorManager 切换节点 (渐进式降�?
            L.step("HotSwitch", 2, 2, "Calling SelectorManager.switchNode...")

            when (val result = serviceSelectorManager.switchNode(nodeTag)) {
                is com.openworld.app.service.manager.SelectorManager.SwitchResult.Success -> {
                    L.result("HotSwitch", true, "Switched to $nodeTag via ${result.method}")
                    requestNotificationUpdate(force = true)
                    return true
                }
                is com.openworld.app.service.manager.SelectorManager.SwitchResult.NeedRestart -> {
                    L.warn("HotSwitch", "Need restart: ${result.reason}")
                    // 需要完整重启，返回 false 让调用者处�?
                    return false
                }
                is com.openworld.app.service.manager.SelectorManager.SwitchResult.Failed -> {
                    L.error("HotSwitch", "Failed: ${result.error}")
                    return false
                }
            }
        } catch (e: Exception) {
            L.error("HotSwitch", "Unexpected exception", e)
            return false
        }
    }

    private var vpnInterface: ParcelFileDescriptor? = null

    private var currentSettings: AppSettings? = null
    private val serviceSupervisorJob = SupervisorJob()
    private val serviceScope = CoroutineScope(Dispatchers.IO + serviceSupervisorJob)
    private val cleanupSupervisorJob = SupervisorJob()
    private val cleanupScope = CoroutineScope(Dispatchers.IO + cleanupSupervisorJob)
    @Volatile private var isStopping: Boolean = false
    @Volatile private var stopSelfRequested: Boolean = false
    @Volatile private var cleanupJob: Job? = null
    @Volatile private var pendingStartConfigPath: String? = null
    @Volatile private var pendingCleanCache: Boolean = false

    @Volatile private var startVpnJob: Job? = null
    @Volatile private var realTimeNodeName: String? = null
// @Volatile private var nodePollingJob: Job? = null // Removed in favor of CommandClient

    private val isConnectingTun = AtomicBoolean(false)

// Command 相关变量已移�?CommandManager
// 保留这些作为兼容性别�?(委托�?commandManager)
    private val activeConnectionNode: String? get() = commandManager.activeConnectionNode
    private val activeConnectionLabel: String? get() = commandManager.activeConnectionLabel
    private val recentConnectionIds: List<String> get() = commandManager.recentConnectionIds

// 速度计算相关 - 委托�?TrafficMonitor
    @Volatile private var showNotificationSpeed: Boolean = true
    private var currentUploadSpeed: Long = 0L
    private var currentDownloadSpeed: Long = 0L

// TrafficMonitor 实例 - 统一管理流量监控和卡死检测
    private val trafficMonitor = TrafficMonitor(serviceScope)
    private val trafficListener = object : TrafficMonitor.Listener {
        override fun onTrafficUpdate(snapshot: TrafficMonitor.TrafficSnapshot) {
            currentUploadSpeed = snapshot.uploadSpeed
            currentDownloadSpeed = snapshot.downloadSpeed
            if (showNotificationSpeed) {
                requestNotificationUpdate(force = false)
            }
        }

        override fun onTrafficStall(consecutiveCount: Int) {
            stallRefreshAttempts++
            val maxAttempts = maxStallRefreshAttempts
            Log.d(TAG, "Traffic stall detected (count=$consecutiveCount, attempt=$stallRefreshAttempts/$maxAttempts)")

            if (stallRefreshAttempts >= maxStallRefreshAttempts * 2) {
                Log.w(TAG, "Persistent traffic stall after $stallRefreshAttempts attempts")
                LogRepository.getInstance().addLog(
                    "WARN: Traffic stall detected, attempting gentle recovery..."
                )
                stallRefreshAttempts = 0
                trafficMonitor.resetStallCounter()
                serviceScope.launch {
                    val closed = BoxWrapperManager.closeIdleConnections(30)
                    Log.i(TAG, "Closed $closed idle connections for traffic stall")
                }
            } else {
                serviceScope.launch {
                    try {
                        val closed = BoxWrapperManager.closeIdleConnections(30)
                        if (closed > 0) {
                            Log.i(TAG, "Closed $closed idle connections after stall")
                        }
                    } catch (e: Exception) {
                        Log.w(TAG, "Failed to close idle connections after stall", e)
                    }
                    trafficMonitor.resetStallCounter()
                }
            }
        }

        override fun onProxyIdle(idleDurationMs: Long) {
            val idleSeconds = idleDurationMs / 1000

            // 条件化恢复：避免在“无连接/无需恢复”时触发重置导致抖动�?
            if (!BoxWrapperManager.isAvailable()) {
                Log.d(TAG, "Proxy idle detected (${idleSeconds}s) but Box not available, skip reset")
                return
            }

            val connCount = runCatching { BoxWrapperManager.getConnectionCount() }.getOrDefault(0)
            val needRecovery = runCatching { BoxWrapperManager.isNetworkRecoveryNeeded() }.getOrDefault(false)

            if (connCount <= 0 && !needRecovery) {
                Log.d(
                    TAG,
                    "Proxy idle detected (${idleSeconds}s) but no active connections and recovery not needed"
                )
                return
            }

            Log.i(
                TAG,
                "Proxy idle ($idleSeconds s), reset conn (cnt=$connCount need=$needRecovery)"
            )
            serviceScope.launch {
                BoxWrapperManager.resetAllConnections(true)
            }
        }
    }

    private var stallRefreshAttempts: Int = 0
    private val maxStallRefreshAttempts: Int = 3 // 连续3次stall刷新后仍无流量则重启服务

// NetworkManager 实例 - 统一管理网络状态和底层网络切换
    private var networkManager: NetworkManager? = null

    @Volatile private var lastRuleSetCheckMs: Long = 0L
    private val ruleSetCheckIntervalMs: Long = 6 * 60 * 60 * 1000L

    private val uidToPackageCache = ConcurrentHashMap<Int, String>()
    private val maxUidToPackageCacheSize: Int = 512

    private fun cacheUidToPackage(uid: Int, pkg: String) {
        if (uid <= 0 || pkg.isBlank()) return
        uidToPackageCache[uid] = pkg
        if (uidToPackageCache.size > maxUidToPackageCacheSize) {
            uidToPackageCache.clear()
        }
    }

    private fun requestCoreNetworkReset(reason: String, force: Boolean = false) {
        val now = SystemClock.elapsedRealtime()
        val parsedReason = parseRecoveryReason(reason)
        val request = RecoveryRequest(
            reason = parsedReason,
            rawReason = reason,
            force = force,
            requestedAtMs = now,
            merged = false
        )
        submitRecoveryRequest(request)
    }

    private fun parseRecoveryReason(reason: String): RecoveryReason {
        val normalized = reason.trim().lowercase()
        return when {
            normalized.contains("network_type_changed") ||
                normalized.contains("typechange") -> RecoveryReason.NETWORK_TYPE_CHANGED
            normalized.contains("doze_exit") -> RecoveryReason.DOZE_EXIT
            normalized.contains("network_validated") -> RecoveryReason.NETWORK_VALIDATED
            normalized.contains("vpnhealth") || normalized.contains("vpn_health") -> RecoveryReason.VPN_HEALTH
            normalized.contains("app_foreground") -> RecoveryReason.APP_FOREGROUND
            normalized.contains("screen_on") -> RecoveryReason.SCREEN_ON
            else -> RecoveryReason.UNKNOWN
        }
    }

    @Suppress("CognitiveComplexMethod", "LongMethod")
    private fun submitRecoveryRequest(request: RecoveryRequest) {
        synchronized(this) {
            // 2025-fix-v7: APP_FOREGROUND + force 走快车道，不进合并窗�?            // 直接 wake + resetNetwork，跳�?800ms 合并等待和多级探�?
            if (request.reason == RecoveryReason.APP_FOREGROUND && request.force && !recoveryInFlight) {
                recoveryInFlight = true
                serviceScope.launch {
                    try {
                        executeForegroundFastRecovery(request)
                    } finally {
                        val nextRequest = synchronized(this@OpenWorldService) {
                            recoveryInFlight = false
                            val next = pendingRecoveryRequest
                            pendingRecoveryRequest = null
                            next
                        }
                        if (nextRequest != null) {
                            executeRecoveryRequest(nextRequest)
                        }
                    }
                }
                return
            }

            if (recoveryInFlight) {
                val current = pendingRecoveryRequest
                pendingRecoveryRequest = if (current == null) {
                    request.copy(merged = true)
                } else {
                    chooseHigherPriorityRecovery(current, request.copy(merged = true))
                }
                recoveryMergedCount.incrementAndGet()
                logRecoveryEvent(
                    event = "merged_inflight",
                    request = request,
                    mode = null,
                    merged = true,
                    skipped = false,
                    outcome = null
                )
                return
            }

            val existingMerge = pendingMergeRequest
            pendingMergeRequest = if (existingMerge == null) {
                request
            } else {
                chooseHigherPriorityRecovery(existingMerge, request.copy(merged = true))
            }

            val hadExisting = existingMerge != null
            if (hadExisting) {
                recoveryMergedCount.incrementAndGet()
                logRecoveryEvent(
                    event = "merged_window",
                    request = request,
                    mode = null,
                    merged = true,
                    skipped = false,
                    outcome = null
                )
            }

            if (recoveryMergeJob?.isActive != true) {
                recoveryMergeJob = serviceScope.launch {
                    delay(recoveryMergeWindowMs)
                    val toRun = synchronized(this@OpenWorldService) {
                        val r = pendingMergeRequest
                        pendingMergeRequest = null
                        r
                    }
                    if (toRun != null) {
                        executeRecoveryRequest(toRun)
                    }
                }
            }
        }
    }

    private fun chooseHigherPriorityRecovery(a: RecoveryRequest, b: RecoveryRequest): RecoveryRequest {
        return when {
            a.force != b.force -> if (a.force) a else b
            a.reason.priority != b.reason.priority -> if (a.reason.priority >= b.reason.priority) a else b
            else -> if (a.requestedAtMs >= b.requestedAtMs) a else b
        }
    }

    private data class RecoveryDebounceContext(
        val now: Long,
        val lane: String,
        val effectiveGlobalDebounceMs: Long,
        val effectiveSourceDebounceMs: Long,
        val reasonKey: String
    )

    private fun buildRecoveryDebounceContext(request: RecoveryRequest): RecoveryDebounceContext {
        val lane = if (request.reason.isFastLane) "fast" else "normal"
        val effectiveGlobalDebounceMs = if (request.reason.isFastLane) {
            recoveryFastLaneGlobalDebounceMs
        } else {
            recoveryGlobalDebounceMs
        }
        val effectiveSourceDebounceMs = if (request.reason.isFastLane) {
            minOf(request.reason.sourceDebounceMs, recoveryFastLaneSourceDebounceCapMs)
        } else {
            request.reason.sourceDebounceMs
        }
        return RecoveryDebounceContext(
            now = SystemClock.elapsedRealtime(),
            lane = lane,
            effectiveGlobalDebounceMs = effectiveGlobalDebounceMs,
            effectiveSourceDebounceMs = effectiveSourceDebounceMs,
            reasonKey = request.reason.name
        )
    }

    private fun shouldSkipByGlobalDebounce(
        request: RecoveryRequest,
        context: RecoveryDebounceContext
    ): Boolean {
        val lastGlobal = recoveryLastTriggeredAtMs.get()
        if (!request.force && context.now - lastGlobal < context.effectiveGlobalDebounceMs) {
            recoverySkippedDebounceCount.incrementAndGet()
            logRecoveryEvent(
                event = "skipped_global_debounce",
                request = request,
                mode = null,
                merged = request.merged,
                skipped = true,
                outcome = "debounce(lane=${context.lane},threshold=${context.effectiveGlobalDebounceMs}ms)"
            )
            return true
        }
        return false
    }

    private fun shouldSkipBySourceDebounce(
        request: RecoveryRequest,
        context: RecoveryDebounceContext
    ): Boolean {
        val reasonLast = recoveryReasonLastAtMs[context.reasonKey] ?: 0L
        if (!request.force && context.now - reasonLast < context.effectiveSourceDebounceMs) {
            recoverySkippedDebounceCount.incrementAndGet()
            logRecoveryEvent(
                event = "skipped_source_debounce",
                request = request,
                mode = null,
                merged = request.merged,
                skipped = true,
                outcome = "debounce(lane=${context.lane},threshold=${context.effectiveSourceDebounceMs}ms)"
            )
            return true
        }
        return false
    }

    @Suppress("LongMethod")
    private suspend fun executeRecoveryRequest(request: RecoveryRequest) {
        synchronized(this) {
            recoveryInFlight = true
        }
        try {
            val context = buildRecoveryDebounceContext(request)
            if (shouldSkipByGlobalDebounce(request, context)) return
            if (shouldSkipBySourceDebounce(request, context)) return

            recoveryLastTriggeredAtMs.set(context.now)
            recoveryReasonLastAtMs[context.reasonKey] = context.now
            recoveryTriggerCount.incrementAndGet()

            // 使用智能恢复替代原有�?SOFT/HARD 二级恢复
            val smartResult = BoxWrapperManager.smartRecover(
                context = this@OpenWorldService,
                source = request.rawReason,
                skipProbe = request.force // 强制恢复时跳过探测
            )

            // 映射 smartRecover 结果到原有统�?
            val mode = when (smartResult.level) {
                BoxWrapperManager.RecoveryLevel.NONE,
                BoxWrapperManager.RecoveryLevel.PROBE -> BoxWrapperManager.RecoveryMode.SOFT
                BoxWrapperManager.RecoveryLevel.SELECTIVE -> {
                    recoverySoftCount.incrementAndGet()
                    BoxWrapperManager.RecoveryMode.SOFT
                }
                BoxWrapperManager.RecoveryLevel.NUCLEAR -> {
                    recoveryHardCount.incrementAndGet()
                    BoxWrapperManager.RecoveryMode.HARD
                }
            }

            val success = smartResult.success
            if (success) {
                recoverySuccessCount.incrementAndGet()
                recoveryConsecutiveFailureCount.set(0)
            } else {
                recoveryFailureCount.incrementAndGet()
                recoveryConsecutiveFailureCount.incrementAndGet()
            }

            val successRate = calculateRecoverySuccessRate()
            val outcomeDetail = buildString {
                append(if (success) "success" else "failed")
                append("(level=${smartResult.level}")
                smartResult.probeLatencyMs?.let { append(",probe=${it}ms") }
                if (smartResult.closedConnections > 0) {
                    append(",closed=${smartResult.closedConnections}")
                }
                append(",rate=$successRate)")
            }
            logRecoveryEvent(
                event = "executed",
                request = request,
                mode = mode,
                merged = request.merged,
                skipped = false,
                outcome = outcomeDetail
            )

            // smartRecover 已包含渐进升级逻辑，不再需�?foregroundHardFallback
            // 仅当 PROBE 级别（链路正常无需恢复）时才考虑调度兜底
            if (smartResult.level == BoxWrapperManager.RecoveryLevel.PROBE) {
                scheduleForegroundHardFallbackIfNeeded(request, mode, success)
            }
        } finally {
            val nextRequest = synchronized(this) {
                recoveryInFlight = false
                val next = pendingRecoveryRequest
                pendingRecoveryRequest = null
                next
            }
            if (nextRequest != null) {
                executeRecoveryRequest(nextRequest)
            }
        }
    }

    private fun calculateRecoverySuccessRate(): String {
        val success = recoverySuccessCount.get()
        val failure = recoveryFailureCount.get()
        val total = success + failure
        if (total <= 0L) return "n/a"
        val percentage = (success * 100.0) / total.toDouble()
        return "%.1f%%".format(java.util.Locale.US, percentage)
    }

    /**
     * 2025-fix-v7: 前台快速恢�?- 跳过探测，直�?wake + resetNetwork
     * �?smartRecover �?2-5 秒（不做 PROBE + SELECTIVE 的验证循环）
     * 仅在 APP_FOREGROUND + force 时使�?     */
    private fun executeForegroundFastRecovery(request: RecoveryRequest) {
        val startMs = SystemClock.elapsedRealtime()

        // 2026-fix: wake + 清理僵死连接 + resetNetwork
        // 息屏/后台期间 TCP 连接已超时，必须清理旧连接引�?        // 否则前台应用复用旧连接会一�?loading
        BoxWrapperManager.wake()
        BoxWrapperManager.closeAllTrackedConnections()
        BoxWrapperManager.resetAllConnections(true)
        BoxWrapperManager.resetNetwork()

        val elapsedMs = SystemClock.elapsedRealtime() - startMs
        Log.i(TAG, "[ForegroundFastRecovery] completed in ${elapsedMs}ms")

        recoveryLastTriggeredAtMs.set(SystemClock.elapsedRealtime())
        recoveryTriggerCount.incrementAndGet()
        recoverySoftCount.incrementAndGet()
        recoverySuccessCount.incrementAndGet()
        recoveryConsecutiveFailureCount.set(0)

        logRecoveryEvent(
            event = "foreground_fast_recovery",
            request = request,
            mode = BoxWrapperManager.RecoveryMode.SOFT,
            merged = false,
            skipped = false,
            outcome = "fast_path(${elapsedMs}ms)"
        )
    }

    private fun shouldScheduleForegroundHardFallback(
        request: RecoveryRequest,
        mode: BoxWrapperManager.RecoveryMode,
        success: Boolean
    ): Boolean {
        if (request.reason != RecoveryReason.APP_FOREGROUND) return false
        if (request.force) return false
        return mode == BoxWrapperManager.RecoveryMode.SOFT && success
    }

    private fun evaluateForegroundFallbackState(): ForegroundFallbackState {
        val stateSkipOutcome = "state_running=$isRunning," +
            "isStarting=$isStarting,isStopping=$isStopping,isManuallyStopped=$isManuallyStopped"
        val shouldSkipByState = !isRunning || isStarting || isStopping || isManuallyStopped

        val now = SystemClock.elapsedRealtime()
        val elapsed = now - lastForegroundHardFallbackAtMs.get()
        val shouldSkipByDebounce = elapsed in 0 until foregroundHardFallbackDebounceMs

        val skipReason = when {
            shouldSkipByState -> "state"
            vpnLinkValidated -> "validated"
            shouldSkipByDebounce -> "debounce"
            else -> null
        }

        return when (skipReason) {
            "state" -> ForegroundFallbackState(
                shouldSkip = true,
                event = "foreground_hard_fallback_skipped_state",
                outcome = stateSkipOutcome
            )
            "validated" -> ForegroundFallbackState(
                shouldSkip = true,
                event = "foreground_hard_fallback_skipped_validated",
                outcome = "vpn_link_validated"
            )
            "debounce" -> ForegroundFallbackState(
                shouldSkip = true,
                event = "foreground_hard_fallback_skipped_debounce",
                outcome = "debounce(elapsed=${elapsed}ms," +
                    "threshold=${foregroundHardFallbackDebounceMs}ms)"
            )
            else -> {
                lastForegroundHardFallbackAtMs.set(now)
                ForegroundFallbackState(
                    shouldSkip = false,
                    event = "foreground_hard_fallback_enqueued",
                    outcome = "grace=${foregroundRecoveryGraceMs}ms"
                )
            }
        }
    }

    private fun scheduleForegroundHardFallbackIfNeeded(
        request: RecoveryRequest,
        mode: BoxWrapperManager.RecoveryMode,
        success: Boolean
    ) {
        if (!shouldScheduleForegroundHardFallback(request, mode, success)) {
            return
        }

        foregroundHardFallbackJob?.cancel()
        foregroundHardFallbackJob = serviceScope.launch {
            delay(foregroundRecoveryGraceMs)

            // 先探�?VPN 链路，如果正常则跳过 HARD fallback
            val probeOk = runCatching {
                ProbeManager.probeFirstSuccessViaVpn(
                    context = this@OpenWorldService,
                    timeoutMs = 1500L
                )
            }.getOrNull() != null

            if (probeOk) {
                logRecoveryEvent(
                    event = "foreground_hard_fallback_skipped_probe_ok",
                    request = request,
                    mode = BoxWrapperManager.RecoveryMode.HARD,
                    merged = false,
                    skipped = true,
                    outcome = "vpn_link_healthy_on_probe"
                )
                return@launch
            }

            val state = evaluateForegroundFallbackState()
            logRecoveryEvent(
                event = state.event,
                request = request,
                mode = BoxWrapperManager.RecoveryMode.HARD,
                merged = false,
                skipped = state.shouldSkip,
                outcome = state.outcome
            )
            if (state.shouldSkip) {
                return@launch
            }

            val hardRequest = RecoveryRequest(
                reason = RecoveryReason.APP_FOREGROUND,
                rawReason = "app_foreground_hard_fallback",
                force = true,
                requestedAtMs = SystemClock.elapsedRealtime(),
                merged = false
            )

            submitRecoveryRequest(hardRequest)
        }
    }

    @Suppress("LongParameterList")
    private fun logRecoveryEvent(
        event: String,
        request: RecoveryRequest,
        mode: BoxWrapperManager.RecoveryMode?,
        merged: Boolean,
        skipped: Boolean,
        outcome: String?
    ) {
        val modeText = mode?.name ?: "n/a"
        val lane = if (request.reason.isFastLane) "fast" else "normal"
        val message = buildString {
            append("[RecoveryGate] event=")
            append(event)
            append(" lane=")
            append(lane)
            append(" reason=")
            append(request.reason.name)
            append(" raw=")
            append(request.rawReason)
            append(" priority=")
            append(request.reason.priority)
            append(" mode=")
            append(modeText)
            append(" merged=")
            append(merged)
            append(" skipped=")
            append(skipped)
            append(" force=")
            append(request.force)
            append(" trigger_count=")
            append(recoveryTriggerCount.get())
            append(" merged_count=")
            append(recoveryMergedCount.get())
            append(" skipped_debounce=")
            append(recoverySkippedDebounceCount.get())
            append(" soft_count=")
            append(recoverySoftCount.get())
            append(" hard_count=")
            append(recoveryHardCount.get())
            append(" success_rate=")
            append(calculateRecoverySuccessRate())
            if (!outcome.isNullOrBlank()) {
                append(" outcome=")
                append(outcome)
            }
        }
        Log.i(TAG, message)
        runCatching { LogRepository.getInstance().addLog("INFO: $message") }
    }

/**
     * 重启 VPN 服务以彻底清理网络状�?     * 用于处理网络栈重置无效的严重情况
     */
    @Suppress("UnusedPrivateMember")
    private suspend fun restartVpnService(reason: String) = withContext(Dispatchers.Main) {
        L.vpn("Restart", "Restarting: $reason")

        // 保存当前配置路径
        val configPath = lastConfigPath ?: run {
            L.warn("Restart", "Cannot restart: no config path")
            return@withContext
        }

        try {
            // 停止当前服务 (不停�?Service 本身)
            stopVpn(stopService = false)

            // 等待完全停止
            var waitCount = 0
            while (isStopping && waitCount < 50) {
                delay(100)
                waitCount++
            }

            // 短暂延迟确保资源完全释放
            delay(500)

            // 重新启动
            startVpn(configPath)

            L.result("Restart", true, "VPN restarted")
        } catch (e: Exception) {
            L.error("Restart", "Failed to restart VPN", e)
            setLastError("Failed to restart VPN: ${e.message}")
        }
    }

// 屏幕/前台状态从 ScreenStateManager 读取
    private val isScreenOn: Boolean get() = screenStateManager.isScreenOn
    private val isAppInForeground: Boolean get() = screenStateManager.isAppInForeground

// Auto reconnect
    private var connectivityManager: ConnectivityManager? = null

    private var currentInterfaceListener: InterfaceUpdateListener? = null
    private var defaultInterfaceName: String = ""
    private val mainHandler = android.os.Handler(android.os.Looper.getMainLooper())
    private var lastKnownNetwork: Network? = null
    private var vpnHealthJob: Job? = null
    @Volatile private var vpnLinkValidated: Boolean = false

// 网络就绪标志：确�?Libbox 启动前网络回调已完成初始采样
    @Volatile private var networkCallbackReady: Boolean = false
    @Volatile private var noPhysicalNetworkWarningLogged: Boolean = false

// setUnderlyingNetworks 防抖机制 - 避免频繁调用触发系统提示
    private val lastSetUnderlyingNetworksAtMs = AtomicLong(0)
    private val setUnderlyingNetworksDebounceMs: Long = 2000L // 2秒防�?
// VPN 启动窗口期保�?// �?VPN 启动后的短时间内，updateDefaultInterface 跳过 setUnderlyingNetworks 调用
    private val vpnStartedAtMs = AtomicLong(0)
    private val vpnStartupWindowMs: Long = 3000L

    @Volatile private var lastConnectionsResetAtMs: Long = 0L
    private val connectionsResetDebounceMs: Long = 2000L

// ACTION_PREPARE_RESTART 防抖：避免短时间内重复触发导致网络反复震荡
    private val lastPrepareRestartAtMs = AtomicLong(0L)
    private val prepareRestartDebounceMs: Long = 1500L

    private enum class RecoveryReason(
        val priority: Int,
        val sourceDebounceMs: Long,
        val isFastLane: Boolean
    ) {
        NETWORK_TYPE_CHANGED(priority = 100, sourceDebounceMs = 3000L, isFastLane = true),
        DOZE_EXIT(priority = 90, sourceDebounceMs = 3000L, isFastLane = true),
        NETWORK_VALIDATED(priority = 80, sourceDebounceMs = 3000L, isFastLane = false),
        VPN_HEALTH(priority = 70, sourceDebounceMs = 30000L, isFastLane = false),
        APP_FOREGROUND(priority = 50, sourceDebounceMs = 1500L, isFastLane = true),
        SCREEN_ON(priority = 50, sourceDebounceMs = 1500L, isFastLane = true),
        UNKNOWN(priority = 10, sourceDebounceMs = 3000L, isFastLane = false)
    }

    private val recoveryGlobalDebounceMs: Long = 1200L
    private val recoveryFastLaneGlobalDebounceMs: Long = 250L
    private val recoveryFastLaneSourceDebounceCapMs: Long = 600L
    private val recoveryMergeWindowMs: Long = 400L

    @Volatile private var recoveryInFlight: Boolean = false
    @Volatile private var pendingRecoveryRequest: RecoveryRequest? = null
    @Volatile private var recoveryMergeJob: Job? = null
    @Volatile private var pendingMergeRequest: RecoveryRequest? = null

    private val recoveryLastTriggeredAtMs = AtomicLong(0L)
    private val recoveryTriggerCount = AtomicLong(0L)
    private val recoveryMergedCount = AtomicLong(0L)
    private val recoverySkippedDebounceCount = AtomicLong(0L)
    private val recoverySoftCount = AtomicLong(0L)
    private val recoveryHardCount = AtomicLong(0L)
    private val recoverySuccessCount = AtomicLong(0L)
    private val recoveryFailureCount = AtomicLong(0L)
    private val recoveryConsecutiveFailureCount = AtomicInteger(0)

    private val recoveryReasonLastAtMs = ConcurrentHashMap<String, Long>()

    private val foregroundRecoveryGraceMs: Long = 3000L
    private var foregroundHardFallbackJob: Job? = null
    private val lastForegroundHardFallbackAtMs = AtomicLong(0L)
    private val foregroundHardFallbackDebounceMs: Long = 15000L

    private data class ForegroundFallbackState(
        val shouldSkip: Boolean,
        val event: String,
        val outcome: String
    )

    private data class RecoveryRequest(
        val reason: RecoveryReason,
        val rawReason: String,
        val force: Boolean,
        val requestedAtMs: Long,
        val merged: Boolean
    )

    private fun findBestPhysicalNetwork(): Network? {
        // 优先使用 ConnectManager (新架�?
        connectManager.getCurrentNetwork()?.let { return it }
        // 回退�?NetworkManager
        networkManager?.findBestPhysicalNetwork()?.let { return it }
        // �?networkManager �?null 时（服务重启期间），使用 NetworkHelper 的回退逻辑
        return networkHelper.findBestPhysicalNetworkFallback()
    }

    private fun updateDefaultInterface(network: Network) {
        networkHelper.updateDefaultInterface(
            network = network,
            vpnStartedAtMs = vpnStartedAtMs.get(),
            startupWindowMs = vpnStartupWindowMs,
            defaultInterfaceName = defaultInterfaceName,
            lastKnownNetwork = lastKnownNetwork,
            lastSetUnderlyingAtMs = lastSetUnderlyingNetworksAtMs.get(),
            debounceMs = setUnderlyingNetworksDebounceMs,
            isRunning = isRunning,
            setUnderlyingNetworks = { networks -> setUnderlyingNetworks(networks) },
            updateInterfaceListener = { name, index, expensive, constrained ->
                currentInterfaceListener?.updateDefaultInterface(name, index, expensive, constrained)
            },
            updateState = { net, iface, now ->
                lastKnownNetwork = net
                defaultInterfaceName = iface
                lastSetUnderlyingNetworksAtMs.set(now)
                noPhysicalNetworkWarningLogged = false
            }
        )
    }

    override fun onCreate() {
        super.onCreate()
        Log.e(TAG, "OpenWorldService onCreate: pid=${android.os.Process.myPid()} instance=${System.identityHashCode(this)}")
        instance = this

        // Restore manually stopped state from persistent storage
        isManuallyStopped = VpnStateStore.isManuallyStopped()
        Log.i(TAG, "Restored isManuallyStopped state: $isManuallyStopped")

        notificationManager.createNotificationChannel()
        // 初始�?ConnectivityManager
        connectivityManager = getSystemService(ConnectivityManager::class.java)

        // ===== 初始化新架构 Managers =====
        initManagers()

        serviceScope.launch {
            lastErrorFlow.collect {
                requestRemoteStateUpdate(force = false)
            }
        }

        // 监听活动节点变化，更新通知
        serviceScope.launch {
            ConfigRepository.getInstance(this@OpenWorldService).activeNodeId.collect { _ ->
                if (isRunning) {
                    requestNotificationUpdate(force = false)
                    requestRemoteStateUpdate(force = false)
                }
            }
        }

        // 监听通知栏速度显示设置变化
        serviceScope.launch {
            SettingsRepository.getInstance(this@OpenWorldService)
                .settings
                .map { it.showNotificationSpeed }
                .distinctUntilChanged()
                .collect { enabled ->
                    showNotificationSpeed = enabled
                    if (isRunning) {
                        requestNotificationUpdate(force = true)
                    }
                }
        }

        // �?P0修复3: 注册Activity生命周期回调，检测应用返回前�?
        screenStateManager.registerActivityLifecycleCallbacks(application)
    }

/**
     * 监听应用前后台切�?(委托�?ScreenStateManager)
     */
    override fun onTrimMemory(level: Int) {
        super.onTrimMemory(level)

        when (level) {
            android.content.ComponentCallbacks2.TRIM_MEMORY_UI_HIDDEN -> {
                screenStateManager.onAppBackground()
            }
        }
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        Log.i(TAG, "onStartCommand action=${intent?.action}")
        runCatching {
            LogRepository.getInstance().addLog("INFO OpenWorldService: onStartCommand action=${intent?.action}")
        }
        when (intent?.action) {
            ACTION_START -> {
                isManuallyStopped = false
                VpnStateStore.setManuallyStopped(false)
                VpnTileService.persistVpnPending(applicationContext, "starting")

                // 性能优化: 预创�?TUN Builder (非阻�?
                coreManager.preallocateTunBuilder()

                val configPath = intent.getStringExtra(EXTRA_CONFIG_PATH)
                val cleanCache = intent.getBooleanExtra(EXTRA_CLEAN_CACHE, false)

                // P0 Optimization: If config path is missing (Shortcut/Headless), generate it inside Service
                if (configPath == null) {
                    Log.i(TAG, "ACTION_START received without config path, generating config...")
                    serviceScope.launch {
                        try {
                            val repo = ConfigRepository.getInstance(applicationContext)
                            val result = repo.generateConfigFile()
                            if (result != null) {
                                Log.i(TAG, "Config generated successfully: ${result.path}")
                                // Recursively call start command with the generated path
                                val newIntent = Intent(applicationContext, OpenWorldService::class.java).apply {
                                    action = ACTION_START
                                    putExtra(EXTRA_CONFIG_PATH, result.path)
                                    putExtra(EXTRA_CLEAN_CACHE, cleanCache)
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
                    return START_STICKY
                }

                updateServiceState(ServiceState.STARTING)
                synchronized(this) {
                    // FIX: Ensure pendingCleanCache is set from intent even for cold start
                    if (cleanCache) pendingCleanCache = true

                    if (isStarting) {
                        pendingStartConfigPath = configPath
                        stopSelfRequested = false
                        lastConfigPath = configPath
                        // Return STICKY to allow system to restart VPN if killed due to memory pressure
                        return START_STICKY
                    }
                    if (isStopping) {
                        pendingStartConfigPath = configPath
                        stopSelfRequested = false
                        lastConfigPath = configPath
                        // Return STICKY to allow system to restart VPN if killed due to memory pressure
                        return START_STICKY
                    }
                    // If already running, do a clean restart to avoid half-broken tunnel state
                    if (isRunning) {
                        pendingStartConfigPath = configPath
                        stopSelfRequested = false
                        lastConfigPath = configPath
                    }
                }
                if (isRunning) {
                    // 2025-fix: 优先尝试热切换节点，避免重启 VPN 导致连接断开
                    // 只有当需要更改核心配置（如路由规则、DNS 等）时才重启
                    // 目前所有切换都视为可能包含核心变更，但我们可以尝试检�?                    // 暂时保持重启逻辑作为兜底，但在此之前尝试热切�?                    // 注意：如果只是切换节点，并不需要重�?VPN，直�?selectOutbound 即可
                    // 但我们需要一种机制来通知 Service 是在切换节点还是完全重载
                    stopVpn(stopService = false)
                } else {
                    startVpn(configPath)
                }
            }
            ACTION_STOP -> {
                Log.i(TAG, "Received ACTION_STOP (manual) -> stopping VPN")
                isManuallyStopped = true
                VpnStateStore.setManuallyStopped(true)
                VpnTileService.persistVpnPending(applicationContext, "stopping")
                updateServiceState(ServiceState.STOPPING)
                notificationManager.setSuppressUpdates(true)
                notificationManager.cancelNotification()
                synchronized(this) {
                    pendingStartConfigPath = null
                }
                stopVpn(stopService = true)
            }
            ACTION_SWITCH_NODE -> {
                Log.i(TAG, "Received ACTION_SWITCH_NODE -> switching node")
                // �?Intent 中获取目标节�?ID，如果未提供则切换下一�?
                val targetNodeId = intent.getStringExtra("node_id")
                val outboundTag = intent.getStringExtra("outbound_tag")
                runCatching {
                    LogRepository.getInstance().addLog(
                        "INFO OpenWorldService: ACTION_SWITCH_NODE nodeId=${targetNodeId.orEmpty()} outboundTag=${outboundTag.orEmpty()}"
                    )
                }
                // Remember latest config path for fallback restart if hot switch doesn't apply.
                val fallbackConfigPath = intent.getStringExtra(EXTRA_CONFIG_PATH)
                if (!fallbackConfigPath.isNullOrBlank()) {
                    synchronized(this) {
                        pendingHotSwitchFallbackConfigPath = fallbackConfigPath
                    }
                    runCatching {
                        LogRepository.getInstance().addLog("INFO OpenWorldService: SWITCH_NODE fallback configPath=$fallbackConfigPath")
                    }
                }
                if (targetNodeId != null) {
                    nodeSwitchManager.performHotSwitch(
                        nodeId = targetNodeId,
                        outboundTag = outboundTag,
                        serviceClass = OpenWorldService::class.java,
                        actionStart = ACTION_START,
                        extraConfigPath = EXTRA_CONFIG_PATH
                    )
                } else {
                    nodeSwitchManager.switchNextNode(
                        serviceClass = OpenWorldService::class.java,
                        actionStart = ACTION_START,
                        extraConfigPath = EXTRA_CONFIG_PATH
                    )
                }
            }
            ACTION_UPDATE_SETTING -> {
                val key = intent.getStringExtra(EXTRA_SETTING_KEY)
                if (key == "show_notification_speed") {
                    val value = intent.getBooleanExtra(EXTRA_SETTING_VALUE_BOOL, true)
                    Log.i(TAG, "Received setting update: $key = $value")
                    showNotificationSpeed = value
                    if (isRunning) {
                        requestNotificationUpdate(force = true)
                    }
                }
            }
            ACTION_PREPARE_RESTART -> {
                val reason = intent.getStringExtra(EXTRA_PREPARE_RESTART_REASON).orEmpty()
                Log.i(TAG, "Received ACTION_PREPARE_RESTART (reason='$reason') -> preparing for VPN restart")
                performPrepareRestart()
            }
            ACTION_HOT_RELOAD -> {
                // �?2025-fix: 内核级热重载
                // �?VPN 运行时重载配置，不销�?VPN 服务
                Log.i(TAG, "Received ACTION_HOT_RELOAD -> performing hot reload")
                val configContent = intent.getStringExtra(EXTRA_CONFIG_CONTENT)
                if (configContent.isNullOrEmpty()) {
                    Log.e(TAG, "ACTION_HOT_RELOAD: config content is empty")
                } else {
                    performHotReload(configContent)
                }
            }
            ACTION_FULL_RESTART -> {
                Log.i(TAG, "Received ACTION_FULL_RESTART -> performing full restart (TUN rebuild)")
                val configPath = intent.getStringExtra(EXTRA_CONFIG_PATH)
                if (configPath.isNullOrEmpty()) {
                    Log.e(TAG, "ACTION_FULL_RESTART: config path is empty")
                } else {
                    performFullRestart(configPath)
                }
            }
            ACTION_RESET_CONNECTIONS -> {
                Log.i(TAG, "Received ACTION_RESET_CONNECTIONS -> user requested connection reset")
                if (isRunning) {
                    serviceScope.launch {
                        BoxWrapperManager.resetAllConnections(true)
                        runCatching {
                            LogRepository.getInstance().addLog("INFO: User triggered connection reset via notification")
                        }
                    }
                }
            }
            ACTION_NETWORK_BUMP -> {
                Log.i(TAG, "Received ACTION_NETWORK_BUMP -> triggering network bump")
                if (isRunning) {
                    serviceScope.launch {
                        BoxWrapperManager.closeIdleConnections(30)
                    }
                }
            }
        }
        // Use START_STICKY to allow system auto-restart if killed due to memory pressure
        // This prevents "VPN mysteriously stops" issue on Android 14+
        // System will restart service with null intent, we handle it gracefully above
        return START_STICKY
    }

    @Volatile private var pendingHotSwitchFallbackConfigPath: String? = null

    /**
     * 执行预清理操�?     */
    private fun performPrepareRestart() {
        if (!isRunning) {
            Log.w(TAG, "performPrepareRestart: VPN not running, skip")
            return
        }

        val now = SystemClock.elapsedRealtime()
        val last = lastPrepareRestartAtMs.get()
        val elapsed = now - last
        if (elapsed < prepareRestartDebounceMs) {
            Log.d(TAG, "performPrepareRestart: skipped (debounce, elapsed=${elapsed}ms)")
            return
        }
        lastPrepareRestartAtMs.set(now)

        serviceScope.launch {
            try {
                Log.i(TAG, "[PrepareRestart] Step 1/3: Wake up core")
                coreManager.wakeService()

                Log.i(TAG, "[PrepareRestart] Step 2/3: Disconnect underlying network")
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP_MR1) {
                    setUnderlyingNetworks(null)
                }

                // Step 3: 等待应用收到广播
                // 不需要太长时间，因为VPN重启本身也需要时�?
                Log.i(TAG, "[PrepareRestart] Step 3/3: Waiting for apps to process network change...")
                delay(100)

                // 注意：不需要调�?closeAllConnectionsImmediate()
                // 因为 VPN 重启时服务关闭会强制关闭所有连�?
                Log.i(TAG, "[PrepareRestart] Complete - apps should now detect network interruption")
            } catch (e: Exception) {
                Log.e(TAG, "performPrepareRestart error", e)
            }
        }
    }

/**
     * 执行内核级热重载
     * �?VPN 运行时重载配置，不销�?VPN 服务
     * 失败�?Toast 报错并关�?VPN，让用户手动重新打开
     */
    private fun performHotReload(configContent: String) {
        if (!isRunning) {
            Log.w(TAG, "performHotReload: VPN not running, skip")
            return
        }

        serviceScope.launch {
            try {
                Log.i(TAG, "[HotReload] Starting kernel-level hot reload...")

                // 更新 CoreManager 的设置，确保后续操作使用最新设�?
                val settings = SettingsRepository.getInstance(applicationContext).settings.first()
                coreManager.setCurrentSettings(settings)

                val result = coreManager.hotReloadConfig(configContent, preserveSelector = true)

                result.onSuccess { success ->
                    if (success) {
                        Log.i(TAG, "[HotReload] Kernel hot reload succeeded")
                        LogRepository.getInstance().addLog("INFO [HotReload] Config reloaded successfully")

                        // Re-init BoxWrapperManager with current CommandServer
                        commandManager.getCommandServer()?.let { server ->
                            BoxWrapperManager.init(server)
                        }

                        // Update notification
                        requestNotificationUpdate(force = true)
                    } else {
                        handleHotReloadFailure("Kernel hot reload not available")
                    }
                }.onFailure { e ->
                    handleHotReloadFailure("Hot reload failed: ${e.message}")
                }
            } catch (e: Exception) {
                Log.e(TAG, "performHotReload error", e)
                handleHotReloadFailure("Hot reload error: ${e.message}")
            }
        }
    }

    private fun handleHotReloadFailure(errorMsg: String) {
        Log.e(TAG, "[HotReload] $errorMsg, stopping VPN")
        LogRepository.getInstance().addLog("ERROR [HotReload] $errorMsg")

        serviceScope.launch(Dispatchers.Main) {
            android.widget.Toast.makeText(
                applicationContext,
                errorMsg,
                android.widget.Toast.LENGTH_LONG
            ).show()
        }

        isManuallyStopped = false
        stopVpn(stopService = true)
    }

    private fun performFullRestart(configPath: String) {
        if (!isRunning) {
            Log.w(TAG, "performFullRestart: VPN not running, starting directly")
            startVpn(configPath)
            return
        }

        serviceScope.launch {
            try {
                Log.i(TAG, "[FullRestart] Step 1/3: Stopping VPN completely...")

                coreManager.closeTunInterface()

                stopVpn(stopService = false)

                var waitCount = 0
                while (isStopping && waitCount < 50) {
                    delay(100)
                    waitCount++
                }

                Log.i(TAG, "[FullRestart] Step 2/3: VPN stopped, waiting for cleanup...")
                delay(200)

                Log.i(TAG, "[FullRestart] Step 3/3: Restarting VPN with new config...")
                lastConfigPath = configPath
                startVpn(configPath)

                Log.i(TAG, "[FullRestart] Complete")
            } catch (e: Exception) {
                Log.e(TAG, "performFullRestart error", e)
                setLastError("Full restart failed: ${e.message}")
            }
        }
    }

    /**
     * 同步版本的热重载，供 IPC 调用
     * 直接调用 Go �?StartOrReloadService，阻塞等待结�?     *
     * 这里使用 runBlocking 是因�?AIDL 接口不支持挂起函数，
     * 调用来自 VPN 进程�?Binder 线程池，使用 Dispatchers.IO 避免阻塞调用线程
     *
     * @return true=成功, false=失败
     */
    fun performHotReloadSync(configContent: String): Boolean {
        if (!isRunning) {
            Log.w(TAG, "performHotReloadSync: VPN not running")
            return false
        }

        return try {
            kotlinx.coroutines.runBlocking(kotlinx.coroutines.Dispatchers.IO) {
                Log.i(TAG, "[HotReload-Sync] Starting kernel-level hot reload...")

                val settings = SettingsRepository.getInstance(applicationContext).settings.first()
                coreManager.setCurrentSettings(settings)

                val result = coreManager.hotReloadConfig(configContent, preserveSelector = true)

                result.getOrNull() == true && result.isSuccess.also { success ->
                    if (success && result.getOrNull() == true) {
                        Log.i(TAG, "[HotReload-Sync] Kernel hot reload succeeded")
                        LogRepository.getInstance().addLog("INFO [HotReload] Config reloaded successfully via IPC")

                        commandManager.getCommandServer()?.let { server ->
                            BoxWrapperManager.init(server)
                        }

                        requestNotificationUpdate(force = true)
                        requestRemoteStateUpdate(force = true)
                    }
                }
            }
        } catch (e: Exception) {
            Log.e(TAG, "performHotReloadSync error", e)
            false
        }
    }

    /**
     * 启动 VPN (重构�?- 委托�?StartupManager)
     * 原方�?~430 行，现在简化为 ~90 �?     */
    private fun startVpn(configPath: String) {
        // 状态检查（保留�?Service 中，因为涉及多线程同步）
        synchronized(this) {
            if (isRunning) {
                Log.w(TAG, "VPN already running, ignore start request")
                return
            }
            if (isStarting) {
                Log.w(TAG, "VPN is already in starting process, ignore start request")
                return
            }
            if (isStopping) {
                Log.w(TAG, "VPN is stopping, queue start request")
                pendingStartConfigPath = configPath
                stopSelfRequested = false
                lastConfigPath = configPath
                return
            }
            isStarting = true
        }

        lastConfigPath = configPath

        // 启动前台通知（必须在协程前调用）
        try {
            val notification = createNotification()
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
                startForeground(
                    VpnNotificationManager.NOTIFICATION_ID,
                    notification,
                    android.content.pm.ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE
                )
            } else {
                startForeground(VpnNotificationManager.NOTIFICATION_ID, notification)
            }
            notificationManager.markForegroundStarted()
        } catch (e: Exception) {
            Log.e(TAG, "Failed to call startForeground", e)
        }

        // 获取清理缓存标志
        val cleanCache = synchronized(this) {
            val c = pendingCleanCache
            pendingCleanCache = false
            c
        }

        // 委托�?StartupManager
        startVpnJob?.cancel()
        startVpnJob = serviceScope.launch {
            val result = startupManager.startVpn(
                configPath = configPath,
                cleanCache = cleanCache,
                coreManager = coreManager,
                connectManager = connectManager,
                callbacks = startupCallbacks
            )

            when (result) {
                is com.openworld.app.service.manager.StartupManager.StartResult.Success -> {
                    updateServiceState(ServiceState.RUNNING)

                    // 初始�?BoxWrapperManager with CommandServer
                    commandManager.getCommandServer()?.let { server ->
                        if (BoxWrapperManager.init(server)) {
                            Log.i(TAG, "BoxWrapperManager initialized")
                        }
                    }

                    tryRegisterRunningServiceForLibbox()
                }
                is com.openworld.app.service.manager.StartupManager.StartResult.Failed -> {
                    stopVpn(stopService = true)
                }
                is com.openworld.app.service.manager.StartupManager.StartResult.NeedPermission -> {
                    updateServiceState(ServiceState.STOPPED)
                    stopSelf()
                }
                is com.openworld.app.service.manager.StartupManager.StartResult.Cancelled -> {
                    // 已在 callbacks.onCancelled() 中处理
                }
            }

            // 清理
            startVpnJob = null
            if (!isRunning && !isStopping && serviceState == ServiceState.STARTING) {
                updateServiceState(ServiceState.STOPPED)
            }
            updateTileState()
        }
    }

    private fun stopVpn(stopService: Boolean) {
        // 状态同步检查（保留�?Service 中，因为涉及多线程同步）
        synchronized(this) {
            stopSelfRequested = stopSelfRequested || stopService
            if (isStopping) {
                return
            }
            isStopping = true
        }

        // 更新状�?
        updateServiceState(ServiceState.STOPPING)
        notificationManager.setSuppressUpdates(true)
        notificationManager.cancelNotification()
        updateTileState()

        // 发�?Tile 刷新广播
        runCatching {
            val intent = Intent(VpnTileService.ACTION_REFRESH_TILE).apply {
                `package` = packageName
            }
            sendBroadcast(intent)
        }

        // 重置 VPN 启动时间�?
        vpnStartedAtMs.set(0)
        stallRefreshAttempts = 0

        // 清理 networkManager (stopService 时释�?
        if (stopService) {
            networkManager?.reset()
            networkManager = null
        } else {
            networkManager?.reset()
        }

        Log.i(TAG, "stopVpn(stopService=$stopService) isManuallyStopped=$isManuallyStopped")

        // 获取代理端口用于等待释放
        val proxyPort = currentSettings?.proxyPort ?: 2080

        // 委托�?ShutdownManager
        // 不需要严格等待端口释放，启动时会强杀进程确保端口可用
        cleanupJob = shutdownManager.stopVpn(
            options = ShutdownManager.ShutdownOptions(
                stopService = stopService,
                preserveTunInterface = !stopService,
                proxyPort = proxyPort,
                strictPortRelease = false
            ),
            coreManager = coreManager,
            commandManager = commandManager,
            trafficMonitor = trafficMonitor,
            networkManager = networkManager,
            notificationManager = notificationManager,
            selectorManager = serviceSelectorManager,
            platformInterfaceImpl = platformInterfaceImpl,
            callbacks = shutdownCallbacks
        )
    }

    private fun updateTileState() {
        try {
            TileService.requestListeningState(this, ComponentName(this, VpnTileService::class.java))

            // 显式触发 TileService 刷新，避免仅依赖 listening/bind 回调导致状态滞�?
            val refreshIntent = Intent(this, VpnTileService::class.java).apply {
                action = VpnTileService.ACTION_REFRESH_TILE
            }
            startService(refreshIntent)
        } catch (e: Exception) {
            Log.e(TAG, "Failed to update tile state", e)
        }
    }

    private fun buildNotificationState(): VpnNotificationManager.NotificationState {
        val configRepository = ConfigRepository.getInstance(this)
        val activeNodeId = configRepository.activeNodeId.value
        // 2025-fix: 优先使用内存中的 realTimeNodeName，然后是持久化的 VpnStateStore.activeLabel
        // 最后才回退�?configRepository（可能在跨进程时不同步）
        val nodeName = realTimeNodeName
            ?: VpnStateStore.getActiveLabel().takeIf { it.isNotBlank() }
            ?: configRepository.nodes.value.find { it.id == activeNodeId }?.name

        return VpnNotificationManager.NotificationState(
            isRunning = isRunning,
            isStopping = isStopping,
            activeNodeName = nodeName,
            showSpeed = showNotificationSpeed,
            uploadSpeed = currentUploadSpeed,
            downloadSpeed = currentDownloadSpeed
        )
    }

    private fun requestNotificationUpdate(force: Boolean = false) {
        notificationManager.requestNotificationUpdate(buildNotificationState(), this, force)
    }

    private fun createNotification(): Notification {
        return notificationManager.createNotification(buildNotificationState())
    }

    override fun onDestroy() {
        Log.i(TAG, "onDestroy called -> stopVpn(stopService=false) pid=${android.os.Process.myPid()}")
        TrafficRepository.getInstance(this).saveStats()

        // 清理省电管理器引�?
        OpenWorldIpcHub.setPowerManager(null)
        screenStateManager.setPowerManager(null)
        backgroundPowerManager.cleanup()

        screenStateManager.unregisterActivityLifecycleCallbacks(application)
        foregroundHardFallbackJob?.cancel()
        foregroundHardFallbackJob = null

        // Ensure critical state is saved synchronously before we potentially halt
        if (!isManuallyStopped) {
            // If we are being destroyed but not manually stopped (e.g. app update or system kill),
            // ensure we don't accidentally mark it as manually stopped, but we DO mark VPN as inactive.
            VpnTileService.persistVpnState(applicationContext, false)
            VpnTileService.persistVpnPending(applicationContext, "")
            VpnStateStore.setMode(VpnStateStore.CoreMode.NONE)
            Log.i(TAG, "onDestroy: Persisted vpn_active=false, vpn_pending='', mode=NONE")
        }

        val shouldStop = runCatching {
            synchronized(this@OpenWorldService) {
                isRunning || isStopping || coreManager.isServiceRunning() || vpnInterface != null
            }
        }.getOrDefault(false)

        if (shouldStop) {
            // Note: stopVpn launches a cleanup job on cleanupScope.
            // If we halt() immediately, that job will die.
            // For app updates, the system kills us anyway, so cleanup might be best-effort.
            stopVpn(stopService = false)
        } else {
            runCatching { stopForeground(STOP_FOREGROUND_REMOVE) }
            VpnTileService.persistVpnState(applicationContext, false)
            VpnTileService.persistVpnPending(applicationContext, "")
            updateServiceState(ServiceState.STOPPED)
            updateTileState()
        }

        serviceSupervisorJob.cancel()
        // cleanupSupervisorJob.cancel() // Allow cleanup to finish naturally

        if (instance == this) {
            instance = null
        }
        super.onDestroy()

        // Kill process to fully reset Go runtime state and prevent zombie states.
        // This ensures clean restart if system decides to recreate the service.
        Log.i(TAG, "OpenWorldService destroyed. Halting process ${android.os.Process.myPid()}.")

        // 同步取消通知，防�?halt(0) 后通知残留
        runCatching {
            val nm = getSystemService(android.app.NotificationManager::class.java)
            nm.cancel(com.openworld.app.service.notification.VpnNotificationManager.NOTIFICATION_ID)
            stopForeground(STOP_FOREGROUND_REMOVE)
        }

        // Give a tiny breath for logs to flush
        try { Thread.sleep(50) } catch (e: Exception) { Log.w(TAG, "Sleep interrupted during force kill", e) }

        Runtime.getRuntime().halt(0)
    }

    override fun onRevoke() {
        Log.i(TAG, "onRevoke called -> stopVpn(stopService=true)")
        isManuallyStopped = true
        // Another VPN took over. Persist OFF state immediately so QS tile won't stay active.
        VpnTileService.persistVpnState(applicationContext, false)
        VpnTileService.persistVpnPending(applicationContext, "")
        setLastError("VPN revoked by system (another VPN may have started)")
        updateServiceState(ServiceState.STOPPED)
        updateTileState()

        // 记录日志，告知用户原�?
        com.openworld.app.repository.LogRepository.getInstance()
            .addLog("WARN: VPN permission revoked by system (possibly another VPN app started)")

        // 发送通知提醒用户
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val manager = getSystemService(NotificationManager::class.java)
            val notification = Notification.Builder(this, VpnNotificationManager.CHANNEL_ID)
                .setContentTitle("VPN Disconnected")
                .setContentText("VPN permission revoked, possibly by another VPN app.")
                .setSmallIcon(android.R.drawable.ic_dialog_alert)
                .setAutoCancel(true)
                .build()
            manager.notify(VpnNotificationManager.NOTIFICATION_ID + 1, notification)
        }

        // 停止服务
        stopVpn(stopService = true)
        super.onRevoke()
    }

    override fun onTaskRemoved(rootIntent: Intent?) {
        super.onTaskRemoved(rootIntent)
        // If the user swiped away the app, we might want to keep the VPN running
        // as a foreground service, but some users expect it to stop.
        // Usually, a foreground service continues running.
        // However, if we want to ensure no "zombie" states, we can at least log or check health.
    }

/**
     * 确保网络回调就绪，最多等待指定超时时�?     * 如果超时仍未就绪，尝试主动采样当前活跃网�?     */
    private suspend fun ensureNetworkCallbackReadyWithTimeout(timeoutMs: Long = 2000L) {
        networkHelper.ensureNetworkCallbackReady(
            isCallbackReady = { networkCallbackReady },
            lastKnownNetwork = { lastKnownNetwork },
            findBestPhysicalNetwork = { findBestPhysicalNetwork() },
            updateNetworkState = { network, ready ->
                lastKnownNetwork = network
                networkCallbackReady = ready
            },
            timeoutMs = timeoutMs
        )
    }

    /**
     * 后台异步更新规则�?- 性能优化
     * VPN 启动成功后延迟执行，在后台静默更新规则集
     * 这样启动时不需要等待规则集下载
     *
     * 2026-fix: 增加延迟时间并检�?CommandClient 状态，防止�?gomobile 回调并发导致
     * go/Seq Unknown reference 崩溃
     */
    private fun scheduleAsyncRuleSetUpdate() {
        serviceScope.launch(Dispatchers.IO) {
            // 2026-fix: 增加延迟�?15 秒，确保 CommandClient 回调已稳�?
            delay(15000)

            if (!isRunning || isStopping) {
                Log.d(TAG, "scheduleAsyncRuleSetUpdate: VPN not running, skip")
                return@launch
            }

            // 2026-fix: 检�?CommandClient 是否已收到回调，避免在初始化阶段并发访问
            val groupsCount = commandManager.getGroupsCount()
            if (groupsCount == 0) {
                Log.d(TAG, "scheduleAsyncRuleSetUpdate: CommandClient not ready yet, skip")
                return@launch
            }

            try {
                val ruleSetRepo = RuleSetRepository.getInstance(this@OpenWorldService)
                val now = System.currentTimeMillis()
                if (now - lastRuleSetCheckMs >= ruleSetCheckIntervalMs) {
                    lastRuleSetCheckMs = now
                    Log.i(TAG, "Starting async rule set update...")
                    val allReady = ruleSetRepo.ensureRuleSetsReady(
                        forceUpdate = false,
                        allowNetwork = true
                    ) { progress ->
                        Log.d(TAG, "Async rule set update: $progress")
                    }
                    Log.i(TAG, "Async rule set update completed, allReady=$allReady")
                }
            } catch (e: Exception) {
                Log.w(TAG, "Async rule set update failed", e)
            }
        }
    }

    private suspend fun waitForUsablePhysicalNetwork(timeoutMs: Long): Network? {
        return networkHelper.waitForUsablePhysicalNetwork(
            lastKnownNetwork = lastKnownNetwork,
            networkManager = networkManager,
            findBestPhysicalNetwork = { findBestPhysicalNetwork() },
            timeoutMs = timeoutMs
        )
    }
}

enum class ServiceState {
    STOPPED,
    STARTING,
    RUNNING,
    STOPPING
}


