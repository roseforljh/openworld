package com.openworld.app.service

import android.content.BroadcastReceiver
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.ServiceConnection
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.net.VpnService
import android.os.Build
import android.os.IBinder
import android.os.SystemClock
import android.util.Log
import android.app.NotificationManager
import android.service.quicksettings.Tile
import android.service.quicksettings.TileService
import android.widget.Toast
import com.openworld.app.aidl.IOpenWorldService
import com.openworld.app.aidl.IOpenWorldServiceCallback
import com.openworld.app.R
import com.openworld.app.ipc.VpnStateStore
import com.openworld.app.ipc.OpenWorldIpcService
import com.openworld.app.manager.VpnServiceManager
import com.openworld.app.repository.ConfigRepository
import com.openworld.app.repository.SettingsRepository
import com.openworld.app.service.notification.VpnNotificationManager
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class VpnTileService : TileService() {
    private val serviceScope = CoroutineScope(Dispatchers.Main + SupervisorJob())
    private var bindTimeoutJob: Job? = null
    @Volatile private var lastServiceState: ServiceState = ServiceState.STOPPED
    private var serviceBound = false
    private var bindRequested = false
    private var tapPending = false
    // 内存标记，用于在重启服务的过程中保持 UI 状态，防止被中间的 STOPPED 状态闪�?    @Volatile private var isStartingSequence = false
    @Volatile private var startSequenceId: Long = 0L

    @Volatile private var remoteService: IOpenWorldService? = null

    private val tileRefreshReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            if (intent?.action == ACTION_REFRESH_TILE) {
                updateTile()
            }
        }
    }

    private val remoteCallback = object : IOpenWorldServiceCallback.Stub() {
        override fun onStateChanged(state: Int, activeLabel: String?, lastError: String?, manuallyStopped: Boolean) {
            serviceScope.launch(Dispatchers.Main) {
                val mappedState = ServiceState.values().getOrNull(state)
                    ?: ServiceState.STOPPED
                lastServiceState = mappedState
                if (mappedState == ServiceState.STOPPING || mappedState == ServiceState.STOPPED) {
                    // 停止态优先，避免启动序列标记覆盖真实停止状�?                    isStartingSequence = false
                    startSequenceId = 0L
                }
                updateTile(activeLabelOverride = activeLabel)
            }
        }
    }

    companion object {
        private const val TAG = "VpnTileService"
        private const val PREFS_NAME = "vpn_state"
        private const val KEY_VPN_ACTIVE = "vpn_active"
        private const val KEY_VPN_PENDING = "vpn_pending"
        const val ACTION_REFRESH_TILE = "com.openworld.app.REFRESH_TILE"
        private const val STOP_NOTIFICATION_CLEANUP_DELAY_MS = 250L
        /**
         * 持久�?VPN 状态到 SharedPreferences
         * �?OpenWorldService 启动/停止时调�?         */
        fun persistVpnState(context: Context, isActive: Boolean) {
            context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
                .edit()
                .putBoolean(KEY_VPN_ACTIVE, isActive)
                .commit()
        }

        fun persistVpnPending(context: Context, pending: String?) {
            val value = pending.orEmpty()
            context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
                .edit()
                .putString(KEY_VPN_PENDING, value)
                .commit()
        }
    }

    override fun onStartListening() {
        super.onStartListening()
        updateTile()
        val filter = IntentFilter(ACTION_REFRESH_TILE)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            registerReceiver(tileRefreshReceiver, filter, Context.RECEIVER_NOT_EXPORTED)
        } else {
            @Suppress("DEPRECATION")
            registerReceiver(tileRefreshReceiver, filter)
        }
        bindService()
    }

    override fun onStopListening() {
        super.onStopListening()
        runCatching { unregisterReceiver(tileRefreshReceiver) }
        unbindService()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_REFRESH_TILE) {
            updateTile()
        }
        return START_NOT_STICKY
    }

    override fun onClick() {
        super.onClick()
        if (isLocked) {
            unlockAndRun { handleClick() }
            return
        }
        handleClick()
    }

    private fun handleClick() {
        val tile = qsTile ?: return

        // 1. 检�?VPN 权限，如果需要授权则无法抢跑，必须跳�?Activity
        val prepareIntent = VpnService.prepare(this)
        if (prepareIntent != null) {
            startActivityAndCollapse(prepareIntent)
            return
        }

        // 2. UI 抢跑：立即根据当前状态更�?UI
        // 如果当前�?Active �?Active (Starting)，则认为是想关闭
        // 如果�?Inactive，则认为是想开�?        val isActive = tile.state == Tile.STATE_ACTIVE

        if (isActive) {
            // 用户想关�?            // 立即更新 UI 为关闭状�?            tile.state = Tile.STATE_INACTIVE
            tile.label = getString(R.string.app_name)
            try {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                    tile.subtitle = null
                }
            } catch (e: Exception) {
                Log.w(TAG, "Failed to set tile subtitle", e)
            }
            tile.updateTile()

            // 异步执行停止逻辑
            executeStopVpn()
        } else {
            // 用户想开�?            // 立即更新 UI 为开启状�?            tile.state = Tile.STATE_ACTIVE
            tile.label = getString(R.string.connection_connecting)
            tile.updateTile()

            // 异步执行开启逻辑
            executeStartVpn()
        }
    }

    @Suppress("LongMethod", "CyclomaticComplexMethod", "CognitiveComplexMethod")
    private fun updateTile(activeLabelOverride: String? = null) {
        var persistedActive = runCatching {
            getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
                .getBoolean(KEY_VPN_ACTIVE, false)
        }.getOrDefault(false)

        val coreMode = VpnStateStore.getMode()

        if (persistedActive && coreMode == VpnStateStore.CoreMode.VPN && !hasSystemVpnTransport()) {
            persistVpnState(this, false)
            persistVpnPending(this, "")
            persistedActive = false
        }

        var pending = runCatching {
            getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
                .getString(KEY_VPN_PENDING, "")
        }.getOrNull().orEmpty()

        // 孤儿状态检测：如果 pending �?stopping/starting �?Service 实际未运行，清理残留状�?        // 这解决了覆盖安装后磁贴灰色不可点击的问题
        if ((pending == "stopping" || pending == "starting") && !isStartingSequence) {
            val serviceActuallyRunning = serviceBound && remoteService != null
            val hasVpnTransport = hasSystemVpnTransport()
            // 如果既没有绑定到 Service，也没有系统 VPN transport，说明是孤儿状�?            if (!serviceActuallyRunning && !hasVpnTransport) {
                persistVpnPending(this, "")
                persistVpnState(this, false)
                pending = ""
                persistedActive = false
            }
        }

        // 仅计�?UI 渲染态，不污�?lastServiceState（lastServiceState 只由回调更新�?        val effectiveState = if (isStartingSequence) {
            ServiceState.STARTING
        } else if (!serviceBound || remoteService == null || pending.isNotEmpty()) {
            when (pending) {
                "starting" -> ServiceState.STARTING
                "stopping" -> ServiceState.STOPPING
                else -> if (persistedActive) ServiceState.RUNNING else ServiceState.STOPPED
            }
        } else {
            lastServiceState
        }

        val tile = qsTile ?: return

        // 如果正在启动序列中，强制显示�?Active，覆盖中间的 STOPPED 状�?        if (isStartingSequence) {
            tile.state = Tile.STATE_ACTIVE
        } else {
            when (effectiveState) {
                ServiceState.STARTING,
                ServiceState.RUNNING -> {
                    tile.state = Tile.STATE_ACTIVE
                }
                ServiceState.STOPPING -> {
                    tile.state = Tile.STATE_UNAVAILABLE
                }
                ServiceState.STOPPED -> {
                    tile.state = Tile.STATE_INACTIVE
                }
            }
        }
        val activeLabel = if (effectiveState == ServiceState.RUNNING ||
            effectiveState == ServiceState.STARTING
        ) {
            activeLabelOverride?.takeIf { it.isNotBlank() }
                ?: runCatching { remoteService?.activeLabel }.getOrNull()?.takeIf { it.isNotBlank() }
                ?: runCatching {
                    val repo = ConfigRepository.getInstance(applicationContext)
                    val nodeId = repo.activeNodeId.value
                    if (!nodeId.isNullOrBlank()) repo.getNodeById(nodeId)?.name else null
                }.getOrNull()
        } else {
            null
        }

        tile.label = activeLabel ?: getString(R.string.app_name)
        try {
            tile.icon = android.graphics.drawable.Icon.createWithResource(this, R.drawable.ic_qs_tile)
        } catch (_: Exception) {
        }
        tile.updateTile()
    }

    private fun hasSystemVpnTransport(): Boolean {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.M) return false
        val cm = getSystemService(ConnectivityManager::class.java) ?: return false
        return cm.allNetworks.any { network ->
            val caps = cm.getNetworkCapabilities(network) ?: return@any false
            caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)
        }
    }

    /**
     * 执行停止 VPN 逻辑 (使用 VpnServiceManager 统一管理)
     */
    private fun executeStopVpn() {
        // 停止操作应立刻终止启动序列，避免状态被 STARTING 覆盖
        isStartingSequence = false
        startSequenceId = 0L

        // 在主线程立即标记状�?防止竞态条件导�?UI 闪烁
        persistVpnPending(this, "stopping")
        persistVpnState(this, false)
        val stopRequestedAt = SystemClock.elapsedRealtime()

        serviceScope.launch(Dispatchers.IO) {
            try {
                VpnServiceManager.stopVpn(this@VpnTileService)

                withContext(Dispatchers.Main) {
                    // 先收�?UI 状态，避免磁贴�?stop 期间长时间停留在 pending
                    persistVpnPending(this@VpnTileService, "")
                    updateTile()
                }

                // 兜底：短延迟后清除通知，防�?Service 进程异常导致通知残留
                delay(STOP_NOTIFICATION_CLEANUP_DELAY_MS)
                withContext(Dispatchers.Main) {
                    runCatching {
                        val nm = getSystemService(NotificationManager::class.java)
                        // 清除 OpenWorldService 通知 (ID=1)
                        nm?.cancel(VpnNotificationManager.NOTIFICATION_ID)
                        // 清除 ProxyOnlyService 通知 (ID=11)
                        nm?.cancel(11)
                    }
                    Log.d(TAG, "executeStopVpn ui settle in ${SystemClock.elapsedRealtime() - stopRequestedAt}ms")
                }
            } catch (e: Exception) {
                Log.e(TAG, "Stop service failed", e)
                // 如果停止失败,恢复 UI 状�?(虽然概率很低)
                handleStartFailure("Stop service failed: ${e.message}")
            }
        }
    }

    /**
     * 执行启动 VPN 逻辑 (使用 VpnServiceManager 统一管理)
     */
    @Suppress("CognitiveComplexMethod")
    private fun executeStartVpn() {
        // 在主线程立即标记状�?防止竞态条件导�?UI 闪烁
        val currentSequenceId = SystemClock.elapsedRealtimeNanos()
        startSequenceId = currentSequenceId
        isStartingSequence = true
        persistVpnPending(this, "starting")

        serviceScope.launch(Dispatchers.IO) {
            try {
                val settings = SettingsRepository.getInstance(applicationContext).settings.first()

                // 双重检�?VPN 权限 (防止在点击间隙权限被吊销)
                if (settings.tunEnabled) {
                    val prepareIntent = VpnService.prepare(this@VpnTileService)
                    if (prepareIntent != null) {
                        // 需要授�?回滚 UI 并跳�?                        withContext(Dispatchers.Main) {
                            revertToInactive()
                            prepareIntent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                            runCatching { startActivityAndCollapse(prepareIntent) }
                        }
                        return@launch
                    }
                }

                // 生成配置文件 (耗时操作)
                val configRepository = ConfigRepository.getInstance(applicationContext)
                val configResult = configRepository.generateConfigFile()

                if (configResult != null) {
                    // 使用 VpnServiceManager 统一启动逻辑
                    // 内部会根�?tunEnabled 选择 OpenWorldService �?ProxyOnlyService
                    VpnServiceManager.startVpn(this@VpnTileService, settings.tunEnabled)

                    // 启动成功�? Service 的回调会触发 updateTile,
                    // 此时 pending 仍为 "starting", updateTile 会保�?Active 状�?                } else {
                    handleStartFailure(getString(R.string.dashboard_config_generation_failed))
                }
            } catch (e: Exception) {
                handleStartFailure("Start failed: ${e.message}")
            } finally {
                // 无论成功失败,结束启动序列标记
                // 延迟一小会儿清除标�?确保 Service 状态已经稳�?                if (isStartingSequence && startSequenceId == currentSequenceId) {
                    delay(2000)
                    if (startSequenceId == currentSequenceId) {
                        isStartingSequence = false
                        startSequenceId = 0L
                        // 最后刷新一次以同步真实状�?                        withContext(Dispatchers.Main) {
                            updateTile()
                        }
                    }
                }
            }
        }
    }

    private suspend fun handleStartFailure(reason: String) {
        startSequenceId = 0L
        isStartingSequence = false // 立即取消标记
        // 清除状�?        persistVpnPending(this@VpnTileService, "")
        persistVpnState(this@VpnTileService, false)
        lastServiceState = ServiceState.STOPPED

        withContext(Dispatchers.Main) {
            revertToInactive()
            Toast.makeText(this@VpnTileService, reason, Toast.LENGTH_LONG).show()
        }
    }

    private fun revertToInactive() {
        val tile = qsTile ?: return
        tile.state = Tile.STATE_INACTIVE
        tile.label = getString(R.string.app_name)
        tile.updateTile()
    }

    // 保留 toggle 方法以防其他地方调用（虽然这�?private�?    private fun toggle() {
        // Redirect to new logic
        handleClick()
    }

    private fun bindService(force: Boolean = false) {
        if (serviceBound || bindRequested) return

        val persistedActive = runCatching {
            getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
                .getBoolean(KEY_VPN_ACTIVE, false)
        }.getOrDefault(false)

        val pending = runCatching {
            getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
                .getString(KEY_VPN_PENDING, "")
        }.getOrNull().orEmpty()

        val shouldTryBind = force || persistedActive || pending == "starting" || pending == "stopping"
        if (!shouldTryBind) return

        val intent = Intent(this, OpenWorldIpcService::class.java)

        val ok = runCatching {
            bindService(intent, serviceConnection, Context.BIND_AUTO_CREATE)
        }.getOrDefault(false)
        bindRequested = ok

        bindTimeoutJob?.cancel()
        bindTimeoutJob = serviceScope.launch {
            delay(1200)
            if (serviceBound || remoteService != null) return@launch
            if (!bindRequested) return@launch

            val active = runCatching {
                getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
                    .getBoolean(KEY_VPN_ACTIVE, false)
            }.getOrDefault(false)
            val p = runCatching {
                getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)
                    .getString(KEY_VPN_PENDING, "")
            }.getOrNull().orEmpty()

            if (p != "starting" && (active || p == "stopping")) {
                unbindService()
                tapPending = false
                persistVpnState(this@VpnTileService, false)
                persistVpnPending(this@VpnTileService, "")
                lastServiceState = ServiceState.STOPPED
                updateTile()
            }
        }

        if (!ok && pending != "starting" && (persistedActive || pending == "stopping")) {
            tapPending = false
            persistVpnState(this, false)
            persistVpnPending(this, "")
            lastServiceState = ServiceState.STOPPED
            updateTile()
        }
    }

    private val serviceConnection = object : ServiceConnection {
        override fun onServiceConnected(name: ComponentName?, service: IBinder?) {
            val binder = IOpenWorldService.Stub.asInterface(service)
            remoteService = binder
            runCatching { binder.registerCallback(remoteCallback) }
            serviceBound = true
            bindRequested = true
            lastServiceState = ServiceState.values().getOrNull(runCatching { binder.state }.getOrNull() ?: -1)
                ?: ServiceState.STOPPED
            updateTile(activeLabelOverride = runCatching { binder.activeLabel }.getOrNull())
            if (tapPending) {
                tapPending = false
                toggle()
            }
        }

        override fun onServiceDisconnected(name: ComponentName?) {
            runCatching { remoteService?.unregisterCallback(remoteCallback) }
            remoteService = null
            serviceBound = false
            bindRequested = false
            updateTile()
        }
    }

    private fun unbindService() {
        if (!bindRequested) return
        bindTimeoutJob?.cancel()
        bindTimeoutJob = null
        runCatching { remoteService?.unregisterCallback(remoteCallback) }
        runCatching { unbindService(serviceConnection) }
        remoteService = null
        serviceBound = false
        bindRequested = false
    }

    override fun onDestroy() {
        unbindService()
        serviceScope.cancel()
        super.onDestroy()
    }
}







