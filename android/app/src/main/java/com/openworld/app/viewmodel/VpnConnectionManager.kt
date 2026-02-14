package com.openworld.app.viewmodel

import android.content.Context
import android.content.Intent
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.net.VpnService
import android.os.Build
import android.util.Log
import com.openworld.app.R
import com.openworld.app.ipc.OpenWorldRemote
import com.openworld.app.ipc.VpnStateStore
import com.openworld.app.model.ConnectionState
import com.openworld.app.repository.ConfigRepository
import com.openworld.app.repository.SettingsRepository
import com.openworld.app.service.ProxyOnlyService
import com.openworld.app.service.ServiceState
import com.openworld.app.service.OpenWorldService
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.TimeoutCancellationException
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.drop
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout

/**
 * VPN 连接管理�? *
 * 负责 VPN 的启动、停止和状态管�? */
class VpnConnectionManager(
    private val context: Context,
    private val scope: CoroutineScope,
    private val configRepository: ConfigRepository,
    private val settingsRepository: SettingsRepository
) {
    companion object {
        private const val TAG = "VpnConnectionManager"
    }

    /**
     * VPN 权限请求回调
     */
    interface PermissionCallback {
        fun onVpnPermissionNeeded()
        fun onStatusMessage(message: String, durationMs: Long = 2000)
        fun onConnectionStateChange(state: ConnectionState)
    }

    private var callback: PermissionCallback? = null

    private val _vpnPermissionNeeded = MutableStateFlow(false)
    val vpnPermissionNeeded: StateFlow<Boolean> = _vpnPermissionNeeded.asStateFlow()

    private var startMonitorJob: kotlinx.coroutines.Job? = null

    fun setCallback(callback: PermissionCallback) {
        this.callback = callback
    }

    /**
     * 切换连接状�?     *
     * @return 是否需�?VPN 权限
     */
    suspend fun toggleConnection(): Boolean {
        return when {
            OpenWorldRemote.isRunning.value || OpenWorldRemote.isStarting.value -> {
                stopVpn()
                false
            }
            checkSystemVpn() -> {
                callback?.onStatusMessage(
                    context.getString(R.string.dashboard_system_vpn_running),
                    3000
                )
                false
            }
            else -> {
                startCore()
                _vpnPermissionNeeded.value
            }
        }
    }

    /**
     * 重启 VPN
     */
    suspend fun restartVpn() {
        if (!OpenWorldRemote.isRunning.value && !OpenWorldRemote.isStarting.value) {
            return
        }

        callback?.onConnectionStateChange(ConnectionState.Connecting)
        stopVpnInternal()

        try {
            withTimeout(5000L) {
                OpenWorldRemote.state.drop(1)
                    .first { it == ServiceState.STOPPED }
            }
        } catch (@Suppress("SwallowedException") e: TimeoutCancellationException) {
            Log.w(TAG, "Timeout waiting for VPN to stop during restart")
        }
        delay(300)

        startCore()
    }

    /**
     * 停止 VPN
     */
    fun stopVpn() {
        startMonitorJob?.cancel()
        startMonitorJob = null
        callback?.onConnectionStateChange(ConnectionState.Idle)
        stopVpnInternal()
    }

    private fun stopVpnInternal() {
        val mode = VpnStateStore.getMode()
        val intent = when (mode) {
            VpnStateStore.CoreMode.PROXY -> Intent(context, ProxyOnlyService::class.java).apply {
                action = ProxyOnlyService.ACTION_STOP
            }
            else -> Intent(context, OpenWorldService::class.java).apply {
                action = OpenWorldService.ACTION_STOP
            }
        }
        context.startService(intent)
    }

    /**
     * 启动 VPN 核心
     */
    private suspend fun startCore() {
        val settings = runCatching {
            settingsRepository.settings.first()
        }.getOrNull()

        val desiredMode = if (settings?.tunEnabled == true) {
            VpnStateStore.CoreMode.VPN
        } else {
            VpnStateStore.CoreMode.PROXY
        }

        if (settings?.tunEnabled == true) {
            val prepareIntent = VpnService.prepare(context)
            if (prepareIntent != null) {
                _vpnPermissionNeeded.value = true
                callback?.onVpnPermissionNeeded()
                return
            }
        }

        callback?.onConnectionStateChange(ConnectionState.Connecting)
        stopOppositeService(desiredMode)

        try {
            val configResult = withContext(Dispatchers.IO) {
                settingsRepository.checkAndMigrateRuleSets()
                configRepository.generateConfigFile()
            }
            if (configResult == null) {
                callback?.onConnectionStateChange(ConnectionState.Error)
                callback?.onStatusMessage(
                    context.getString(R.string.dashboard_config_generation_failed)
                )
                return
            }

            startService(desiredMode, configResult.path)
            startConnectionMonitor()
        } catch (e: Exception) {
            callback?.onConnectionStateChange(ConnectionState.Error)
            callback?.onStatusMessage(
                context.getString(R.string.node_start_failed, e.message ?: "")
            )
        }
    }

    private suspend fun stopOppositeService(desiredMode: VpnStateStore.CoreMode) {
        when (desiredMode) {
            VpnStateStore.CoreMode.VPN -> {
                runCatching {
                    context.startService(Intent(context, ProxyOnlyService::class.java).apply {
                        action = ProxyOnlyService.ACTION_STOP
                    })
                }
            }
            VpnStateStore.CoreMode.PROXY -> {
                runCatching {
                    context.startService(Intent(context, OpenWorldService::class.java).apply {
                        action = OpenWorldService.ACTION_STOP
                    })
                }
            }
            else -> return
        }

        if (OpenWorldRemote.isRunning.value || OpenWorldRemote.isStarting.value) {
            try {
                withTimeout(3000L) {
                    OpenWorldRemote.state.drop(1)
                        .first { it == ServiceState.STOPPED }
                }
            } catch (@Suppress("SwallowedException") e: TimeoutCancellationException) {
                Log.w(TAG, "Timeout waiting for opposite service to stop")
            }
            delay(200)
        }
    }

    private fun startService(mode: VpnStateStore.CoreMode, configPath: String) {
        val useTun = mode == VpnStateStore.CoreMode.VPN
        val intent = if (useTun) {
            Intent(context, OpenWorldService::class.java).apply {
                action = OpenWorldService.ACTION_START
                putExtra(OpenWorldService.EXTRA_CONFIG_PATH, configPath)
                putExtra(OpenWorldService.EXTRA_CLEAN_CACHE, true)
            }
        } else {
            Intent(context, ProxyOnlyService::class.java).apply {
                action = ProxyOnlyService.ACTION_START
                putExtra(ProxyOnlyService.EXTRA_CONFIG_PATH, configPath)
                putExtra(OpenWorldService.EXTRA_CLEAN_CACHE, true)
            }
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            context.startForegroundService(intent)
        } else {
            context.startService(intent)
        }
    }

    @Suppress("CognitiveComplexMethod")
    private fun startConnectionMonitor() {
        startMonitorJob?.cancel()
        startMonitorJob = scope.launch {
            val startTime = System.currentTimeMillis()
            val quickFeedbackMs = 1000L
            var showedStartingHint = false

            while (true) {
                if (OpenWorldRemote.isRunning.value) {
                    callback?.onConnectionStateChange(ConnectionState.Connected)
                    return@launch
                }

                val err = OpenWorldRemote.lastError.value
                if (!err.isNullOrBlank()) {
                    callback?.onConnectionStateChange(ConnectionState.Error)
                    callback?.onStatusMessage(err, 3000)
                    return@launch
                }

                val elapsed = System.currentTimeMillis() - startTime
                if (!showedStartingHint && elapsed >= quickFeedbackMs) {
                    showedStartingHint = true
                    callback?.onStatusMessage(
                        context.getString(R.string.connection_connecting),
                        1200
                    )
                }

                val intervalMs = when {
                    elapsed < 10_000L -> 200L
                    elapsed < 60_000L -> 1000L
                    else -> 5000L
                }
                delay(intervalMs)
            }
        }
    }

    private fun checkSystemVpn(): Boolean {
        val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager
            ?: return false
        val activeNetwork = cm.activeNetwork ?: return false
        val caps = cm.getNetworkCapabilities(activeNetwork) ?: return false
        return caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)
    }

    /**
     * 处理 VPN 权限结果
     */
    fun onVpnPermissionResult(granted: Boolean) {
        _vpnPermissionNeeded.value = false
        if (granted) {
            scope.launch {
                startCore()
            }
        }
    }

    fun cleanup() {
        startMonitorJob?.cancel()
        startMonitorJob = null
        callback = null
    }
}







