package com.openworld.app.service.manager

import android.content.Context
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.os.Build
import android.util.Log

/**
 * 外部 VPN 监控器
 * 监测是否有其他 VPN 应用在运行，并在启动前清理
 */
class ForeignVpnMonitor(
    private val context: Context
) {
    companion object {
        private const val TAG = "ForeignVpnMonitor"
    }

    interface Callbacks {
        val isStarting: Boolean
        val isRunning: Boolean
        val isConnectingTun: Boolean
    }

    private var callbacks: Callbacks? = null
    private var connectivityManager: ConnectivityManager? = null
    private var callback: ConnectivityManager.NetworkCallback? = null
    private var preExistingVpnNetworks: Set<Network> = emptySet()

    fun init(callbacks: Callbacks) {
        this.callbacks = callbacks
    }

    /**
     * 检测当前是否有外部 VPN 网络存在
     * @return 外部 VPN 网络列表，空列表表示没有
     */
    fun detectExistingVpnNetworks(): List<Network> {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.M) return emptyList()

        val cm = connectivityManager ?: context.getSystemService(ConnectivityManager::class.java)
        connectivityManager = cm
        if (cm == null) return emptyList()

        return runCatching {
            @Suppress("DEPRECATION")
            cm.allNetworks.filter { network ->
                val caps = cm.getNetworkCapabilities(network)
                caps?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true
            }
        }.getOrDefault(emptyList())
    }

    /**
     * 检测并尝试请求接管外部 VPN
     * 如果检测到外部 VPN，会记录日志。prepare() 机制会确保用户确认接管。
     * @return true 如果有外部 VPN 存在
     */
    fun hasExistingVpn(): Boolean {
        val vpnNetworks = detectExistingVpnNetworks()
        if (vpnNetworks.isNotEmpty()) {
            Log.w(TAG, "Detected ${vpnNetworks.size} existing VPN network(s): $vpnNetworks")
            return true
        }
        return false
    }

    /**
     * 启动外部 VPN 监控
     */
    fun start() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.M) return
        if (callback != null) return

        val cm = connectivityManager ?: context.getSystemService(ConnectivityManager::class.java)
        connectivityManager = cm
        if (cm == null) return

        preExistingVpnNetworks = runCatching {
            @Suppress("DEPRECATION")
            cm.allNetworks.filter { network ->
                val caps = cm.getNetworkCapabilities(network)
                caps?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true
            }.toSet()
        }.getOrDefault(emptySet())

        val cb = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) {
                val caps = cm.getNetworkCapabilities(network) ?: return
                if (!caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)) return
                if (preExistingVpnNetworks.contains(network)) return
                if (callbacks?.isConnectingTun == true) return

                // Do not abort startup if foreign VPN is detected.
                // Android system handles VPN mutual exclusion automatically (revoke).
                if (callbacks?.isStarting == true && callbacks?.isRunning != true) {
                    Log.w(TAG, "Foreign VPN detected during startup, ignoring: $network")
                }
            }
        }

        callback = cb
        val request = NetworkRequest.Builder()
            .addTransportType(NetworkCapabilities.TRANSPORT_VPN)
            .removeCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
            .build()
        runCatching { cm.registerNetworkCallback(request, cb) }
            .onFailure { Log.w(TAG, "Failed to register foreign VPN monitor", it) }
    }

    /**
     * 停止外部 VPN 监控
     */
    fun stop() {
        val cm = connectivityManager ?: return
        callback?.let { cb ->
            runCatching { cm.unregisterNetworkCallback(cb) }
        }
        callback = null
        preExistingVpnNetworks = emptySet()
    }

    fun cleanup() {
        stop()
        callbacks = null
    }
}
