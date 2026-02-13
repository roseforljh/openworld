package com.openworld.app.service

import android.app.Notification
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.ComponentCallbacks2
import android.content.Context
import android.content.Intent
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.os.PowerManager
import android.util.Log
import com.openworld.app.MainActivity
import com.openworld.app.OpenWorldApp
import com.openworld.app.R
import com.openworld.app.config.ConfigManager
import com.openworld.app.repository.CoreRepository
import com.openworld.app.repository.SettingsStore
import com.openworld.app.util.FormatUtil
import com.openworld.core.OpenWorldCore
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch

class OpenWorldVpnService : VpnService() {

    companion object {
        const val TAG = "OpenWorldVpn"
        const val ACTION_START = "com.openworld.START"
        const val ACTION_STOP = "com.openworld.STOP"
        const val NOTIFICATION_ID = 1
        private const val WAKELOCK_TIMEOUT = 10 * 60 * 1000L // 10 分钟

        fun start(context: Context) {
            val intent = Intent(context, OpenWorldVpnService::class.java).apply { action = ACTION_START }
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) context.startForegroundService(intent)
            else context.startService(intent)
        }

        fun stop(context: Context) {
            val intent = Intent(context, OpenWorldVpnService::class.java).apply { action = ACTION_STOP }
            context.startService(intent)
        }
    }

    private var tunFd: ParcelFileDescriptor? = null
    private var wakeLock: PowerManager.WakeLock? = null
    private var networkCallback: ConnectivityManager.NetworkCallback? = null
    private val serviceScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private var notificationJob: Job? = null
    private var stopping = false

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_START -> startVpn()
            ACTION_STOP -> stopVpn()
        }
        return START_STICKY
    }

    private fun startVpn() {
        if (OpenWorldCore.isRunning()) {
            Log.w(TAG, "Already running")
            return
        }

        startForeground(NOTIFICATION_ID, buildNotification(getString(R.string.vpn_status_connecting)))

        val dnsLocal = ConfigManager.getDnsLocal(this)
        val dnsServers = dnsLocal
            .split(",", " ", "\n", "\t")
            .map { it.trim() }
            .filter { it.isNotEmpty() && !it.contains("://") }
            .ifEmpty { listOf("223.5.5.5") }

        val tunMtu = SettingsStore.getTunMtu(this)
        val tunIpv6Enabled = SettingsStore.getTunIpv6Enabled(this)

        val builder = Builder()
            .setSession("OpenWorld")
            .setMtu(tunMtu)
            .addAddress("172.19.0.1", 30)
            .addRoute("0.0.0.0", 0)

        if (tunIpv6Enabled) {
            builder
                .addAddress("fdfe:dcba:9876::1", 126)
                .addRoute("::", 0)
        }

        dnsServers.forEach { dns ->
            try { builder.addDnsServer(dns) } catch (_: Exception) {}
        }

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) builder.setMetered(false)

        // 始终排除自身
        try { builder.addDisallowedApplication(packageName) } catch (e: Exception) { Log.w(TAG, "Failed to exclude self: $e") }

        // 分应用代理
        val bypassApps = ConfigManager.getBypassApps(this)
        val proxyMode = ConfigManager.getProxyModeApps(this)
        if (bypassApps.isNotEmpty()) {
            when (proxyMode) {
                "only" -> bypassApps.forEach { pkg ->
                    try { builder.addAllowedApplication(pkg) } catch (_: Exception) {}
                }
                else -> bypassApps.forEach { pkg ->
                    if (pkg != packageName) {
                        try { builder.addDisallowedApplication(pkg) } catch (_: Exception) {}
                    }
                }
            }
        }

        tunFd = builder.establish()
        if (tunFd == null) {
            Log.e(TAG, "Failed to establish TUN")
            stopSelf()
            return
        }

        OpenWorldCore.setTunFd(tunFd!!.fd)

        val config = ConfigManager.generateConfig(this)
        val result = OpenWorldCore.start(config)
        if (result != 0) {
            Log.e(TAG, "Core start failed: $result")
            closeTun()
            stopSelf()
            return
        }

        acquireWakeLock()
        registerNetworkCallback()
        startNotificationLoop()
        updateNotification(getString(R.string.vpn_status_connected))
        Log.i(TAG, "VPN started")
    }

    private fun stopVpn() {
        if (stopping) return
        stopping = true
        try {
            notificationJob?.cancel()
            notificationJob = null
            OpenWorldCore.stop()
            closeTun()
            releaseWakeLock()
            unregisterNetworkCallback()
            stopForeground(STOP_FOREGROUND_REMOVE)
            stopSelf()
            Log.i(TAG, "VPN stopped")
        } finally {
            stopping = false
        }
    }

    private fun startNotificationLoop() {
        notificationJob?.cancel()
        notificationJob = serviceScope.launch {
            while (isActive && OpenWorldCore.isRunning()) {
                // WakeLock 续期
                if (wakeLock?.isHeld != true) {
                    wakeLock?.acquire(WAKELOCK_TIMEOUT)
                }

                val info = CoreRepository.getNotificationInfo()
                val text = when (info.status.lowercase()) {
                    "running", "connected" -> {
                        val up = FormatUtil.formatSpeed(info.upload)
                        val down = FormatUtil.formatSpeed(info.download)
                        getString(R.string.vpn_status_speed, up, down, info.active_connections)
                    }
                    "connecting" -> getString(R.string.vpn_status_connecting)
                    else -> getString(R.string.vpn_status_connected)
                }
                updateNotification(text)
                delay(1000)
            }
        }
    }

    private fun closeTun() {
        try { tunFd?.close() } catch (_: Exception) {}
        tunFd = null
    }

    private fun acquireWakeLock() {
        val pm = getSystemService(Context.POWER_SERVICE) as PowerManager
        wakeLock = pm.newWakeLock(PowerManager.PARTIAL_WAKE_LOCK, "OpenWorld::VpnWakeLock")
        if (wakeLock?.isHeld != true) wakeLock?.acquire(WAKELOCK_TIMEOUT)
        OpenWorldCore.wakelockSet(true)
    }

    private fun releaseWakeLock() {
        try { if (wakeLock?.isHeld == true) wakeLock?.release() } catch (_: Exception) {}
        wakeLock = null
        OpenWorldCore.wakelockSet(false)
    }

    private fun registerNetworkCallback() {
        val cm = getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
        val request = NetworkRequest.Builder()
            .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
            .build()

        networkCallback = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) {
                val caps = cm.getNetworkCapabilities(network)
                val type = when {
                    caps?.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) == true -> 1
                    caps?.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) == true -> 2
                    caps?.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) == true -> 3
                    else -> 4
                }
                val metered = caps?.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_METERED) != true
                OpenWorldCore.notifyNetworkChanged(type, "", metered)
                OpenWorldCore.recoverNetworkAuto()
            }

            override fun onLost(network: Network) {
                OpenWorldCore.notifyNetworkChanged(0, "", false)
            }
        }
        cm.registerNetworkCallback(request, networkCallback!!)
    }

    private fun unregisterNetworkCallback() {
        networkCallback?.let {
            val cm = getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
            try { cm.unregisterNetworkCallback(it) } catch (_: Exception) {}
        }
        networkCallback = null
    }

    private fun buildNotification(text: String): Notification {
        val pendingIntent = PendingIntent.getActivity(
            this,
            0,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE
        )

        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            Notification.Builder(this, OpenWorldApp.CHANNEL_VPN)
                .setContentTitle(getString(R.string.vpn_notification_title))
                .setContentText(text)
                .setSmallIcon(android.R.drawable.sym_def_app_icon)
                .setContentIntent(pendingIntent)
                .setOngoing(true)
                .build()
        } else {
            @Suppress("DEPRECATION")
            Notification.Builder(this)
                .setContentTitle(getString(R.string.vpn_notification_title))
                .setContentText(text)
                .setSmallIcon(android.R.drawable.sym_def_app_icon)
                .setContentIntent(pendingIntent)
                .setOngoing(true)
                .build()
        }
    }

    private fun updateNotification(text: String) {
        val nm = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        nm.notify(NOTIFICATION_ID, buildNotification(text))
    }

    override fun onTrimMemory(level: Int) {
        super.onTrimMemory(level)
        if (level >= ComponentCallbacks2.TRIM_MEMORY_MODERATE) {
            try { OpenWorldCore.notifyMemoryLow() } catch (_: Exception) {}
        }
        if (level >= ComponentCallbacks2.TRIM_MEMORY_COMPLETE) {
            try { OpenWorldCore.gc() } catch (_: Exception) {}
        }
    }

    override fun onRevoke() {
        stopVpn()
    }

    override fun onDestroy() {
        stopVpn()
        super.onDestroy()
    }
}
