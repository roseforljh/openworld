package com.openworld.app.service.manager

import android.content.Context
import android.content.pm.PackageManager
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.os.Build
import android.os.Handler
import android.os.SystemClock
import android.provider.Settings
import android.system.OsConstants
import android.util.Log
import io.nekohasekai.libbox.InterfaceUpdateListener
import io.nekohasekai.libbox.NetworkInterfaceIterator
import io.nekohasekai.libbox.PlatformInterface
import io.nekohasekai.libbox.StringIterator
import io.nekohasekai.libbox.TunOptions
import io.nekohasekai.libbox.WIFIState
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import java.io.File
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.NetworkInterface
import java.util.concurrent.atomic.AtomicLong

/**
 * PlatformInterface 实现，从 SingBoxService 中提取
 * 处理 libbox 平台回调：TUN 设备、网络接口、连接所有者查询等
 */
class PlatformInterfaceImpl(
    private val context: Context,
    private val serviceScope: CoroutineScope,
    private val mainHandler: Handler,
    private val callbacks: Callbacks
) : PlatformInterface {

    companion object {
        private const val TAG = "PlatformInterfaceImpl"
        private const val NETWORK_SWITCH_DELAY_MS = 2000L
    }

    // 网络切换管理器
    private val networkSwitchManager: NetworkSwitchManager by lazy {
        NetworkSwitchManager(serviceScope, mainHandler).apply {
            init(networkSwitchCallbacks)
        }
    }

    // NetworkSwitchManager 回调
    private val networkSwitchCallbacks = object : NetworkSwitchManager.Callbacks {
        override fun getConnectivityManager(): ConnectivityManager? = callbacks.getConnectivityManager()

        override fun setUnderlyingNetworks(networks: Array<Network>?) {
            callbacks.setUnderlyingNetworks(networks)
        }

        override fun setLastKnownNetwork(network: Network?) {
            callbacks.setLastKnownNetwork(network)
        }

        override fun getLastKnownNetwork(): Network? = callbacks.getLastKnownNetwork()

        override fun updateInterfaceListener(name: String, index: Int, isExpensive: Boolean, isConstrained: Boolean) {
            currentInterfaceListener?.updateDefaultInterface(name, index, isExpensive, isConstrained)
        }

        override fun isRunning(): Boolean = callbacks.isRunning()

        override fun requestCoreNetworkRecovery(reason: String, force: Boolean) {
            callbacks.requestCoreNetworkReset(reason, force)
        }
    }

    /**
     * 回调接口，由 SingBoxService 实现
     */
    interface Callbacks {
        // VPN 操作
        fun protect(fd: Int): Boolean
        fun openTun(options: TunOptions): Result<Int>

        // 网络状态
        fun getConnectivityManager(): ConnectivityManager?
        fun getCurrentNetwork(): Network?
        fun getLastKnownNetwork(): Network?
        fun setLastKnownNetwork(network: Network?)
        fun markVpnStarted()

        // 网络重置
        fun requestCoreNetworkReset(reason: String, force: Boolean)
        fun resetConnectionsOptimal(reason: String, skipDebounce: Boolean)
        fun setUnderlyingNetworks(networks: Array<Network>?)

        // 状态查询
        fun isRunning(): Boolean
        fun isStarting(): Boolean
        fun isManuallyStopped(): Boolean
        fun getLastConfigPath(): String?
        fun getCurrentSettings(): com.openworld.app.model.AppSettings?

        // 统计
        fun incrementConnectionOwnerCalls()
        fun incrementConnectionOwnerInvalidArgs()
        fun incrementConnectionOwnerUidResolved()
        fun incrementConnectionOwnerSecurityDenied()
        fun incrementConnectionOwnerOtherException()
        fun setConnectionOwnerLastEvent(event: String)
        fun setConnectionOwnerLastUid(uid: Int)
        fun isConnectionOwnerPermissionDeniedLogged(): Boolean
        fun setConnectionOwnerPermissionDeniedLogged(logged: Boolean)

        // 缓存
        fun cacheUidToPackage(uid: Int, packageName: String)
        fun getUidFromCache(uid: Int): String?

        // 接口监听
        fun findBestPhysicalNetwork(): Network?
    }

    // 网络监听状态
    private var connectivityManager: ConnectivityManager? = null
    private var networkCallback: ConnectivityManager.NetworkCallback? = null
    private var vpnNetworkCallback: ConnectivityManager.NetworkCallback? = null
    private var currentInterfaceListener: InterfaceUpdateListener? = null
    private var networkCallbackReady = false
    private var defaultInterfaceName = ""

    // VPN 健康检查
    private var vpnHealthJob: Job? = null
    private var postTunRebindJob: Job? = null
    private var vpnLinkValidated = false

    // 避免在弱网/门户网/ROM异常场景下频繁触发"健康恢复"导致网络抖动
    private val lastVpnHealthRecoveryAtMs = AtomicLong(0L)
    private val vpnHealthRecoveryMinIntervalMs: Long = 30_000L

    // 时间戳
    private val vpnStartedAtMs = AtomicLong(0L)
    private val lastSetUnderlyingNetworksAtMs = AtomicLong(0L)

    // ProcFS readability cache (avoid repeated /proc reads)
    private val lastProcFsCheckAtMs = AtomicLong(0L)
    @Volatile private var cachedProcFsReadable: Boolean? = null
    private val procFsCheckIntervalMs: Long = 5 * 60_000L

    override fun localDNSTransport(): io.nekohasekai.libbox.LocalDNSTransport {
        return com.openworld.app.core.LocalResolverImpl
    }

    override fun autoDetectInterfaceControl(fd: Int) {
        val result = callbacks.protect(fd)
        if (!result) {
            Log.e(TAG, "autoDetectInterfaceControl: protect($fd) failed")
            runCatching {
                com.openworld.app.repository.LogRepository.getInstance()
                    .addLog("ERROR: protect($fd) failed")
            }
        }
    }

    override fun openTun(options: TunOptions?): Int {
        if (options == null) return -1

        try {
            // 检查 VPN lockdown
            val alwaysOnPkg = runCatching {
                Settings.Secure.getString(context.contentResolver, "always_on_vpn_app")
            }.getOrNull() ?: runCatching {
                Settings.Global.getString(context.contentResolver, "always_on_vpn_app")
            }.getOrNull()

            val lockdownSecure = runCatching {
                Settings.Secure.getInt(context.contentResolver, "always_on_vpn_lockdown", 0)
            }.getOrDefault(0)
            val lockdownGlobal = runCatching {
                Settings.Global.getInt(context.contentResolver, "always_on_vpn_lockdown", 0)
            }.getOrDefault(0)
            val lockdown = lockdownSecure != 0 || lockdownGlobal != 0

            if (lockdown && !alwaysOnPkg.isNullOrBlank() && alwaysOnPkg != context.packageName) {
                throw IllegalStateException("VPN lockdown enabled by $alwaysOnPkg")
            }

            // 委托给 Callbacks
            val result = callbacks.openTun(options)

            return result.getOrElse { e ->
                Log.e(TAG, "openTun failed: ${e.message}", e)
                throw e
            }.also { fd ->
                val network = callbacks.getCurrentNetwork()
                if (network != null) {
                    callbacks.setLastKnownNetwork(network)
                    vpnStartedAtMs.set(SystemClock.elapsedRealtime())
                    callbacks.markVpnStarted()
                }
                Log.i(TAG, "TUN interface established with fd: $fd")
            }
        } catch (e: Exception) {
            Log.e(TAG, "openTun exception: ${e.message}", e)
            throw e
        }
    }

    override fun usePlatformAutoDetectInterfaceControl(): Boolean = true

    override fun useProcFS(): Boolean {
        val now = SystemClock.elapsedRealtime()
        val cached = cachedProcFsReadable
        val last = lastProcFsCheckAtMs.get()
        if (cached != null && now - last < procFsCheckIntervalMs) {
            return cached
        }

        val procPaths = listOf(
            "/proc/net/tcp",
            "/proc/net/tcp6",
            "/proc/net/udp",
            "/proc/net/udp6"
        )

        fun hasUidHeader(path: String): Boolean {
            return try {
                val file = File(path)
                if (!file.exists() || !file.canRead()) return false
                val header = file.bufferedReader().use { it.readLine() } ?: return false
                header.contains("uid")
            } catch (_: Exception) {
                false
            }
        }

        val readable = procPaths.all { path -> hasUidHeader(path) }
        cachedProcFsReadable = readable
        lastProcFsCheckAtMs.set(now)

        if (!readable) {
            callbacks.setConnectionOwnerLastEvent("procfs_unreadable_or_no_uid -> force findConnectionOwner")
        }

        return readable
    }

    @Suppress("LongMethod", "CyclomaticComplexMethod", "CognitiveComplexMethod", "ReturnCount")
    override fun findConnectionOwner(
        ipProtocol: Int,
        sourceAddress: String?,
        sourcePort: Int,
        destinationAddress: String?,
        destinationPort: Int
    ): Int {
        callbacks.incrementConnectionOwnerCalls()

        // Avoid expensive /proc scanning when it's known to be unreadable.
        val procFsUsable = runCatching { useProcFS() }.getOrDefault(false)

        fun findUidFromProcFsBySourcePort(protocol: Int, srcPort: Int): Int {
            if (srcPort <= 0) return 0
            if (!procFsUsable) return 0

            val procFiles = when (protocol) {
                OsConstants.IPPROTO_TCP -> listOf("/proc/net/tcp", "/proc/net/tcp6")
                OsConstants.IPPROTO_UDP -> listOf("/proc/net/udp", "/proc/net/udp6")
                else -> emptyList()
            }
            if (procFiles.isEmpty()) return 0

            val targetPortHex = srcPort.toString(16).uppercase().padStart(4, '0')

            fun parseUidFromLine(parts: List<String>): Int {
                if (parts.size < 9) return 0
                val uidStr = parts.getOrNull(7) ?: return 0
                return uidStr.toIntOrNull() ?: 0
            }

            for (path in procFiles) {
                try {
                    val file = File(path)
                    if (!file.exists() || !file.canRead()) continue
                    var resultUid = 0
                    file.bufferedReader().useLines { lines ->
                        for (line in lines.drop(1)) {
                            val parts = line.trim().split(Regex("\\s+")).filter { it.isNotEmpty() }
                            val local = parts.getOrNull(1) ?: continue
                            val portHex = local.substringAfter(':', "").uppercase()
                            if (portHex == targetPortHex) {
                                val uid = parseUidFromLine(parts)
                                if (uid > 0) {
                                    resultUid = uid
                                    break
                                }
                            }
                        }
                    }
                    if (resultUid > 0) return resultUid
                } catch (e: Exception) {
                    // ignore
                }
            }
            return 0
        }

        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q) {
            callbacks.incrementConnectionOwnerInvalidArgs()
            callbacks.setConnectionOwnerLastEvent("api<29")
            return 0
        }

        fun parseAddress(value: String?): InetAddress? {
            if (value.isNullOrBlank()) return null
            val cleaned = value.trim().replace("[", "").replace("]", "").substringBefore("%")
            return try {
                InetAddress.getByName(cleaned)
            } catch (_: Exception) {
                null
            }
        }

        val sourceIp = parseAddress(sourceAddress)
        val destinationIp = parseAddress(destinationAddress)

        val protocol = when (ipProtocol) {
            OsConstants.IPPROTO_TCP -> OsConstants.IPPROTO_TCP
            OsConstants.IPPROTO_UDP -> OsConstants.IPPROTO_UDP
            else -> ipProtocol
        }

        if (sourceIp == null || sourcePort <= 0 || destinationIp == null || destinationPort <= 0) {
            val uid = findUidFromProcFsBySourcePort(protocol, sourcePort)
            if (uid > 0) {
                callbacks.incrementConnectionOwnerUidResolved()
                callbacks.setConnectionOwnerLastUid(uid)
                callbacks.setConnectionOwnerLastEvent(
                    "procfs_fallback uid=$uid proto=$protocol src=$sourceAddress:$sourcePort dst=$destinationAddress:$destinationPort"
                )
                return uid
            }

            callbacks.incrementConnectionOwnerInvalidArgs()
            callbacks.setConnectionOwnerLastEvent(
                "invalid_args src=$sourceAddress:$sourcePort dst=$destinationAddress:$destinationPort proto=$ipProtocol"
            )
            return 0
        }

        return try {
            val cm = callbacks.getConnectivityManager() ?: return 0
            val uid = cm.getConnectionOwnerUid(
                protocol,
                InetSocketAddress(sourceIp, sourcePort),
                InetSocketAddress(destinationIp, destinationPort)
            )
            if (uid > 0) {
                callbacks.incrementConnectionOwnerUidResolved()
                callbacks.setConnectionOwnerLastUid(uid)
                callbacks.setConnectionOwnerLastEvent(
                    "resolved uid=$uid proto=$protocol $sourceIp:$sourcePort->$destinationIp:$destinationPort"
                )
                uid
            } else {
                callbacks.setConnectionOwnerLastEvent(
                    "unresolved uid=$uid proto=$protocol $sourceIp:$sourcePort->$destinationIp:$destinationPort"
                )
                0
            }
        } catch (e: SecurityException) {
            callbacks.incrementConnectionOwnerSecurityDenied()
            callbacks.setConnectionOwnerLastEvent(
                "SecurityException findConnectionOwner proto=$protocol $sourceIp:$sourcePort->$destinationIp:$destinationPort"
            )
            if (!callbacks.isConnectionOwnerPermissionDeniedLogged()) {
                callbacks.setConnectionOwnerPermissionDeniedLogged(true)
                Log.w(TAG, "findConnectionOwner permission denied; app routing may not work on this ROM", e)
                com.openworld.app.repository.LogRepository.getInstance()
                    .addLog("WARN: findConnectionOwner permission denied; per-app routing disabled on this ROM")
            }
            val uid = findUidFromProcFsBySourcePort(protocol, sourcePort)
            if (uid > 0) {
                callbacks.incrementConnectionOwnerUidResolved()
                callbacks.setConnectionOwnerLastUid(uid)
                callbacks.setConnectionOwnerLastEvent("procfs_fallback_after_security uid=$uid")
                uid
            } else {
                0
            }
        } catch (e: Exception) {
            callbacks.incrementConnectionOwnerOtherException()
            callbacks.setConnectionOwnerLastEvent("Exception ${e.javaClass.simpleName}: ${e.message}")
            val uid = findUidFromProcFsBySourcePort(protocol, sourcePort)
            if (uid > 0) {
                callbacks.incrementConnectionOwnerUidResolved()
                callbacks.setConnectionOwnerLastUid(uid)
                callbacks.setConnectionOwnerLastEvent("procfs_fallback_after_exception uid=$uid")
                uid
            } else {
                0
            }
        }
    }

    override fun packageNameByUid(uid: Int): String {
        if (uid <= 0) return ""
        return try {
            val pkgs = context.packageManager.getPackagesForUid(uid)
            if (!pkgs.isNullOrEmpty()) {
                pkgs[0].also { callbacks.cacheUidToPackage(uid, it) }
            } else {
                val name = runCatching { context.packageManager.getNameForUid(uid) }.getOrNull().orEmpty()
                if (name.isNotBlank()) {
                    callbacks.cacheUidToPackage(uid, name)
                    name
                } else {
                    callbacks.getUidFromCache(uid) ?: ""
                }
            }
        } catch (_: Exception) {
            val name = runCatching { context.packageManager.getNameForUid(uid) }.getOrNull().orEmpty()
            if (name.isNotBlank()) {
                callbacks.cacheUidToPackage(uid, name)
                name
            } else {
                callbacks.getUidFromCache(uid) ?: ""
            }
        }
    }

    override fun uidByPackageName(packageName: String?): Int {
        if (packageName.isNullOrBlank()) return 0
        return try {
            val appInfo = context.packageManager.getApplicationInfo(packageName, PackageManager.GET_META_DATA)
            val uid = appInfo.uid
            if (uid > 0) uid else 0
        } catch (_: Exception) {
            0
        }
    }

    override fun startDefaultInterfaceMonitor(listener: InterfaceUpdateListener?) {
        currentInterfaceListener = listener

        // 提前设置启动窗口期时间戳
        vpnStartedAtMs.set(SystemClock.elapsedRealtime())
        lastSetUnderlyingNetworksAtMs.set(SystemClock.elapsedRealtime())
        networkSwitchManager.markVpnStarted()

        connectivityManager = callbacks.getConnectivityManager()

        // 使用 Application 层预缓存的网络
        var initialNetwork: Network? = com.openworld.app.utils.DefaultNetworkListener.underlyingNetwork

        // 如果预缓存不可用，尝试使用之前保存的 lastKnownNetwork
        if (initialNetwork == null) {
            val lastKnown = callbacks.getLastKnownNetwork()
            if (lastKnown != null) {
                val caps = connectivityManager?.getNetworkCapabilities(lastKnown)
                val isVpn = caps?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true
                val hasInternet = caps?.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) == true
                if (!isVpn && hasInternet) {
                    initialNetwork = lastKnown
                    Log.i(TAG, "startDefaultInterfaceMonitor: using preserved lastKnownNetwork: $lastKnown")
                }
            }
        }

        // 最后尝试 activeNetwork
        if (initialNetwork == null) {
            val activeNet = connectivityManager?.activeNetwork
            if (activeNet != null) {
                val caps = connectivityManager?.getNetworkCapabilities(activeNet)
                val isVpn = caps?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true
                if (!isVpn && caps?.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET) == true) {
                    initialNetwork = activeNet
                }
            }
        }

        if (initialNetwork != null) {
            networkCallbackReady = true
            callbacks.setLastKnownNetwork(initialNetwork)

            val linkProperties = connectivityManager?.getLinkProperties(initialNetwork)
            val interfaceName = linkProperties?.interfaceName ?: ""
            if (interfaceName.isNotEmpty()) {
                defaultInterfaceName = interfaceName
                val index = try {
                    NetworkInterface.getByName(interfaceName)?.index ?: 0
                } catch (e: Exception) { 0 }
                val caps = connectivityManager?.getNetworkCapabilities(initialNetwork)
                val isExpensive = caps?.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_METERED) == false
                currentInterfaceListener?.updateDefaultInterface(interfaceName, index, isExpensive, false)
            }

            Log.i(TAG, "startDefaultInterfaceMonitor: initialized with network=$initialNetwork, interface=$defaultInterfaceName")
        } else {
            Log.w(TAG, "startDefaultInterfaceMonitor: no usable physical network found at startup")
        }

        // 将 NetworkCallback 注册延迟到 cgo callback 返回之后
        mainHandler.post {
            registerNetworkCallbacksDeferred()
        }
    }

    private fun registerNetworkCallbacksDeferred() {
        if (networkCallback != null) return

        val cm = connectivityManager ?: return

        networkCallback = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) {
                val caps = cm.getNetworkCapabilities(network)
                val isVpn = caps?.hasTransport(NetworkCapabilities.TRANSPORT_VPN) == true
                if (isVpn) return

                val isActiveDefault = cm.activeNetwork == network
                if (isActiveDefault) {
                    networkCallbackReady = true
                    Log.i(TAG, "Network available: $network (active default)")
                    updateDefaultInterface(network)
                }
            }

            override fun onLost(network: Network) {
                Log.i(TAG, "Network lost: $network")
                if (network != callbacks.getLastKnownNetwork()) {
                    return
                }

                val newActive = cm.activeNetwork
                if (newActive != null && newActive != network) {
                    Log.i(TAG, "Switching to new active network: $newActive")
                    updateDefaultInterface(newActive)
                    return
                }

                mainHandler.postDelayed({
                    if (callbacks.getLastKnownNetwork() != network) {
                        return@postDelayed
                    }
                    val delayedActive = cm.activeNetwork
                    if (delayedActive != null && delayedActive != network) {
                        Log.i(TAG, "Delayed switch to new active network: $delayedActive")
                        updateDefaultInterface(delayedActive)
                    } else {
                        Log.i(TAG, "No replacement network after delay, waiting for onAvailable")
                    }
                }, NETWORK_SWITCH_DELAY_MS)
            }

            override fun onCapabilitiesChanged(network: Network, caps: NetworkCapabilities) {
                val isVpn = caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)
                if (isVpn) return

                if (cm.activeNetwork == network) {
                    networkCallbackReady = true
                    updateDefaultInterface(network)
                }
            }
        }

        val request = NetworkRequest.Builder()
            .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
            .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
            .build()

        try {
            cm.registerNetworkCallback(request, networkCallback!!)
        } catch (e: Exception) {
            Log.w(TAG, "Failed to register network callback", e)
        }

        vpnNetworkCallback = object : ConnectivityManager.NetworkCallback() {
            override fun onCapabilitiesChanged(network: Network, caps: NetworkCapabilities) {
                if (!callbacks.isRunning()) return
                val isValidated = caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)
                if (isValidated) {
                    vpnLinkValidated = true
                    if (vpnHealthJob?.isActive == true) {
                        Log.i(TAG, "VPN link validated, cancelling recovery job")
                        vpnHealthJob?.cancel()
                    }
                } else {
                    vpnLinkValidated = false

                    // Captive portal / no internet: do not spam recovery; user action is required.
                    val hasInternet = caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
                    val isCaptivePortal = caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_CAPTIVE_PORTAL)
                    if (!hasInternet || isCaptivePortal) {
                        Log.w(
                            TAG,
                            "VPN link not validated (hasInternet=$hasInternet, " +
                                "captivePortal=$isCaptivePortal), skip recovery"
                        )
                        return
                    }

                    if (vpnHealthJob?.isActive != true) {
                        val now = SystemClock.elapsedRealtime()
                        val last = lastVpnHealthRecoveryAtMs.get()
                        val elapsed = now - last
                        if (elapsed in 0 until vpnHealthRecoveryMinIntervalMs) {
                            Log.w(
                                TAG,
                                "VPN link not validated, skip recovery (throttled, elapsed=${elapsed}ms)"
                            )
                            return
                        }

                        Log.w(TAG, "VPN link not validated, scheduling recovery in 5s")
                        lastVpnHealthRecoveryAtMs.set(now)
                        vpnHealthJob = serviceScope.launch {
                            delay(5000)
                            if (callbacks.isRunning() && !callbacks.isStarting() &&
                                !callbacks.isManuallyStopped() && callbacks.getLastConfigPath() != null) {
                                Log.w(TAG, "VPN link still not validated after 5s, attempting rebind and reset")
                                try {
                                    val bestNetwork = callbacks.findBestPhysicalNetwork()
                                    if (bestNetwork != null && Build.VERSION.SDK_INT >= Build.VERSION_CODES.LOLLIPOP_MR1) {
                                        callbacks.setUnderlyingNetworks(arrayOf(bestNetwork))
                                        callbacks.setLastKnownNetwork(bestNetwork)
                                        Log.i(TAG, "Rebound underlying network to $bestNetwork during health recovery")
                                        com.openworld.app.repository.LogRepository.getInstance()
                                            .addLog("INFO VPN health recovery: rebound to $bestNetwork")
                                    }
                                    callbacks.requestCoreNetworkReset(reason = "vpnHealthRecovery", force = false)
                                } catch (e: Exception) {
                                    Log.e(TAG, "Failed to reset network stack during health recovery", e)
                                }
                            }
                        }
                    }
                }
            }

            override fun onLost(network: Network) {
                vpnHealthJob?.cancel()
            }
        }

        val vpnRequest = NetworkRequest.Builder()
            .addTransportType(NetworkCapabilities.TRANSPORT_VPN)
            .removeCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
            .build()

        try {
            cm.registerNetworkCallback(vpnRequest, vpnNetworkCallback!!)
        } catch (e: Exception) {
            Log.w(TAG, "Failed to register VPN network callback", e)
        }
    }

    override fun closeDefaultInterfaceMonitor(listener: InterfaceUpdateListener?) {
        networkCallback?.let {
            try {
                connectivityManager?.unregisterNetworkCallback(it)
            } catch (_: Exception) {}
        }
        vpnNetworkCallback?.let {
            try {
                connectivityManager?.unregisterNetworkCallback(it)
            } catch (_: Exception) {}
        }
        vpnHealthJob?.cancel()
        postTunRebindJob?.cancel()
        postTunRebindJob = null
        vpnNetworkCallback = null
        networkCallback = null
        currentInterfaceListener = null
        networkCallbackReady = false
        networkSwitchManager.cleanup()
    }

    override fun getInterfaces(): NetworkInterfaceIterator? {
        return try {
            val interfaces = java.util.Collections.list(java.net.NetworkInterface.getNetworkInterfaces())
            object : NetworkInterfaceIterator {
                private val iterator = interfaces.filter { !it.isLoopback }.iterator()

                override fun hasNext(): Boolean = iterator.hasNext()

                override fun next(): io.nekohasekai.libbox.NetworkInterface {
                    val iface = iterator.next()
                    return io.nekohasekai.libbox.NetworkInterface().apply {
                        name = iface.name
                        index = iface.index
                        mtu = iface.mtu

                        var flagsStr = 0
                        if (iface.isUp) flagsStr = flagsStr or 1
                        if (iface.isLoopback) flagsStr = flagsStr or 4
                        if (iface.isPointToPoint) flagsStr = flagsStr or 8
                        if (iface.supportsMulticast()) flagsStr = flagsStr or 16
                        flags = flagsStr

                        val addrList = ArrayList<String>()
                        for (addr in iface.interfaceAddresses) {
                            val ip = addr.address.hostAddress
                            val cleanIp = if (ip != null && ip.contains("%")) ip.substring(0, ip.indexOf("%")) else ip
                            if (cleanIp != null) {
                                addrList.add("$cleanIp/${addr.networkPrefixLength}")
                            }
                        }
                        addresses = StringIteratorImpl(addrList)
                    }
                }
            }
        } catch (e: Exception) {
            Log.e(TAG, "Failed to get interfaces", e)
            null
        }
    }

    override fun underNetworkExtension(): Boolean = false

    override fun includeAllNetworks(): Boolean = false

    override fun readWIFIState(): WIFIState? = null

    override fun clearDNSCache() {}

    override fun sendNotification(notification: io.nekohasekai.libbox.Notification?) {}

    override fun systemCertificates(): StringIterator? = null

    override fun writeLog(message: String?) {
        if (message.isNullOrBlank()) return
        com.openworld.app.repository.LogRepository.getInstance().addLog(message)
    }

    // ========== 内部方法 ==========

    private fun updateDefaultInterface(network: Network) {
        // 委托给 NetworkSwitchManager 处理
        networkSwitchManager.handleNetworkUpdate(network)
    }

    private class StringIteratorImpl(private val list: List<String>) : StringIterator {
        private var index = 0
        override fun hasNext(): Boolean = index < list.size
        override fun next(): String = list[index++]
        override fun len(): Int = list.size
    }
}
