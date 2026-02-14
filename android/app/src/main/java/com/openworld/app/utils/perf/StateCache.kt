package com.openworld.app.utils.perf

import android.net.Network
import android.os.SystemClock
import android.util.Log
import java.util.concurrent.atomic.AtomicLong
import java.util.concurrent.atomic.AtomicReference

/**
 * 状态缓存
 * 缓存频繁访问的状态，减少 IPC 调用
 */
object StateCache {
    private const val TAG = "StateCache"

    // 网络状态缓存
    private val cachedNetwork = AtomicReference<NetworkCache?>(null)
    private val networkCacheTtlMs = 5000L // 5秒缓存有效期

    // VPN 状态缓存
    private val cachedVpnState = AtomicReference<VpnStateCache?>(null)
    private val vpnStateCacheTtlMs = 1000L // 1秒缓存有效期

    // 设置缓存
    private val cachedSettings = AtomicReference<SettingsCache?>(null)
    private val settingsCacheTtlMs = 10000L // 10秒缓存有效期

    // IPC 统计
    private val ipcSavedCount = AtomicLong(0)
    private val ipcTotalCount = AtomicLong(0)

    data class NetworkCache(
        val network: Network?,
        val isValid: Boolean,
        val timestampMs: Long
    )

    data class VpnStateCache(
        val isRunning: Boolean,
        val isConnecting: Boolean,
        val activeNode: String?,
        val timestampMs: Long
    )

    data class SettingsCache(
        val data: Any?,
        val timestampMs: Long
    )

    /**
     * 获取缓存的网络，如果缓存有效则返回缓存值
     * @param fetcher 当缓存无效时获取新值的函数
     * @return 网络对象
     */
    fun getNetwork(fetcher: () -> Network?): Network? {
        ipcTotalCount.incrementAndGet()

        val cached = cachedNetwork.get()
        val now = SystemClock.elapsedRealtime()

        if (cached != null && cached.isValid && (now - cached.timestampMs) < networkCacheTtlMs) {
            ipcSavedCount.incrementAndGet()
            return cached.network
        }

        val network = fetcher()
        cachedNetwork.set(NetworkCache(network, network != null, now))
        return network
    }

    /**
     * 更新网络缓存
     */
    fun updateNetworkCache(network: Network?) {
        cachedNetwork.set(NetworkCache(
            network = network,
            isValid = network != null,
            timestampMs = SystemClock.elapsedRealtime()
        ))
    }

    /**
     * 使网络缓存失效
     */
    fun invalidateNetworkCache() {
        cachedNetwork.set(null)
    }

    /**
     * 获取缓存的 VPN 状态
     * @param fetcher 当缓存无效时获取新值的函数
     */
    fun getVpnState(fetcher: () -> VpnStateCache): VpnStateCache {
        ipcTotalCount.incrementAndGet()

        val cached = cachedVpnState.get()
        val now = SystemClock.elapsedRealtime()

        if (cached != null && (now - cached.timestampMs) < vpnStateCacheTtlMs) {
            ipcSavedCount.incrementAndGet()
            return cached
        }

        val state = fetcher()
        cachedVpnState.set(state.copy(timestampMs = now))
        return state
    }

    /**
     * 更新 VPN 状态缓存
     */
    fun updateVpnState(isRunning: Boolean, isConnecting: Boolean, activeNode: String?) {
        cachedVpnState.set(VpnStateCache(
            isRunning = isRunning,
            isConnecting = isConnecting,
            activeNode = activeNode,
            timestampMs = SystemClock.elapsedRealtime()
        ))
    }

    /**
     * 使 VPN 状态缓存失效
     */
    fun invalidateVpnState() {
        cachedVpnState.set(null)
    }

    /**
     * 获取缓存的设置
     * @param fetcher 当缓存无效时获取新值的函数
     */
    @Suppress("UNCHECKED_CAST")
    fun <T> getSettings(fetcher: () -> T): T {
        ipcTotalCount.incrementAndGet()

        val cached = cachedSettings.get()
        val now = SystemClock.elapsedRealtime()

        if (cached != null && cached.data != null && (now - cached.timestampMs) < settingsCacheTtlMs) {
            ipcSavedCount.incrementAndGet()
            return cached.data as T
        }

        val settings = fetcher()
        cachedSettings.set(SettingsCache(settings, now))
        return settings
    }

    /**
     * 使设置缓存失效
     */
    fun invalidateSettings() {
        cachedSettings.set(null)
    }

    /**
     * 清除所有缓存
     */
    fun clearAll() {
        cachedNetwork.set(null)
        cachedVpnState.set(null)
        cachedSettings.set(null)
    }

    /**
     * 获取 IPC 节省统计
     * @return Pair<savedCount, totalCount>
     */
    fun getIpcStats(): Pair<Long, Long> {
        return Pair(ipcSavedCount.get(), ipcTotalCount.get())
    }

    /**
     * 获取 IPC 节省百分比
     */
    fun getIpcSavedPercent(): Int {
        val total = ipcTotalCount.get()
        if (total == 0L) return 0
        return ((ipcSavedCount.get() * 100) / total).toInt()
    }

    /**
     * 打印缓存统计
     */
    fun logStats() {
        val (saved, total) = getIpcStats()
        val percent = getIpcSavedPercent()
        Log.i(TAG, "IPC Stats: saved=$saved, total=$total, saved_percent=$percent%")
    }

    /**
     * 重置统计
     */
    fun resetStats() {
        ipcSavedCount.set(0)
        ipcTotalCount.set(0)
    }
}
