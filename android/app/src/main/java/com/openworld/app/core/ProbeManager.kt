package com.openworld.app.core

import android.content.Context
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.os.Build
import android.util.Log
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
import java.net.InetSocketAddress
import java.net.Socket

/**
 * VPN 链路探测管理器
 *
 * 功能:
 * - 通过 VPN 网络发起 TCP 连接探测
 * - 支持多个探测目标并行探测
 * - 返回结构化的探测结果
 *
 * 使用场景:
 * - 检测 VPN 链路是否正常工作
 * - 诊断网络连接问题
 * - 验证代理节点可达性
 */
object ProbeManager {
    private const val TAG = "ProbeManager"

    /**
     * 默认探测目标列表
     * 使用知名 DNS 服务器的 53 端口作为探测目标
     */
    private val DEFAULT_PROBE_TARGETS = listOf(
        ProbeTarget("1.1.1.1", 53, "Cloudflare DNS"),
        ProbeTarget("8.8.8.8", 53, "Google DNS"),
        ProbeTarget("223.5.5.5", 53, "Alibaba DNS")
    )

    /**
     * 默认超时时间 (毫秒)
     */
    private const val DEFAULT_TIMEOUT_MS = 2000L

    /**
     * 探测目标
     */
    data class ProbeTarget(
        val host: String,
        val port: Int,
        val name: String = "$host:$port"
    )

    /**
     * 探测结果密封类
     */
    sealed class ProbeResult {
        /**
         * 探测成功
         * @param target 探测目标
         * @param latencyMs 延迟时间 (毫秒)
         */
        data class Success(
            val target: ProbeTarget,
            val latencyMs: Long
        ) : ProbeResult()

        /**
         * 探测超时
         * @param target 探测目标
         * @param timeoutMs 超时时间 (毫秒)
         */
        data class Timeout(
            val target: ProbeTarget,
            val timeoutMs: Long
        ) : ProbeResult()

        /**
         * 探测错误
         * @param target 探测目标
         * @param error 错误信息
         * @param exception 异常对象 (可选)
         */
        data class Error(
            val target: ProbeTarget,
            val error: String,
            val exception: Throwable? = null
        ) : ProbeResult()
    }

    /**
     * 批量探测结果
     */
    data class BatchProbeResult(
        val results: List<ProbeResult>,
        val successCount: Int,
        val totalCount: Int,
        val firstSuccessLatencyMs: Long?
    ) {
        val isAnySuccess: Boolean get() = successCount > 0
        val allSuccess: Boolean get() = successCount == totalCount
    }

    /**
     * 通过 VPN 网络探测单个目标
     *
     * @param context Android Context
     * @param target 探测目标
     * @param timeoutMs 超时时间 (毫秒)
     * @return 探测结果
     */
    suspend fun probeViaVpn(
        context: Context,
        target: ProbeTarget = DEFAULT_PROBE_TARGETS.first(),
        timeoutMs: Long = DEFAULT_TIMEOUT_MS
    ): ProbeResult = withContext(Dispatchers.IO) {
        Log.i(TAG, "probeViaVpn: starting probe to ${target.name}")

        val vpnNetwork = findVpnNetwork(context)
        if (vpnNetwork == null) {
            Log.w(TAG, "probeViaVpn: VPN network not found")
            return@withContext ProbeResult.Error(
                target = target,
                error = "VPN network not found"
            )
        }

        Log.d(TAG, "probeViaVpn: found VPN network $vpnNetwork")
        probeTarget(vpnNetwork, target, timeoutMs)
    }

    /**
     * 通过 VPN 网络批量探测多个目标
     *
     * @param context Android Context
     * @param targets 探测目标列表，默认使用内置目标
     * @param timeoutMs 单个探测的超时时间 (毫秒)
     * @return 批量探测结果
     */
    suspend fun probeAllViaVpn(
        context: Context,
        targets: List<ProbeTarget> = DEFAULT_PROBE_TARGETS,
        timeoutMs: Long = DEFAULT_TIMEOUT_MS
    ): BatchProbeResult = withContext(Dispatchers.IO) {
        Log.i(TAG, "probeAllViaVpn: starting batch probe for ${targets.size} targets")

        val vpnNetwork = findVpnNetwork(context)
        if (vpnNetwork == null) {
            Log.w(TAG, "probeAllViaVpn: VPN network not found")
            val errorResults = targets.map { target ->
                ProbeResult.Error(
                    target = target,
                    error = "VPN network not found"
                )
            }
            return@withContext BatchProbeResult(
                results = errorResults,
                successCount = 0,
                totalCount = targets.size,
                firstSuccessLatencyMs = null
            )
        }

        Log.d(TAG, "probeAllViaVpn: found VPN network $vpnNetwork")

        // 并行探测所有目标
        val results = coroutineScope {
            targets.map { target ->
                async {
                    probeTarget(vpnNetwork, target, timeoutMs)
                }
            }.map { it.await() }
        }

        val successResults = results.filterIsInstance<ProbeResult.Success>()
        val firstSuccessLatency = successResults.minByOrNull { it.latencyMs }?.latencyMs

        Log.i(
            TAG,
            "probeAllViaVpn: completed, success=${successResults.size}/${targets.size}, " +
                "firstLatency=${firstSuccessLatency}ms"
        )

        BatchProbeResult(
            results = results,
            successCount = successResults.size,
            totalCount = targets.size,
            firstSuccessLatencyMs = firstSuccessLatency
        )
    }

    /**
     * 快速探测 - 任一目标成功即返回
     *
     * @param context Android Context
     * @param targets 探测目标列表
     * @param timeoutMs 超时时间 (毫秒)
     * @return 第一个成功的结果，或所有失败时返回 null
     */
    suspend fun probeFirstSuccessViaVpn(
        context: Context,
        targets: List<ProbeTarget> = DEFAULT_PROBE_TARGETS,
        timeoutMs: Long = DEFAULT_TIMEOUT_MS
    ): ProbeResult.Success? = withContext(Dispatchers.IO) {
        Log.i(TAG, "probeFirstSuccessViaVpn: starting quick probe (parallel)")

        val vpnNetwork = findVpnNetwork(context)
        if (vpnNetwork == null) {
            Log.w(TAG, "probeFirstSuccessViaVpn: VPN network not found")
            return@withContext null
        }

        // 2026-fix: 并行探测所有目标，任一成功即返回
        // 避免串行探测时前面的目标超时导致整体耗时过长
        val result = coroutineScope {
            val deferred = targets.map { target ->
                async { probeTarget(vpnNetwork, target, timeoutMs) }
            }
            var firstSuccess: ProbeResult.Success? = null
            for (d in deferred) {
                val r = d.await()
                if (r is ProbeResult.Success) {
                    firstSuccess = r
                    // 取消剩余探测
                    deferred.forEach { it.cancel() }
                    break
                }
            }
            firstSuccess
        }

        if (result != null) {
            Log.i(TAG, "probeFirstSuccessViaVpn: success on ${result.target.name}, latency=${result.latencyMs}ms")
        } else {
            Log.w(TAG, "probeFirstSuccessViaVpn: all targets failed")
        }
        result
    }

    /**
     * 检查 VPN 链路是否可用
     *
     * @param context Android Context
     * @param timeoutMs 超时时间 (毫秒)
     * @return true 如果至少一个探测目标可达
     */
    suspend fun isVpnLinkAvailable(
        context: Context,
        timeoutMs: Long = DEFAULT_TIMEOUT_MS
    ): Boolean {
        return probeFirstSuccessViaVpn(context, DEFAULT_PROBE_TARGETS, timeoutMs) != null
    }

    /**
     * 查找 VPN 网络
     *
     * @param context Android Context
     * @return VPN Network 对象，未找到返回 null
     */
    private fun findVpnNetwork(context: Context): Network? {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.M) {
            Log.w(TAG, "findVpnNetwork: API level < 23, not supported")
            return null
        }

        val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager
        if (cm == null) {
            Log.e(TAG, "findVpnNetwork: ConnectivityManager not available")
            return null
        }

        return try {
            @Suppress("DEPRECATION")
            cm.allNetworks.firstOrNull { network ->
                val caps = cm.getNetworkCapabilities(network) ?: return@firstOrNull false
                caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)
            }
        } catch (e: Exception) {
            Log.e(TAG, "findVpnNetwork: failed to enumerate networks", e)
            null
        }
    }

    /**
     * 探测单个目标
     *
     * @param network 要使用的网络 (VPN 网络)
     * @param target 探测目标
     * @param timeoutMs 超时时间 (毫秒)
     * @return 探测结果
     */
    private suspend fun probeTarget(
        network: Network,
        target: ProbeTarget,
        timeoutMs: Long
    ): ProbeResult = withContext(Dispatchers.IO) {
        Log.d(TAG, "probeTarget: probing ${target.name} via network $network")

        val startTime = System.currentTimeMillis()

        val result = withTimeoutOrNull(timeoutMs) {
            try {
                val socket = Socket()
                try {
                    // 将 socket 绑定到 VPN 网络
                    network.bindSocket(socket)
                    Log.d(TAG, "probeTarget: socket bound to VPN network")

                    // 连接到目标
                    socket.connect(
                        InetSocketAddress(target.host, target.port),
                        timeoutMs.toInt()
                    )

                    val latencyMs = System.currentTimeMillis() - startTime
                    Log.i(TAG, "probeTarget: ${target.name} connected, latency=${latencyMs}ms")

                    ProbeResult.Success(target, latencyMs)
                } finally {
                    runCatching { socket.close() }
                }
            } catch (e: Exception) {
                val elapsed = System.currentTimeMillis() - startTime
                Log.w(TAG, "probeTarget: ${target.name} failed after ${elapsed}ms: ${e.message}")

                ProbeResult.Error(
                    target = target,
                    error = e.message ?: "Unknown error",
                    exception = e
                )
            }
        }

        if (result == null) {
            Log.w(TAG, "probeTarget: ${target.name} timed out after ${timeoutMs}ms")
            ProbeResult.Timeout(target, timeoutMs)
        } else {
            result
        }
    }

    /**
     * 获取默认探测目标列表
     */
    fun getDefaultTargets(): List<ProbeTarget> = DEFAULT_PROBE_TARGETS.toList()

    /**
     * 创建自定义探测目标
     */
    fun createTarget(host: String, port: Int, name: String? = null): ProbeTarget {
        return ProbeTarget(host, port, name ?: "$host:$port")
    }
}
