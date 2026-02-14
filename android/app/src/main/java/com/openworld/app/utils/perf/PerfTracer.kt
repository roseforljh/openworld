package com.openworld.app.utils.perf

import android.os.SystemClock
import android.util.Log
import java.util.concurrent.ConcurrentHashMap

/**
 * 性能追踪器
 * 用于测量和记录各个操作的耗时
 */
object PerfTracer {
    private const val TAG = "PerfTracer"

    // 活跃的追踪任务
    private val activeTraces = ConcurrentHashMap<String, TraceInfo>()

    // 历史统计数据
    private val stats = ConcurrentHashMap<String, TraceStats>()

    data class TraceInfo(
        val name: String,
        val startTimeMs: Long,
        val parent: String? = null
    )

    data class TraceStats(
        val name: String,
        var count: Int = 0,
        var totalMs: Long = 0L,
        var minMs: Long = Long.MAX_VALUE,
        var maxMs: Long = 0L
    ) {
        val avgMs: Long get() = if (count > 0) totalMs / count else 0L
    }

    /**
     * 开始追踪
     * @param name 追踪名称
     * @param parent 父追踪名称（可选）
     */
    fun begin(name: String, parent: String? = null) {
        activeTraces[name] = TraceInfo(
            name = name,
            startTimeMs = SystemClock.elapsedRealtime(),
            parent = parent
        )
    }

    /**
     * 结束追踪并记录耗时
     * @param name 追踪名称
     * @return 耗时毫秒数，如果未找到对应的开始则返回 -1
     */
    fun end(name: String): Long {
        val trace = activeTraces.remove(name) ?: return -1
        val durationMs = SystemClock.elapsedRealtime() - trace.startTimeMs

        // 更新统计
        stats.compute(name) { _, existing ->
            (existing ?: TraceStats(name)).apply {
                count++
                totalMs += durationMs
                if (durationMs < minMs) minMs = durationMs
                if (durationMs > maxMs) maxMs = durationMs
            }
        }

        // 记录日志
        val parentInfo = trace.parent?.let { " (parent: $it)" } ?: ""
        Log.d(TAG, "[$name] completed in ${durationMs}ms$parentInfo")

        return durationMs
    }

    /**
     * 测量代码块执行时间
     * @param name 追踪名称
     * @param block 要测量的代码块
     * @return 代码块的返回值
     */
    inline fun <T> trace(name: String, block: () -> T): T {
        begin(name)
        return try {
            block()
        } finally {
            end(name)
        }
    }

    /**
     * 测量挂起代码块执行时间
     * @param name 追踪名称
     * @param block 要测量的挂起代码块
     * @return 代码块的返回值
     */
    suspend inline fun <T> traceSuspend(name: String, block: () -> T): T {
        begin(name)
        return try {
            block()
        } finally {
            end(name)
        }
    }

    /**
     * 获取指定操作的统计信息
     */
    fun getStats(name: String): TraceStats? = stats[name]

    /**
     * 获取所有统计信息
     */
    fun getAllStats(): Map<String, TraceStats> = stats.toMap()

    /**
     * 打印所有统计信息到日志
     */
    fun logStats() {
        if (stats.isEmpty()) {
            Log.i(TAG, "No performance stats recorded")
            return
        }

        val sb = StringBuilder("\n=== Performance Stats ===\n")
        stats.values.sortedByDescending { it.avgMs }.forEach { stat ->
            sb.append("${stat.name}: avg=${stat.avgMs}ms, ")
            sb.append("min=${stat.minMs}ms, max=${stat.maxMs}ms, ")
            sb.append("count=${stat.count}\n")
        }
        sb.append("========================")
        Log.i(TAG, sb.toString())
    }

    /**
     * 清除所有统计数据
     */
    fun clearStats() {
        stats.clear()
        activeTraces.clear()
    }

    /**
     * VPN 启动阶段追踪常量
     */
    object Phases {
        const val VPN_STARTUP = "vpn_startup"
        const val PARALLEL_INIT = "parallel_init"
        const val NETWORK_WAIT = "network_wait"
        const val RULESET_CHECK = "ruleset_check"
        const val SETTINGS_LOAD = "settings_load"
        const val CONFIG_LOAD = "config_load"
        const val LIBBOX_START = "libbox_start"
        const val TUN_CREATE = "tun_create"
        const val VPN_VALIDATE = "vpn_validate"
        const val CORE_READY = "core_ready"
        const val DNS_PREWARM = "dns_prewarm"
    }
}
