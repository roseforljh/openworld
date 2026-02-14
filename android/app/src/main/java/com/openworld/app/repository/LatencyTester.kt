package com.openworld.app.repository

import android.content.Context
import android.util.Log
import com.openworld.app.R
import com.openworld.app.core.OpenWorldCore
import com.openworld.app.model.Outbound
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.util.concurrent.ConcurrentHashMap

/**
 * 延迟测试�?- 负责节点延迟测试
 *
 * 功能:
 * - 单节点延迟测试（带去重）
 * - 批量节点延迟测试
 * - 延迟结果缓存
 */
class LatencyTester(
    private val context: Context,
    private val singBoxCore: OpenWorldCore
) {
    companion object {
        private const val TAG = "LatencyTester"
    }

    // 正在进行的延迟测试（用于去重�?    private val inFlightTests = ConcurrentHashMap<String, CompletableDeferred<Long>>()

    /**
     * 测试单个节点的延�?     *
     * @param nodeId 节点 ID
     * @param outbound 节点出站配置
     * @param onResult 结果回调（用于更�?UI 状态）
     * @return 延迟时间（毫秒）�?1 表示测试失败
     */
    suspend fun testNode(
        nodeId: String,
        outbound: Outbound,
        allOutbounds: List<Outbound> = emptyList(),
        onResult: ((Long) -> Unit)? = null
    ): Long {
        // 检查是否已有相同测试在进行
        val existing = inFlightTests[nodeId]
        if (existing != null) {
            return existing.await()
        }

        val deferred = CompletableDeferred<Long>()
        val prev = inFlightTests.putIfAbsent(nodeId, deferred)
        if (prev != null) {
            return prev.await()
        }

        try {
            val result = withContext(Dispatchers.IO) {
                try {
                    val latency = singBoxCore.testOutboundLatency(outbound, allOutbounds)
                    onResult?.invoke(latency)
                    latency
                } catch (e: Exception) {
                    if (e is kotlinx.coroutines.CancellationException) {
                        -1L
                    } else {
                        Log.e(TAG, "Latency test error for $nodeId", e)
                        LogRepository.getInstance().addLog(
                            context.getString(R.string.nodes_test_failed, outbound.tag) + ": ${e.message}"
                        )
                        -1L
                    }
                }
            }
            deferred.complete(result)
            return result
        } catch (e: Exception) {
            deferred.complete(-1L)
            return -1L
        } finally {
            inFlightTests.remove(nodeId, deferred)
        }
    }

    /**
     * 批量测试节点延迟
     *
     * @param outbounds 要测试的出站配置列表
     * @param onNodeComplete 单个节点完成回调 (tag, latency)
     */
    suspend fun testBatch(
        outbounds: List<Outbound>,
        onNodeComplete: ((String, Long) -> Unit)? = null
    ) = withContext(Dispatchers.IO) {
        if (outbounds.isEmpty()) {
            Log.w(TAG, "No outbounds to test")
            return@withContext
        }

        singBoxCore.testOutboundsLatency(outbounds) { tag, latency ->
            val latencyValue = if (latency > 0) latency else -1L
            onNodeComplete?.invoke(tag, latencyValue)
        }
    }

    /**
     * 取消所有正在进行的测试
     */
    fun cancelAll() {
        inFlightTests.values.forEach { deferred ->
            if (!deferred.isCompleted) {
                deferred.complete(-1L)
            }
        }
        inFlightTests.clear()
    }

    /**
     * 检查是否有测试正在进行
     */
    fun isTestingNode(nodeId: String): Boolean {
        return inFlightTests.containsKey(nodeId)
    }

    /**
     * 获取正在测试的节点数�?     */
    fun getActiveTestCount(): Int {
        return inFlightTests.size
    }
}







