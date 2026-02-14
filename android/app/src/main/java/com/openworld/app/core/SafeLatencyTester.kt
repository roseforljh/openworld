package com.openworld.app.core

import android.util.Log
import com.openworld.app.model.Outbound
import com.openworld.app.service.SingBoxService
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.withTimeoutOrNull
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong

/**
 * 安全延迟测试器 - 保护主网络连接不受测试影响
 *
 * v1.12.20 适配:
 * - 使用 CommandClient.urlTest(groupTag) 触发整组测试
 * - 通过 CommandManager.urlTestGroup() 获取结果
 * - 不再支持单节点测试，改为整组测试
 */
@Suppress("TooManyFunctions")
class SafeLatencyTester private constructor() {

    companion object {
        private const val TAG = "SafeLatencyTester"

        // 默认 group 标签
        private const val DEFAULT_GROUP_TAG = "PROXY"

        // 测试超时
        private const val URL_TEST_TIMEOUT_MS = 15000L

        // 熔断参数
        private const val CIRCUIT_BREAKER_THRESHOLD = 3
        private const val CIRCUIT_BREAKER_COOLDOWN_MS = 10000L

        /** v1.12.20 中不再使用并发测试，保留兼容 */
        const val DEFAULT_CONCURRENCY = 1

        @Volatile
        private var instance: SafeLatencyTester? = null

        fun getInstance(): SafeLatencyTester {
            return instance ?: synchronized(this) {
                instance ?: SafeLatencyTester().also { instance = it }
            }
        }
    }

    // 状态追踪
    private val isTestingActive = AtomicBoolean(false)
    private val consecutiveFailures = AtomicInteger(0)
    private val lastCircuitBreakerTrip = AtomicLong(0)

    // 主连接保护
    private var guardJob: Job? = null

    /**
     * 安全的批量延迟测试
     * v1.12.20: 使用 CommandClient.urlTest(groupTag) 触发整组测试
     *
     * @param outbounds 待测试的节点列表
     * @param targetUrl 测试 URL (v1.12.20 中忽略，使用配置中的 URL)
     * @param timeoutMs 超时时间
     * @param onResult 每个节点测试完成的回调
     */
    @Suppress("UNUSED_PARAMETER")
    suspend fun testOutboundsLatencySafe(
        outbounds: List<Outbound>,
        targetUrl: String,
        timeoutMs: Int,
        onResult: (tag: String, latency: Long) -> Unit
    ) {
        if (outbounds.isEmpty()) return

        if (isCircuitBreakerOpen()) {
            Log.w(TAG, "Circuit breaker is open, skipping test")
            outbounds.forEach { onResult(it.tag, -1L) }
            return
        }

        if (!isTestingActive.compareAndSet(false, true)) {
            Log.w(TAG, "Another test is in progress, skipping")
            outbounds.forEach { onResult(it.tag, -1L) }
            return
        }

        try {
            Log.i(TAG, "Starting URL test for ${outbounds.size} nodes via group API")

            // 触发整组测试并获取结果
            val results = triggerGroupUrlTest(DEFAULT_GROUP_TAG)

            if (results.isEmpty()) {
                Log.w(TAG, "URL test returned no results, marking all as failed")
                handleTestFailure()
                outbounds.forEach { onResult(it.tag, -1L) }
                return
            }

            // 重置失败计数
            consecutiveFailures.set(0)

            // 返回结果
            var successCount = 0
            outbounds.forEach { outbound ->
                val delay = results[outbound.tag]
                if (delay != null && delay > 0) {
                    onResult(outbound.tag, delay.toLong())
                    successCount++
                } else {
                    onResult(outbound.tag, -1L)
                }
            }

            Log.i(TAG, "URL test completed: $successCount/${outbounds.size} succeeded")
        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            Log.e(TAG, "URL test failed: ${e.message}")
            handleTestFailure()
            outbounds.forEach { onResult(it.tag, -1L) }
        } finally {
            isTestingActive.set(false)
        }
    }

    /**
     * 触发 Group URL 测试
     * 使用 CommandManager.urlTestGroup() API
     */
    private suspend fun triggerGroupUrlTest(groupTag: String): Map<String, Int> {
        val service = SingBoxService.instance
        if (service == null) {
            Log.w(TAG, "SingBoxService not available")
            return emptyMap()
        }

        return try {
            withTimeoutOrNull(URL_TEST_TIMEOUT_MS) {
                service.urlTestGroup(groupTag, URL_TEST_TIMEOUT_MS)
            } ?: run {
                Log.w(TAG, "URL test timeout for group: $groupTag")
                emptyMap()
            }
        } catch (e: Exception) {
            Log.e(TAG, "URL test error: ${e.message}")
            emptyMap()
        }
    }

    /**
     * 处理测试失败
     */
    private fun handleTestFailure() {
        val failures = consecutiveFailures.incrementAndGet()
        if (failures >= CIRCUIT_BREAKER_THRESHOLD) {
            tripCircuitBreaker()
        }
    }

    /**
     * 检查熔断器状态
     */
    private fun isCircuitBreakerOpen(): Boolean {
        val lastTrip = lastCircuitBreakerTrip.get()
        if (lastTrip == 0L) return false

        val elapsed = System.currentTimeMillis() - lastTrip
        return elapsed < CIRCUIT_BREAKER_COOLDOWN_MS
    }

    /**
     * 触发熔断
     */
    private fun tripCircuitBreaker() {
        lastCircuitBreakerTrip.set(System.currentTimeMillis())
        Log.e(TAG, "Circuit breaker tripped! Cooling down for ${CIRCUIT_BREAKER_COOLDOWN_MS}ms")
    }

    /**
     * 取消当前测试
     */
    fun cancelTest() {
        guardJob?.cancel()
        guardJob = null
    }

    /**
     * 检查是否正在测试
     */
    fun isTesting(): Boolean = isTestingActive.get()
}
