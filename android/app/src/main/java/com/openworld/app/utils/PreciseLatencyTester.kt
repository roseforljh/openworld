package com.openworld.app.utils

import android.util.Log
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.Call
import okhttp3.EventListener
import okhttp3.OkHttpClient
import okhttp3.Protocol
import okhttp3.Request
import java.io.IOException
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Proxy
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicLong

/**
 * 精确延迟测试�? *
 * 使用 OkHttp EventListener 精确测量各阶段耗时�? * - RTT: �?TLS 握手完成到收到首字节的时间（排除连接建立开销�? * - Handshake: TLS 握手时间
 * - Total: 完整请求时间
 *
 * 相比简单的 System.nanoTime() 测量，此方案�? * 1. 更精确：排除了本地代理连接开销
 * 2. 更稳定：预热请求消除首次连接抖动
 * 3. 更灵活：支持多种测量标准
 */
object PreciseLatencyTester {
    private const val TAG = "PreciseLatencyTester"

    /**
     * 测量标准
     */
    enum class Standard {
        /** RTT: 从握手完成到收到首字节（推荐，最接近真实延迟�?*/
        RTT,
        /** Handshake: TLS 握手时间 */
        HANDSHAKE,
        /** FirstByte: 从请求开始到收到首字�?*/
        FIRST_BYTE,
        /** Total: 完整请求时间（包含连接建立） */
        TOTAL
    }

    /**
     * 延迟测试结果
     */
    data class LatencyResult(
        val latencyMs: Long,
        val dnsTimeMs: Long = 0,
        val connectTimeMs: Long = 0,
        val tlsHandshakeMs: Long = 0,
        val firstByteMs: Long = 0,
        val totalMs: Long = 0
    ) {
        val isSuccess: Boolean get() = latencyMs >= 0
    }

    /**
     * 精确延迟测试
     *
     * @param proxyPort 本地代理端口
     * @param url 测试 URL
     * @param timeoutMs 超时时间（毫秒）
     * @param standard 测量标准
     * @param warmup 是否预热（首次请求不计入结果�?     */
    suspend fun test(
        proxyPort: Int,
        url: String,
        timeoutMs: Int,
        standard: Standard = Standard.RTT,
        warmup: Boolean = true
    ): LatencyResult = withContext(Dispatchers.IO) {
        val timingListener = TimingEventListener()

        val client = OkHttpClient.Builder()
            .proxy(Proxy(Proxy.Type.HTTP, InetSocketAddress("127.0.0.1", proxyPort)))
            .connectTimeout(1000L, TimeUnit.MILLISECONDS)
            .readTimeout(timeoutMs.toLong(), TimeUnit.MILLISECONDS)
            .writeTimeout(timeoutMs.toLong(), TimeUnit.MILLISECONDS)
            .callTimeout(timeoutMs.toLong(), TimeUnit.MILLISECONDS)
            .eventListener(timingListener)
            // 关键：根据测量标准决定是否禁�?Keep-Alive
            .apply {
                if (standard == Standard.HANDSHAKE) {
                    // 测量握手时间时禁用连接复用，确保每次都执行握�?                    connectionPool(okhttp3.ConnectionPool(0, 1, TimeUnit.MILLISECONDS))
                }
            }
            .followRedirects(false) // 不跟随重定向
            .build()

        try {
            val request = Request.Builder()
                .url(url)
                .get()
                .build()

            // 预热请求（可选）
            if (warmup) {
                try {
                    timingListener.reset()
                    client.newCall(request).execute().use { resp ->
                        resp.body?.close()
                    }
                } catch (e: Exception) {
                    // 预热失败不影响正式测�?                    Log.d(TAG, "Warmup request failed: ${e.message}")
                }
            }

            // 正式测试
            timingListener.reset()
            val response = client.newCall(request).execute()
            response.use { resp ->
                if (resp.code >= 400) {
                    return@withContext LatencyResult(-1L)
                }
                resp.body?.close()
            }

            // 根据测量标准计算延迟
            val latency = when (standard) {
                Standard.RTT -> {
                    // RTT: 从握手完成到收到首字�?                    val handshakeEnd = timingListener.secureConnectEnd.get()
                        .takeIf { it > 0 } ?: timingListener.connectEnd.get()
                    val firstByte = timingListener.responseHeadersStart.get()
                    if (handshakeEnd > 0 && firstByte > handshakeEnd) {
                        firstByte - handshakeEnd
                    } else {
                        // 回退�?Total 测量
                        timingListener.callEnd.get() - timingListener.callStart.get()
                    }
                }
                Standard.HANDSHAKE -> {
                    // TLS 握手时间
                    val start = timingListener.secureConnectStart.get()
                    val end = timingListener.secureConnectEnd.get()
                    if (start > 0 && end > start) {
                        end - start
                    } else {
                        // HTTP 连接（无 TLS），返回 TCP 连接时间
                        timingListener.connectEnd.get() - timingListener.connectStart.get()
                    }
                }
                Standard.FIRST_BYTE -> {
                    // 从请求开始到收到首字�?                    timingListener.responseHeadersStart.get() - timingListener.callStart.get()
                }
                Standard.TOTAL -> {
                    // 完整请求时间
                    timingListener.callEnd.get() - timingListener.callStart.get()
                }
            }

            // 构建详细结果
            LatencyResult(
                latencyMs = latency.coerceAtLeast(0),
                dnsTimeMs = (timingListener.dnsEnd.get() - timingListener.dnsStart.get()).coerceAtLeast(0),
                connectTimeMs = (timingListener.connectEnd.get() - timingListener.connectStart.get()).coerceAtLeast(0),
                tlsHandshakeMs = (timingListener.secureConnectEnd.get() - timingListener.secureConnectStart.get()).coerceAtLeast(0),
                firstByteMs = (timingListener.responseHeadersStart.get() - timingListener.callStart.get()).coerceAtLeast(0),
                totalMs = (timingListener.callEnd.get() - timingListener.callStart.get()).coerceAtLeast(0)
            )
        } catch (e: Exception) {
            Log.w(TAG, "Latency test failed: ${e.message}")
            LatencyResult(-1L)
        } finally {
            client.connectionPool.evictAll()
            client.dispatcher.executorService.shutdown()
        }
    }

    /**
     * 简化版延迟测试（兼容现有接口）
     */
    suspend fun testSimple(
        proxyPort: Int,
        url: String,
        timeoutMs: Int
    ): Long {
        val result = test(proxyPort, url, timeoutMs, Standard.RTT, warmup = false)
        return if (result.isSuccess) result.latencyMs else -1L
    }

    /**
     * 事件监听�?- 记录各阶段时间戳
     */
    private class TimingEventListener : EventListener() {
        val callStart = AtomicLong(0)
        val callEnd = AtomicLong(0)
        val dnsStart = AtomicLong(0)
        val dnsEnd = AtomicLong(0)
        val connectStart = AtomicLong(0)
        val connectEnd = AtomicLong(0)
        val secureConnectStart = AtomicLong(0)
        val secureConnectEnd = AtomicLong(0)
        val requestHeadersStart = AtomicLong(0)
        val requestHeadersEnd = AtomicLong(0)
        val responseHeadersStart = AtomicLong(0)
        val responseHeadersEnd = AtomicLong(0)

        fun reset() {
            callStart.set(0)
            callEnd.set(0)
            dnsStart.set(0)
            dnsEnd.set(0)
            connectStart.set(0)
            connectEnd.set(0)
            secureConnectStart.set(0)
            secureConnectEnd.set(0)
            requestHeadersStart.set(0)
            requestHeadersEnd.set(0)
            responseHeadersStart.set(0)
            responseHeadersEnd.set(0)
        }

        private fun now(): Long = System.currentTimeMillis()

        override fun callStart(call: Call) {
            callStart.set(now())
        }

        override fun callEnd(call: Call) {
            callEnd.set(now())
        }

        override fun callFailed(call: Call, ioe: IOException) {
            callEnd.set(now())
        }

        override fun dnsStart(call: Call, domainName: String) {
            dnsStart.set(now())
        }

        override fun dnsEnd(call: Call, domainName: String, inetAddressList: List<InetAddress>) {
            dnsEnd.set(now())
        }

        override fun connectStart(call: Call, inetSocketAddress: InetSocketAddress, proxy: Proxy) {
            connectStart.set(now())
        }

        override fun connectEnd(call: Call, inetSocketAddress: InetSocketAddress, proxy: Proxy, protocol: Protocol?) {
            connectEnd.set(now())
        }

        override fun connectFailed(call: Call, inetSocketAddress: InetSocketAddress, proxy: Proxy, protocol: Protocol?, ioe: IOException) {
            connectEnd.set(now())
        }

        override fun secureConnectStart(call: Call) {
            secureConnectStart.set(now())
        }

        override fun secureConnectEnd(call: Call, handshake: okhttp3.Handshake?) {
            secureConnectEnd.set(now())
        }

        override fun requestHeadersStart(call: Call) {
            requestHeadersStart.set(now())
        }

        override fun requestHeadersEnd(call: Call, request: Request) {
            requestHeadersEnd.set(now())
        }

        override fun responseHeadersStart(call: Call) {
            responseHeadersStart.set(now())
        }

        override fun responseHeadersEnd(call: Call, response: okhttp3.Response) {
            responseHeadersEnd.set(now())
        }
    }
}







