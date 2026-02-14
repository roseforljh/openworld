package com.openworld.app.utils

import android.content.Context
import android.util.Log
import com.openworld.app.core.BoxWrapperManager
import com.openworld.app.ipc.VpnStateStore
import com.openworld.app.repository.SettingsRepository
import io.nekohasekai.libbox.Libbox
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.withContext

/**
 * 内核级 HTTP 客户端
 *
 * v1.12.20: 使用 Libbox.newHTTPClient() API 通过本地 SOCKS5 代理发起请求
 *
 * 使用场景:
 * - 订阅更新 (需要翻墙的订阅源)
 * - 规则集下载
 * - 任何需要走代理的 HTTP 请求
 */
object KernelHttpClient {
    private const val TAG = "KernelHttpClient"

    // 默认超时 30 秒
    private const val DEFAULT_TIMEOUT_MS = 30000

    // 默认代理端口
    private const val DEFAULT_PROXY_PORT = 2080

    // 缓存的代理端口 (避免频繁读取设置)
    @Volatile
    private var cachedProxyPort: Int = DEFAULT_PROXY_PORT

    /**
     * Fetch 结果封装
     */
    data class HttpResult(
        val success: Boolean,
        val statusCode: Int,
        val body: String,
        val error: String?
    ) {
        val isOk: Boolean get() = success && statusCode in 200..299

        companion object {
            fun error(message: String): HttpResult {
                return HttpResult(false, 0, "", message)
            }
        }
    }

    /**
     * 更新缓存的代理端口
     * 在 VPN 启动时调用，避免运行时频繁读取设置
     */
    fun updateProxyPort(port: Int) {
        cachedProxyPort = port
        Log.d(TAG, "Proxy port updated to $port")
    }

    /**
     * 从 Context 更新代理端口
     */
    suspend fun updateProxyPortFromSettings(context: Context) {
        try {
            val settings = SettingsRepository.getInstance(context).settings.first()
            cachedProxyPort = settings.proxyPort
            Log.d(TAG, "Proxy port loaded from settings: $cachedProxyPort")
        } catch (e: Exception) {
            Log.w(TAG, "Failed to load proxy port from settings: ${e.message}")
        }
    }

    /**
     * 获取当前代理端口
     */
    fun getProxyPort(): Int = cachedProxyPort

    /**
     * 使用运行中的 VPN 服务发起请求
     * v1.12.20: 使用 Libbox.newHTTPClient() 通过本地 SOCKS5 代理
     *
     * @param url 请求 URL
     * @param outboundTag 使用的出站标签 (已忽略，v1.12.20 不支持指定出站)
     * @param timeoutMs 超时时间 (毫秒)
     * @return HttpResult
     */
    @Suppress("UNUSED_PARAMETER")
    suspend fun fetch(
        url: String,
        outboundTag: String = "proxy",
        timeoutMs: Int = DEFAULT_TIMEOUT_MS
    ): HttpResult = withContext(Dispatchers.IO) {
        // 优先尝试内核 HTTP 客户端
        if (isKernelFetchAvailable()) {
            val kernelResult = fetchViaKernel(url)
            if (kernelResult.success) {
                return@withContext kernelResult
            }
            Log.w(TAG, "Kernel fetch failed, falling back to OkHttp: ${kernelResult.error}")
        }

        // 回退到 OkHttp
        Log.d(TAG, "fetch: $url (using OkHttp)")
        fetchWithOkHttp(url, timeoutMs)
    }

    /**
     * 使用运行中的 VPN 服务发起请求 (带自定义 Headers)
     * v1.12.20: 使用 Libbox.newHTTPClient() 支持自定义 Headers
     *
     * @param url 请求 URL
     * @param headers 请求头 Map
     * @param outboundTag 使用的出站标签
     * @param timeoutMs 超时时间 (毫秒)
     * @return HttpResult
     */
    @Suppress("UNUSED_PARAMETER")
    suspend fun fetchWithHeaders(
        url: String,
        headers: Map<String, String>,
        outboundTag: String = "proxy",
        timeoutMs: Int = DEFAULT_TIMEOUT_MS
    ): HttpResult = withContext(Dispatchers.IO) {
        // 优先尝试内核 HTTP 客户端
        if (isKernelFetchAvailable()) {
            val kernelResult = fetchViaKernel(url, headers)
            if (kernelResult.success) {
                return@withContext kernelResult
            }
            Log.w(TAG, "Kernel fetch with headers failed, falling back to OkHttp: ${kernelResult.error}")
        }

        // 回退到 OkHttp
        Log.d(TAG, "fetchWithHeaders: $url (using OkHttp)")
        fetchWithOkHttpAndHeaders(url, headers, timeoutMs)
    }

    /**
     * 智能请求 - 自动选择最佳方式
     * v1.12.20: VPN 运行时优先使用内核 HTTP 客户端
     *
     * @param url 请求 URL
     * @param preferKernel 是否优先使用内核
     * @param timeoutMs 超时时间
     * @return HttpResult
     */
    @Suppress("UNUSED_PARAMETER")
    suspend fun smartFetch(
        url: String,
        preferKernel: Boolean = true,
        timeoutMs: Int = DEFAULT_TIMEOUT_MS
    ): HttpResult = withContext(Dispatchers.IO) {
        // 如果优先使用内核且内核可用，尝试内核请求
        if (preferKernel && isKernelFetchAvailable()) {
            val kernelResult = fetchViaKernel(url)
            if (kernelResult.success) {
                return@withContext kernelResult
            }
            Log.w(TAG, "smartFetch kernel failed, falling back to OkHttp: ${kernelResult.error}")
        }

        // 回退到 OkHttp
        fetchWithOkHttp(url, timeoutMs)
    }

    /**
     * 使用 OkHttp 发起请求
     */
    private fun fetchWithOkHttp(url: String, timeoutMs: Int): HttpResult {
        return try {
            val client = NetworkClient.createClientWithTimeout(
                connectTimeoutSeconds = (timeoutMs / 1000).toLong(),
                readTimeoutSeconds = (timeoutMs / 1000).toLong()
            )

            val request = okhttp3.Request.Builder()
                .url(url)
                .header("User-Agent", "OpenWorld/1.0")
                .build()

            val response = client.newCall(request).execute()
            val body = response.body?.string() ?: ""

            HttpResult(
                success = true,
                statusCode = response.code,
                body = body,
                error = null
            )
        } catch (e: Exception) {
            Log.e(TAG, "OkHttp fetch error: ${e.message}")
            HttpResult.error("OkHttp error: ${e.message}")
        }
    }

    /**
     * 使用 OkHttp 发起带 Headers 的请求
     */
    private fun fetchWithOkHttpAndHeaders(
        url: String,
        headers: Map<String, String>,
        timeoutMs: Int
    ): HttpResult {
        return try {
            val client = NetworkClient.createClientWithTimeout(
                connectTimeoutSeconds = (timeoutMs / 1000).toLong(),
                readTimeoutSeconds = (timeoutMs / 1000).toLong()
            )

            val requestBuilder = okhttp3.Request.Builder()
                .url(url)
                .header("User-Agent", "OpenWorld/1.0")

            headers.forEach { (key, value) ->
                requestBuilder.header(key, value)
            }

            val response = client.newCall(requestBuilder.build()).execute()
            val body = response.body?.string() ?: ""

            HttpResult(
                success = true,
                statusCode = response.code,
                body = body,
                error = null
            )
        } catch (e: Exception) {
            Log.e(TAG, "OkHttp fetch with headers error: ${e.message}")
            HttpResult.error("OkHttp error: ${e.message}")
        }
    }

    /**
     * 使用内核 HTTP 客户端发起请求
     * 通过本地 SOCKS5 代理走 VPN 通道
     *
     * @param url 请求 URL
     * @param headers 可选的请求头
     * @return HttpResult
     */
    private fun fetchViaKernel(
        url: String,
        headers: Map<String, String> = emptyMap()
    ): HttpResult {
        var client: io.nekohasekai.libbox.HTTPClient? = null
        try {
            // 创建 HTTP 客户端
            client = Libbox.newHTTPClient()

            // 配置通过本地 SOCKS5 代理
            val proxyPort = cachedProxyPort
            client.trySocks5(proxyPort)

            // 启用现代 TLS 和 Keep-Alive
            client.modernTLS()
            client.keepAlive()

            // 创建请求
            val request = client.newRequest()
            request.setURL(url)
            request.setMethod("GET")
            request.randomUserAgent()

            // 设置自定义 Headers
            headers.forEach { (key, value) ->
                request.setHeader(key, value)
            }

            // 执行请求
            val response = request.execute()
            val content = response.content?.value ?: ""

            Log.d(TAG, "Kernel fetch success: $url (${content.length} bytes)")

            return HttpResult(
                success = true,
                statusCode = 200, // HTTPResponse 不提供状态码，假设成功为 200
                body = content,
                error = null
            )
        } catch (e: Exception) {
            Log.e(TAG, "Kernel fetch error: ${e.message}")
            return HttpResult.error("Kernel error: ${e.message}")
        } finally {
            try {
                client?.close()
            } catch (e: Exception) {
                Log.w(TAG, "Failed to close HTTP client: ${e.message}")
            }
        }
    }

    /**
     * 检查内核 Fetch 是否可用
     * v1.12.20: 当 VPN 运行时返回 true
     */
    fun isKernelFetchAvailable(): Boolean {
        // 检查 VPN 是否运行中
        val vpnActive = VpnStateStore.getActive()
        val boxAvailable = BoxWrapperManager.isAvailable()
        return vpnActive && boxAvailable
    }

    /**
     * 检查 VPN 是否运行中
     */
    fun isVpnRunning(): Boolean {
        return BoxWrapperManager.isAvailable()
    }
}
