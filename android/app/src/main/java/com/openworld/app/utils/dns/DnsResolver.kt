package com.openworld.app.utils.dns

import android.util.Log
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.selects.select
import kotlinx.coroutines.sync.Semaphore
import kotlinx.coroutines.sync.withPermit
import kotlinx.coroutines.withContext
import kotlin.coroutines.resume
import kotlinx.coroutines.suspendCancellableCoroutine
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import java.net.InetAddress
import java.nio.ByteBuffer
import java.util.concurrent.TimeUnit

/**
 * DNS 解析结果
 */
data class DnsResolveResult(
    val ip: String?,
    val source: String,
    val error: String? = null
) {
    val isSuccess: Boolean get() = ip != null && error == null
}

/**
 * DoH (DNS over HTTPS) 解析器
 *
 * 支持通过 HTTPS 安全地解析域名，绕过本地 DNS 污染
 */
class DnsResolver(
    private val client: OkHttpClient = createDefaultClient()
) {
    companion object {
        private const val TAG = "DnsResolver"

        // 预定义的 DoH 服务器
        const val DOH_CLOUDFLARE = "https://1.1.1.1/dns-query"
        const val DOH_GOOGLE = "https://8.8.8.8/dns-query"
        const val DOH_ALIDNS = "https://223.5.5.5/dns-query"

        private val IPV4_REGEX = Regex("^\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}$")
        private val IPV6_REGEX = Regex("^[0-9a-fA-F:]+$")

        private fun createDefaultClient(): OkHttpClient {
            return OkHttpClient.Builder()
                .connectTimeout(3, TimeUnit.SECONDS)
                .readTimeout(3, TimeUnit.SECONDS)
                .writeTimeout(3, TimeUnit.SECONDS)
                .build()
        }

        /**
         * 判断是否为 IP 地址
         */
        fun isIpAddress(host: String): Boolean {
            return IPV4_REGEX.matches(host) || (host.contains(":") && IPV6_REGEX.matches(host))
        }
    }

    /**
     * 使用 DoH 解析域名
     *
     * @param domain 要解析的域名
     * @param dohServer DoH 服务器地址
     * @return 解析结果
     */
    suspend fun resolveViaDoH(
        domain: String,
        dohServer: String = DOH_CLOUDFLARE
    ): DnsResolveResult = withContext(Dispatchers.IO) {
        if (isIpAddress(domain)) {
            return@withContext DnsResolveResult(domain, "direct")
        }

        try {
            executeDoHRequest(domain, dohServer)
        } catch (e: Exception) {
            Log.w(TAG, "DoH resolve failed for $domain: ${e.message}")
            DnsResolveResult(null, "doh", e.message)
        }
    }

    private fun executeDoHRequest(domain: String, dohServer: String): DnsResolveResult {
        val query = buildDnsQuery(domain)

        val request = Request.Builder()
            .url(dohServer)
            .header("Accept", "application/dns-message")
            .header("Content-Type", "application/dns-message")
            .post(query.toRequestBody("application/dns-message".toMediaType()))
            .build()

        client.newCall(request).execute().use { response ->
            if (!response.isSuccessful) {
                return DnsResolveResult(null, "doh", "HTTP ${response.code}")
            }

            val body = response.body?.bytes()
                ?: return DnsResolveResult(null, "doh", "Empty response")

            val ip = parseDnsResponse(body)
            return if (ip != null) {
                Log.d(TAG, "DoH resolved $domain -> $ip")
                DnsResolveResult(ip, "doh")
            } else {
                DnsResolveResult(null, "doh", "No A record found")
            }
        }
    }

    /**
     * 使用系统 DNS 解析
     */
    suspend fun resolveViaSystem(domain: String): DnsResolveResult = withContext(Dispatchers.IO) {
        if (isIpAddress(domain)) {
            return@withContext DnsResolveResult(domain, "direct")
        }

        try {
            val addresses = InetAddress.getAllByName(domain)
            val ip = addresses.firstOrNull()?.hostAddress
            if (ip != null) {
                Log.d(TAG, "System resolved $domain -> $ip")
                DnsResolveResult(ip, "system")
            } else {
                DnsResolveResult(null, "system", "No address found")
            }
        } catch (e: Exception) {
            Log.w(TAG, "System resolve failed for $domain: ${e.message}")
            DnsResolveResult(null, "system", e.message)
        }
    }

    /**
     * 使用 DoH 异步解析（可取消）
     */
    @Suppress("CognitiveComplexMethod")
    private suspend fun resolveViaDoHAsync(
        domain: String,
        dohServer: String
    ): DnsResolveResult = suspendCancellableCoroutine { cont ->
        val query = buildDnsQuery(domain)

        val request = Request.Builder()
            .url(dohServer)
            .header("Accept", "application/dns-message")
            .header("Content-Type", "application/dns-message")
            .post(query.toRequestBody("application/dns-message".toMediaType()))
            .build()

        val call = client.newCall(request)

        cont.invokeOnCancellation {
            call.cancel()
        }

        call.enqueue(object : okhttp3.Callback {
            override fun onFailure(call: okhttp3.Call, e: java.io.IOException) {
                if (cont.isActive) {
                    Log.w(TAG, "DoH resolve failed for $domain: ${e.message}")
                    cont.resume(DnsResolveResult(null, "doh", e.message))
                }
            }

            override fun onResponse(call: okhttp3.Call, response: okhttp3.Response) {
                if (!cont.isActive) {
                    response.close()
                    return
                }

                response.use { resp ->
                    if (!resp.isSuccessful) {
                        cont.resume(DnsResolveResult(null, "doh", "HTTP ${resp.code}"))
                        return
                    }

                    val body = resp.body?.bytes()
                    if (body == null) {
                        cont.resume(DnsResolveResult(null, "doh", "Empty response"))
                        return
                    }

                    val ip = parseDnsResponse(body)
                    if (ip != null) {
                        Log.d(TAG, "DoH resolved $domain -> $ip")
                        cont.resume(DnsResolveResult(ip, "doh"))
                    } else {
                        cont.resume(DnsResolveResult(null, "doh", "No A record found"))
                    }
                }
            }
        })
    }

    /**
     * 竞速解析：同时启动 DoH 和系统 DNS，谁先成功用谁
     */
    @Suppress("CognitiveComplexMethod")
    suspend fun resolve(
        domain: String,
        dohServer: String? = DOH_CLOUDFLARE
    ): DnsResolveResult = withContext(Dispatchers.IO) {
        if (isIpAddress(domain)) {
            return@withContext DnsResolveResult(domain, "direct")
        }

        // 同时启动两个解析任务
        val dohDeferred = if (dohServer != null) {
            async { resolveViaDoHAsync(domain, dohServer) }
        } else null

        val systemDeferred = async { resolveViaSystem(domain) }

        // select: 谁先完成且成功就用谁
        val winner = select {
            dohDeferred?.onAwait { if (it.isSuccess) it else null }
            systemDeferred.onAwait { if (it.isSuccess) it else null }
        }

        if (winner != null) {
            dohDeferred?.cancel()
            systemDeferred.cancel()
            return@withContext winner
        }

        // 第一个失败了，等另一个
        val fallback = select {
            if (dohDeferred != null && dohDeferred.isActive) {
                dohDeferred.onAwait { it }
            }
            if (systemDeferred.isActive) {
                systemDeferred.onAwait { it }
            }
        }

        dohDeferred?.cancel()
        systemDeferred.cancel()
        fallback
    }

    /**
     * 批量解析多个域名
     *
     * @param domains 域名列表
     * @param dohServer DoH 服务器
     * @param concurrency 并发数
     * @return 域名到解析结果的映射
     */
    suspend fun resolveBatch(
        domains: List<String>,
        dohServer: String? = DOH_CLOUDFLARE,
        concurrency: Int = 8
    ): Map<String, DnsResolveResult> = withContext(Dispatchers.IO) {
        val uniqueDomains = domains.filter { !isIpAddress(it) }.distinct()
        if (uniqueDomains.isEmpty()) {
            return@withContext emptyMap()
        }

        Log.d(TAG, "Batch resolving ${uniqueDomains.size} domains...")

        val semaphore = Semaphore(concurrency)
        val results = uniqueDomains.map { domain ->
            async {
                semaphore.withPermit {
                    domain to resolve(domain, dohServer)
                }
            }
        }.awaitAll()

        val resultMap = results.toMap()
        val successCount = resultMap.values.count { result -> result.isSuccess }
        Log.d(TAG, "Batch resolved: $successCount/${uniqueDomains.size} succeeded")

        resultMap
    }

    /**
     * 构建 DNS 查询报文 (A 记录)
     */
    private fun buildDnsQuery(domain: String): ByteArray {
        val buffer = ByteBuffer.allocate(512)

        // Transaction ID (random)
        buffer.putShort((System.currentTimeMillis() and 0xFFFF).toShort())

        // Flags: standard query, recursion desired
        buffer.putShort(0x0100.toShort())

        // Questions: 1, Answers: 0, Authority: 0, Additional: 0
        buffer.putShort(1)
        buffer.putShort(0)
        buffer.putShort(0)
        buffer.putShort(0)

        // Question section
        val labels = domain.split(".")
        for (label in labels) {
            buffer.put(label.length.toByte())
            buffer.put(label.toByteArray(Charsets.US_ASCII))
        }
        buffer.put(0) // End of name

        // Type: A (1)
        buffer.putShort(1)
        // Class: IN (1)
        buffer.putShort(1)

        val result = ByteArray(buffer.position())
        buffer.flip()
        buffer.get(result)
        return result
    }

    /**
     * 解析 DNS 响应报文
     */
    private fun parseDnsResponse(data: ByteArray): String? {
        if (data.size < 12) return null

        val buffer = ByteBuffer.wrap(data)

        // Skip header (12 bytes)
        buffer.position(12)

        // Skip question section
        skipName(buffer)
        buffer.position(buffer.position() + 4) // Type + Class

        // Read answer count from header
        val answerCount = ((data[6].toInt() and 0xFF) shl 8) or (data[7].toInt() and 0xFF)

        // Parse answers
        repeat(answerCount) {
            if (buffer.remaining() < 12) return null

            skipName(buffer)

            val type = buffer.short.toInt() and 0xFFFF
            buffer.short // Class
            buffer.int // TTL
            val rdLength = buffer.short.toInt() and 0xFFFF

            if (type == 1 && rdLength == 4) {
                // A record - IPv4 address
                val ip = ByteArray(4)
                buffer.get(ip)
                return "${ip[0].toInt() and 0xFF}.${ip[1].toInt() and 0xFF}." +
                    "${ip[2].toInt() and 0xFF}.${ip[3].toInt() and 0xFF}"
            } else {
                // Skip this record
                buffer.position(buffer.position() + rdLength)
            }
        }

        return null
    }

    /**
     * 跳过 DNS 名称字段
     */
    @Suppress("LoopWithTooManyJumpStatements")
    private fun skipName(buffer: ByteBuffer) {
        while (buffer.hasRemaining()) {
            val len = buffer.get().toInt() and 0xFF
            if (len == 0) break
            if ((len and 0xC0) == 0xC0) {
                buffer.get() // Compression pointer
                break
            }
            buffer.position(buffer.position() + len)
        }
    }
}
