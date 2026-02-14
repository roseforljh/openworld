package com.openworld.app.utils.perf

import android.util.Log
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.sync.Semaphore
import kotlinx.coroutines.sync.withPermit
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
import java.net.InetAddress
import java.util.concurrent.ConcurrentHashMap

/**
 * DNS 预热器
 * 在 VPN 启动前并行预解析节点域名，减少 libbox 启动时的 DNS 等待时间
 *
 * 工作原理:
 * 1. 从配置 JSON 中提取所有节点服务器域名
 * 2. 使用系统 DNS 并行解析这些域名
 * 3. 解析结果会被系统 DNS 缓存
 * 4. sing-box 启动时可以直接使用缓存的 DNS 结果
 *
 * 预期效果:
 * - 单个域名解析: 50-200ms
 * - 10 个域名并行解析: 100-300ms (而非串行的 500-2000ms)
 * - libbox 启动时 DNS 查询: 接近 0ms (命中缓存)
 */
object DnsPrewarmer {
    private const val TAG = "DnsPrewarmer"

    // DNS 缓存 - 避免重复解析
    private val dnsCache = ConcurrentHashMap<String, List<String>>()

    // 缓存有效期 (5 分钟)
    private const val CACHE_TTL_MS = 5 * 60 * 1000L
    private val cacheTimestamps = ConcurrentHashMap<String, Long>()

    // 并发限制
    private const val MAX_CONCURRENCY = 8

    // 单个域名解析超时
    private const val RESOLVE_TIMEOUT_MS = 2000L

    // 总预热超时
    private const val TOTAL_TIMEOUT_MS = 3000L

    /**
     * 预热结果
     */
    data class PrewarmResult(
        val totalDomains: Int,
        val resolvedDomains: Int,
        val cachedDomains: Int,
        val failedDomains: Int,
        val durationMs: Long
    )

    /**
     * 从配置中提取所有节点域名并并行预解析
     * @param configContent 配置 JSON 内容
     * @return 预热结果
     */
    suspend fun prewarm(configContent: String): PrewarmResult = withContext(Dispatchers.IO) {
        PerfTracer.begin(PerfTracer.Phases.DNS_PREWARM)

        val domains = extractNodeDomains(configContent)
        if (domains.isEmpty()) {
            val duration = PerfTracer.end(PerfTracer.Phases.DNS_PREWARM)
            return@withContext PrewarmResult(0, 0, 0, 0, duration)
        }

        Log.d(TAG, "Prewarming ${domains.size} domains...")

        var resolvedCount = 0
        var cachedCount = 0
        var failedCount = 0

        // 使用超时包装整个预热过程
        withTimeoutOrNull(TOTAL_TIMEOUT_MS) {
            val semaphore = Semaphore(MAX_CONCURRENCY)

            coroutineScope {
                domains.map { domain ->
                    async {
                        semaphore.withPermit {
                            val result = resolveWithCache(domain)
                            synchronized(this@DnsPrewarmer) {
                                when (result) {
                                    ResolveResult.RESOLVED -> resolvedCount++
                                    ResolveResult.CACHED -> cachedCount++
                                    ResolveResult.FAILED -> failedCount++
                                }
                            }
                        }
                    }
                }.awaitAll()
            }
        }

        val duration = PerfTracer.end(PerfTracer.Phases.DNS_PREWARM)
        val result = PrewarmResult(
            totalDomains = domains.size,
            resolvedDomains = resolvedCount,
            cachedDomains = cachedCount,
            failedDomains = failedCount,
            durationMs = duration
        )

        Log.i(
            TAG,
            "DNS prewarm completed: ${result.resolvedDomains} resolved, " +
                "${result.cachedDomains} cached, ${result.failedDomains} failed " +
                "in ${result.durationMs}ms"
        )

        result
    }

    /**
     * 快速预热 - 只解析最重要的域名 (当前活跃节点)
     */
    suspend fun prewarmSingle(domain: String): Boolean = withContext(Dispatchers.IO) {
        if (domain.isBlank() || isIpAddress(domain)) {
            return@withContext true
        }

        val result = resolveWithCache(domain)
        result != ResolveResult.FAILED
    }

    /**
     * 清除 DNS 缓存
     */
    fun clearCache() {
        dnsCache.clear()
        cacheTimestamps.clear()
        Log.d(TAG, "DNS cache cleared")
    }

    /**
     * 获取缓存的 DNS 结果
     */
    fun getCachedAddresses(domain: String): List<String>? {
        val timestamp = cacheTimestamps[domain] ?: return null
        if (System.currentTimeMillis() - timestamp > CACHE_TTL_MS) {
            dnsCache.remove(domain)
            cacheTimestamps.remove(domain)
            return null
        }
        return dnsCache[domain]
    }

    private enum class ResolveResult {
        RESOLVED,
        CACHED,
        FAILED
    }

    private suspend fun resolveWithCache(domain: String): ResolveResult {
        // 检查缓存
        val cached = getCachedAddresses(domain)
        if (cached != null) {
            Log.v(TAG, "DNS cache hit: $domain -> ${cached.firstOrNull()}")
            return ResolveResult.CACHED
        }

        // 解析域名
        return withTimeoutOrNull(RESOLVE_TIMEOUT_MS) {
            try {
                val addresses = InetAddress.getAllByName(domain)
                if (addresses.isNotEmpty()) {
                    val addressList = addresses.map { it.hostAddress ?: "" }.filter { it.isNotEmpty() }
                    dnsCache[domain] = addressList
                    cacheTimestamps[domain] = System.currentTimeMillis()
                    Log.v(TAG, "DNS resolved: $domain -> ${addressList.firstOrNull()}")
                    ResolveResult.RESOLVED
                } else {
                    ResolveResult.FAILED
                }
            } catch (e: Exception) {
                Log.w(TAG, "DNS resolve failed: $domain - ${e.message}")
                ResolveResult.FAILED
            }
        } ?: ResolveResult.FAILED
    }

    /**
     * 从配置 JSON 中提取所有节点服务器域名
     * 使用正则快速解析，避免完整 JSON 解析的开销
     */
    private fun extractNodeDomains(configJson: String): Set<String> {
        val domains = mutableSetOf<String>()

        // 匹配 "server": "xxx" 模式
        val serverRegex = """"server"\s*:\s*"([^"]+)"""".toRegex()
        serverRegex.findAll(configJson).forEach { match ->
            val server = match.groupValues[1]
            if (server.isNotBlank() && !isIpAddress(server) && isValidDomain(server)) {
                domains.add(server)
            }
        }

        // 匹配 "address": "xxx" 模式 (DNS 服务器)
        val addressRegex = """"address"\s*:\s*"([^"]+)"""".toRegex()
        addressRegex.findAll(configJson).forEach { match ->
            val address = match.groupValues[1]
            // 提取 DoH URL 中的域名
            if (address.startsWith("https://") || address.startsWith("tls://")) {
                val host = extractHostFromUrl(address)
                if (host != null && !isIpAddress(host) && isValidDomain(host)) {
                    domains.add(host)
                }
            }
        }

        return domains
    }

    /**
     * 验证是否为有效域名（而非 sing-box 内部 tag 如 "local", "remote", "fakeip-dns"）
     */
    private fun isValidDomain(host: String): Boolean {
        if (!host.contains('.')) return false
        if (host.startsWith('.') || host.endsWith('.')) return false
        return host.matches(Regex("""^[a-zA-Z0-9][a-zA-Z0-9\-.]*[a-zA-Z0-9]$"""))
    }

    private fun extractHostFromUrl(url: String): String? {
        return try {
            val withoutScheme = url.substringAfter("://")
            val hostPort = withoutScheme.substringBefore("/")
            hostPort.substringBefore(":")
        } catch (_: Exception) {
            null
        }
    }

    private fun isIpAddress(host: String): Boolean {
        // IPv4
        if (host.matches(Regex("""^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"""))) {
            return true
        }
        // IPv6
        if (host.contains(":") && host.matches(Regex("""^[0-9a-fA-F:]+$"""))) {
            return true
        }
        // IPv6 with brackets
        if (host.startsWith("[") && host.endsWith("]")) {
            return true
        }
        return false
    }
}
