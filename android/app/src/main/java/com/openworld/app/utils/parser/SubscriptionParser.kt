package com.openworld.app.utils.parser

import android.util.Log
import com.openworld.app.model.Outbound
import com.openworld.app.model.OpenWorldConfig
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.withContext
import java.net.InetAddress
import java.util.concurrent.ConcurrentHashMap

/**
 * 订阅转换引擎接口
 */
interface SubscriptionParser {
    /**
     * 判断是否能解析该内容
     */
    fun canParse(content: String): Boolean

    /**
     * 解析内容并返�?OpenWorldConfig
     */
    fun parse(content: String): OpenWorldConfig?
}

/**
 * DNS 预解析缓�? * 用于加速节点连接，避免 DNS 污染
 */
object DnsResolveCache {
    private const val TAG = "DnsResolveCache"

    /**
     * 缓存条目，包�?IP 和时间戳
     */
    private data class CacheEntry(val ip: String, val timestamp: Long)

    // 域名 -> 缓存条目（包�?IP 和时间戳�?    private val cache = ConcurrentHashMap<String, CacheEntry>()

    // 解析失败的域名（避免重复尝试�?    private val failedDomains = ConcurrentHashMap<String, Long>()

    // 缓存有效�?(30 分钟) - DNS 记录通常有较长的 TTL
    private const val CACHE_TTL_MS = 30 * 60 * 1000L

    // 失败重试间隔 (5 分钟)
    private const val RETRY_INTERVAL_MS = 5 * 60 * 1000L

    /**
     * 获取缓存�?IP 地址
     * 如果缓存已过期，返回 null
     */
    fun getResolvedIp(domain: String): String? {
        val entry = cache[domain] ?: return null
        val currentTime = System.currentTimeMillis()
        return if (currentTime - entry.timestamp < CACHE_TTL_MS) {
            entry.ip
        } else {
            // 缓存过期，移除并返回 null
            cache.remove(domain)
            null
        }
    }

    /**
     * 预解析域名列�?     * @param domains 需要解析的域名列表
     * @return 解析成功的数�?     */
    suspend fun preResolve(domains: List<String>): Int = withContext(Dispatchers.IO) {
        val currentTime = System.currentTimeMillis()

        // 先清理过期的失败记录
        failedDomains.entries.removeIf { currentTime - it.value >= RETRY_INTERVAL_MS }

        val toResolve = domains.filter { domain ->
            // 跳过有效缓存�?            val entry = cache[domain]
            if (entry != null && currentTime - entry.timestamp < CACHE_TTL_MS) {
                return@filter false
            }
            // 跳过最近失败的
            val failedTime = failedDomains[domain]
            if (failedTime != null && currentTime - failedTime < RETRY_INTERVAL_MS) {
                return@filter false
            }
            // 跳过已经�?IP 地址�?            if (isIpAddress(domain)) return@filter false
            true
        }.distinct()

        if (toResolve.isEmpty()) return@withContext 0

        Log.d(TAG, "Pre-resolving ${toResolve.size} domains...")

        val results = toResolve.map { domain ->
            async {
                try {
                    val addresses = InetAddress.getAllByName(domain)
                    val ip = addresses.firstOrNull()?.hostAddress
                    if (ip != null) {
                        cache[domain] = CacheEntry(ip, currentTime)
                        Log.d(TAG, "Resolved $domain -> $ip")
                        1
                    } else {
                        failedDomains[domain] = currentTime
                        0
                    }
                } catch (e: Exception) {
                    failedDomains[domain] = currentTime
                    Log.w(TAG, "Failed to resolve $domain: ${e.message}")
                    0
                }
            }
        }.awaitAll()

        val successCount = results.sum()
        Log.d(TAG, "Pre-resolved $successCount/${toResolve.size} domains")
        successCount
    }

    /**
     * 从节点列表中提取所有需要解析的域名
     */
    fun extractDomains(outbounds: List<Outbound>): List<String> {
        return outbounds.mapNotNull { outbound ->
            val server = outbound.server ?: return@mapNotNull null
            // 跳过 IP 地址
            if (isIpAddress(server)) return@mapNotNull null
            server
        }.distinct()
    }

    /**
     * 判断是否�?IP 地址
     */
    private fun isIpAddress(host: String): Boolean {
        // IPv4 简单判�?        if (host.matches(Regex("^\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}$"))) {
            return true
        }
        // IPv6 判断
        if (host.contains(":") && !host.contains(".")) {
            return true
        }
        return false
    }

    /**
     * 清空缓存
     */
    fun clear() {
        cache.clear()
        failedDomains.clear()
    }

    /**
     * 获取缓存统计
     */
    fun getStats(): Pair<Int, Int> = Pair(cache.size, failedDomains.size)
}

/**
 * 订阅解析管理�? */
class SubscriptionManager(private val parsers: List<SubscriptionParser>) {

    companion object {
        private const val TAG = "SubscriptionManager"

        /**
         * 生成节点去重 key
         * 基于 type://server:port + 认证信息，相同组合视为重复节�?         */
        private fun getDeduplicationKey(outbound: Outbound): String? {
            val server = outbound.server ?: return null
            val port = outbound.serverPort ?: return null
            val type = outbound.type

            // 对于 selector/urltest 类型，不参与去重
            if (type == "selector" || type == "urltest" || type == "direct" || type == "block" || type == "dns") {
                return null
            }

            // 加入认证信息区分同服务器不同账号的节�?            val credential = outbound.password ?: outbound.uuid ?: ""
            return "$type://$credential@$server:$port"
        }

        /**
         * 对节点列表进行去�?         * 保留第一个出现的节点，后续重复节点被忽略
         */
        fun deduplicateOutbounds(outbounds: List<Outbound>): List<Outbound> {
            val seen = mutableSetOf<String>()
            val result = mutableListOf<Outbound>()
            var duplicateCount = 0

            for (outbound in outbounds) {
                val key = getDeduplicationKey(outbound)
                if (key == null) {
                    // 非代理节点（selector/urltest/direct 等），直接保�?                    result.add(outbound)
                } else if (seen.add(key)) {
                    // 第一次见到这�?key，保�?                    result.add(outbound)
                } else {
                    // 重复节点，跳�?                    duplicateCount++
                }
            }

            if (duplicateCount > 0) {
                Log.d(TAG, "Deduplicated $duplicateCount duplicate nodes, ${result.size} unique nodes remaining")
            }

            return result
        }
    }

    /**
     * 解析订阅内容
     */
    fun parse(content: String): OpenWorldConfig? {
        for (parser in parsers) {
            if (parser.canParse(content)) {
                try {
                    val config = parser.parse(content)
                    if (config != null && !config.outbounds.isNullOrEmpty()) {
                        // 对节点进行去�?                        val deduplicatedOutbounds = deduplicateOutbounds(config.outbounds)
                        return config.copy(outbounds = deduplicatedOutbounds)
                    }
                } catch (e: Exception) {
                    Log.e(TAG, "Parser ${parser.javaClass.simpleName} failed", e)
                }
            }
        }
        return null
    }

    /**
     * 解析订阅内容并预解析 DNS
     * @param content 订阅内容
     * @param preResolveDns 是否预解�?DNS
     * @return 解析结果�?DNS 解析数量
     */
    suspend fun parseWithDnsPreResolve(content: String, preResolveDns: Boolean = true): Pair<OpenWorldConfig?, Int> {
        val config = parse(content)
        if (config == null || config.outbounds.isNullOrEmpty()) {
            return Pair(null, 0)
        }

        if (!preResolveDns) {
            return Pair(config, 0)
        }

        // 提取域名并预解析
        val domains = DnsResolveCache.extractDomains(config.outbounds)
        val resolvedCount = DnsResolveCache.preResolve(domains)

        return Pair(config, resolvedCount)
    }
}







