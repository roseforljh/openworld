package com.openworld.app.repository.subscription

import android.util.Log
import com.openworld.app.model.OpenWorldConfig
import com.openworld.app.utils.parser.SubscriptionManager
import okhttp3.OkHttpClient
import okhttp3.Request

/**
 * 订阅用户信息
 */
data class SubscriptionUserInfo(
    val upload: Long = 0,
    val download: Long = 0,
    val total: Long = 0,
    val expire: Long = 0
)

/**
 * 订阅服务 - 负责订阅的获取和解析
 *
 * 功能:
 * - �?URL 获取订阅内容
 * - 解析订阅配置（支持多种格式）
 * - 提取用户信息（流量、到期时间等�? */
class SubscriptionFetcher(
    private val client: OkHttpClient,
    private val subscriptionManager: SubscriptionManager
) {
    companion object {
        private const val TAG = "SubscriptionFetcher"

        // �?User-Agent 轮询策略
        private val USER_AGENTS = listOf(
            "clash-verge/v1.3.8",
            "ClashforWindows/0.20.39",
            "Clash/1.18.0",
            "v2rayN/6.23",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        )

        // 预编译的正则表达�?        private val REGEX_SANITIZE_UUID = Regex("(?i)uuid\\s*[:=]\\s*[^\\\\n]+")
        private val REGEX_SANITIZE_PASSWORD = Regex("(?i)password\\s*[:=]\\s*[^\\\\n]+")
        private val REGEX_SANITIZE_TOKEN = Regex("(?i)token\\s*[:=]\\s*[^\\\\n]+")
    }

    /**
     * 获取并解析订�?     *
     * @param url 订阅 URL
     * @param onProgress 进度回调
     * @return 解析结果，包含配置和用户信息
     */
    fun fetch(
        url: String,
        onProgress: (String) -> Unit = {}
    ): FetchResult? {
        var lastError: Exception? = null

        for ((index, userAgent) in USER_AGENTS.withIndex()) {
            try {
                onProgress("尝试获取订阅 (${index + 1}/${USER_AGENTS.size})...")

                val request = Request.Builder()
                    .url(url)
                    .header("User-Agent", userAgent)
                    .header("Accept", "application/yaml,text/yaml,text/plain,application/json,*/*")
                    .build()

                var parsedConfig: OpenWorldConfig? = null
                var userInfo: SubscriptionUserInfo? = null

                client.newCall(request).execute().use { response ->
                    if (!response.isSuccessful) {
                        Log.w(TAG, "Request failed with UA '$userAgent': HTTP ${response.code}")
                        if (index == USER_AGENTS.lastIndex) {
                            throw Exception("HTTP ${response.code}: ${response.message}")
                        }
                        return@use
                    }

                    val responseBody = response.body?.string()
                    if (responseBody.isNullOrBlank()) {
                        Log.w(TAG, "Empty response with UA '$userAgent'")
                        if (index == USER_AGENTS.lastIndex) {
                            throw Exception("服务器返回空内容")
                        }
                        return@use
                    }

                    // 解析用户信息
                    userInfo = parseUserInfo(response.header("Subscription-Userinfo"), responseBody)

                    onProgress("正在解析配置...")

                    // 使用 SubscriptionManager 解析配置
                    val config = subscriptionManager.parse(responseBody)
                    if (config != null && !config.outbounds.isNullOrEmpty()) {
                        parsedConfig = config
                    } else {
                        Log.w(TAG, "Failed to parse response with UA '$userAgent'")
                    }
                }

                if (parsedConfig != null) {
                    Log.i(TAG, "Successfully parsed subscription with UA '$userAgent', got ${parsedConfig!!.outbounds?.size ?: 0} outbounds")
                    return FetchResult(parsedConfig!!, userInfo)
                }
            } catch (e: Exception) {
                Log.w(TAG, "Error with UA '$userAgent': ${e.message}")
                lastError = e
                if (index == USER_AGENTS.lastIndex) {
                    throw e
                }
            }
        }

        lastError?.let { Log.e(TAG, "All User-Agents failed", it) }
        return null
    }

    /**
     * 解析用户信息
     */
    private fun parseUserInfo(header: String?, body: String): SubscriptionUserInfo? {
        // �?Header 解析
        if (!header.isNullOrBlank()) {
            val info = parseUserInfoHeader(header)
            if (info != null) return info
        }

        // �?Body 解析
        return parseUserInfoFromBody(body)
    }

    /**
     * �?Header 解析用户信息
     * 格式: upload=xxx; download=xxx; total=xxx; expire=xxx
     */
    private fun parseUserInfoHeader(header: String): SubscriptionUserInfo? {
        try {
            var upload = 0L
            var download = 0L
            var total = 0L
            var expire = 0L

            header.split(";").forEach { part ->
                val kv = part.trim().split("=", limit = 2)
                if (kv.size == 2) {
                    val key = kv[0].trim().lowercase()
                    val value = kv[1].trim()
                    when (key) {
                        "upload" -> upload = value.toLongOrNull() ?: 0L
                        "download" -> download = value.toLongOrNull() ?: 0L
                        "total" -> total = value.toLongOrNull() ?: 0L
                        "expire" -> expire = value.toLongOrNull() ?: 0L
                    }
                }
            }

            if (upload > 0 || download > 0 || total > 0 || expire > 0) {
                return SubscriptionUserInfo(upload, download, total, expire)
            }
        } catch (e: Exception) {
            Log.w(TAG, "Failed to parse user info header", e)
        }
        return null
    }

    /**
     * �?Body 解析用户信息
     */
    private fun parseUserInfoFromBody(body: String): SubscriptionUserInfo? {
        // 简化实现，实际逻辑�?ConfigRepository 中更复杂
        return null
    }

    /**
     * 脱敏订阅内容片段（用于日志）
     */
    fun sanitizeSnippet(body: String, maxLen: Int = 220): String {
        var s = body
            .replace("\r", "")
            .replace("\n", "\\n")
            .trim()
        if (s.length > maxLen) s = s.substring(0, maxLen)

        s = s.replace(REGEX_SANITIZE_UUID, "uuid:***")
        s = s.replace(REGEX_SANITIZE_PASSWORD, "password:***")
        s = s.replace(REGEX_SANITIZE_TOKEN, "token:***")
        return s
    }

    /**
     * 获取结果
     */
    data class FetchResult(
        val config: OpenWorldConfig,
        val userInfo: SubscriptionUserInfo?
    )
}







