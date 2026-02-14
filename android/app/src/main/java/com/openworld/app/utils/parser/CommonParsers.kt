package com.openworld.app.utils.parser

import android.util.Base64
import android.util.Log
import com.google.gson.Gson
import com.google.gson.JsonParser
import com.google.gson.reflect.TypeToken
import com.openworld.app.model.Outbound
import com.openworld.app.model.OpenWorldConfig

/**
 * Sing-box JSON 格式解析�? * 只提�?outbounds 节点，忽略规则配�? * 防止�?sing-box 规则版本更新导致解析失败
 */
class SingBoxParser(private val gson: Gson) : SubscriptionParser {
    companion object {
        private const val TAG = "SingBoxParser"
        private val OUTBOUND_LIST_TYPE = object : TypeToken<List<Outbound>>() {}.type
    }

    override fun canParse(content: String): Boolean {
        val trimmed = content.trim()
        return (trimmed.startsWith("{") && trimmed.endsWith("}")) ||
            (trimmed.startsWith("[") && trimmed.endsWith("]"))
    }

    override fun parse(content: String): OpenWorldConfig? {
        val trimmed = content.trim()

        // 如果是数组格式，直接解析�?outbounds 列表
        if (trimmed.startsWith("[")) {
            return parseAsOutboundArray(trimmed)
        }

        // 对象格式：只提取 outbounds 字段，忽略其他可能不兼容的字�?        return parseAsConfigObject(trimmed)
    }

    /**
     * 解析 JSON 数组格式（直接是 outbounds 列表�?     */
    private fun parseAsOutboundArray(content: String): OpenWorldConfig? {
        return try {
            val outbounds: List<Outbound> = gson.fromJson(content, OUTBOUND_LIST_TYPE)
            if (outbounds.isNotEmpty()) {
                OpenWorldConfig(outbounds = outbounds)
            } else null
        } catch (e: Exception) {
            Log.w(TAG, "Failed to parse as outbound array: ${e.message}")
            null
        }
    }

    /**
     * 解析 JSON 对象格式，只提取 outbounds/proxies 字段
     */
    private fun parseAsConfigObject(content: String): OpenWorldConfig? {
        return try {
            val jsonObject = JsonParser.parseString(content).asJsonObject

            // 优先尝试 outbounds 字段，其�?proxies
            val outboundsElement = jsonObject.get("outbounds") ?: jsonObject.get("proxies")

            if (outboundsElement != null && outboundsElement.isJsonArray) {
                val outbounds: List<Outbound> = gson.fromJson(outboundsElement, OUTBOUND_LIST_TYPE)
                if (outbounds.isNotEmpty()) {
                    return OpenWorldConfig(outbounds = outbounds)
                }
            }
            null
        } catch (e: Exception) {
            Log.w(TAG, "Failed to extract outbounds from JSON: ${e.message}")
            null
        }
    }
}

/**
 * Base64 订阅格式解析器（通用链接�? */
class Base64Parser(private val nodeParser: (String) -> Outbound?) : SubscriptionParser {
    private val LINK_PREFIXES = listOf(
        "vmess://",
        "vless://",
        "ss://",
        "ssr://",
        "trojan://",
        "hysteria://",
        "hysteria2://",
        "hy2://",
        "tuic://",
        "anytls://",
        "wireguard://",
        "ssh://",
        "socks5://",
        "socks://",
        "http://",
        "https://"
    )

    override fun canParse(content: String): Boolean {
        val trimmed = content.trim()
        return !trimmed.startsWith("{") && !trimmed.startsWith("proxies:") && !trimmed.startsWith("proxy-groups:")
    }

    override fun parse(content: String): OpenWorldConfig? {
        android.util.Log.d("Base64Parser", "Parsing content, length: ${content.length}, starts with: ${content.take(20)}")
        val trimmed = content.trim()

        // 如果内容已经是协议链接，不要尝试 base64 解码
        val isAlreadyLink = LINK_PREFIXES.any { trimmed.startsWith(it) }
        val decoded = if (isAlreadyLink) trimmed else (tryDecodeBase64(trimmed) ?: trimmed)
        val normalized = decoded
            .replace("\u2028", "\n")
            .replace("\u2029", "\n")
        val candidates = normalized.lines().flatMap { extractLinksFromLine(it) }
            .ifEmpty { normalized.split(Regex("\\s+")).flatMap { extractLinksFromLine(it) } }
        android.util.Log.d("Base64Parser", "Found ${candidates.size} link candidates")
        val outbounds = mutableListOf<Outbound>()

        for (candidate in candidates) {
            android.util.Log.d("Base64Parser", "Trying to parse candidate: ${candidate.take(30)}...")
            val outbound = nodeParser(candidate)
            if (outbound != null) {
                android.util.Log.d("Base64Parser", "Successfully parsed: ${outbound.tag}")
                outbounds.add(outbound)
            } else {
                android.util.Log.w("Base64Parser", "Failed to parse candidate")
            }
        }

        android.util.Log.d("Base64Parser", "Total outbounds parsed: ${outbounds.size}")
        if (outbounds.isEmpty()) return null

        return OpenWorldConfig(outbounds = outbounds)
    }

    private fun extractLinksFromLine(line: String): List<String> {
        val normalized = line.trim()
            .trimStart('\uFEFF', '\u200B', '\u200C', '\u200D')
            .removePrefix("- ")
            .removePrefix("�?")
            .trim()
            .trim('`', '"', '\'')

        if (normalized.isBlank()) return emptyList()

        // 按前缀长度降序排列，确保长前缀（如 vmess://）先于短前缀（如 ss://）被匹配
        // 这样可以避免 vmess:// 被误识别�?ss://
        val sortedPrefixes = LINK_PREFIXES.sortedByDescending { it.length }

        // 找到所有链接的起始位置，使用贪婪匹配（最长前缀优先�?        val linkPositions = mutableListOf<Pair<Int, String>>() // (位置, 前缀)
        val usedPositions = mutableSetOf<Int>()

        for (prefix in sortedPrefixes) {
            var searchFrom = 0
            while (searchFrom < normalized.length) {
                val index = normalized.indexOf(prefix, searchFrom)
                if (index < 0) break

                // 检查这个位置是否已经被更长的前缀占用
                val isOverlapped = usedPositions.any { usedPos ->
                    index >= usedPos && index < usedPos + sortedPrefixes.find {
                        normalized.substring(usedPos).startsWith(it)
                    }!!.length
                }

                if (!isOverlapped) {
                    linkPositions.add(index to prefix)
                    usedPositions.add(index)
                }
                searchFrom = index + 1
            }
        }

        if (linkPositions.isEmpty()) return emptyList()

        // 按位置排�?        val sortedPositions = linkPositions.sortedBy { it.first }

        val results = mutableListOf<String>()
        for (i in sortedPositions.indices) {
            val start = sortedPositions[i].first
            val end = if (i + 1 < sortedPositions.size) sortedPositions[i + 1].first else normalized.length
            var candidate = normalized.substring(start, end).trim()
            candidate = candidate.trimEnd(',', ';')
            if (candidate.isNotBlank()) {
                results.add(candidate)
            }
        }
        return results
    }

    private fun tryDecodeBase64(content: String): String? {
        val candidates = arrayOf(
            Base64.DEFAULT,
            Base64.NO_WRAP,
            Base64.URL_SAFE or Base64.NO_WRAP,
            Base64.URL_SAFE or Base64.NO_PADDING or Base64.NO_WRAP
        )
        for (flags in candidates) {
            try {
                val decoded = Base64.decode(content, flags)
                val text = String(decoded)
                // 验证解码结果是否看起来像文本 (包含常见协议头或换行)
                if (text.isNotBlank() && (
                        text.contains("://") ||
                            text.contains("\n") ||
                            text.contains("\r") ||
                            text.all { it.isLetterOrDigit() || it.isWhitespace() || "=/-_:.".contains(it) }
                        )) {
                    return text
                }
            } catch (_: Exception) {}
        }
        return null
    }
}







