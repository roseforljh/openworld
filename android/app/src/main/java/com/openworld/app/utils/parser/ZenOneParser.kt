package com.openworld.app.utils.parser

import android.util.Log
import com.google.gson.Gson
import com.google.gson.annotations.SerializedName
import com.google.gson.JsonObject
import com.google.gson.JsonParser
import com.openworld.app.model.OpenWorldConfig
import com.openworld.app.model.Outbound
import com.openworld.app.model.RealityConfig
import com.openworld.app.model.TlsConfig
import com.openworld.app.model.TransportConfig
import com.openworld.app.model.UtlsConfig

/**
 * ZenOne 格式解析器
 *
 * 用于解析从内核返回的完整 ZenOne YAML/JSON 配置
 * 支持提取节点、分组、路由、DNS，元数据等完整信息
 */
class ZenOneParser(private val gson: Gson = Gson()) {

    companion object {
        private const val TAG = "ZenOneParser"
    }

    /**
     * ZenOne 转换结果
     */
    data class ZenOneResult(
        val success: Boolean,
        val zenoneYaml: String? = null,
        val nodeCount: Int = 0,
        val hasGroups: Boolean = false,
        val hasRouter: Boolean = false,
        val hasDns: Boolean = false,
        val metadata: ZenOneMetadata? = null,
        val error: String? = null
    )

    /**
     * ZenOne 元数据
     */
    data class ZenOneMetadata(
        @SerializedName("name") val name: String? = null,
        @SerializedName("source_url") val sourceUrl: String? = null,
        @SerializedName("update_interval") val updateInterval: Long? = null,
        @SerializedName("expire_at") val expireAt: String? = null,
        @SerializedName("upload") val upload: Long? = null,
        @SerializedName("download") val download: Long? = null,
        @SerializedName("total") val total: Long? = null
    )

    /**
     * 解析内核返回的转换结果 JSON
     */
    fun parseConvertResult(json: String): ZenOneResult {
        return try {
            val root = JsonParser.parseString(json).asJsonObject

            val success = root.get("success")?.asBoolean ?: false

            if (success) {
                ZenOneResult(
                    success = true,
                    zenoneYaml = root.get("zenone_yaml")?.asString,
                    nodeCount = root.get("node_count")?.asInt ?: 0,
                    hasGroups = root.get("has_groups")?.asBoolean ?: false,
                    hasRouter = root.get("has_router")?.asBoolean ?: false,
                    hasDns = root.get("has_dns")?.asBoolean ?: false,
                    metadata = root.get("metadata")?.asJsonObject?.let { parseMetadata(it) }
                )
            } else {
                ZenOneResult(
                    success = false,
                    error = root.get("error")?.asString ?: "Unknown error"
                )
            }
        } catch (e: Exception) {
            Log.e(TAG, "Failed to parse convert result", e)
            ZenOneResult(success = false, error = "解析失败: ${e.message}")
        }
    }

    private fun parseMetadata(json: JsonObject): ZenOneMetadata {
        return ZenOneMetadata(
            name = json.get("name")?.asString,
            sourceUrl = json.get("source_url")?.asString,
            updateInterval = json.get("update_interval")?.asLong,
            expireAt = json.get("expire_at")?.asString,
            upload = json.get("upload")?.asLong,
            download = json.get("download")?.asLong,
            total = json.get("total")?.asLong
        )
    }

    /**
     * 解析 ZenOne YAML/JSON 为 OpenWorldConfig
     */
    fun parse(zenoneContent: String): OpenWorldConfig? {
        return try {
            val root = if (zenoneContent.trim().startsWith("{")) {
                JsonParser.parseString(zenoneContent).asJsonObject
            } else {
                // YAML 解析 - 简化处理，假设内核返回的是 YAML
                parseYamlAsJson(zenoneContent)
            }

            if (root == null) return null

            // 提取节点
            val nodes = root.get("nodes")?.asJsonArray?.let { parseNodes(it) } ?: emptyList()

            // 提取代理组（如果有）
            val groups = root.get("groups")?.asJsonArray?.let { parseGroups(it, nodes.map { n -> n.tag }) } ?: emptyList()

            OpenWorldConfig(
                outbounds = nodes + groups
            )
        } catch (e: Exception) {
            Log.e(TAG, "Failed to parse ZenOne content", e)
            null
        }
    }

    /**
     * 解析节点数组
     */
    private fun parseNodes(array: com.google.gson.JsonArray): List<Outbound> {
        return array.mapNotNull { element ->
            try {
                parseNode(element.asJsonObject)
            } catch (e: Exception) {
                Log.w(TAG, "Failed to parse node: ${e.message}")
                null
            }
        }
    }

    /**
     * 解析单个节点
     */
    private fun parseNode(json: JsonObject): Outbound {
        val type = json.get("type")?.asString ?: "unknown"
        val name = json.get("name")?.asString ?: ""

        return Outbound(
            type = type,
            tag = name,
            server = json.get("address")?.asString,
            serverPort = json.get("port")?.asInt,
            uuid = json.get("uuid")?.asString,
            password = json.get("password")?.asString,
            method = json.get("method")?.asString,
            flow = json.get("flow")?.asString,
            alterId = json.get("alter-id")?.asInt,
            upMbps = json.get("up-mbps")?.asInt,
            downMbps = json.get("down-mbps")?.asInt,
            // TLS 配置
            tls = parseTlsConfig(json),
            // 传输层配置
            transport = parseTransportConfig(json),
            // WireGuard
            privateKey = json.get("private-key")?.asString,
            peerPublicKey = json.get("peer-public-key")?.asString,
            preSharedKey = json.get("preshared-key")?.asString,
            localAddress = json.get("local-address")?.asString?.split(","),
            mtu = json.get("mtu")?.asInt,
            // SSH
            user = json.get("username")?.asString,
            // 其他
            serverPorts = json.get("server-ports")?.asString?.split(","),
            congestionControl = json.get("congestion-control")?.asString,
            heartbeat = json.get("heartbeat")?.asString
        )
    }

    /**
     * 解析 TLS 配置
     */
    private fun parseTlsConfig(json: JsonObject): TlsConfig? {
        val tlsObj = json.get("tls")?.asJsonObject ?: return null

        // 检查是否有 TLS 配置
        val hasTls = tlsObj.has("enabled") || tlsObj.has("sni") || tlsObj.has("server_name")
        if (!hasTls) return null

        val enabled = tlsObj.get("enabled")?.asBoolean
            ?: tlsObj.get("enabled")?.asString?.toBooleanStrictOrNull()
            ?: true

        return TlsConfig(
            enabled = enabled,
            serverName = tlsObj.get("sni")?.asString
                ?: tlsObj.get("server_name")?.asString,
            insecure = tlsObj.get("insecure")?.asBoolean,
            alpn = tlsObj.get("alpn")?.asJsonArray?.map { it.asString },
            utls = tlsObj.get("fingerprint")?.asString?.let { fp ->
                UtlsConfig(enabled = true, fingerprint = fp)
            },
            // Reality
            reality = tlsObj.get("reality")?.asJsonObject?.let { r ->
                RealityConfig(
                    enabled = true,
                    publicKey = r.get("public-key")?.asString,
                    shortId = r.get("short-id")?.asString
                )
            }
        )
    }

    /**
     * 解析传输层配置
     */
    private fun parseTransportConfig(json: JsonObject): TransportConfig? {
        val network = json.get("network")?.asString ?: return null
        if (network == "tcp") return null

        return TransportConfig(
            type = network,
            path = json.get("ws-path")?.asString
                ?: json.get("http-path")?.asString
                ?: json.get("path")?.asString,
            host = json.get("host")?.asString?.split(","),
            headers = parseHeaders(json.get("ws-headers")?.asJsonObject),
            serviceName = json.get("grpc-serviceName")?.asString
                ?: json.get("service_name")?.asString,
            mode = json.get("mode")?.asString,
            maxEarlyData = json.get("ws-max-early-data")?.asInt,
            earlyDataHeaderName = json.get("early-data-header-name")?.asString
        )
    }

    /**
     * 解析 HTTP 头
     */
    private fun parseHeaders(json: JsonObject?): Map<String, String>? {
        if (json == null) return null
        return json.entrySet().associate { it.key to it.value.asString }
    }

    /**
     * 解析代理组
     */
    private fun parseGroups(array: com.google.gson.JsonArray, availableNodes: List<String>): List<Outbound> {
        return array.mapNotNull { element ->
            try {
                val json = element.asJsonObject
                val name = json.get("name")?.asString ?: return@mapNotNull null
                val groupType = json.get("type")?.asString ?: "select"

                // 解析节点列表
                val nodes = json.get("nodes")?.asJsonArray?.map { it.asString }
                    ?: json.get("proxies")?.asJsonArray?.map { it.asString }
                    ?: emptyList()

                Outbound(
                    type = groupType,
                    tag = name,
                    outbounds = nodes,
                    url = json.get("url")?.asString,
                    interval = json.get("interval")?.asString,
                    tolerance = json.get("tolerance")?.asInt,
                    default = json.get("default")?.asString
                )
            } catch (e: Exception) {
                Log.w(TAG, "Failed to parse group: ${e.message}")
                null
            }
        }
    }

    /**
     * 简化 YAML 解析 - 提取关键字段
     * 注意：这是简化实现，完整解析需要 YAML 库
     */
    private fun parseYamlAsJson(yaml: String): JsonObject? {
        try {
            val result = JsonObject()
            val lines = yaml.lines()
            var currentSection: String? = null
            var inNodes = false
            var inGroups = false

            for (line in lines) {
                val trimmed = line.trim()

                when {
                    trimmed == "nodes:" -> {
                        inNodes = true
                        inGroups = false
                        currentSection = "nodes"
                    }
                    trimmed == "groups:" -> {
                        inNodes = false
                        inGroups = true
                        currentSection = "groups"
                    }
                    trimmed.startsWith("zen-version:") -> {
                        result.addProperty("zen-version", trimmed.substringAfter(":").trim().toIntOrNull())
                    }
                    inNodes && trimmed.startsWith("- name:") -> {
                        // 简化处理：提取节点名
                        // 实际需要更完整的 YAML 解析
                    }
                }
            }

            return if (result.size() > 0) result else null
        } catch (e: Exception) {
            Log.e(TAG, "Failed to parse YAML", e)
            return null
        }
    }

    /**
     * 检测订阅格式
     */
    fun detectFormat(content: String): SubscriptionFormat {
        return try {
            val root = JsonParser.parseString(content).asJsonObject

            // ZenOne 检测
            if (root.has("zen-version")) {
                return SubscriptionFormat.ZENONE
            }

            // sing-box 检测
            if (root.has("outbounds")) {
                return SubscriptionFormat.SINGBOX
            }

            // Clash 检测
            if (root.has("proxies")) {
                return SubscriptionFormat.CLASH
            }

            SubscriptionFormat.UNKNOWN
        } catch (e: Exception) {
            // 可能是 YAML 或纯文本
            when {
                content.contains("zen-version:") -> SubscriptionFormat.ZENONE
                content.contains("proxies:") -> SubscriptionFormat.CLASH
                content.contains("outbounds:") -> SubscriptionFormat.SINGBOX
                content.contains("://") -> SubscriptionFormat.URI
                else -> SubscriptionFormat.UNKNOWN
            }
        }
    }

    /**
     * 获取订阅内容中的节点名称列表（用于检测）
     */
    fun extractNodeNames(zenoneContent: String): List<String> {
        return try {
            val root = if (zenoneContent.trim().startsWith("{")) {
                JsonParser.parseString(zenoneContent).asJsonObject
            } else {
                // YAML 简化解析
                parseYamlAsJson(zenoneContent)
            } ?: return emptyList()

            root.get("nodes")?.asJsonArray?.mapNotNull { node ->
                node.asJsonObject.get("name")?.asString
            } ?: emptyList()
        } catch (e: Exception) {
            emptyList()
        }
    }
}

/**
 * 订阅格式枚举
 */
enum class SubscriptionFormat {
    ZENONE,   // ZenOne 格式
    CLASH,    // Clash YAML
    SINGBOX,  // sing-box JSON
    BASE64,   // Base64 编码
    URI,      // 单节点链接
    UNKNOWN   // 未知格式
}
