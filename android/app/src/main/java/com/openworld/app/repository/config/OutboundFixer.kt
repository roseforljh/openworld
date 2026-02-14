package com.openworld.app.repository.config

import com.openworld.app.model.Outbound
import com.openworld.app.repository.SettingsRepository

/**
 * Outbound 运行时修复器
 * 处理各种协议的配置修复和规范�? */
object OutboundFixer {

    // TCP Keepalive 配置缓存
    private var cachedTcpKeepAliveEnabled: Boolean? = null
    private var cachedTcpKeepAliveInterval: String? = null
    private var cachedConnectTimeout: String? = null

    /**
     * 获取 TCP Keepalive 配置
     * �?SettingsRepository 读取并缓�?     */
    private fun getTcpKeepAliveConfig(context: android.content.Context): Triple<Boolean, String?, String?> {
        // 如果已缓存，直接返回
        if (cachedTcpKeepAliveEnabled != null) {
            return Triple(cachedTcpKeepAliveEnabled!!, cachedTcpKeepAliveInterval, cachedConnectTimeout)
        }

        // �?SettingsRepository 读取
        val settings = SettingsRepository.getInstance(context).settings.value
        val enabled = settings.tcpKeepAliveEnabled
        val interval = if (enabled) "${settings.tcpKeepAliveInterval}s" else null
        val timeout = if (enabled) "${settings.connectTimeout}s" else null

        // 缓存配置
        cachedTcpKeepAliveEnabled = enabled
        cachedTcpKeepAliveInterval = interval
        cachedConnectTimeout = timeout

        return Triple(enabled, interval, timeout)
    }

    /**
     * 清除 TCP Keepalive 配置缓存
     * 当设置变更时调用
     */
    fun clearTcpKeepAliveCache() {
        cachedTcpKeepAliveEnabled = null
        cachedTcpKeepAliveInterval = null
        cachedConnectTimeout = null
    }

    // 正则表达式常�?    private val REGEX_INTERVAL_DIGITS = Regex("^\\d+$")
    private val REGEX_INTERVAL_DECIMAL = Regex("^\\d+\\.\\d+$")
    private val REGEX_INTERVAL_UNIT = Regex("^\\d+(\\.\\d+)?[smhSMH]$")
    private val REGEX_IPV4 = Regex("^\\d{1,3}(\\.\\d{1,3}){3}$")
    private val REGEX_IPV6 = Regex("^[0-9a-fA-F:]+$")
    private val REGEX_ED_PARAM_START = Regex("\\?ed=\\d+")
    private val REGEX_ED_PARAM_MID = Regex("&ed=\\d+")

    /**
     * 运行时修�?Outbound 配置
     * 包括：修�?interval 单位、清�?flow、补�?ALPN、补�?User-Agent、补充缺省�?     */
    fun fix(outbound: Outbound): Outbound {
        var result = outbound

        // Fix interval
        val interval = result.interval
        if (interval != null) {
            val fixedInterval = when {
                REGEX_INTERVAL_DIGITS.matches(interval) -> "${interval}s"
                REGEX_INTERVAL_DECIMAL.matches(interval) -> "${interval}s"
                REGEX_INTERVAL_UNIT.matches(interval) -> interval.lowercase()
                else -> interval
            }
            if (fixedInterval != interval) {
                result = result.copy(interval = fixedInterval)
            }
        }

        // Fix flow
        val cleanedFlow = result.flow?.takeIf { it.isNotBlank() }
        val normalizedFlow = cleanedFlow?.let { flowValue ->
            if (flowValue.contains("xtls-rprx-vision")) {
                "xtls-rprx-vision"
            } else {
                flowValue
            }
        }
        if (normalizedFlow != result.flow) {
            result = result.copy(flow = normalizedFlow)
        }

        // Fix URLTest - Convert to selector to avoid sing-box core panic during InterfaceUpdated
        if (result.type == "urltest" || result.type == "url-test") {
            var newOutbounds = result.outbounds
            if (newOutbounds.isNullOrEmpty()) {
                newOutbounds = listOf("direct")
            }

            result = result.copy(
                type = "selector",
                outbounds = newOutbounds,
                default = newOutbounds.firstOrNull(),
                interruptExistConnections = false,
                url = null,
                interval = null,
                tolerance = null
            )
        }

        // Fix Selector empty outbounds
        if (result.type == "selector" && result.outbounds.isNullOrEmpty()) {
            result = result.copy(outbounds = listOf("direct"))
        }

        // Fix TLS SNI for WebSocket
        val tls = result.tls
        val transport = result.transport
        if (transport?.type == "ws" && tls?.enabled == true) {
            val wsHost = transport.headers?.get("Host")
                ?: transport.headers?.get("host")
                ?: transport.host?.firstOrNull()
            val sni = tls.serverName?.trim().orEmpty()
            val server = result.server?.trim().orEmpty()
            if (!wsHost.isNullOrBlank() && !isIpLiteral(wsHost)) {
                val needFix = sni.isBlank() || isIpLiteral(sni) || (server.isNotBlank() && sni.equals(server, ignoreCase = true))
                if (needFix && !wsHost.equals(sni, ignoreCase = true)) {
                    result = result.copy(tls = tls.copy(serverName = wsHost))
                }
            }
        }

        // Fix ALPN for WebSocket + TLS
        val tlsAfterSni = result.tls
        if (result.transport?.type == "ws" && tlsAfterSni?.enabled == true && (tlsAfterSni.alpn == null || tlsAfterSni.alpn.isEmpty())) {
            result = result.copy(tls = tlsAfterSni.copy(alpn = listOf("http/1.1")))
        }

        // Fix User-Agent and path for WS
        if (transport != null && transport.type == "ws") {
            val headers = transport.headers?.toMutableMap() ?: mutableMapOf()
            var needUpdate = false

            if (!headers.containsKey("Host")) {
                val host = transport.host?.firstOrNull()
                    ?: result.tls?.serverName
                    ?: result.server
                if (!host.isNullOrBlank()) {
                    headers["Host"] = host
                    needUpdate = true
                }
            }

            if (!headers.containsKey("User-Agent")) {
                val fingerprint = result.tls?.utls?.fingerprint
                val userAgent = if (fingerprint?.contains("chrome") == true) {
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36"
                } else {
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/115.0"
                }
                headers["User-Agent"] = userAgent
                needUpdate = true
            }

            val rawPath = transport.path ?: "/"
            val cleanPath = rawPath
                .replace(REGEX_ED_PARAM_START, "")
                .replace(REGEX_ED_PARAM_MID, "")
                .trimEnd('?', '&')
                .ifEmpty { "/" }

            val pathChanged = cleanPath != rawPath

            if (needUpdate || pathChanged) {
                result = result.copy(transport = transport.copy(
                    headers = headers,
                    path = cleanPath
                ))
            }
        }

        // 强制清理 VLESS 协议中的 security 字段 (sing-box 不支�?
        if (result.type == "vless" && result.security != null) {
            result = result.copy(security = null)
        }

        // Hysteria/Hysteria2: 补充缺省带宽，清理空字符串字段，修复端口范围格式
        if (result.type == "hysteria" || result.type == "hysteria2") {
            val up = result.upMbps
            val down = result.downMbps
            val defaultMbps = 50
            // 清理空的 serverPorts 列表，并将短横线端口范围 (40000-50000) 转换�?sing-box 格式 (40000:50000)
            val cleanedServerPorts = result.serverPorts
                ?.filter { it.isNotBlank() }
                ?.map { convertPortRangeFormat(it) }
                ?.takeIf { it.isNotEmpty() }
            val cleanedHopInterval = result.hopInterval?.takeIf { it.isNotBlank() }
            result = result.copy(
                upMbps = up ?: defaultMbps,
                downMbps = down ?: defaultMbps,
                serverPorts = cleanedServerPorts,
                hopInterval = cleanedHopInterval
            )
        }

        // 补齐 VMess packetEncoding 缺省�?        if (result.type == "vmess" && result.packetEncoding.isNullOrBlank()) {
            result = result.copy(packetEncoding = "xudp")
        }

        // 清理 TLS 配置中的�?ALPN 列表（sing-box 不接受空数组�?        val currentTls = result.tls
        if (currentTls != null && currentTls.alpn?.isEmpty() == true) {
            result = result.copy(tls = currentTls.copy(alpn = null))
        }

        return result
    }

    /**
     * 构建运行�?Outbound，只保留必要字段
     * @param context Android Context，用于读�?TCP Keepalive 配置
     */
    @Suppress("LongMethod")
    fun buildForRuntime(context: android.content.Context, outbound: Outbound): Outbound {
        val fixed = fix(outbound)

        // 获取 TCP Keepalive 配置
        val (tcpKeepAliveEnabled, tcpKeepAliveInterval, connectTimeout) = getTcpKeepAliveConfig(context)

        return when (fixed.type) {
            "selector", "urltest", "url-test" -> Outbound(
                type = "selector",
                tag = fixed.tag,
                outbounds = fixed.outbounds,
                default = fixed.default,
                interruptExistConnections = fixed.interruptExistConnections
            )

            "direct", "block", "dns" -> Outbound(type = fixed.type, tag = fixed.tag)

            "vmess" -> Outbound(
                type = fixed.type,
                tag = fixed.tag,
                server = fixed.server,
                serverPort = fixed.serverPort,
                uuid = fixed.uuid,
                alterId = fixed.alterId,
                security = fixed.security,
                packetEncoding = fixed.packetEncoding,
                tls = fixed.tls,
                transport = fixed.transport,
                multiplex = fixed.multiplex,
                // TCP Keepalive 参数 (完美方案 - 防止连接假死)
                tcpKeepAlive = tcpKeepAliveInterval,
                tcpKeepAliveInterval = tcpKeepAliveInterval,
                connectTimeout = connectTimeout
            )

            "vless" -> Outbound(
                type = fixed.type,
                tag = fixed.tag,
                server = fixed.server,
                serverPort = fixed.serverPort,
                uuid = fixed.uuid,
                flow = fixed.flow,
                packetEncoding = fixed.packetEncoding,
                tls = fixed.tls,
                transport = fixed.transport,
                multiplex = fixed.multiplex,
                // TCP Keepalive 参数 (完美方案 - 防止连接假死)
                tcpKeepAlive = tcpKeepAliveInterval,
                tcpKeepAliveInterval = tcpKeepAliveInterval,
                connectTimeout = connectTimeout
            )

            "trojan" -> Outbound(
                type = fixed.type,
                tag = fixed.tag,
                server = fixed.server,
                serverPort = fixed.serverPort,
                password = fixed.password,
                tls = fixed.tls,
                transport = fixed.transport,
                multiplex = fixed.multiplex,
                // TCP Keepalive 参数 (完美方案 - 防止连接假死)
                tcpKeepAlive = tcpKeepAliveInterval,
                tcpKeepAliveInterval = tcpKeepAliveInterval,
                connectTimeout = connectTimeout
            )

            "shadowsocks" -> Outbound(
                type = fixed.type,
                tag = fixed.tag,
                server = fixed.server,
                serverPort = fixed.serverPort,
                method = fixed.method,
                password = fixed.password,
                plugin = fixed.plugin,
                pluginOpts = fixed.pluginOpts,
                udpOverTcp = fixed.udpOverTcp,
                multiplex = fixed.multiplex,
                detour = fixed.detour,
                network = fixed.network,
                // TCP Keepalive 参数 (完美方案 - 防止连接假死)
                tcpKeepAlive = tcpKeepAliveInterval,
                tcpKeepAliveInterval = tcpKeepAliveInterval,
                connectTimeout = connectTimeout
            )

            "hysteria", "hysteria2" -> Outbound(
                type = fixed.type,
                tag = fixed.tag,
                server = fixed.server,
                serverPort = fixed.serverPort,
                password = fixed.password,
                authStr = fixed.authStr,
                upMbps = fixed.upMbps,
                downMbps = fixed.downMbps,
                obfs = fixed.obfs,
                recvWindowConn = fixed.recvWindowConn,
                recvWindow = fixed.recvWindow,
                disableMtuDiscovery = fixed.disableMtuDiscovery,
                hopInterval = fixed.hopInterval,
                serverPorts = fixed.serverPorts,
                tls = fixed.tls,
                multiplex = fixed.multiplex,
                // TCP Keepalive 参数 (完美方案 - 防止连接假死)
                tcpKeepAlive = tcpKeepAliveInterval,
                tcpKeepAliveInterval = tcpKeepAliveInterval,
                connectTimeout = connectTimeout
            )

            "tuic" -> Outbound(
                type = fixed.type,
                tag = fixed.tag,
                server = fixed.server,
                serverPort = fixed.serverPort,
                uuid = fixed.uuid,
                password = fixed.password,
                congestionControl = fixed.congestionControl,
                udpRelayMode = fixed.udpRelayMode,
                zeroRttHandshake = fixed.zeroRttHandshake,
                heartbeat = fixed.heartbeat,
                disableSni = fixed.disableSni,
                mtu = fixed.mtu,
                tls = fixed.tls,
                multiplex = fixed.multiplex,
                // TCP Keepalive 参数 (完美方案 - 防止连接假死)
                tcpKeepAlive = tcpKeepAliveInterval,
                tcpKeepAliveInterval = tcpKeepAliveInterval,
                connectTimeout = connectTimeout
            )

            "anytls" -> Outbound(
                type = fixed.type,
                tag = fixed.tag,
                server = fixed.server,
                serverPort = fixed.serverPort,
                password = fixed.password,
                idleSessionCheckInterval = fixed.idleSessionCheckInterval,
                idleSessionTimeout = fixed.idleSessionTimeout,
                minIdleSession = fixed.minIdleSession,
                tls = fixed.tls,
                multiplex = fixed.multiplex,
                // TCP Keepalive 参数 (完美方案 - 防止连接假死)
                tcpKeepAlive = tcpKeepAliveInterval,
                tcpKeepAliveInterval = tcpKeepAliveInterval,
                connectTimeout = connectTimeout
            )

            "wireguard" -> Outbound(
                type = fixed.type,
                tag = fixed.tag,
                localAddress = fixed.localAddress,
                privateKey = fixed.privateKey,
                peerPublicKey = fixed.peerPublicKey,
                preSharedKey = fixed.preSharedKey,
                reserved = fixed.reserved,
                peers = fixed.peers,
                // TCP Keepalive 参数 (完美方案 - 防止连接假死)
                tcpKeepAlive = tcpKeepAliveInterval,
                tcpKeepAliveInterval = tcpKeepAliveInterval,
                connectTimeout = connectTimeout
            )

            "ssh" -> Outbound(
                type = fixed.type,
                tag = fixed.tag,
                server = fixed.server,
                serverPort = fixed.serverPort,
                user = fixed.user,
                password = fixed.password,
                privateKeyPath = fixed.privateKeyPath,
                privateKeyPassphrase = fixed.privateKeyPassphrase,
                hostKey = fixed.hostKey,
                hostKeyAlgorithms = fixed.hostKeyAlgorithms,
                clientVersion = fixed.clientVersion,
                // TCP Keepalive 参数 (完美方案 - 防止连接假死)
                tcpKeepAlive = tcpKeepAliveInterval,
                tcpKeepAliveInterval = tcpKeepAliveInterval,
                connectTimeout = connectTimeout
            )

            "shadowtls" -> Outbound(
                type = fixed.type,
                tag = fixed.tag,
                server = fixed.server,
                serverPort = fixed.serverPort,
                version = fixed.version,
                password = fixed.password,
                tls = fixed.tls,
                // TCP Keepalive 参数 (完美方案 - 防止连接假死)
                tcpKeepAlive = tcpKeepAliveInterval,
                tcpKeepAliveInterval = tcpKeepAliveInterval,
                connectTimeout = connectTimeout
            )

            else -> fixed
        }
    }

    private fun isIpLiteral(value: String): Boolean {
        val v = value.trim()
        if (v.isEmpty()) return false
        if (REGEX_IPV4.matches(v)) {
            return v.split(".").all { it.toIntOrNull()?.let { n -> n in 0..255 } == true }
        }
        return v.contains(":") && REGEX_IPV6.matches(v)
    }

    /**
     * 将端口范围从短横线格�?(40000-50000) 转换�?sing-box 格式 (40000:50000)
     * 支持逗号分隔的多个范围，�?"40000-50000,60000-70000"
     */
    private fun convertPortRangeFormat(portSpec: String): String {
        return portSpec.split(",").joinToString(",") { part ->
            val trimmed = part.trim()
            if (trimmed.contains("-") && !trimmed.contains(":")) {
                trimmed.replace("-", ":")
            } else {
                trimmed
            }
        }
    }
}







