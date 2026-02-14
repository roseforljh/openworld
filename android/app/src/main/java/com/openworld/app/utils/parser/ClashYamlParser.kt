package com.openworld.app.utils.parser

import com.openworld.app.model.MultiplexConfig
import com.openworld.app.model.Outbound
import com.openworld.app.model.OpenWorldConfig
import com.openworld.app.model.TlsConfig
import com.openworld.app.model.TransportConfig
import com.openworld.app.model.UtlsConfig
import org.yaml.snakeyaml.Yaml
import org.yaml.snakeyaml.error.YAMLException

/**
 * YAML 订阅格式解析�? */
class ClashYamlParser : SubscriptionParser {
    override fun canParse(content: String): Boolean {
        val trimmed = content.trim()

        // 排除明显是节点链接的情况
        val nodeLinkPrefixes = listOf(
            "vmess://", "vless://", "ss://", "trojan://",
            "hysteria2://", "hy2://", "hysteria://",
            "tuic://", "anytls://", "wireguard://", "ssh://"
        )
        if (nodeLinkPrefixes.any { trimmed.startsWith(it) }) {
            return false
        }

        // 简单特征判断：包含 proxies: �?proxy-groups: 关键�?        return trimmed.contains("proxies:") || trimmed.contains("proxy-groups:")
    }

    override fun parse(content: String): OpenWorldConfig? {
        val root = try {
            Yaml().load<Any>(content)
        } catch (_: YAMLException) {
            return null
        } catch (_: Exception) {
            return null
        }

        val rootMap = (root as? Map<*, *>) ?: return null
        val proxiesRaw = rootMap["proxies"] as? List<*> ?: return null

        // 读取全局客户端指纹（扩展 YAML 特性）
        val globalClientFingerprint = asString(rootMap["global-client-fingerprint"])

        // 读取全局 TLS 版本限制（扩�?YAML 特性）
        // 格式: tls-version: "1.3" �?min-tls-version: "1.3"
        val globalTlsMinVersion = asString(rootMap["tls-version"])
            ?: asString(rootMap["min-tls-version"])

        val outbounds = mutableListOf<Outbound>()
        var skippedCount = 0

        for (p in proxiesRaw) {
            val m = p as? Map<*, *> ?: continue

            val obs = parseProxy(m, globalClientFingerprint, globalTlsMinVersion)
            if (obs != null && obs.isNotEmpty()) {
                outbounds.addAll(obs)
            } else {
                skippedCount++
            }
        }

        if (skippedCount > 0) {
            android.util.Log.d("ClashYamlParser", "Parsed ${outbounds.size} proxies, skipped $skippedCount")
        }

        // 解析 proxy-groups
        val proxyGroupsRaw = rootMap["proxy-groups"] as? List<*>
        if (proxyGroupsRaw != null) {
            for (g in proxyGroupsRaw) {
                val gm = g as? Map<*, *> ?: continue
                val name = asString(gm["name"]) ?: continue
                val type = asString(gm["type"])?.lowercase() ?: continue
                val proxies = (gm["proxies"] as? List<*>)?.mapNotNull { asString(it) }?.filter { it.isNotBlank() } ?: emptyList()
                if (proxies.isEmpty()) continue

                when (type) {
                    "select", "selector" -> {
                        outbounds.add(
                            Outbound(
                                type = "selector",
                                tag = name,
                                outbounds = proxies,
                                default = proxies.firstOrNull(),
                                interruptExistConnections = false
                            )
                        )
                    }
                    "url-test", "urltest" -> {
                        val url = asString(gm["url"]) ?: "http://www.gstatic.com/generate_204"
                        val interval = asString(gm["interval"]) ?: asInt(gm["interval"])?.toString() ?: "300s"
                        val tolerance = asInt(gm["tolerance"]) ?: 50
                        outbounds.add(
                            Outbound(
                                type = "urltest",
                                tag = name,
                                outbounds = proxies,
                                url = url,
                                interval = interval,
                                tolerance = tolerance,
                                interruptExistConnections = false
                            )
                        )
                    }
                }
            }
        }

        // 如果没有解析出任何代理节点，返回 null
        if (outbounds.isEmpty()) return null

        return OpenWorldConfig(outbounds = outbounds)
    }

    private fun parseProxy(proxyMap: Map<*, *>, globalFingerprint: String? = null, globalTlsMinVersion: String? = null): List<Outbound>? {
        val name = asString(proxyMap["name"]) ?: run {
            android.util.Log.w("ClashYamlParser", "Proxy missing name field: ${proxyMap.keys}")
            return null
        }
        val type = asString(proxyMap["type"])?.lowercase() ?: run {
            android.util.Log.w("ClashYamlParser", "Proxy '$name' missing type field")
            return null
        }

        val server = asString(proxyMap["server"])
        val port = asInt(proxyMap["port"])

        // SS + ShadowTLS 插件需要返回多�?outbound
        if (type == "ss" || type == "shadowsocks") {
            val outbounds = parseShadowsocksWithPlugin(proxyMap, name, server, port, globalFingerprint)
            if (outbounds != null && outbounds.isNotEmpty()) {
                return outbounds
            }
            return null
        }

        val outbound = when (type) {
            "vless" -> parseVLess(proxyMap, name, server, port, globalFingerprint, globalTlsMinVersion)
            "vmess" -> parseVMess(proxyMap, name, server, port, globalFingerprint, globalTlsMinVersion)
            "trojan" -> parseTrojan(proxyMap, name, server, port, globalFingerprint, globalTlsMinVersion)
            "hysteria2", "hy2" -> parseHysteria2(proxyMap, name, server, port, globalFingerprint, globalTlsMinVersion)
            "hysteria" -> parseHysteria(proxyMap, name, server, port, globalFingerprint, globalTlsMinVersion)
            "tuic", "tuic-v5" -> parseTuic(proxyMap, name, server, port, globalFingerprint, globalTlsMinVersion)
            "anytls" -> parseAnyTLS(proxyMap, name, server, port, globalFingerprint, globalTlsMinVersion)
            "ssh" -> parseSSH(proxyMap, name, server, port)
            "wireguard" -> parseWireGuard(proxyMap, name, server, port)
            "http" -> parseHttp(proxyMap, name, server, port, globalFingerprint, globalTlsMinVersion)
            "socks5" -> parseSocks(proxyMap, name, server, port)
            "shadowtls" -> parseShadowTLS(proxyMap, name, server, port, globalFingerprint)
            else -> null
        }

        if (outbound == null && (type.contains("tuic") || type.contains("anytls"))) {
            android.util.Log.w("ClashYamlParser", "Failed to parse $type node '$name'. Server: $server, Port: $port, Map: $proxyMap")
        }

        return outbound?.let { listOf(it) }
    }

    private fun parseVLess(map: Map<*, *>, name: String, server: String?, port: Int?, globalFingerprint: String? = null, globalTlsMinVersion: String? = null): Outbound? {
        if (server == null || port == null) return null
        val uuid = asString(map["uuid"]) ?: return null
        val network = asString(map["network"])?.lowercase()
        val tlsEnabled = asBool(map["tls"]) == true
        val serverName = asString(map["servername"]) ?: asString(map["sni"]) ?: server
        // 优先使用节点配置的指纹，否则使用全局指纹
        val fingerprint = asString(map["client-fingerprint"]) ?: globalFingerprint
        val insecure = asBool(map["skip-cert-verify"]) == true
        val alpn = asStringList(map["alpn"])
        val flow = asString(map["flow"])
        val packetEncoding = asString(map["packet-encoding"]) ?: "xudp"

        // TLS 版本限制
        val tlsMinVersion = asString(map["tls-version"]) ?: asString(map["min-tls-version"]) ?: globalTlsMinVersion

        // Reality support
        val realityOpts = map["reality-opts"] as? Map<*, *>
        val realityPublicKey = asString(realityOpts?.get("public-key"))
        val realityShortId = asString(realityOpts?.get("short-id"))

        // 自动补充 ALPN
        val finalAlpn = if (tlsEnabled && network == "ws" && (alpn == null || alpn.isEmpty())) listOf("http/1.1") else alpn

        val tlsConfig = if (tlsEnabled) {
            TlsConfig(
                enabled = true,
                serverName = serverName,
                insecure = insecure,
                alpn = finalAlpn,
                minVersion = tlsMinVersion,
                utls = fingerprint?.let { UtlsConfig(enabled = true, fingerprint = it) },
                reality = if (realityPublicKey != null) {
                    com.openworld.app.model.RealityConfig(
                        enabled = true,
                        publicKey = realityPublicKey,
                        shortId = realityShortId
                    )
                } else null
            )
        } else null

        val transport = when (network) {
            "ws" -> {
                val wsOpts = map["ws-opts"] as? Map<*, *>
                val path = asString(wsOpts?.get("path")) ?: "/"
                val headersRaw = wsOpts?.get("headers") as? Map<*, *>
                val headers = mutableMapOf<String, String>()
                headersRaw?.forEach { (k, v) ->
                    val ks = asString(k) ?: return@forEach
                    val vs = asString(v) ?: return@forEach
                    headers[ks] = vs
                }

                // 自动补充 Host �?User-Agent
                val host = headers["Host"] ?: headers["host"] ?: serverName
                if (!host.isNullOrBlank()) headers["Host"] = host

                if (!headers.containsKey("User-Agent")) {
                    headers["User-Agent"] = getUserAgent(fingerprint)
                }

                // 处理 max-early-data
                val maxEarlyData = asInt(wsOpts?.get("max-early-data")) ?: 2048
                val earlyDataHeaderName = asString(wsOpts?.get("early-data-header-name")) ?: "Sec-WebSocket-Protocol"

                // 检�?httpupgrade (v2ray-http-upgrade)
                val isHttpUpgrade = asBool(wsOpts?.get("v2ray-http-upgrade")) == true

                TransportConfig(
                    type = if (isHttpUpgrade) "httpupgrade" else "ws",
                    path = path,
                    headers = headers,
                    maxEarlyData = if (isHttpUpgrade) null else maxEarlyData,
                    earlyDataHeaderName = if (isHttpUpgrade) null else earlyDataHeaderName
                )
            }
            "grpc" -> {
                val grpcOpts = map["grpc-opts"] as? Map<*, *>
                val serviceName = asString(grpcOpts?.get("grpc-service-name"))
                    ?: asString(grpcOpts?.get("service-name"))
                    ?: asString(map["grpc-service-name"])
                    ?: ""
                TransportConfig(type = "grpc", serviceName = serviceName)
            }
            "h2", "http" -> {
                val h2Opts = map["h2-opts"] as? Map<*, *>
                val path = asString(map["path"]) ?: asString(h2Opts?.get("path"))
                val host = asString(map["host"])?.let { listOf(it) } ?: asStringList(h2Opts?.get("host"))
                TransportConfig(type = "http", path = path, host = host)
            }
            "xhttp", "splithttp" -> {
                val xhttpOpts = map["xhttp-opts"] as? Map<*, *>
                    ?: map["splithttp-opts"] as? Map<*, *>
                val path = asString(xhttpOpts?.get("path")) ?: "/"
                val host = asString(xhttpOpts?.get("host"))?.let { listOf(it) }
                val mode = asString(xhttpOpts?.get("mode"))
                val xPaddingBytes = asString(xhttpOpts?.get("xPaddingBytes"))
                    ?: asString(xhttpOpts?.get("x-padding-bytes"))
                TransportConfig(
                    type = "xhttp",
                    path = path,
                    host = host,
                    mode = mode,
                    xPaddingBytes = xPaddingBytes
                )
            }
            else -> null
        }

        // 解析 smux 多路复用配置
        val multiplex = parseSmux(map)

        return Outbound(
            type = "vless",
            tag = name,
            server = server,
            serverPort = port,
            uuid = uuid,
            flow = flow,
            tls = tlsConfig,
            transport = transport,
            packetEncoding = packetEncoding,
            multiplex = multiplex
        )
    }

    private fun parseVMess(map: Map<*, *>, name: String, server: String?, port: Int?, globalFingerprint: String? = null, globalTlsMinVersion: String? = null): Outbound? {
        if (server == null || port == null) return null
        val uuid = asString(map["uuid"]) ?: return null
        // 注意：sing-box 1.9+ 支持 alter_id (legacy VMess MD5)
        val alterId = asInt(map["alterId"]) ?: 0
        android.util.Log.i("ClashYamlParser", "VMess node '$name': alterId=$alterId (raw=${map["alterId"]})")
        val cipher = asString(map["cipher"]) ?: "auto"
        val network = asString(map["network"])?.lowercase()
        val tlsEnabled = asBool(map["tls"]) == true
        val serverName = asString(map["servername"]) ?: asString(map["sni"]) ?: server
        // 优先使用节点配置的指纹，否则使用全局指纹
        val fingerprint = asString(map["client-fingerprint"]) ?: globalFingerprint
        // 对于 VMess，如果没有明确设�?skip-cert-verify，默认跳过证书验�?        // 因为很多 VMess 节点使用自签名证书或动态域�?        // 即使设置�?skip-cert-verify: false，对于看起来像动态域名的也强制跳�?        val skipCertVerifyValue = map["skip-cert-verify"]
        val insecure = when {
            skipCertVerifyValue == null -> true
            asBool(skipCertVerifyValue) == true -> true
            // 对于动态域名（包含多个连字符的随机子域名），强制跳过证书验�?            server.count { it == '-' } >= 2 && server.split(".").firstOrNull()?.length ?: 0 > 10 -> true
            else -> false
        }
        val alpn = asStringList(map["alpn"])
        val packetEncoding = asString(map["packet-encoding"]) ?: "xudp"

        // TLS 版本限制
        val tlsMinVersion = asString(map["tls-version"]) ?: asString(map["min-tls-version"]) ?: globalTlsMinVersion

        val finalAlpn = if (tlsEnabled && network == "ws" && (alpn == null || alpn.isEmpty())) listOf("http/1.1") else alpn

        val tlsConfig = if (tlsEnabled) {
            TlsConfig(
                enabled = true,
                serverName = serverName,
                insecure = insecure,
                alpn = finalAlpn,
                minVersion = tlsMinVersion,
                utls = fingerprint?.let { UtlsConfig(enabled = true, fingerprint = it) }
            )
        } else null

        val transport = when (network) {
            "ws" -> {
                val wsOpts = map["ws-opts"] as? Map<*, *>
                val path = asString(wsOpts?.get("path")) ?: "/"
                val headersRaw = wsOpts?.get("headers") as? Map<*, *>
                val headers = mutableMapOf<String, String>()
                headersRaw?.forEach { (k, v) ->
                    val ks = asString(k) ?: return@forEach
                    val vs = asString(v) ?: return@forEach
                    headers[ks] = vs
                }
                val host = headers["Host"] ?: headers["host"] ?: serverName
                if (!host.isNullOrBlank()) headers["Host"] = host
                if (!headers.containsKey("User-Agent")) {
                    headers["User-Agent"] = getUserAgent(fingerprint)
                }

                // 处理 max-early-data
                val maxEarlyData = asInt(wsOpts?.get("max-early-data")) ?: 2048
                val earlyDataHeaderName = asString(wsOpts?.get("early-data-header-name")) ?: "Sec-WebSocket-Protocol"

                // 检�?httpupgrade (v2ray-http-upgrade)
                val isHttpUpgrade = asBool(wsOpts?.get("v2ray-http-upgrade")) == true

                TransportConfig(
                    type = if (isHttpUpgrade) "httpupgrade" else "ws",
                    path = path,
                    headers = headers,
                    maxEarlyData = if (isHttpUpgrade) null else maxEarlyData,
                    earlyDataHeaderName = if (isHttpUpgrade) null else earlyDataHeaderName
                )
            }
            "grpc" -> {
                val grpcOpts = map["grpc-opts"] as? Map<*, *>
                val serviceName = asString(grpcOpts?.get("grpc-service-name")) ?: ""
                TransportConfig(type = "grpc", serviceName = serviceName)
            }
            "h2", "http" -> {
                val h2Opts = map["h2-opts"] as? Map<*, *>
                val path = asString(h2Opts?.get("path"))
                val host = asStringList(h2Opts?.get("host"))
                TransportConfig(type = "http", path = path, host = host)
            }
            "xhttp", "splithttp" -> {
                val xhttpOpts = map["xhttp-opts"] as? Map<*, *>
                    ?: map["splithttp-opts"] as? Map<*, *>
                val path = asString(xhttpOpts?.get("path")) ?: "/"
                val host = asString(xhttpOpts?.get("host"))?.let { listOf(it) }
                val mode = asString(xhttpOpts?.get("mode"))
                val xPaddingBytes = asString(xhttpOpts?.get("xPaddingBytes"))
                    ?: asString(xhttpOpts?.get("x-padding-bytes"))
                TransportConfig(
                    type = "xhttp",
                    path = path,
                    host = host,
                    mode = mode,
                    xPaddingBytes = xPaddingBytes
                )
            }
            else -> null
        }

        // 解析 smux 多路复用配置
        val multiplex = parseSmux(map)

        return Outbound(
            type = "vmess",
            tag = name,
            server = server,
            serverPort = port,
            uuid = uuid,
            alterId = if (alterId > 0) alterId else null,
            // alterId 字段已添加到 Outbound 模型，sing-box 1.9+ 支持 legacy VMess
            security = cipher,
            tls = tlsConfig,
            transport = transport,
            packetEncoding = packetEncoding,
            multiplex = multiplex
        )
    }

    /**
     * SS + ShadowTLS/obfs 插件解析
     *
     * YAML 格式 (plugin: shadow-tls):
     *   - type: ss
     *     plugin: shadow-tls
     *     plugin-opts:
     *       host: example.com
     *       password: xxx
     *       version: 3
     *
     * sing-box 需要两�?outbound:
     *   1. shadowtls outbound (连接实际服务�?
     *   2. shadowsocks outbound (通过 detour 指向 shadowtls)
     */
    private fun parseShadowsocksWithPlugin(
        map: Map<*, *>,
        name: String,
        server: String?,
        port: Int?,
        globalFingerprint: String?
    ): List<Outbound>? {
        if (server == null || port == null) return null
        val cipher = asString(map["cipher"]) ?: return null
        val password = asString(map["password"]) ?: return null
        val plugin = asString(map["plugin"])?.lowercase()
        val pluginOpts = map["plugin-opts"] as? Map<*, *>

        val multiplex = parseSmux(map)
        val udpEnabled = asBool(map["udp"]) != false

        when (plugin) {
            "shadow-tls", "shadowtls" -> {
                if (pluginOpts == null) {
                    android.util.Log.w("ClashYamlParser", "SS node '$name' has shadow-tls plugin but no plugin-opts")
                    return null
                }

                val stlsPassword = asString(pluginOpts["password"]) ?: return null
                val stlsVersion = asInt(pluginOpts["version"]) ?: 3
                val stlsHost = asString(pluginOpts["host"]) ?: server
                val fingerprint = asString(map["client-fingerprint"]) ?: globalFingerprint

                val shadowTlsTag = "${name}_shadowtls"

                val shadowTlsOutbound = Outbound(
                    type = "shadowtls",
                    tag = shadowTlsTag,
                    server = server,
                    serverPort = port,
                    version = stlsVersion,
                    password = stlsPassword,
                    tls = TlsConfig(
                        enabled = true,
                        serverName = stlsHost,
                        utls = fingerprint?.let { UtlsConfig(enabled = true, fingerprint = it) }
                    )
                )

                val ssOutbound = Outbound(
                    type = "shadowsocks",
                    tag = name,
                    method = cipher,
                    password = password,
                    detour = shadowTlsTag,
                    multiplex = multiplex,
                    network = if (!udpEnabled) "tcp" else null
                )

                return listOf(ssOutbound, shadowTlsOutbound)
            }

            "obfs", "obfs-local", "simple-obfs" -> {
                val obfsMode = asString(pluginOpts?.get("mode"))?.lowercase()
                val obfsHost = asString(pluginOpts?.get("host")) ?: server

                val transport = when (obfsMode) {
                    "http" -> TransportConfig(
                        type = "http",
                        host = listOf(obfsHost)
                    )
                    "tls" -> null
                    else -> null
                }

                return listOf(Outbound(
                    type = "shadowsocks",
                    tag = name,
                    server = server,
                    serverPort = port,
                    method = cipher,
                    password = password,
                    multiplex = multiplex,
                    transport = transport,
                    network = if (!udpEnabled) "tcp" else null
                ))
            }

            "v2ray-plugin" -> {
                val mode = asString(pluginOpts?.get("mode"))?.lowercase() ?: "websocket"
                val tlsEnabled = asBool(pluginOpts?.get("tls")) == true
                val host = asString(pluginOpts?.get("host")) ?: server
                val path = asString(pluginOpts?.get("path")) ?: "/"
                val fingerprint = asString(map["client-fingerprint"]) ?: globalFingerprint

                val transport = when (mode) {
                    "websocket", "ws" -> TransportConfig(
                        type = "ws",
                        path = path,
                        headers = mapOf("Host" to host)
                    )
                    "quic" -> TransportConfig(type = "quic")
                    "grpc" -> TransportConfig(
                        type = "grpc",
                        serviceName = asString(pluginOpts?.get("grpc-service-name")) ?: ""
                    )
                    else -> null
                }

                val tlsConfig = if (tlsEnabled) {
                    TlsConfig(
                        enabled = true,
                        serverName = host,
                        utls = fingerprint?.let { UtlsConfig(enabled = true, fingerprint = it) }
                    )
                } else null

                return listOf(Outbound(
                    type = "shadowsocks",
                    tag = name,
                    server = server,
                    serverPort = port,
                    method = cipher,
                    password = password,
                    multiplex = multiplex,
                    transport = transport,
                    tls = tlsConfig,
                    network = if (!udpEnabled) "tcp" else null
                ))
            }

            null, "" -> {
                return listOf(Outbound(
                    type = "shadowsocks",
                    tag = name,
                    server = server,
                    serverPort = port,
                    method = cipher,
                    password = password,
                    multiplex = multiplex,
                    network = if (!udpEnabled) "tcp" else null
                ))
            }

            else -> {
                android.util.Log.w("ClashYamlParser", "SS node '$name' has unsupported plugin: $plugin")
                return listOf(Outbound(
                    type = "shadowsocks",
                    tag = name,
                    server = server,
                    serverPort = port,
                    method = cipher,
                    password = password,
                    multiplex = multiplex,
                    network = if (!udpEnabled) "tcp" else null
                ))
            }
        }
    }

    private fun parseTrojan(map: Map<*, *>, name: String, server: String?, port: Int?, globalFingerprint: String? = null, globalTlsMinVersion: String? = null): Outbound? {
        if (server == null || port == null) return null
        val password = asString(map["password"]) ?: return null
        val network = asString(map["network"])?.lowercase()
        val sni = asString(map["sni"]) ?: server
        // 优先使用节点配置的指纹，否则使用全局指纹
        val fingerprint = asString(map["client-fingerprint"]) ?: globalFingerprint
        val insecure = asBool(map["skip-cert-verify"]) == true
        val alpn = asStringList(map["alpn"])

        // TLS 版本限制
        val tlsMinVersion = asString(map["tls-version"]) ?: asString(map["min-tls-version"]) ?: globalTlsMinVersion

        val tlsConfig = TlsConfig(
            enabled = true,
            serverName = sni,
            insecure = insecure,
            alpn = alpn,
            minVersion = tlsMinVersion,
            utls = fingerprint?.let { UtlsConfig(enabled = true, fingerprint = it) }
        )

        val transport = parseTrojanTransport(network, map, sni, fingerprint)

        // 解析 smux 多路复用配置
        val multiplex = parseSmux(map)

        return Outbound(
            type = "trojan",
            tag = name,
            server = server,
            serverPort = port,
            password = password,
            tls = tlsConfig,
            transport = transport,
            multiplex = multiplex
        )
    }

    private fun parseTrojanTransport(
        network: String?,
        map: Map<*, *>,
        sni: String,
        fingerprint: String?
    ): TransportConfig? {
        return when (network) {
            "ws" -> {
                val wsOpts = map["ws-opts"] as? Map<*, *>
                val path = asString(wsOpts?.get("path")) ?: "/"
                val headersRaw = wsOpts?.get("headers") as? Map<*, *>
                val headers = mutableMapOf<String, String>()
                headersRaw?.forEach { (k, v) -> headers[asString(k) ?: ""] = asString(v) ?: "" }
                if (!headers.containsKey("Host")) headers["Host"] = sni
                if (!headers.containsKey("User-Agent")) {
                    headers["User-Agent"] = getUserAgent(fingerprint)
                }

                // 处理 max-early-data
                val maxEarlyData = asInt(wsOpts?.get("max-early-data")) ?: 2048
                val earlyDataHeaderName = asString(wsOpts?.get("early-data-header-name")) ?: "Sec-WebSocket-Protocol"

                // 检�?httpupgrade (v2ray-http-upgrade)
                val isHttpUpgrade = asBool(wsOpts?.get("v2ray-http-upgrade")) == true

                TransportConfig(
                    type = if (isHttpUpgrade) "httpupgrade" else "ws",
                    path = path,
                    headers = headers,
                    maxEarlyData = if (isHttpUpgrade) null else maxEarlyData,
                    earlyDataHeaderName = if (isHttpUpgrade) null else earlyDataHeaderName
                )
            }
            "grpc" -> {
                val grpcOpts = map["grpc-opts"] as? Map<*, *>
                val serviceName = asString(grpcOpts?.get("grpc-service-name")) ?: ""
                TransportConfig(type = "grpc", serviceName = serviceName)
            }
            "xhttp", "splithttp" -> {
                val xhttpOpts = map["xhttp-opts"] as? Map<*, *>
                    ?: map["splithttp-opts"] as? Map<*, *>
                val path = asString(xhttpOpts?.get("path")) ?: "/"
                val host = asString(xhttpOpts?.get("host"))?.let { listOf(it) }
                val mode = asString(xhttpOpts?.get("mode"))
                val xPaddingBytes = asString(xhttpOpts?.get("xPaddingBytes"))
                    ?: asString(xhttpOpts?.get("x-padding-bytes"))
                TransportConfig(
                    type = "xhttp",
                    path = path,
                    host = host,
                    mode = mode,
                    xPaddingBytes = xPaddingBytes
                )
            }
            else -> null
        }
    }

    private fun parseHysteria2(map: Map<*, *>, name: String, server: String?, port: Int?, globalFingerprint: String? = null, globalTlsMinVersion: String? = null): Outbound? {
        if (server == null || port == null) return null
        val password = asString(map["password"]) ?: return null
        val sni = asString(map["sni"]) ?: server
        val insecure = asBool(map["skip-cert-verify"]) == true
        val alpn = asStringList(map["alpn"])
        // 优先使用节点配置的指纹，否则使用全局指纹
        val fingerprint = asString(map["client-fingerprint"]) ?: globalFingerprint
        val obfs = asString(map["obfs"])
        val obfsPassword = asString(map["obfs-password"])

        // TLS 版本限制
        val tlsMinVersion = asString(map["tls-version"]) ?: asString(map["min-tls-version"]) ?: globalTlsMinVersion

        // 网络协议 (tcp/udp)，Hysteria2 默认支持两�?        val network = asString(map["network"])

        // 带宽限制
        val upMbps = asInt(map["up"]) ?: asInt(map["up-mbps"])
        val downMbps = asInt(map["down"]) ?: asInt(map["down-mbps"])

        // 端口跳跃 - 转换�?List<String> 格式
        val portsStr = asString(map["ports"])?.takeIf { it.isNotBlank() }
        val serverPorts = portsStr?.let { listOf(it) }
        val hopInterval = asString(map["hop-interval"])?.takeIf { it.isNotBlank() }

        return Outbound(
            type = "hysteria2",
            tag = name,
            server = server,
            serverPort = port,
            password = password,
            network = network,
            upMbps = upMbps,
            downMbps = downMbps,
            serverPorts = serverPorts,
            hopInterval = hopInterval,
            tls = TlsConfig(
                enabled = true,
                serverName = sni,
                insecure = insecure,
                alpn = alpn,
                minVersion = tlsMinVersion,
                utls = fingerprint?.let { UtlsConfig(enabled = true, fingerprint = it) }
            ),
            obfs = if (obfs != null) com.openworld.app.model.ObfsConfig(type = obfs, password = obfsPassword) else null
        )
    }

    private fun parseTuic(map: Map<*, *>, name: String, server: String?, port: Int?, globalFingerprint: String? = null, globalTlsMinVersion: String? = null): Outbound? {
        if (server == null || port == null) return null
        val uuid = asString(map["uuid"]) ?: return null

        // 密码可能�?password �?token，如果都为空则使�?uuid
        val password = asString(map["password"]) ?: asString(map["token"]) ?: uuid

        val sni = asString(map["sni"]) ?: asString(map["servername"]) ?: server
        val insecure = asBool(map["skip-cert-verify"]) == true || asBool(map["allow-insecure"]) == true || asBool(map["insecure"]) == true
        val alpn = asStringList(map["alpn"])
        // 优先使用节点配置的指纹，否则使用全局指纹
        val fingerprint = asString(map["client-fingerprint"]) ?: asString(map["fingerprint"]) ?: globalFingerprint
        val congestion = asString(map["congestion-controller"]) ?: asString(map["congestion"]) ?: "bbr"
        val udpRelayMode = asString(map["udp-relay-mode"]) ?: "native"
        val zeroRtt = asBool(map["reduce-rtt"]) == true || asBool(map["zero-rtt-handshake"]) == true

        // TLS 版本限制
        val tlsMinVersion = asString(map["tls-version"]) ?: asString(map["min-tls-version"]) ?: globalTlsMinVersion

        return Outbound(
            type = "tuic",
            tag = name,
            server = server,
            serverPort = port,
            uuid = uuid,
            password = password,
            congestionControl = congestion,
            udpRelayMode = udpRelayMode,
            zeroRttHandshake = zeroRtt,
            tls = TlsConfig(
                enabled = true,
                serverName = sni,
                insecure = insecure,
                alpn = alpn,
                minVersion = tlsMinVersion,
                utls = fingerprint?.let { UtlsConfig(enabled = true, fingerprint = it) }
            )
        )
    }

    private fun parseSSH(map: Map<*, *>, name: String, server: String?, port: Int?): Outbound? {
        if (server == null || port == null) return null
        val user = asString(map["username"]) ?: "root"
        val password = asString(map["password"])
        val privateKey = asString(map["private-key"])

        return Outbound(
            type = "ssh",
            tag = name,
            server = server,
            serverPort = port,
            user = user,
            password = password,
            privateKey = privateKey
        )
    }

    private fun parseWireGuard(map: Map<*, *>, name: String, server: String?, port: Int?): Outbound? {
        if (server == null || port == null) return null
        val privateKey = asString(map["private-key"]) ?: return null
        val publicKey = asString(map["public-key"]) ?: return null // Peer public key
        val preSharedKey = asString(map["pre-shared-key"])
        val address = asStringList(map["ip"]) // Local Address
        val mtu = asInt(map["mtu"]) ?: 1420

        val peer = com.openworld.app.model.WireGuardPeer(
            server = server,
            serverPort = port,
            publicKey = publicKey,
            preSharedKey = preSharedKey
        )

        return Outbound(
            type = "wireguard",
            tag = name,
            localAddress = address,
            privateKey = privateKey,
            peers = listOf(peer),
            mtu = mtu
        )
    }

    private fun parseAnyTLS(map: Map<*, *>, name: String, server: String?, port: Int?, globalFingerprint: String? = null, globalTlsMinVersion: String? = null): Outbound? {
        if (server == null || port == null) return null

        // 尝试�?password, uuid, token 读取密码
        val password = asString(map["password"])
            ?: asString(map["uuid"])
            ?: asString(map["token"])
            ?: return null

        val sni = asString(map["sni"]) ?: asString(map["servername"]) ?: server
        val insecure = asBool(map["skip-cert-verify"]) == true || asBool(map["allow-insecure"]) == true || asBool(map["insecure"]) == true
        val alpn = asStringList(map["alpn"])
        // 优先使用节点配置的指纹，否则使用全局指纹
        val fingerprint = asString(map["client-fingerprint"]) ?: asString(map["fingerprint"]) ?: globalFingerprint

        // TLS 版本限制
        val tlsMinVersion = asString(map["tls-version"]) ?: asString(map["min-tls-version"]) ?: globalTlsMinVersion

        val idleSessionCheckInterval = asString(map["idle-session-check-interval"])
        val idleSessionTimeout = asString(map["idle-session-timeout"])
        val minIdleSession = asInt(map["min-idle-session"])

        return Outbound(
            type = "anytls",
            tag = name,
            server = server,
            serverPort = port,
            password = password,
            idleSessionCheckInterval = idleSessionCheckInterval,
            idleSessionTimeout = idleSessionTimeout,
            minIdleSession = minIdleSession,
            tls = TlsConfig(
                enabled = true,
                serverName = sni,
                insecure = insecure,
                alpn = alpn,
                minVersion = tlsMinVersion,
                utls = fingerprint?.let { UtlsConfig(enabled = true, fingerprint = it) }
            )
        )
    }

    private fun parseHysteria(map: Map<*, *>, name: String, server: String?, port: Int?, globalFingerprint: String? = null, globalTlsMinVersion: String? = null): Outbound? {
        if (server == null || port == null) return null
        val authStr = asString(map["auth-str"]) ?: asString(map["auth_str"]) ?: asString(map["auth"])
        val upMbps = asInt(map["up"]) ?: asInt(map["up-mbps"])
        val downMbps = asInt(map["down"]) ?: asInt(map["down-mbps"])
        val sni = asString(map["sni"]) ?: server
        val insecure = asBool(map["skip-cert-verify"]) == true
        val alpn = asStringList(map["alpn"])
        // 优先使用节点配置的指纹，否则使用全局指纹
        val fingerprint = asString(map["client-fingerprint"]) ?: globalFingerprint
        val obfs = asString(map["obfs"])

        // TLS 版本限制
        val tlsMinVersion = asString(map["tls-version"]) ?: asString(map["min-tls-version"]) ?: globalTlsMinVersion

        // 端口跳跃 - 转换�?List<String> 格式 (sing-box 1.12.0+)
        val portsStr = asString(map["ports"])?.takeIf { it.isNotBlank() }
        val serverPorts = portsStr?.let { listOf(it) }
        val hopInterval = asString(map["hop-interval"])?.takeIf { it.isNotBlank() }

        return Outbound(
            type = "hysteria",
            tag = name,
            server = server,
            serverPort = port,
            authStr = authStr,
            upMbps = upMbps,
            downMbps = downMbps,
            serverPorts = serverPorts,
            hopInterval = hopInterval,
            tls = TlsConfig(
                enabled = true,
                serverName = sni,
                insecure = insecure,
                alpn = alpn,
                minVersion = tlsMinVersion,
                utls = fingerprint?.let { UtlsConfig(enabled = true, fingerprint = it) }
            ),
            obfs = if (obfs != null) com.openworld.app.model.ObfsConfig(type = obfs) else null
        )
    }

    private fun parseHttp(map: Map<*, *>, name: String, server: String?, port: Int?, globalFingerprint: String? = null, globalTlsMinVersion: String? = null): Outbound? {
        if (server == null || port == null) return null

        val username = asString(map["username"])
        val password = asString(map["password"])

        // sing-box HTTP outbound 支持 TLS
        val tlsEnabled = asBool(map["tls"]) == true
        // 优先使用节点配置的指纹，否则使用全局指纹
        val fingerprint = asString(map["client-fingerprint"]) ?: asString(map["fingerprint"]) ?: globalFingerprint
        val tlsConfig = if (tlsEnabled) {
            val sni = asString(map["sni"]) ?: asString(map["servername"]) ?: server
            // 对于 HTTP+TLS 代理，默认跳过证书验证（许多代理服务使用自签名证书）
            // 只有当用户明确设�?skip-cert-verify: false 时才进行证书验证
            val skipCertVerify = map["skip-cert-verify"]
            val insecure = if (skipCertVerify == null) true else asBool(skipCertVerify) == true
            val alpn = asStringList(map["alpn"])
            // TLS 版本限制
            val tlsMinVersion = asString(map["tls-version"]) ?: asString(map["min-tls-version"]) ?: globalTlsMinVersion
            TlsConfig(
                enabled = true,
                serverName = sni,
                insecure = insecure,
                alpn = alpn,
                minVersion = tlsMinVersion,
                utls = fingerprint?.let { UtlsConfig(enabled = true, fingerprint = it) }
            )
        } else null

        // HTTP outbound 支持 path �?headers 字段
        val path = asString(map["path"])
        val headersRaw = map["headers"] as? Map<*, *>
        val headers = if (headersRaw != null) {
            val headerMap = mutableMapOf<String, String>()
            headersRaw.forEach { (k, v) ->
                val ks = asString(k) ?: return@forEach
                val vs = asString(v) ?: return@forEach
                headerMap[ks] = vs
            }
            headerMap.takeIf { it.isNotEmpty() }
        } else null

        return Outbound(
            type = "http",
            tag = name,
            server = server,
            serverPort = port,
            username = username,
            password = password,
            tls = tlsConfig,
            path = path,
            headers = headers
        )
    }

    private fun parseSocks(map: Map<*, *>, name: String, server: String?, port: Int?): Outbound? {
        if (server == null || port == null) return null

        // sing-box �?socks 出站类型不支�?TLS，但仍然导入节点（忽�?TLS 设置�?        val tlsEnabled = asBool(map["tls"]) == true
        if (tlsEnabled) {
            android.util.Log.w("ClashYamlParser", "SOCKS proxy '$name' has TLS enabled but sing-box does not support it, importing without TLS")
        }

        val username = asString(map["username"])
        val password = asString(map["password"])

        return Outbound(
            type = "socks",
            tag = name,
            server = server,
            serverPort = port,
            username = username,
            password = password
        )
    }

    private fun parseShadowTLS(map: Map<*, *>, name: String, server: String?, port: Int?, globalFingerprint: String? = null): Outbound? {
        if (server == null || port == null) return null
        val password = asString(map["password"]) ?: return null
        val version = asInt(map["version"]) ?: 3
        val sni = asString(map["sni"]) ?: server
        val fingerprint = asString(map["client-fingerprint"]) ?: globalFingerprint

        return Outbound(
            type = "shadowtls",
            tag = name,
            server = server,
            serverPort = port,
            version = version,
            password = password,
            tls = TlsConfig(
                enabled = true,
                serverName = sni,
                utls = fingerprint?.let { UtlsConfig(enabled = true, fingerprint = it) }
            )
        )
    }

    // --- Helpers ---

    /**
     * 解析 smux 多路复用配置
     * 扩展 YAML 格式:
     * smux:
     *   enabled: true
     *   protocol: smux  # smux/yamux/h2mux
     *   max-connections: 4
     *   min-streams: 4
     *   max-streams: 0
     *   padding: false
     */
    private fun parseSmux(map: Map<*, *>): MultiplexConfig? {
        val smuxOpts = map["smux"] as? Map<*, *> ?: return null
        val enabled = asBool(smuxOpts["enabled"]) == true
        if (!enabled) return null

        return MultiplexConfig(
            enabled = true,
            protocol = asString(smuxOpts["protocol"]) ?: "smux",
            maxConnections = asInt(smuxOpts["max-connections"]),
            minStreams = asInt(smuxOpts["min-streams"]),
            maxStreams = asInt(smuxOpts["max-streams"]),
            padding = asBool(smuxOpts["padding"])
        )
    }

    private fun getUserAgent(fingerprint: String?): String {
        return if (fingerprint?.contains("chrome", ignoreCase = true) == true) {
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36"
        } else {
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/115.0"
        }
    }

    private fun asString(v: Any?): String? = when (v) {
        is String -> v
        is Number -> v.toString()
        is Boolean -> v.toString()
        is List<*> -> v.firstOrNull()?.toString()
        else -> null
    }

    private fun asInt(v: Any?): Int? = when (v) {
        is Int -> v
        is Long -> v.toInt()
        is Number -> v.toInt()
        is String -> v.toIntOrNull()
        else -> null
    }

    private fun asBool(v: Any?): Boolean? = when (v) {
        is Boolean -> v
        is String -> when (v.lowercase()) {
            "true", "1", "yes", "y" -> true
            "false", "0", "no", "n" -> false
            else -> null
        }
        else -> null
    }

    private fun asStringList(v: Any?): List<String>? {
        return when (v) {
            is List<*> -> v.mapNotNull { asString(it) }.takeIf { it.isNotEmpty() }
            is String -> v.split(",").map { it.trim() }.filter { it.isNotEmpty() }.takeIf { it.isNotEmpty() }
            else -> null
        }
    }
}







