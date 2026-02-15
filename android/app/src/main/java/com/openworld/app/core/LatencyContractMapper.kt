package com.openworld.app.core

import com.openworld.app.model.Outbound

object LatencyContractMapper {
    private val nonTestableTypes = setOf(
        "direct",
        "block",
        "reject",
        "dns",
        "selector",
        "urltest",
        "url-test"
    )

    private fun isNonTestableType(outbound: Outbound): Boolean {
        return outbound.type.lowercase() in nonTestableTypes
    }

    fun validateOutbounds(outbounds: List<Outbound>): List<String> {
        return outbounds.mapIndexedNotNull { index, outbound ->
            if (isNonTestableType(outbound)) {
                return@mapIndexedNotNull null
            }
            when {
                outbound.tag.isBlank() -> "outbounds[$index].tag is required"
                outbound.server.isNullOrBlank() -> "outbounds[$index].server is required"
                outbound.serverPort == null -> "outbounds[$index].serverPort is required"
                else -> null
            }
        }
    }

    fun toPayload(outbounds: List<Outbound>): LatencyInitPayload {
        return LatencyInitPayload(
            schemaVersion = 1,
            outbounds = outbounds
                .filterNot(::isNonTestableType)
                .map { it.toLatencyOutboundConfig() }
        )
    }
}

fun Outbound.toLatencyOutboundConfig(): LatencyOutboundConfig {
    val address = requireNotNull(server) { "outbound[$tag].server is required" }
    val port = requireNotNull(serverPort) { "outbound[$tag].serverPort is required" }

    return LatencyOutboundConfig(
        tag = tag,
        protocol = type,
        settings = LatencyOutboundSettings(
            address = address,
            port = port,
            uuid = uuid,
            password = password,
            method = method,
            security = security,
            sni = tls?.serverName,
            serverName = tls?.serverName,
            fingerprint = tls?.utls?.fingerprint,
            alpn = tls?.alpn,
            flow = flow,
            alterId = alterId,
            network = network,
            upMbps = upMbps,
            downMbps = downMbps,
            authStr = authStr,
            serverPorts = serverPorts,
            hopInterval = hopInterval,
            obfs = obfs?.let {
                LatencyObfsConfig(
                    type = it.type,
                    password = it.password
                )
            },
            tls = tls?.let {
                LatencyTlsConfig(
                    enabled = it.enabled,
                    serverName = it.serverName,
                    sni = it.serverName,
                    fingerprint = it.utls?.fingerprint,
                    alpn = it.alpn,
                    reality = it.reality?.let { reality ->
                        LatencyRealityConfig(
                            enabled = reality.enabled,
                            publicKey = reality.publicKey,
                            shortId = reality.shortId
                        )
                    }
                )
            },
            transport = transport?.let {
                LatencyTransportConfig(
                    type = it.type,
                    path = it.path,
                    headers = it.headers,
                    serviceName = it.serviceName
                )
            }
        )
    )
}
