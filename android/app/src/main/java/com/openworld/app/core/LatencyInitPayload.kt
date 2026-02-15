package com.openworld.app.core

import com.google.gson.annotations.SerializedName

data class LatencyInitPayload(
    @SerializedName("schema_version")
    val schemaVersion: Int = 1,
    @SerializedName("outbounds")
    val outbounds: List<LatencyOutboundConfig>
)

data class LatencyOutboundConfig(
    @SerializedName("tag")
    val tag: String,
    @SerializedName("protocol")
    val protocol: String,
    @SerializedName("settings")
    val settings: LatencyOutboundSettings
)

data class LatencyOutboundSettings(
    @SerializedName("address")
    val address: String,
    @SerializedName("port")
    val port: Int,
    @SerializedName("uuid")
    val uuid: String? = null,
    @SerializedName("password")
    val password: String? = null,
    @SerializedName("method")
    val method: String? = null,
    @SerializedName("security")
    val security: String? = null,
    @SerializedName("sni")
    val sni: String? = null,
    @SerializedName("server_name")
    val serverName: String? = null,
    @SerializedName("fingerprint")
    val fingerprint: String? = null,
    @SerializedName("alpn")
    val alpn: List<String>? = null,
    @SerializedName("flow")
    val flow: String? = null,
    @SerializedName("alter_id")
    val alterId: Int? = null,
    @SerializedName("network")
    val network: String? = null,
    @SerializedName("up_mbps")
    val upMbps: Int? = null,
    @SerializedName("down_mbps")
    val downMbps: Int? = null,
    @SerializedName("auth_str")
    val authStr: String? = null,
    @SerializedName("server_ports")
    val serverPorts: List<String>? = null,
    @SerializedName("hop_interval")
    val hopInterval: String? = null,
    @SerializedName("obfs")
    val obfs: LatencyObfsConfig? = null,
    @SerializedName("tls")
    val tls: LatencyTlsConfig? = null,
    @SerializedName("transport")
    val transport: LatencyTransportConfig? = null
)

data class LatencyTlsConfig(
    @SerializedName("enabled")
    val enabled: Boolean? = null,
    @SerializedName("server_name")
    val serverName: String? = null,
    @SerializedName("sni")
    val sni: String? = null,
    @SerializedName("fingerprint")
    val fingerprint: String? = null,
    @SerializedName("alpn")
    val alpn: List<String>? = null,
    @SerializedName("reality")
    val reality: LatencyRealityConfig? = null
)

data class LatencyRealityConfig(
    @SerializedName("enabled")
    val enabled: Boolean? = null,
    @SerializedName("public_key")
    val publicKey: String? = null,
    @SerializedName("short_id")
    val shortId: String? = null
)

data class LatencyTransportConfig(
    @SerializedName("type")
    val type: String? = null,
    @SerializedName("path")
    val path: String? = null,
    @SerializedName("headers")
    val headers: Map<String, String>? = null,
    @SerializedName("service_name")
    val serviceName: String? = null
)

data class LatencyObfsConfig(
    @SerializedName("type")
    val type: String? = null,
    @SerializedName("password")
    val password: String? = null
)
