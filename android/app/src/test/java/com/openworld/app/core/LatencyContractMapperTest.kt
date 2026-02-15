package com.openworld.app.core

import com.google.gson.Gson
import com.openworld.app.model.ObfsConfig
import com.openworld.app.model.Outbound
import com.openworld.app.model.RealityConfig
import com.openworld.app.model.TlsConfig
import com.openworld.app.model.TransportConfig
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test

class LatencyContractMapperTest {
    private val gson = Gson()

    @Test
    fun `vless reality fields should be preserved in canonical payload`() {
        val outbound = Outbound(
            type = "vless",
            tag = "reality-node",
            server = "reality.example.com",
            serverPort = 443,
            uuid = "550e8400-e29b-41d4-a716-446655440000",
            tls = TlsConfig(
                enabled = true,
                serverName = "reality.example.com",
                reality = RealityConfig(
                    enabled = true,
                    publicKey = "test-public-key",
                    shortId = "abcd1234"
                )
            )
        )

        val payload = LatencyContractMapper.toPayload(listOf(outbound))
        val json = gson.toJson(payload)
        val decoded = gson.fromJson(json, LatencyInitPayload::class.java)

        assertEquals(1, decoded.schemaVersion)
        val first = decoded.outbounds.first()
        assertEquals("reality-node", first.tag)
        assertEquals("vless", first.protocol)
        assertEquals("reality.example.com", first.settings.address)
        assertEquals(443, first.settings.port)
        assertEquals("reality.example.com", first.settings.tls?.serverName)
        assertEquals("test-public-key", first.settings.tls?.reality?.publicKey)
        assertEquals("abcd1234", first.settings.tls?.reality?.shortId)
    }

    @Test
    fun `ws transport fields should be preserved in canonical payload`() {
        val outbound = Outbound(
            type = "vmess",
            tag = "ws-node",
            server = "ws.example.com",
            serverPort = 443,
            uuid = "650e8400-e29b-41d4-a716-446655440000",
            transport = TransportConfig(
                type = "ws",
                path = "/api/v1/ws",
                headers = mapOf(
                    "Host" to "cdn.example.com",
                    "User-Agent" to "Mozilla/5.0"
                )
            )
        )

        val payload = LatencyContractMapper.toPayload(listOf(outbound))
        val first = payload.outbounds.first()

        assertEquals("ws", first.settings.transport?.type)
        assertEquals("/api/v1/ws", first.settings.transport?.path)
        assertEquals("cdn.example.com", first.settings.transport?.headers?.get("Host"))
        assertEquals("Mozilla/5.0", first.settings.transport?.headers?.get("User-Agent"))
    }

    @Test
    fun `hy2 tls and bandwidth auth fields should be preserved in canonical payload`() {
        val outbound = Outbound(
            type = "hysteria2",
            tag = "hy2-node",
            server = "hy2.example.com",
            serverPort = 8443,
            password = "hy2-password",
            upMbps = 20,
            downMbps = 100,
            authStr = "hy2-auth",
            serverPorts = listOf("8443", "9000-9100"),
            hopInterval = "20s",
            obfs = ObfsConfig(type = "salamander", password = "obfs-pass"),
            tls = TlsConfig(
                enabled = true,
                serverName = "hy2.example.com",
                alpn = listOf("h3")
            )
        )

        val payload = LatencyContractMapper.toPayload(listOf(outbound))
        val first = payload.outbounds.first()

        assertEquals("hy2-node", first.tag)
        assertEquals("hysteria2", first.protocol)
        assertEquals(20, first.settings.upMbps)
        assertEquals(100, first.settings.downMbps)
        assertEquals("hy2-auth", first.settings.authStr)
        assertEquals(listOf("8443", "9000-9100"), first.settings.serverPorts)
        assertEquals("20s", first.settings.hopInterval)
        assertNotNull(first.settings.tls)
        assertEquals("hy2.example.com", first.settings.tls?.serverName)
        assertEquals(listOf("h3"), first.settings.tls?.alpn)
        assertEquals("salamander", first.settings.obfs?.type)
        assertEquals("obfs-pass", first.settings.obfs?.password)
    }

    @Test
    fun `invalid outbound should be reported instead of silently filtered`() {
        val invalid = Outbound(
            type = "vless",
            tag = "invalid-node",
            server = null,
            serverPort = 443,
            uuid = "550e8400-e29b-41d4-a716-446655440000"
        )

        val violations = LatencyContractMapper.validateOutbounds(listOf(invalid))

        assertTrue(violations.isNotEmpty())
        assertTrue(violations.first().contains("server is required"))
    }
}
