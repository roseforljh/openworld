package com.openworld.app.core

import com.openworld.app.utils.parser.ClashYamlParser
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Test

class LatencyContractFixtureTest {
    private fun loadFixture(path: String): String {
        val stream = javaClass.classLoader?.getResourceAsStream(path)
        requireNotNull(stream) { "fixture not found: $path" }
        return stream.bufferedReader().use { it.readText() }
    }

    @Test
    fun `clash parser to latency payload should preserve reality ws hy2 fields`() {
        val yaml = loadFixture("subscriptions/lu71.yaml")
        val config = ClashYamlParser().parse(yaml)
        assertNotNull(config)
        val outbounds = requireNotNull(config?.outbounds)

        val payload = LatencyContractMapper.toPayload(outbounds)
        assertEquals(1, payload.schemaVersion)

        val reality = payload.outbounds.first { it.tag == "reality-ws-node" }
        assertEquals("vless", reality.protocol)
        assertEquals("reality.example.com", reality.settings.address)
        assertEquals(443, reality.settings.port)
        assertEquals("reality-public-key-001", reality.settings.tls?.reality?.publicKey)
        assertEquals("a1b2c3d4", reality.settings.tls?.reality?.shortId)
        assertEquals("ws", reality.settings.transport?.type)
        assertEquals("/edge", reality.settings.transport?.path)
        assertEquals(
            "cdn.reality.example.com",
            reality.settings.transport?.headers?.get("Host")
        )

        val wsNode = payload.outbounds.first { it.tag == "vmess-ws-node" }
        assertEquals("vmess", wsNode.protocol)
        assertEquals("ws", wsNode.settings.transport?.type)
        assertEquals("/api/ws", wsNode.settings.transport?.path)
        assertEquals("ws.vmess.example.com", wsNode.settings.transport?.headers?.get("Host"))

        val hy2 = payload.outbounds.first { it.tag == "hy2-node" }
        assertEquals("hysteria2", hy2.protocol)
        assertEquals(30, hy2.settings.upMbps)
        assertEquals(150, hy2.settings.downMbps)
        assertEquals("hy2-password", hy2.settings.password)
        assertEquals("20s", hy2.settings.hopInterval)
        assertEquals(listOf("8443", "9000-9010"), hy2.settings.serverPorts)
        assertEquals("salamander", hy2.settings.obfs?.type)
        assertEquals("hy2-obfs-password", hy2.settings.obfs?.password)
        assertEquals("hy2.example.com", hy2.settings.tls?.serverName)
    }
}
