package com.openworld.app.repository.config

import com.openworld.app.model.AppSettings
import com.openworld.app.model.Inbound
import com.openworld.app.model.TunStack

/**
 * 入站配置构建�? */
object InboundBuilder {

    /**
     * 构建运行时入站配�?     */
    fun build(settings: AppSettings, effectiveTunStack: TunStack): List<Inbound> {
        val inbounds = mutableListOf<Inbound>()

        // 1. 添加混合入站 (Mixed Port)
        // �?inbound 层启�?sniff + sniff_override_destination�?        // 确保 FakeIP 场景下目标地址被嗅探到的真实域名覆盖，
        // 避免�?TLS 协议（如 MTProto）因 sniff 失败导致连接超时�?        if (settings.proxyPort > 0) {
            inbounds.add(
                Inbound(
                    type = "mixed",
                    tag = "mixed-in",
                    listen = if (settings.allowLan) "0.0.0.0" else "127.0.0.1",
                    listenPort = settings.proxyPort,
                    reuseAddr = true,
                    sniff = true,
                    sniffOverrideDestination = true
                )
            )
        }

        if (settings.tunEnabled) {
            inbounds.add(
                Inbound(
                    type = "tun",
                    tag = "tun-in",
                    interfaceName = settings.tunInterfaceName,
                    inet4AddressRaw = listOf("172.19.0.1/30"),
                    inet6AddressRaw = listOf("fd00::1/126"),
                    mtu = settings.tunMtu,
                    autoRoute = false,
                    strictRoute = false,
                    stack = effectiveTunStack.name.lowercase(),
                    endpointIndependentNat = settings.endpointIndependentNat,
                    gso = null,
                    sniff = true,
                    sniffOverrideDestination = true
                )
            )
        } else if (settings.proxyPort <= 0) {
            inbounds.add(
                Inbound(
                    type = "mixed",
                    tag = "mixed-in",
                    listen = "127.0.0.1",
                    listenPort = 2080,
                    reuseAddr = true,
                    sniff = true,
                    sniffOverrideDestination = true
                )
            )
        }

        return inbounds
    }
}







