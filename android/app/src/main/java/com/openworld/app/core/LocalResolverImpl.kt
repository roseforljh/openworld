package com.openworld.app.core

import android.util.Log
import com.openworld.app.core.bridge.LocalDNSTransport
import java.net.Inet4Address
import java.net.Inet6Address
import java.net.InetAddress

/**
 * OpenWorld 本地 DNS 传输接口
 * 用于处理本地 DNS 查询
 */
object LocalResolverImpl : LocalDNSTransport {
    private const val TAG = "LocalResolverImpl"

    /**
     * 执行 DNS 查询
     * @param network 网络类型: "ip4", "ip6", "ip"
     * @param domain 域名
     * @return 查询结果，包�?IP 地址列表（按换行分隔），失败返回 null
     */
    fun lookup(network: String, domain: String): String? {
        return try {
            val addresses = InetAddress.getAllByName(domain)
            val result = StringBuilder()
            for (address in addresses) {
                if (network == "ip4" && address is Inet4Address) {
                    if (result.isNotEmpty()) result.append("\n")
                    result.append(address.hostAddress)
                } else if (network == "ip6" && address is Inet6Address) {
                    if (result.isNotEmpty()) result.append("\n")
                    result.append(address.hostAddress)
                } else if (network == "ip") {
                    // 返回所有地址
                    if (result.isNotEmpty()) result.append("\n")
                    result.append(address.hostAddress)
                }
            }
            if (result.isNotEmpty()) {
                result.toString()
            } else {
                null
            }
        } catch (e: Exception) {
            Log.w(TAG, "DNS lookup failed for $domain: ${e.message}")
            null
        }
    }

    /**
     * 检查是否支持原�?DNS 模式
     */
    fun isRawMode(): Boolean = false
}







