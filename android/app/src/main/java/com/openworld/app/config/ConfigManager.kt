package com.openworld.app.config

import android.content.Context
import android.content.SharedPreferences
import com.google.gson.Gson
import com.google.gson.JsonParser
import java.io.File

/**
 * 配置管理器：生成 OpenWorld 内核所需的 YAML/JSON 配置
 */
object ConfigManager {

    private const val PREFS_NAME = "openworld_settings"
    private const val KEY_ACTIVE_PROFILE = "active_profile"
    private const val KEY_ROUTING_MODE = "routing_mode"
    private const val KEY_DNS_LOCAL = "dns_local"
    private const val KEY_DNS_REMOTE = "dns_remote"
    private const val KEY_BYPASS_APPS = "bypass_apps"
    private const val KEY_PROXY_MODE_APPS = "proxy_mode_apps"

    private const val SUBSCRIPTION_PREFS = "profile_subscriptions"

    private fun prefs(context: Context): SharedPreferences =
        context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)

    private fun subPrefs(context: Context): SharedPreferences =
        context.getSharedPreferences(SUBSCRIPTION_PREFS, Context.MODE_PRIVATE)

    fun getActiveProfile(context: Context): String =
        prefs(context).getString(KEY_ACTIVE_PROFILE, "default") ?: "default"

    fun setActiveProfile(context: Context, name: String) =
        prefs(context).edit().putString(KEY_ACTIVE_PROFILE, name).apply()

    fun getRoutingMode(context: Context): String =
        prefs(context).getString(KEY_ROUTING_MODE, "rule") ?: "rule"

    fun setRoutingMode(context: Context, mode: String) =
        prefs(context).edit().putString(KEY_ROUTING_MODE, mode).apply()

    fun getDnsLocal(context: Context): String =
        prefs(context).getString(KEY_DNS_LOCAL, "223.5.5.5") ?: "223.5.5.5"

    fun setDnsLocal(context: Context, dns: String) =
        prefs(context).edit().putString(KEY_DNS_LOCAL, dns).apply()

    fun getDnsRemote(context: Context): String =
        prefs(context).getString(KEY_DNS_REMOTE, "tls://8.8.8.8") ?: "tls://8.8.8.8"

    fun setDnsRemote(context: Context, dns: String) =
        prefs(context).edit().putString(KEY_DNS_REMOTE, dns).apply()

    // ── 分应用代理 ──

    fun getBypassApps(context: Context): Set<String> {
        val raw = prefs(context).getString(KEY_BYPASS_APPS, "") ?: ""
        if (raw.isEmpty()) return emptySet()
        return raw.split(",").filter { it.isNotEmpty() }.toSet()
    }

    fun setBypassApps(context: Context, apps: Set<String>) {
        prefs(context).edit().putString(KEY_BYPASS_APPS, apps.joinToString(",")).apply()
    }

    fun getProxyModeApps(context: Context): String =
        prefs(context).getString(KEY_PROXY_MODE_APPS, "bypass") ?: "bypass"

    fun setProxyModeApps(context: Context, mode: String) =
        prefs(context).edit().putString(KEY_PROXY_MODE_APPS, mode).apply()

    // ── 订阅 URL 管理 ──

    fun getSubscriptionUrl(context: Context, profileName: String): String? =
        subPrefs(context).getString(profileName, null)

    fun setSubscriptionUrl(context: Context, profileName: String, url: String) =
        subPrefs(context).edit().putString(profileName, url).apply()

    fun removeSubscriptionUrl(context: Context, profileName: String) =
        subPrefs(context).edit().remove(profileName).apply()

    // ── 配置文件管理 ──

    fun configDir(context: Context): File {
        val dir = File(context.filesDir, "configs")
        if (!dir.exists()) dir.mkdirs()
        return dir
    }

    fun listProfiles(context: Context): List<String> {
        return configDir(context).listFiles()
            ?.filter { it.extension in listOf("yaml", "yml", "json") }
            ?.map { it.nameWithoutExtension }
            ?: emptyList()
    }

    fun saveProfile(context: Context, name: String, content: String) {
        val file = File(configDir(context), "$name.yaml")
        file.writeText(content)
    }

    fun loadProfile(context: Context, name: String): String? {
        val yamlFile = File(configDir(context), "$name.yaml")
        if (yamlFile.exists()) return yamlFile.readText()
        val jsonFile = File(configDir(context), "$name.json")
        if (jsonFile.exists()) return jsonFile.readText()
        return null
    }

    fun deleteProfile(context: Context, name: String): Boolean {
        val yamlFile = File(configDir(context), "$name.yaml")
        val jsonFile = File(configDir(context), "$name.json")
        removeSubscriptionUrl(context, name)
        return yamlFile.delete() || jsonFile.delete()
    }

    /**
     * 生成运行时配置（传给内核的 JSON）
     */
    fun generateConfig(context: Context): String {
        val activeProfile = getActiveProfile(context)
        val profileContent = loadProfile(context, activeProfile)

        if (profileContent != null) {
            return profileContent
        }

        val dnsLocal = getDnsLocal(context)
        val dnsRemote = getDnsRemote(context)

        return """
{
  "log": { "level": "info" },
  "inbounds": [
    {
      "tag": "tun-in",
      "type": "tun",
      "interface_name": "openworld0",
      "mtu": 1500,
      "inet4_address": "172.19.0.1/30",
      "inet6_address": "fdfe:dcba:9876::1/126",
      "auto_route": true,
      "strict_route": true,
      "stack": "mixed",
      "sniff": true,
      "sniff_override_destination": true,
      "sniff_timeout": "300ms"
    },
    {
      "tag": "mixed-in",
      "type": "mixed",
      "listen": "127.0.0.1",
      "listen_port": 7890
    }
  ],
  "outbounds": [
    { "tag": "direct", "type": "direct" },
    { "tag": "reject", "type": "block" }
  ],
  "dns": {
    "servers": [
      { "tag": "local", "address": "$dnsLocal", "detour": "direct" },
      { "tag": "remote", "address": "$dnsRemote", "detour": "direct" }
    ],
    "rules": [
      { "server": "local", "rule_set": ["geosite-cn"] },
      { "server": "remote" }
    ]
  },
  "route": {
    "auto_detect_interface": true,
    "default_interface": "",
    "final": "direct"
  }
}
        """.trimIndent()
    }

    /**
     * 纯 JSON 格式校验（不触发内核热重载）
     */
    fun isFormatValid(config: String): Boolean {
        return try {
            JsonParser.parseString(config)
            true
        } catch (_: Exception) {
            false
        }
    }

    /**
     * 验证配置：内核未运行时仅做格式校验，运行中时热重载验证
     */
    fun validateConfig(config: String): Boolean {
        return try {
            if (!com.openworld.core.OpenWorldCore.isRunning()) {
                isFormatValid(config)
            } else {
                com.openworld.core.OpenWorldCore.reloadConfig(config) == 0
            }
        } catch (_: Exception) {
            false
        }
    }
}
