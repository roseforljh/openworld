package com.openworld.app.repository

import android.content.Context
import android.content.SharedPreferences
import com.openworld.app.model.AppThemeMode

object SettingsStore {

    private const val PREFS_NAME = "openworld_settings"
    private const val KEY_THEME = "app_theme"
    private const val KEY_TUN_MTU = "tun_mtu"
    private const val KEY_TUN_IPV6 = "tun_ipv6"
    private const val KEY_DNS_MODE = "dns_mode"
    private const val KEY_DNS_SERVERS = "dns_servers"
    private const val KEY_BOOT_AUTO_START = "boot_auto_start"
    private const val KEY_AUTO_CONNECT = "auto_connect"
    private const val KEY_FOREGROUND_KEEPALIVE = "foreground_keepalive"
    private const val KEY_APP_LANGUAGE = "app_language"

    private fun prefs(context: Context): SharedPreferences =
        context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE)

    fun getThemeMode(context: Context): AppThemeMode {
        val name = prefs(context).getString(KEY_THEME, AppThemeMode.SYSTEM.name)
        return try {
            AppThemeMode.valueOf(name ?: AppThemeMode.SYSTEM.name)
        } catch (_: Exception) {
            AppThemeMode.SYSTEM
        }
    }

    fun setThemeMode(context: Context, mode: AppThemeMode) {
        prefs(context).edit().putString(KEY_THEME, mode.name).apply()
    }

    fun getTunMtu(context: Context): Int = prefs(context).getInt(KEY_TUN_MTU, 1500)

    fun setTunMtu(context: Context, mtu: Int) {
        prefs(context).edit().putInt(KEY_TUN_MTU, mtu.coerceIn(1200, 9000)).apply()
    }

    fun getTunIpv6Enabled(context: Context): Boolean = prefs(context).getBoolean(KEY_TUN_IPV6, true)

    fun setTunIpv6Enabled(context: Context, enabled: Boolean) {
        prefs(context).edit().putBoolean(KEY_TUN_IPV6, enabled).apply()
    }

    fun getDnsMode(context: Context): String = prefs(context).getString(KEY_DNS_MODE, "split") ?: "split"

    fun setDnsMode(context: Context, mode: String) {
        prefs(context).edit().putString(KEY_DNS_MODE, mode).apply()
    }

    fun getDnsServers(context: Context): List<String> {
        val raw = prefs(context).getString(KEY_DNS_SERVERS, "") ?: ""
        if (raw.isBlank()) return listOf("223.5.5.5", "tls://8.8.8.8")
        return raw.split("\n").map { it.trim() }.filter { it.isNotBlank() }
    }

    fun setDnsServers(context: Context, servers: List<String>) {
        val normalized = servers.map { it.trim() }.filter { it.isNotBlank() }
        prefs(context).edit().putString(KEY_DNS_SERVERS, normalized.joinToString("\n")).apply()
    }

    fun getBootAutoStart(context: Context): Boolean = prefs(context).getBoolean(KEY_BOOT_AUTO_START, false)

    fun setBootAutoStart(context: Context, enabled: Boolean) {
        prefs(context).edit().putBoolean(KEY_BOOT_AUTO_START, enabled).apply()
    }

    fun getAutoConnect(context: Context): Boolean = prefs(context).getBoolean(KEY_AUTO_CONNECT, false)

    fun setAutoConnect(context: Context, enabled: Boolean) {
        prefs(context).edit().putBoolean(KEY_AUTO_CONNECT, enabled).apply()
    }

    fun getForegroundKeepAlive(context: Context): Boolean = prefs(context).getBoolean(KEY_FOREGROUND_KEEPALIVE, true)

    fun setForegroundKeepAlive(context: Context, enabled: Boolean) {
        prefs(context).edit().putBoolean(KEY_FOREGROUND_KEEPALIVE, enabled).apply()
    }

    fun getAppLanguage(context: Context): String =
        prefs(context).getString(KEY_APP_LANGUAGE, "system") ?: "system"

    fun setAppLanguage(context: Context, language: String) {
        prefs(context).edit().putString(KEY_APP_LANGUAGE, language).apply()
    }
}
