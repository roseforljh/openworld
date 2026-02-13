package com.openworld.app.viewmodel

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.openworld.app.config.ConfigManager
import com.openworld.app.model.AppThemeMode
import com.openworld.app.repository.SettingsStore
import com.openworld.core.OpenWorldCore
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch

class SettingsViewModel(app: Application) : AndroidViewModel(app) {

    data class UiState(
        val routingMode: String = "rule",
        val clashMode: String = "rule",
        val dnsLocal: String = "223.5.5.5",
        val dnsRemote: String = "tls://8.8.8.8",
        val coreVersion: String = "",
        val appVersion: String = "",
        val memoryUsage: Long = 0,
        val debugLogging: Boolean = false,
        val appTheme: String = AppThemeMode.SYSTEM.name,
        val tunMtu: Int = 1500,
        val tunIpv6Enabled: Boolean = true,
        val dnsMode: String = "split",
        val dnsServers: List<String> = listOf("223.5.5.5", "tls://8.8.8.8"),
        val bootAutoStart: Boolean = false,
        val autoConnect: Boolean = false,
        val foregroundKeepAlive: Boolean = true,
        val appLanguage: String = "system"
    )

    private val _state = MutableStateFlow(UiState())
    val state: StateFlow<UiState> = _state.asStateFlow()

    init {
        refresh()
    }

    fun refresh() {
        viewModelScope.launch(Dispatchers.IO) {
            val ctx = getApplication<Application>()
            val coreVer = try { OpenWorldCore.version() } catch (_: Exception) { "N/A" }
            val clashMode = try { OpenWorldCore.getClashMode() ?: "rule" } catch (_: Exception) { "rule" }
            val mem = try { OpenWorldCore.getMemoryUsage() } catch (_: Exception) { 0L }

            _state.value = UiState(
                routingMode = ConfigManager.getRoutingMode(ctx),
                clashMode = clashMode,
                dnsLocal = ConfigManager.getDnsLocal(ctx),
                dnsRemote = ConfigManager.getDnsRemote(ctx),
                coreVersion = coreVer,
                appVersion = try {
                    ctx.packageManager.getPackageInfo(ctx.packageName, 0).versionName ?: "1.0"
                } catch (_: Exception) { "1.0" },
                memoryUsage = mem,
                debugLogging = _state.value.debugLogging,
                appTheme = SettingsStore.getThemeMode(ctx).name,
                tunMtu = SettingsStore.getTunMtu(ctx),
                tunIpv6Enabled = SettingsStore.getTunIpv6Enabled(ctx),
                dnsMode = SettingsStore.getDnsMode(ctx),
                dnsServers = SettingsStore.getDnsServers(ctx),
                bootAutoStart = SettingsStore.getBootAutoStart(ctx),
                autoConnect = SettingsStore.getAutoConnect(ctx),
                foregroundKeepAlive = SettingsStore.getForegroundKeepAlive(ctx),
                appLanguage = SettingsStore.getAppLanguage(ctx)
            )
        }
    }

    fun setRoutingMode(mode: String) {
        viewModelScope.launch(Dispatchers.IO) {
            val ctx = getApplication<Application>()
            ConfigManager.setRoutingMode(ctx, mode)
            try { OpenWorldCore.setClashMode(mode) } catch (_: Exception) {}
            _state.value = _state.value.copy(routingMode = mode, clashMode = mode)
        }
    }

    fun setDnsLocal(dns: String) {
        viewModelScope.launch(Dispatchers.IO) {
            ConfigManager.setDnsLocal(getApplication(), dns)
            _state.value = _state.value.copy(dnsLocal = dns)
        }
    }

    fun setDnsRemote(dns: String) {
        viewModelScope.launch(Dispatchers.IO) {
            ConfigManager.setDnsRemote(getApplication(), dns)
            _state.value = _state.value.copy(dnsRemote = dns)
        }
    }

    fun setClashMode(mode: String) {
        viewModelScope.launch(Dispatchers.IO) {
            try { OpenWorldCore.setClashMode(mode) } catch (_: Exception) {}
            _state.value = _state.value.copy(clashMode = mode)
        }
    }

    fun setDebugLoggingEnabled(enabled: Boolean) {
        _state.value = _state.value.copy(debugLogging = enabled)
    }

    fun setAppTheme(themeName: String) {
        val ctx = getApplication<Application>()
        val mode = try {
            AppThemeMode.valueOf(themeName)
        } catch (_: Exception) {
            AppThemeMode.SYSTEM
        }
        SettingsStore.setThemeMode(ctx, mode)
        _state.value = _state.value.copy(appTheme = mode.name)
    }

    fun setTunMtu(mtu: Int) {
        val ctx = getApplication<Application>()
        val value = mtu.coerceIn(1200, 9000)
        SettingsStore.setTunMtu(ctx, value)
        _state.value = _state.value.copy(tunMtu = value)
    }

    fun setTunIpv6Enabled(enabled: Boolean) {
        val ctx = getApplication<Application>()
        SettingsStore.setTunIpv6Enabled(ctx, enabled)
        _state.value = _state.value.copy(tunIpv6Enabled = enabled)
    }

    fun setDnsMode(mode: String) {
        val ctx = getApplication<Application>()
        SettingsStore.setDnsMode(ctx, mode)
        _state.value = _state.value.copy(dnsMode = mode)
    }

    fun setDnsServers(servers: List<String>) {
        val ctx = getApplication<Application>()
        SettingsStore.setDnsServers(ctx, servers)
        _state.value = _state.value.copy(dnsServers = SettingsStore.getDnsServers(ctx))
    }

    fun setBootAutoStart(enabled: Boolean) {
        val ctx = getApplication<Application>()
        SettingsStore.setBootAutoStart(ctx, enabled)
        _state.value = _state.value.copy(bootAutoStart = enabled)
    }

    fun setAutoConnect(enabled: Boolean) {
        val ctx = getApplication<Application>()
        SettingsStore.setAutoConnect(ctx, enabled)
        _state.value = _state.value.copy(autoConnect = enabled)
    }

    fun setForegroundKeepAlive(enabled: Boolean) {
        val ctx = getApplication<Application>()
        SettingsStore.setForegroundKeepAlive(ctx, enabled)
        _state.value = _state.value.copy(foregroundKeepAlive = enabled)
    }

    fun setAppLanguage(language: String) {
        val ctx = getApplication<Application>()
        val safe = when (language.lowercase()) {
            "system", "zh-cn", "en" -> language.lowercase()
            else -> "system"
        }
        SettingsStore.setAppLanguage(ctx, safe)
        _state.value = _state.value.copy(appLanguage = safe)
    }
}

