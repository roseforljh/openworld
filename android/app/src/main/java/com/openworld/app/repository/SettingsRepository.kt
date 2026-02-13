package com.openworld.app.repository

import android.content.Context
import android.util.Log
import com.google.gson.Gson
import com.openworld.app.model.AppSettings
import com.openworld.app.model.AppThemeMode
import com.openworld.app.model.AppLanguage
import com.openworld.app.model.RuleSet
import com.openworld.app.model.RuleSetType
import com.openworld.app.model.RuleSetOutboundMode
import com.openworld.app.model.GhProxyMirror
import com.openworld.app.model.BackgroundPowerSavingDelay
import com.openworld.app.model.RoutingMode
import com.openworld.app.model.TunStack
import com.openworld.app.model.VpnRouteMode
import com.openworld.app.model.VpnAppMode
import com.openworld.app.model.DnsStrategy
import com.openworld.app.model.DefaultRule
import com.openworld.app.model.NodeSortType
import com.openworld.app.model.NodeFilter
import com.openworld.app.model.LatencyTestMethod
import com.openworld.app.model.CustomRule
import com.openworld.app.model.AppRule
import com.openworld.app.model.AppGroup
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import java.util.concurrent.Executors

/**
 * SettingsRepository: Persistent settings storage using SharedPreferences
 */
class SettingsRepository private constructor(context: Context) {

    private val prefs = context.getSharedPreferences("settings_repo", Context.MODE_PRIVATE)
    private val gson = Gson()

    private val _settings = MutableStateFlow(loadSettings())
    val settings: StateFlow<AppSettings> = _settings.asStateFlow()

    private fun loadSettings(): AppSettings {
        val json = prefs.getString("app_settings_json", null)
        return if (json != null) {
            try {
                gson.fromJson(json, AppSettings::class.java)
            } catch (e: Exception) {
                Log.e("SettingsRepository", "Failed to load settings", e)
                AppSettings()
            }
        } else {
            AppSettings()
        }
    }

    private fun saveSettings(newSettings: AppSettings) {
        val json = gson.toJson(newSettings)
        prefs.edit().putString("app_settings_json", json).apply()
        _settings.value = newSettings
    }
    
    // Simulate updating settings consistently
    private suspend fun updateSettings(transform: (AppSettings) -> AppSettings) {
        val current = _settings.value
        val newSettings = transform(current)
        saveSettings(newSettings)
    }

    // ==================== Methods matching KunBox's SettingsRepository ====================

    fun getDefaultRuleSets(): List<RuleSet> {
        val geositeBase = "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set"
        val geoipBase = "https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set"
        return listOf(
            RuleSet(
                tag = "geosite-cn",
                type = RuleSetType.REMOTE,
                url = "$geositeBase/geosite-cn.srs",
                enabled = false,
                outboundMode = RuleSetOutboundMode.DIRECT
            ),
            RuleSet(
                tag = "geoip-cn",
                type = RuleSetType.REMOTE,
                url = "$geoipBase/geoip-cn.srs",
                enabled = false,
                outboundMode = RuleSetOutboundMode.DIRECT
            ),
             RuleSet(
                tag = "geosite-geolocation-!cn",
                type = RuleSetType.REMOTE,
                url = "$geositeBase/geosite-geolocation-!cn.srs",
                enabled = false,
                outboundMode = RuleSetOutboundMode.PROXY
            )
        )
    }

    suspend fun setAutoConnect(value: Boolean) = updateSettings { it.copy(autoConnect = value) }
    suspend fun setExcludeFromRecent(value: Boolean) = updateSettings { it.copy(excludeFromRecent = value) }
    suspend fun setAppTheme(value: AppThemeMode) = updateSettings { it.copy(appTheme = value) }
    suspend fun setAppLanguage(value: AppLanguage) = updateSettings { it.copy(appLanguage = value) }
    suspend fun setShowNotificationSpeed(value: Boolean) = updateSettings { it.copy(showNotificationSpeed = value) }

    suspend fun setTunEnabled(value: Boolean) = updateSettings { it.copy(tunEnabled = value) }
    suspend fun setTunStack(value: TunStack) = updateSettings { it.copy(tunStack = value) }
    suspend fun setTunMtu(value: Int) = updateSettings { it.copy(tunMtu = value) }
    suspend fun setTunMtuAuto(value: Boolean) = updateSettings { it.copy(tunMtuAuto = value) }
    suspend fun setTunInterfaceName(value: String) = updateSettings { it.copy(tunInterfaceName = value) }
    suspend fun setAutoRoute(value: Boolean) = updateSettings { it.copy(autoRoute = value) }
    suspend fun setStrictRoute(value: Boolean) = updateSettings { it.copy(strictRoute = value) }
    suspend fun setEndpointIndependentNat(value: Boolean) = updateSettings { it.copy(endpointIndependentNat = value) }
    suspend fun setVpnRouteMode(value: VpnRouteMode) = updateSettings { it.copy(vpnRouteMode = value) }
    suspend fun setVpnRouteIncludeCidrs(value: String) = updateSettings { it.copy(vpnRouteIncludeCidrs = value) }
    suspend fun setVpnAppMode(value: VpnAppMode) = updateSettings { it.copy(vpnAppMode = value) }
    suspend fun setVpnAllowlist(value: String) = updateSettings { it.copy(vpnAllowlist = value) }
    suspend fun setVpnBlocklist(value: String) = updateSettings { it.copy(vpnBlocklist = value) }

    suspend fun setLocalDns(value: String) = updateSettings { it.copy(localDns = value) }
    suspend fun setRemoteDns(value: String) = updateSettings { it.copy(remoteDns = value) }
    suspend fun setFakeDnsEnabled(value: Boolean) = updateSettings { it.copy(fakeDnsEnabled = value) }
    suspend fun setFakeIpRange(value: String) = updateSettings { it.copy(fakeIpRange = value) }
    suspend fun setDnsStrategy(value: DnsStrategy) = updateSettings { it.copy(dnsStrategy = value) }
    suspend fun setRemoteDnsStrategy(value: DnsStrategy) = updateSettings { it.copy(remoteDnsStrategy = value) }
    suspend fun setDirectDnsStrategy(value: DnsStrategy) = updateSettings { it.copy(directDnsStrategy = value) }
    suspend fun setServerAddressStrategy(value: DnsStrategy) = updateSettings { it.copy(serverAddressStrategy = value) }
    suspend fun setDnsCacheEnabled(value: Boolean) = updateSettings { it.copy(dnsCacheEnabled = value) }

    suspend fun setRoutingMode(value: RoutingMode, notifyRestartRequired: Boolean = true) = updateSettings { it.copy(routingMode = value) }
    suspend fun setDefaultRule(value: DefaultRule) = updateSettings { it.copy(defaultRule = value) }
    suspend fun setBlockQuic(value: Boolean) = updateSettings { it.copy(blockQuic = value) }
    suspend fun setDebugLoggingEnabled(value: Boolean) = updateSettings { it.copy(debugLoggingEnabled = value) }
    suspend fun setLatencyTestMethod(value: LatencyTestMethod) = updateSettings { it.copy(latencyTestMethod = value) }
    suspend fun setLatencyTestUrl(value: String) = updateSettings { it.copy(latencyTestUrl = value) }
    suspend fun setLatencyTestTimeout(value: Int) = updateSettings { it.copy(latencyTestTimeout = value) }
    suspend fun setLatencyTestConcurrency(value: Int) = updateSettings { it.copy(latencyTestConcurrency = value) }
    suspend fun setBypassLan(value: Boolean) = updateSettings { it.copy(bypassLan = value) }
    suspend fun setWakeResetConnections(value: Boolean) = updateSettings { it.copy(wakeResetConnections = value) }
    suspend fun setGhProxyMirror(value: GhProxyMirror) = updateSettings { it.copy(ghProxyMirror = value) }
    suspend fun setProxyPort(value: Int) = updateSettings { it.copy(proxyPort = value) }
    suspend fun setAllowLan(value: Boolean) = updateSettings { it.copy(allowLan = value) }
    suspend fun setAppendHttpProxy(value: Boolean) = updateSettings { it.copy(appendHttpProxy = value) }

    suspend fun setCustomRules(value: List<CustomRule>) = updateSettings { it.copy(customRules = value) }
    suspend fun setRuleSets(value: List<RuleSet>, notify: Boolean = true) = updateSettings { it.copy(ruleSets = value) }
    suspend fun getRuleSets(): List<RuleSet> = settings.value.ruleSets
    suspend fun setAppRules(value: List<AppRule>) = updateSettings { it.copy(appRules = value) }
    suspend fun setAppGroups(value: List<AppGroup>) = updateSettings { it.copy(appGroups = value) }

    suspend fun setRuleSetAutoUpdateEnabled(value: Boolean) = updateSettings { it.copy(ruleSetAutoUpdateEnabled = value) }
    suspend fun setRuleSetAutoUpdateInterval(value: Int) = updateSettings { it.copy(ruleSetAutoUpdateInterval = value) }
    suspend fun setSubscriptionUpdateTimeout(value: Int) = updateSettings { it.copy(subscriptionUpdateTimeout = value) }
    suspend fun setAutoCheckUpdate(value: Boolean) = updateSettings { it.copy(autoCheckUpdate = value) }
    suspend fun setBackgroundPowerSavingDelay(value: BackgroundPowerSavingDelay) = updateSettings { it.copy(backgroundPowerSavingDelay = value) }

    suspend fun setNodeFilter(value: NodeFilter) = updateSettings { it.copy(nodeFilter = value) }
    suspend fun setNodeSortType(sortType: NodeSortType) = updateSettings { it.copy(nodeSortType = sortType) }
    
    companion object {
        @Volatile
        private var INSTANCE: SettingsRepository? = null

        fun getInstance(context: Context): SettingsRepository {
            return INSTANCE ?: synchronized(this) {
                INSTANCE ?: SettingsRepository(context.applicationContext).also { INSTANCE = it }
            }
        }
    }
}
