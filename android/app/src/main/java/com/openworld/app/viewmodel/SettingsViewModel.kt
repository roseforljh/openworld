package com.openworld.app.viewmodel

import android.app.Application
import android.net.Uri
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.openworld.app.model.AppSettings
import com.openworld.app.model.CustomRule
import com.openworld.app.model.DefaultRule
import com.openworld.app.model.DnsStrategy
import com.openworld.app.model.AppThemeMode
import com.openworld.app.model.AppLanguage
import com.openworld.app.model.RoutingMode
import com.openworld.app.model.AppRule
import com.openworld.app.model.AppGroup
import com.openworld.app.model.RuleSet
import com.openworld.app.model.RuleSetType
import com.openworld.app.model.TunStack
import com.openworld.app.model.LatencyTestMethod
import com.openworld.app.model.VpnAppMode
import com.openworld.app.model.VpnRouteMode
import com.openworld.app.model.GhProxyMirror
import com.openworld.app.model.BackgroundPowerSavingDelay
import com.openworld.app.repository.SettingsRepository
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch

class SettingsViewModel(application: Application) : AndroidViewModel(application) {

    private val repository = SettingsRepository.getInstance(application)
    
    // Stubbed repositories/classes for now
    // private val ruleSetRepository = RuleSetRepository.getInstance(application)
    // private val dataExportRepository = DataExportRepository.getInstance(application)

    private val _downloadingRuleSets = MutableStateFlow<Set<String>>(emptySet())
    val downloadingRuleSets: StateFlow<Set<String>> = _downloadingRuleSets.asStateFlow()

    private val _exportState = MutableStateFlow<ExportState>(ExportState.Idle)
    val exportState: StateFlow<ExportState> = _exportState.asStateFlow()

    private val _importState = MutableStateFlow<ImportState>(ImportState.Idle)
    val importState: StateFlow<ImportState> = _importState.asStateFlow()

    val settings: StateFlow<AppSettings> = repository.settings
        .stateIn(
            scope = viewModelScope,
            started = SharingStarted.WhileSubscribed(5000),
            initialValue = AppSettings()
        )

    fun ensureDefaultRuleSetsReady() {
        // Todo: Implement RuleSet download logic
        viewModelScope.launch {
            if (repository.getRuleSets().isEmpty()) {
                repository.setRuleSets(repository.getDefaultRuleSets(), notify = false)
            }
        }
    }

    // ==================== General Settings ====================
    fun setAutoConnect(value: Boolean) {
        viewModelScope.launch { repository.setAutoConnect(value) }
    }

    fun setAppTheme(value: AppThemeMode) {
        viewModelScope.launch { repository.setAppTheme(value) }
    }

    fun setAppLanguage(value: AppLanguage) {
        viewModelScope.launch { repository.setAppLanguage(value) }
    }

    fun setAutoCheckUpdate(value: Boolean) {
        viewModelScope.launch { repository.setAutoCheckUpdate(value) }
    }

    // ==================== TUN/VPN Settings ====================
    fun setTunEnabled(value: Boolean) {
        viewModelScope.launch { repository.setTunEnabled(value) }
    }

    // ... Other simple setters ...
    
    fun setDebugLoggingEnabled(value: Boolean) {
        viewModelScope.launch { repository.setDebugLoggingEnabled(value) }
    }

    fun setRuleSetAutoUpdateEnabled(value: Boolean) {
        viewModelScope.launch { repository.setRuleSetAutoUpdateEnabled(value) }
    }
    
    fun setRuleSetAutoUpdateInterval(value: Int) {
         viewModelScope.launch { repository.setRuleSetAutoUpdateInterval(value) }
    }

    // ==================== Connection Settings ====================
    fun setWakeResetConnections(value: Boolean) {
        viewModelScope.launch { repository.setWakeResetConnections(value) }
    }

    fun setBackgroundPowerSavingDelay(value: BackgroundPowerSavingDelay) {
        viewModelScope.launch { repository.setBackgroundPowerSavingDelay(value) }
    }

    fun setExcludeFromRecent(value: Boolean) {
        viewModelScope.launch { repository.setExcludeFromRecent(value) }
    }

    fun setShowNotificationSpeed(value: Boolean) {
        viewModelScope.launch { repository.setShowNotificationSpeed(value) }
    }

    fun setProxyPort(value: Int) { // Renamed from updateProxyPort
        viewModelScope.launch { repository.setProxyPort(value) }
    }

    fun setAllowLan(value: Boolean) { // Renamed from updateAllowLan
        viewModelScope.launch { repository.setAllowLan(value) }
    }

    fun setAppendHttpProxy(value: Boolean) { // Renamed from updateAppendHttpProxy
        viewModelScope.launch { repository.setAppendHttpProxy(value) }
    }

    fun setLatencyTestConcurrency(value: Int) { // Renamed from updateLatencyTestConcurrency
        viewModelScope.launch { repository.setLatencyTestConcurrency(value) }
    }

    fun setLatencyTestTimeout(value: Int) { // Renamed from updateLatencyTestTimeout
        viewModelScope.launch { repository.setLatencyTestTimeout(value) }
    }

    // ==================== Routing Settings ====================
    fun setRoutingMode(value: RoutingMode) {
        viewModelScope.launch { repository.setRoutingMode(value) }
    }

    fun setDefaultRule(value: DefaultRule) {
        viewModelScope.launch { repository.setDefaultRule(value) }
    }

    fun setLatencyTestMethod(value: LatencyTestMethod) {
        viewModelScope.launch { repository.setLatencyTestMethod(value) }
    }

    fun setLatencyTestUrl(value: String) {
        viewModelScope.launch { repository.setLatencyTestUrl(value) }
    }

    fun setGhProxyMirror(value: GhProxyMirror) {
        viewModelScope.launch { repository.setGhProxyMirror(value) }
    }

    fun setSubscriptionUpdateTimeout(value: Int) {
        viewModelScope.launch { repository.setSubscriptionUpdateTimeout(value) }
    }

    fun setBlockQuic(value: Boolean) {
        viewModelScope.launch { repository.setBlockQuic(value) }
    }

    fun setBypassLan(value: Boolean) {
        viewModelScope.launch { repository.setBypassLan(value) }
    }

    // ==================== DNS Settings ====================
    fun setLocalDns(value: String) {
        viewModelScope.launch { repository.setLocalDns(value) }
    }

    fun setRemoteDns(value: String) {
        viewModelScope.launch { repository.setRemoteDns(value) }
    }

    fun setFakeDnsEnabled(value: Boolean) {
        viewModelScope.launch { repository.setFakeDnsEnabled(value) }
    }

    fun setFakeIpRange(value: String) {
        viewModelScope.launch { repository.setFakeIpRange(value) }
    }

    fun setDnsStrategy(value: DnsStrategy) {
        viewModelScope.launch { repository.setDnsStrategy(value) }
    }

    fun setRemoteDnsStrategy(value: DnsStrategy) {
        viewModelScope.launch { repository.setRemoteDnsStrategy(value) }
    }

    fun setDirectDnsStrategy(value: DnsStrategy) {
        viewModelScope.launch { repository.setDirectDnsStrategy(value) }
    }

    fun setServerAddressStrategy(value: DnsStrategy) {
        viewModelScope.launch { repository.setServerAddressStrategy(value) }
    }

    fun setDnsCacheEnabled(value: Boolean) {
        viewModelScope.launch { repository.setDnsCacheEnabled(value) }
    }

    // ==================== Tun/VPN Settings ====================
    fun setTunStack(value: TunStack) {
        viewModelScope.launch { repository.setTunStack(value) }
    }

    fun setTunMtu(value: Int) {
        viewModelScope.launch { repository.setTunMtu(value) }
    }

    fun setTunMtuAuto(value: Boolean) { // Note: Existing code might have this? No, it wasn't in list.
        viewModelScope.launch { repository.setTunMtuAuto(value) }
    }

    fun setTunInterfaceName(value: String) {
        viewModelScope.launch { repository.setTunInterfaceName(value) }
    }

    fun setAutoRoute(value: Boolean) {
        viewModelScope.launch { repository.setAutoRoute(value) }
    }

    fun setStrictRoute(value: Boolean) {
        viewModelScope.launch { repository.setStrictRoute(value) }
    }

    fun setEndpointIndependentNat(value: Boolean) {
        viewModelScope.launch { repository.setEndpointIndependentNat(value) }
    }

    fun setVpnRouteMode(value: VpnRouteMode) {
        viewModelScope.launch { repository.setVpnRouteMode(value) }
    }

    fun setVpnRouteIncludeCidrs(value: String) {
        viewModelScope.launch { repository.setVpnRouteIncludeCidrs(value) }
    }

    fun setVpnAppMode(value: VpnAppMode) {
        viewModelScope.launch { repository.setVpnAppMode(value) }
    }

    fun setVpnAllowlist(value: String) {
        viewModelScope.launch { repository.setVpnAllowlist(value) }
    }

    // ==================== Export/Import Stubs ====================
    fun exportData(uri: Uri) {
         // Placeholder
         _exportState.value = ExportState.Error("Not implemented yet")
    }
    
    fun validateImportFile(uri: Uri) {
         // Placeholder
         _importState.value = ImportState.Error("Not implemented yet")
    }

    fun resetExportState() {
        _exportState.value = ExportState.Idle
    }

    fun resetImportState() {
        _importState.value = ImportState.Idle
    }
    
    fun confirmImport(uri: Uri, options: Any) {
         // Placeholder
    }
}

sealed class ExportState {
    object Idle : ExportState()
    object Exporting : ExportState()
    object Success : ExportState()
    data class Error(val message: String) : ExportState()
}

sealed class ImportState {
    object Idle : ImportState()
    object Validating : ImportState()
    data class Preview(val uri: Uri, val data: Any, val summary: Any) : ImportState()
    object Importing : ImportState()
    object Success : ImportState()
    data class Error(val message: String) : ImportState()
}
