package com.openworld.app.viewmodel

import android.app.Application
import android.net.Uri
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.openworld.app.R
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
import com.openworld.app.repository.RuleSetRepository
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.launch
import kotlinx.coroutines.Job
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.CancellationException

data class DefaultRuleSetDownloadState(
    val isActive: Boolean = false,
    val total: Int = 0,
    val completed: Int = 0,
    val currentTag: String? = null,
    val cancelled: Boolean = false
)

class SettingsViewModel(application: Application) : AndroidViewModel(application) {

    private val repository = SettingsRepository.getInstance(application)
    private val ruleSetRepository = RuleSetRepository.getInstance(application)
    
    // private val dataExportRepository = DataExportRepository.getInstance(application) // Still missing

    private val _downloadingRuleSets = MutableStateFlow<Set<String>>(emptySet())
    val downloadingRuleSets: StateFlow<Set<String>> = _downloadingRuleSets.asStateFlow()

    private val _defaultRuleSetDownloadState = MutableStateFlow(DefaultRuleSetDownloadState())
    val defaultRuleSetDownloadState: StateFlow<DefaultRuleSetDownloadState> = _defaultRuleSetDownloadState.asStateFlow()

    private var defaultRuleSetDownloadJob: Job? = null
    private val defaultRuleSetDownloadTags = mutableSetOf<String>()

    private val _exportState = MutableStateFlow<ExportState>(ExportState.Idle)
    val exportState: StateFlow<ExportState> = _exportState.asStateFlow()

    private val _importState = MutableStateFlow<ImportState>(ImportState.Idle)
    val importState: StateFlow<ImportState> = _importState.asStateFlow()

    private val installedAppsRepository = com.openworld.app.repository.InstalledAppsRepository.getInstance(application)
    val installedApps: StateFlow<List<com.openworld.app.model.InstalledApp>> = installedAppsRepository.installedApps

    val settings: StateFlow<AppSettings> = repository.settings
        .stateIn(
            scope = viewModelScope,
            started = SharingStarted.WhileSubscribed(5000),
            initialValue = AppSettings()
        )

    val appRules: StateFlow<List<AppRule>> = settings.map { it.appRules }
        .stateIn(
            scope = viewModelScope,
            started = SharingStarted.WhileSubscribed(5000),
            initialValue = emptyList()
        )
    
    val appGroups: StateFlow<List<AppGroup>> = settings.map { it.appGroups }
        .stateIn(
            scope = viewModelScope,
            started = SharingStarted.WhileSubscribed(5000),
            initialValue = emptyList()
        )

    init {
        viewModelScope.launch {
             installedAppsRepository.loadApps()
        }
    }

    fun ensureDefaultRuleSetsReady() {
        viewModelScope.launch {
            if (defaultRuleSetDownloadJob?.isActive == true) return@launch
            val currentRuleSets = repository.getRuleSets()
            if (currentRuleSets.isNotEmpty()) return@launch

            val defaultRuleSets = repository.getDefaultRuleSets()
            repository.setRuleSets(defaultRuleSets, notify = false)
            startDefaultRuleSetDownload(defaultRuleSets)
        }
    }
    
    fun cancelDefaultRuleSetDownload() {
        defaultRuleSetDownloadJob?.cancel()
        defaultRuleSetDownloadJob = null
        defaultRuleSetDownloadTags.forEach { tag ->
             val current = _downloadingRuleSets.value.toMutableSet()
             current.remove(tag)
             _downloadingRuleSets.value = current
        }
        defaultRuleSetDownloadTags.clear()
        _defaultRuleSetDownloadState.value = _defaultRuleSetDownloadState.value.copy(
            isActive = false,
            currentTag = null,
            cancelled = true
        )
    }

    private fun startDefaultRuleSetDownload(ruleSets: List<RuleSet>) {
        defaultRuleSetDownloadJob?.cancel()
        defaultRuleSetDownloadTags.clear()

        defaultRuleSetDownloadJob = viewModelScope.launch {
            val remoteRuleSets = ruleSets.filter { it.type == RuleSetType.REMOTE }
            if (remoteRuleSets.isEmpty()) {
                _defaultRuleSetDownloadState.value = DefaultRuleSetDownloadState()
                return@launch
            }

            var completedCount = 0
            _defaultRuleSetDownloadState.value = DefaultRuleSetDownloadState(
                isActive = true,
                total = remoteRuleSets.size,
                completed = 0
            )

            try {
                for (ruleSet in remoteRuleSets) {
                    ensureActive()
                    _defaultRuleSetDownloadState.value = _defaultRuleSetDownloadState.value.copy(
                        currentTag = ruleSet.tag
                    )

                    defaultRuleSetDownloadTags.add(ruleSet.tag)
                    val currentDownloading = _downloadingRuleSets.value.toMutableSet()
                    currentDownloading.add(ruleSet.tag)
                    _downloadingRuleSets.value = currentDownloading
                    
                    try {
                        ruleSetRepository.prefetchRuleSet(ruleSet, forceUpdate = false, allowNetwork = true)
                    } finally {
                        val current = _downloadingRuleSets.value.toMutableSet()
                        current.remove(ruleSet.tag)
                        _downloadingRuleSets.value = current
                        defaultRuleSetDownloadTags.remove(ruleSet.tag)
                    }

                    completedCount += 1
                    _defaultRuleSetDownloadState.value = _defaultRuleSetDownloadState.value.copy(
                        completed = completedCount
                    )
                }

                _defaultRuleSetDownloadState.value = _defaultRuleSetDownloadState.value.copy(
                    isActive = false,
                    currentTag = null,
                    cancelled = false
                )
            } catch (e: CancellationException) {
                defaultRuleSetDownloadTags.forEach { tag ->
                     val current = _downloadingRuleSets.value.toMutableSet()
                     current.remove(tag)
                     _downloadingRuleSets.value = current
                }
                defaultRuleSetDownloadTags.clear()
                _defaultRuleSetDownloadState.value = _defaultRuleSetDownloadState.value.copy(
                    isActive = false,
                    currentTag = null,
                    cancelled = true
                )
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
    
    fun setTunStack(value: TunStack) {
        viewModelScope.launch { repository.setTunStack(value) }
    }

    fun setTunMtu(value: Int) {
        viewModelScope.launch { repository.setTunMtu(value) }
    }

    fun setTunMtuAuto(value: Boolean) { 
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
    
    fun setVpnBlocklist(value: String) {
        viewModelScope.launch { repository.setVpnBlocklist(value) }
    }
    
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

    fun setProxyPort(value: Int) { 
        viewModelScope.launch { repository.setProxyPort(value) }
    }

    fun setAllowLan(value: Boolean) { 
        viewModelScope.launch { repository.setAllowLan(value) }
    }

    fun setAppendHttpProxy(value: Boolean) { 
        viewModelScope.launch { repository.setAppendHttpProxy(value) }
    }

    fun setLatencyTestConcurrency(value: Int) { 
        viewModelScope.launch { repository.setLatencyTestConcurrency(value) }
    }

    fun setLatencyTestTimeout(value: Int) { 
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
    
    // ==================== Advanced Routing ====================
    fun addCustomRule(rule: CustomRule) {
        viewModelScope.launch {
            val currentRules = settings.value.customRules.toMutableList()
            currentRules.add(rule)
            repository.setCustomRules(currentRules)
        }
    }

    fun updateCustomRule(rule: CustomRule) {
        viewModelScope.launch {
            val currentRules = settings.value.customRules.toMutableList()
            val index = currentRules.indexOfFirst { it.id == rule.id }
            if (index != -1) {
                currentRules[index] = rule
                repository.setCustomRules(currentRules)
            }
        }
    }

    fun deleteCustomRule(ruleId: String) {
        viewModelScope.launch {
            val currentRules = settings.value.customRules.toMutableList()
            currentRules.removeAll { it.id == ruleId }
            repository.setCustomRules(currentRules)
        }
    }
    
    fun addRuleSet(ruleSet: RuleSet, onResult: (Boolean, String) -> Unit = { _, _ -> }) {
        viewModelScope.launch {
            // Simplified logic compared to KunBox
             val currentSets = repository.getRuleSets().toMutableList()
            val exists = currentSets.any { it.tag == ruleSet.tag }
            if (exists) {
                onResult(false, "Rule set exists")
            } else {
                currentSets.add(ruleSet)
                repository.setRuleSets(currentSets)

                if (ruleSet.type == RuleSetType.REMOTE) {
                     val currentDownloading = _downloadingRuleSets.value.toMutableSet()
                     currentDownloading.add(ruleSet.tag)
                     _downloadingRuleSets.value = currentDownloading
                }

                val downloadOk = try {
                    ruleSetRepository.prefetchRuleSet(ruleSet, forceUpdate = false, allowNetwork = true)
                } finally {
                    if (ruleSet.type == RuleSetType.REMOTE) {
                        val currentDownloading = _downloadingRuleSets.value.toMutableSet()
                        currentDownloading.remove(ruleSet.tag)
                        _downloadingRuleSets.value = currentDownloading
                    }
                }

                if (downloadOk) {
                    onResult(true, "Rule set added and downloaded")
                } else {
                    onResult(true, "Rule set added but download failed")
                }
            }
        }
    }

    fun updateRuleSet(ruleSet: RuleSet) {
        viewModelScope.launch {
            val currentSets = settings.value.ruleSets.toMutableList()
            val index = currentSets.indexOfFirst { it.id == ruleSet.id }
            if (index != -1) {
                val previous = currentSets[index]
                currentSets[index] = ruleSet
                repository.setRuleSets(currentSets)

                if (!previous.enabled && ruleSet.enabled && ruleSet.type == RuleSetType.REMOTE) {
                    if (!_downloadingRuleSets.value.contains(ruleSet.tag)) {
                         val currentDownloading = _downloadingRuleSets.value.toMutableSet()
                         currentDownloading.add(ruleSet.tag)
                         _downloadingRuleSets.value = currentDownloading
                         
                        launch {
                            try {
                                ruleSetRepository.prefetchRuleSet(ruleSet, forceUpdate = false, allowNetwork = true)
                            } finally {
                                 val current = _downloadingRuleSets.value.toMutableSet()
                                 current.remove(ruleSet.tag)
                                 _downloadingRuleSets.value = current
                            }
                        }
                    }
                }
            }
        }
    }
    
    fun deleteRuleSet(ruleSetId: String) {
        viewModelScope.launch {
            val currentSets = settings.value.ruleSets.toMutableList()
            currentSets.removeAll { it.id == ruleSetId }
            repository.setRuleSets(currentSets)
        }
    }

    fun deleteRuleSets(ruleSetIds: List<String>) {
        viewModelScope.launch {
            val idsToDelete = ruleSetIds.toSet()
            val currentSets = settings.value.ruleSets.toMutableList()
            currentSets.removeAll { it.id in idsToDelete }
            repository.setRuleSets(currentSets)
        }
    }
    
    fun reorderRuleSets(newOrder: List<RuleSet>) {
        viewModelScope.launch {
            repository.setRuleSets(newOrder)
        }
    }
    
    // App Rules
    fun addAppRule(rule: AppRule) {
        viewModelScope.launch {
            val currentRules = settings.value.appRules.toMutableList()
            currentRules.removeAll { it.packageName == rule.packageName }
            currentRules.add(rule)
            repository.setAppRules(currentRules)
        }
    }

    fun updateAppRule(rule: AppRule) {
        viewModelScope.launch {
            val currentRules = settings.value.appRules.toMutableList()
            val index = currentRules.indexOfFirst { it.id == rule.id }
            if (index != -1) {
                currentRules[index] = rule
                repository.setAppRules(currentRules)
            }
        }
    }

    fun deleteAppRule(ruleId: String) {
        viewModelScope.launch {
            val currentRules = settings.value.appRules.toMutableList()
            currentRules.removeAll { it.id == ruleId }
            repository.setAppRules(currentRules)
        }
    }

    fun toggleAppRuleEnabled(ruleId: String) {
        viewModelScope.launch {
            val currentRules = settings.value.appRules.toMutableList()
            val index = currentRules.indexOfFirst { it.id == ruleId }
            if (index != -1) {
                val rule = currentRules[index]
                currentRules[index] = rule.copy(enabled = !rule.enabled)
                repository.setAppRules(currentRules)
            }
        }
    }

    // App Groups
    fun addAppGroup(group: AppGroup) {
        viewModelScope.launch {
            val currentGroups = settings.value.appGroups.toMutableList()
            currentGroups.add(group)
            repository.setAppGroups(currentGroups)
        }
    }

    fun updateAppGroup(group: AppGroup) {
        viewModelScope.launch {
            val currentGroups = settings.value.appGroups.toMutableList()
            val index = currentGroups.indexOfFirst { it.id == group.id }
            if (index != -1) {
                currentGroups[index] = group
                repository.setAppGroups(currentGroups)
            }
        }
    }

    fun deleteAppGroup(groupId: String) {
        viewModelScope.launch {
            val currentGroups = settings.value.appGroups.toMutableList()
            currentGroups.removeAll { it.id == groupId }
            repository.setAppGroups(currentGroups)
        }
    }

    fun toggleAppGroupEnabled(groupId: String) {
        viewModelScope.launch {
            val currentGroups = settings.value.appGroups.toMutableList()
            val index = currentGroups.indexOfFirst { it.id == groupId }
            if (index != -1) {
                val group = currentGroups[index]
                currentGroups[index] = group.copy(enabled = !group.enabled)
                repository.setAppGroups(currentGroups)
            }
        }
    }

    // ==================== Export/Import Stubs ====================
    fun exportData(uri: Uri) {
         _exportState.value = ExportState.Error("Not implemented yet")
    }
    
    fun validateImportFile(uri: Uri) {
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
