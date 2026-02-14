package com.openworld.app.viewmodel

import com.openworld.app.R
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
import com.openworld.app.model.ExportData
import com.openworld.app.model.ExportDataSummary
import com.openworld.app.model.ImportOptions
import com.openworld.app.model.ImportResult
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
import com.openworld.app.repository.DataExportRepository
import com.openworld.app.repository.RuleSetRepository
import com.openworld.app.repository.SettingsRepository
import com.openworld.app.service.RuleSetAutoUpdateWorker
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Job
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch

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
    private val dataExportRepository = DataExportRepository.getInstance(application)

    private val _downloadingRuleSets = MutableStateFlow<Set<String>>(emptySet())
    val downloadingRuleSets: StateFlow<Set<String>> = _downloadingRuleSets.asStateFlow()

    private val _defaultRuleSetDownloadState = MutableStateFlow(DefaultRuleSetDownloadState())
    val defaultRuleSetDownloadState: StateFlow<DefaultRuleSetDownloadState> = _defaultRuleSetDownloadState.asStateFlow()

    private var defaultRuleSetDownloadJob: Job? = null
    private val defaultRuleSetDownloadTags = mutableSetOf<String>()

    // 导入导出状�?    private val _exportState = MutableStateFlow<ExportState>(ExportState.Idle)
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
        viewModelScope.launch {
            if (defaultRuleSetDownloadJob?.isActive == true) return@launch
            val currentRuleSets = repository.getRuleSets()
            if (currentRuleSets.isNotEmpty()) return@launch

            val defaultRuleSets = repository.getDefaultRuleSets()
            repository.setRuleSets(defaultRuleSets)
            startDefaultRuleSetDownload(defaultRuleSets)
        }
    }

    fun cancelDefaultRuleSetDownload() {
        defaultRuleSetDownloadJob?.cancel()
        defaultRuleSetDownloadJob = null
        defaultRuleSetDownloadTags.forEach { tag ->
            _downloadingRuleSets.value -= tag
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
                    _downloadingRuleSets.value += ruleSet.tag
                    try {
                        ruleSetRepository.prefetchRuleSet(ruleSet, forceUpdate = false, allowNetwork = true)
                    } finally {
                        _downloadingRuleSets.value -= ruleSet.tag
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
                    _downloadingRuleSets.value -= tag
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

    // 通用设置
    fun setAutoConnect(value: Boolean) {
        viewModelScope.launch { repository.setAutoConnect(value) }
    }

    fun setExcludeFromRecent(value: Boolean) {
        viewModelScope.launch { repository.setExcludeFromRecent(value) }
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

    fun setBackgroundPowerSavingDelay(value: BackgroundPowerSavingDelay) {
        viewModelScope.launch {
            repository.setBackgroundPowerSavingDelay(value)
            // 同步更新 AppLifecycleObserver 的超时时�?            com.openworld.app.lifecycle.AppLifecycleObserver.setBackgroundTimeout(value.delayMs)
        }
    }

    fun setShowNotificationSpeed(value: Boolean) {
        viewModelScope.launch {
            repository.setShowNotificationSpeed(value)

            // 跨进程通知 Service 立即更新设置 (因为 Service 运行在独立进程，无法实时监听 DataStore)
            if (com.openworld.app.ipc.OpenWorldRemote.isRunning.value) {
                try {
                    val intent = android.content.Intent(getApplication(), com.openworld.app.service.OpenWorldService::class.java).apply {
                        action = com.openworld.app.service.OpenWorldService.ACTION_UPDATE_SETTING
                        putExtra(com.openworld.app.service.OpenWorldService.EXTRA_SETTING_KEY, "show_notification_speed")
                        putExtra(com.openworld.app.service.OpenWorldService.EXTRA_SETTING_VALUE_BOOL, value)
                    }
                    getApplication<Application>().startService(intent)
                } catch (e: Exception) {
                    android.util.Log.e("SettingsViewModel", "Failed to update service setting", e)
                }
            }
        }
    }

    // TUN/VPN 设置
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

    // DNS 设置
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

    // 路由设置
    fun setRoutingMode(value: RoutingMode, notifyRestartRequired: Boolean = true) {
        viewModelScope.launch { repository.setRoutingMode(value, notifyRestartRequired) }
    }

    fun setDefaultRule(value: DefaultRule) {
        viewModelScope.launch { repository.setDefaultRule(value) }
    }

    fun setBlockQuic(value: Boolean) {
        viewModelScope.launch { repository.setBlockQuic(value) }
    }

    fun setDebugLoggingEnabled(value: Boolean) {
        viewModelScope.launch { repository.setDebugLoggingEnabled(value) }
    }

    fun setLatencyTestMethod(value: LatencyTestMethod) {
        viewModelScope.launch { repository.setLatencyTestMethod(value) }
    }

    fun setLatencyTestUrl(value: String) {
        viewModelScope.launch { repository.setLatencyTestUrl(value) }
    }

    fun setLatencyTestTimeout(value: Int) {
        viewModelScope.launch { repository.setLatencyTestTimeout(value) }
    }

    fun setBypassLan(value: Boolean) {
        viewModelScope.launch { repository.setBypassLan(value) }
    }

    fun setWakeResetConnections(value: Boolean) {
        viewModelScope.launch { repository.setWakeResetConnections(value) }
    }

    fun updateLatencyTestConcurrency(value: Int) {
        viewModelScope.launch { repository.setLatencyTestConcurrency(value) }
    }

    fun updateLatencyTestTimeout(value: Int) {
        viewModelScope.launch { repository.setLatencyTestTimeout(value) }
    }

    fun setGhProxyMirror(value: GhProxyMirror) {
        viewModelScope.launch { repository.setGhProxyMirror(value) }
    }

    fun setSubscriptionUpdateTimeout(value: Int) {
        viewModelScope.launch { repository.setSubscriptionUpdateTimeout(value) }
    }

    // 代理设置
    fun updateProxyPort(value: Int) {
        viewModelScope.launch { repository.setProxyPort(value) }
    }

    fun updateAllowLan(value: Boolean) {
        viewModelScope.launch { repository.setAllowLan(value) }
    }

    fun updateAppendHttpProxy(value: Boolean) {
        viewModelScope.launch { repository.setAppendHttpProxy(value) }
    }

    // 高级路由
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
            fun normalizeRuleSetUrl(url: String, mirrorUrl: String): String {
                val rawPrefix = "https://raw.githubusercontent.com/"
                val cdnPrefix = "https://cdn.jsdelivr.net/gh/"

                // 先还原到原始 URL
                var rawUrl = url

                // 1. 如果�?jsDelivr 格式，还原为 raw 格式
                if (rawUrl.startsWith(cdnPrefix)) {
                    val path = rawUrl.removePrefix(cdnPrefix)
                    val parts = path.split("@", limit = 2)
                    if (parts.size == 2) {
                        val userRepo = parts[0]
                        val branchPath = parts[1]
                        rawUrl = "$rawPrefix$userRepo/$branchPath"
                    }
                } else {
                    // 2. 如果是其他前缀代理，移除前缀
                    val oldMirrors = listOf(
                        "https://ghp.ci/",
                        "https://mirror.ghproxy.com/",
                        "https://ghproxy.com/",
                        "https://ghproxy.net/",
                        "https://ghfast.top/",
                        "https://gh-proxy.com/"
                    )

                    for (mirror in oldMirrors) {
                        if (rawUrl.startsWith(mirror)) {
                            rawUrl = rawUrl.replace(mirror, rawPrefix)
                        }
                    }
                    // 3. 处理已有�?raw 链接被代理的情况
                    if (rawUrl.contains("raw.githubusercontent.com") && !rawUrl.startsWith(rawPrefix)) {
                        val path = rawUrl.substringAfter("raw.githubusercontent.com/")
                        rawUrl = rawPrefix + path
                    }
                }

                var updatedUrl = rawUrl

                // 应用当前选择的镜�?                if (mirrorUrl.contains("cdn.jsdelivr.net")) {
                    if (rawUrl.startsWith(rawPrefix)) {
                        val path = rawUrl.removePrefix(rawPrefix)
                        val parts = path.split("/", limit = 4)
                        if (parts.size >= 4) {
                            val user = parts[0]
                            val repo = parts[1]
                            val branch = parts[2]
                            val filePath = parts[3]
                            updatedUrl = "$cdnPrefix$user/$repo@$branch/$filePath"
                        }
                    }
                } else if (mirrorUrl != rawPrefix) {
                    if (rawUrl.startsWith(rawPrefix)) {
                        updatedUrl = rawUrl.replace(rawPrefix, mirrorUrl)
                    }
                }

                return updatedUrl
            }

            val normalizedRuleSet = if (ruleSet.type == RuleSetType.REMOTE) {
                val mirrorUrl = settings.value.ghProxyMirror.url
                ruleSet.copy(url = normalizeRuleSetUrl(ruleSet.url, mirrorUrl))
            } else {
                ruleSet
            }

            val currentSets = repository.getRuleSets().toMutableList()
            val exists = currentSets.any { it.tag == normalizedRuleSet.tag }
            if (exists) {
                onResult(false, getApplication<Application>().getString(R.string.rulesets_exists, normalizedRuleSet.tag))
            } else {
                currentSets.add(normalizedRuleSet)
                repository.setRuleSets(currentSets)

                if (normalizedRuleSet.type == RuleSetType.REMOTE) {
                    _downloadingRuleSets.value += normalizedRuleSet.tag
                }

                val downloadOk = try {
                    ruleSetRepository.prefetchRuleSet(normalizedRuleSet, forceUpdate = false, allowNetwork = true)
                } finally {
                    if (normalizedRuleSet.type == RuleSetType.REMOTE) {
                        _downloadingRuleSets.value -= normalizedRuleSet.tag
                    }
                }

                if (downloadOk) {
                    onResult(true, getApplication<Application>().getString(R.string.rulesets_added_downloaded, normalizedRuleSet.tag))
                } else {
                    onResult(true, getApplication<Application>().getString(R.string.rulesets_added_failed, normalizedRuleSet.tag))
                }
            }
        }
    }

    fun addRuleSets(ruleSets: List<RuleSet>, onResult: (Int) -> Unit = { _ -> }) {
        viewModelScope.launch {
            val currentSets = repository.getRuleSets().toMutableList()
            val addedRuleSets = mutableListOf<RuleSet>()

            fun normalizeRuleSetUrl(url: String, mirrorUrl: String): String {
                val rawPrefix = "https://raw.githubusercontent.com/"
                val cdnPrefix = "https://cdn.jsdelivr.net/gh/"

                // 先还原到原始 URL
                var rawUrl = url

                // 1. 如果�?jsDelivr 格式，还原为 raw 格式
                if (rawUrl.startsWith(cdnPrefix)) {
                    val path = rawUrl.removePrefix(cdnPrefix)
                    val parts = path.split("@", limit = 2)
                    if (parts.size == 2) {
                        val userRepo = parts[0]
                        val branchPath = parts[1]
                        rawUrl = "$rawPrefix$userRepo/$branchPath"
                    }
                } else {
                    // 2. 如果是其他前缀代理，移除前缀
                    val oldMirrors = listOf(
                        "https://ghp.ci/",
                        "https://mirror.ghproxy.com/",
                        "https://ghproxy.com/",
                        "https://ghproxy.net/",
                        "https://ghfast.top/",
                        "https://gh-proxy.com/"
                    )

                    for (mirror in oldMirrors) {
                        if (rawUrl.startsWith(mirror)) {
                            rawUrl = rawUrl.replace(mirror, rawPrefix)
                        }
                    }
                    // 3. 处理已有�?raw 链接被代理的情况
                    if (rawUrl.contains("raw.githubusercontent.com") && !rawUrl.startsWith(rawPrefix)) {
                        val path = rawUrl.substringAfter("raw.githubusercontent.com/")
                        rawUrl = rawPrefix + path
                    }
                }

                var updatedUrl = rawUrl

                // 应用当前选择的镜�?                if (mirrorUrl.contains("cdn.jsdelivr.net")) {
                    if (rawUrl.startsWith(rawPrefix)) {
                        val path = rawUrl.removePrefix(rawPrefix)
                        val parts = path.split("/", limit = 4)
                        if (parts.size >= 4) {
                            val user = parts[0]
                            val repo = parts[1]
                            val branch = parts[2]
                            val filePath = parts[3]
                            updatedUrl = "$cdnPrefix$user/$repo@$branch/$filePath"
                        }
                    }
                } else if (mirrorUrl != rawPrefix) {
                    if (rawUrl.startsWith(rawPrefix)) {
                        updatedUrl = rawUrl.replace(rawPrefix, mirrorUrl)
                    }
                }

                return updatedUrl
            }

            fun normalizeRuleSet(ruleSet: RuleSet): RuleSet {
                if (ruleSet.type != RuleSetType.REMOTE) return ruleSet
                val mirrorUrl = settings.value.ghProxyMirror.url
                return ruleSet.copy(url = normalizeRuleSetUrl(ruleSet.url, mirrorUrl))
            }

            ruleSets.forEach { ruleSet ->
                val normalized = normalizeRuleSet(ruleSet)
                val exists = currentSets.any { it.tag == normalized.tag }
                if (!exists) {
                    currentSets.add(normalized)
                    addedRuleSets.add(normalized)
                }
            }

            repository.setRuleSets(currentSets)

            // Best-effort prefetch for newly added rule sets.
            addedRuleSets.forEach { ruleSet ->
                if (ruleSet.type == RuleSetType.REMOTE) {
                    _downloadingRuleSets.value += ruleSet.tag
                }
                launch {
                    try {
                        ruleSetRepository.prefetchRuleSet(ruleSet, forceUpdate = false, allowNetwork = true)
                    } finally {
                        if (ruleSet.type == RuleSetType.REMOTE) {
                            _downloadingRuleSets.value -= ruleSet.tag
                        }
                    }
                }
            }

            onResult(addedRuleSets.size)
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
                        _downloadingRuleSets.value += ruleSet.tag
                        launch {
                            try {
                                ruleSetRepository.prefetchRuleSet(ruleSet, forceUpdate = false, allowNetwork = true)
                            } finally {
                                _downloadingRuleSets.value -= ruleSet.tag
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

    // 全局规则集自动更新设�?    fun setRuleSetAutoUpdateEnabled(value: Boolean) {
        viewModelScope.launch {
            val currentSettings = repository.settings.first()
            repository.setRuleSetAutoUpdateEnabled(value)

            // 根据开关状态调度或取消自动更新任务
            if (value && currentSettings.ruleSetAutoUpdateInterval > 0) {
                RuleSetAutoUpdateWorker.schedule(
                    getApplication(),
                    currentSettings.ruleSetAutoUpdateInterval
                )
            } else {
                RuleSetAutoUpdateWorker.cancel(getApplication())
            }
        }
    }

    fun setRuleSetAutoUpdateInterval(value: Int) {
        viewModelScope.launch {
            val currentSettings = repository.settings.first()
            repository.setRuleSetAutoUpdateInterval(value)

            // 如果自动更新已启用，重新调度任务
            if (currentSettings.ruleSetAutoUpdateEnabled && value > 0) {
                RuleSetAutoUpdateWorker.schedule(getApplication(), value)
            }
        }
    }

    fun reorderRuleSets(newOrder: List<RuleSet>) {
        viewModelScope.launch {
            repository.setRuleSets(newOrder)
        }
    }

    // App 分流规则
    fun addAppRule(rule: AppRule) {
        viewModelScope.launch {
            val currentRules = settings.value.appRules.toMutableList()
            // 避免重复添加同一个应�?            currentRules.removeAll { it.packageName == rule.packageName }
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

    // App 分组
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

    // ==================== 导入导出功能 ====================

    /**
     * 导出数据到文�?     */
    fun exportData(uri: Uri) {
        viewModelScope.launch {
            _exportState.value = ExportState.Exporting

            val result = dataExportRepository.exportToFile(uri)

            _exportState.value = if (result.isSuccess) {
                ExportState.Success
            } else {
                ExportState.Error(result.exceptionOrNull()?.message ?: getApplication<Application>().getString(R.string.export_failed))
            }
        }
    }

    /**
     * 验证导入文件（用于预览）
     */
    fun validateImportFile(uri: Uri) {
        viewModelScope.launch {
            _importState.value = ImportState.Validating

            val result = dataExportRepository.validateFromFile(uri)

            _importState.value = if (result.isSuccess) {
                val exportData = result.getOrThrow()
                val summary = dataExportRepository.getExportDataSummary(exportData)
                ImportState.Preview(uri, exportData, summary)
            } else {
                ImportState.Error(result.exceptionOrNull()?.message ?: getApplication<Application>().getString(R.string.data_validation_failed))
            }
        }
    }

    /**
     * 确认导入数据
     */
    fun confirmImport(uri: Uri, options: ImportOptions = ImportOptions()) {
        viewModelScope.launch {
            _importState.value = ImportState.Importing

            val result = dataExportRepository.importFromFile(uri, options)

            _importState.value = if (result.isSuccess) {
                when (val importResult = result.getOrThrow()) {
                    is ImportResult.Success -> ImportState.Success(
                        profilesImported = importResult.profilesImported,
                        nodesImported = importResult.nodesImported,
                        settingsImported = importResult.settingsImported
                    )
                    is ImportResult.PartialSuccess -> ImportState.PartialSuccess(
                        profilesImported = importResult.profilesImported,
                        profilesFailed = importResult.profilesFailed,
                        errors = importResult.errors
                    )
                    is ImportResult.Failed -> ImportState.Error(importResult.error)
                }
            } else {
                ImportState.Error(result.exceptionOrNull()?.message ?: getApplication<Application>().getString(R.string.import_failed))
            }
        }
    }

    /**
     * 重置导出状�?     */
    fun resetExportState() {
        _exportState.value = ExportState.Idle
    }

    /**
     * 重置导入状�?     */
    fun resetImportState() {
        _importState.value = ImportState.Idle
    }
}

/**
 * 导出状�? */
sealed class ExportState {
    object Idle : ExportState()
    object Exporting : ExportState()
    object Success : ExportState()
    data class Error(val message: String) : ExportState()
}

/**
 * 导入状�? */
sealed class ImportState {
    object Idle : ImportState()
    object Validating : ImportState()
    data class Preview(
        val uri: Uri,
        val data: ExportData,
        val summary: ExportDataSummary
    ) : ImportState()
    object Importing : ImportState()
    data class Success(
        val profilesImported: Int,
        val nodesImported: Int,
        val settingsImported: Boolean
    ) : ImportState()
    data class PartialSuccess(
        val profilesImported: Int,
        val profilesFailed: Int,
        val errors: List<String>
    ) : ImportState()
    data class Error(val message: String) : ImportState()
}







