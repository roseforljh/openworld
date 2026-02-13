package com.openworld.app.viewmodel

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.google.gson.Gson
import com.google.gson.reflect.TypeToken
import com.openworld.app.config.ConfigManager
import com.openworld.app.repository.CoreRepository
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch

class RuleRoutingViewModel(app: Application) : AndroidViewModel(app) {

    data class RuleSetUi(
        val name: String,
        val url: String,
        val nodeCount: Int,
        val lastUpdated: Long
    )

    data class DomainRuleUi(
        val id: String,
        val type: String,
        val domain: String,
        val outbound: String,
        val coreIndex: Int? = null
    )

    data class AppRuleUi(
        val id: String,
        val packageName: String,
        val outbound: String
    )

    data class UiState(
        val loading: Boolean = false,
        val saving: Boolean = false,
        val error: String? = null,
        val warning: String? = null,
        val ruleSets: List<RuleSetUi> = emptyList(),
        val domainRules: List<DomainRuleUi> = emptyList(),
        val appRoutingMode: String = "whitelist",
        val appRules: List<AppRuleUi> = emptyList(),
        val outbounds: List<String> = emptyList(),
        val selectedOutbound: String = "",
        val hasSelector: Boolean = false,
        val needsReconnectHint: Boolean = false
    )

    private val _state = MutableStateFlow(UiState())
    val state: StateFlow<UiState> = _state.asStateFlow()

    private val _toast = MutableSharedFlow<String>(extraBufferCapacity = 1)
    val toast: SharedFlow<String> = _toast.asSharedFlow()

    private val gson = Gson()

    init {
        refreshAll()
    }

    fun refreshAll() {
        viewModelScope.launch(Dispatchers.IO) {
            _state.value = _state.value.copy(loading = true, error = null)
            val providers = CoreRepository.listProviders().map {
                RuleSetUi(
                    name = it.name,
                    url = it.url,
                    nodeCount = it.nodeCount,
                    lastUpdated = it.lastUpdated
                )
            }
            val domainRules = loadDomainRules()
            val appRoutingMode = loadAppRoutingMode()
            val appRules = loadAppRules()
            syncAppRulesToProxyConfig(appRules)
            val outbounds = CoreRepository.listOutbounds().map { it.tag }.ifEmpty {
                listOf("direct", "proxy", "reject")
            }
            val selectedOutbound = CoreRepository.getSelectedOutbound()
            val hasSelector = CoreRepository.hasSelector()
            _state.value = _state.value.copy(
                loading = false,
                ruleSets = providers,
                domainRules = domainRules,
                appRoutingMode = appRoutingMode,
                appRules = appRules,
                outbounds = outbounds,
                selectedOutbound = selectedOutbound,
                hasSelector = hasSelector,
                warning = if (hasSelector || selectedOutbound.isNotBlank()) null else "当前内核未暴露默认出站选择器，默认策略将以配置为准",
                needsReconnectHint = false
            )
        }
    }

    fun addRuleSet(name: String, url: String, intervalHours: Int) {
        viewModelScope.launch(Dispatchers.IO) {
            val trimmedName = name.trim()
            val trimmedUrl = url.trim()
            if (trimmedName.isBlank() || trimmedUrl.isBlank()) {
                _toast.tryEmit("规则集名称和 URL 不能为空")
                return@launch
            }
            _state.value = _state.value.copy(saving = true)
            val ok = CoreRepository.addHttpProvider(trimmedName, trimmedUrl, (intervalHours.coerceIn(1, 168) * 3600L))
            _state.value = _state.value.copy(saving = false)
            if (ok) {
                _toast.tryEmit("规则集已导入")
                refreshAll()
            } else {
                _toast.tryEmit("导入失败，请检查名称或 URL")
            }
        }
    }

    fun updateRuleSet(name: String) {
        viewModelScope.launch(Dispatchers.IO) {
            _state.value = _state.value.copy(saving = true)
            val code = CoreRepository.updateProvider(name)
            _state.value = _state.value.copy(saving = false)
            if (code >= 0) {
                _toast.tryEmit("规则集更新完成")
                refreshAll()
            } else {
                _toast.tryEmit("规则集更新失败")
            }
        }
    }

    fun removeRuleSet(name: String) {
        viewModelScope.launch(Dispatchers.IO) {
            _state.value = _state.value.copy(saving = true)
            val ok = CoreRepository.removeProvider(name)
            _state.value = _state.value.copy(saving = false)
            if (ok) {
                _toast.tryEmit("规则集已删除")
                refreshAll()
            } else {
                _toast.tryEmit("删除失败")
            }
        }
    }

    fun addDomainRule(type: String, domain: String, outbound: String) {
        viewModelScope.launch(Dispatchers.IO) {
            val safeDomain = domain.trim()
            if (safeDomain.isBlank()) {
                _toast.tryEmit("域名不能为空")
                return@launch
            }
            _state.value = _state.value.copy(saving = true)
            val index = CoreRepository.addRule(ruleJson(type, safeDomain, outbound))
            val item = DomainRuleUi(
                id = "${System.currentTimeMillis()}_${safeDomain.hashCode()}",
                type = type,
                domain = safeDomain,
                outbound = outbound,
                coreIndex = if (index >= 0) index else null
            )
            val next = _state.value.domainRules + item
            saveDomainRules(next)
            _state.value = _state.value.copy(
                domainRules = next,
                saving = false,
                warning = if (index >= 0) null else "域名规则未写入内核，仅本地保存"
            )
            _toast.tryEmit(if (index >= 0) "规则已添加" else "规则已本地添加（内核写入失败）")
        }
    }

    fun updateDomainRule(id: String, type: String, domain: String, outbound: String) {
        viewModelScope.launch(Dispatchers.IO) {
            val target = _state.value.domainRules.firstOrNull { it.id == id } ?: return@launch
            val safeDomain = domain.trim()
            if (safeDomain.isBlank()) {
                _toast.tryEmit("域名不能为空")
                return@launch
            }
            _state.value = _state.value.copy(saving = true)

            target.coreIndex?.let { idx ->
                if (!CoreRepository.removeRule(idx)) {
                    removeRuleByMatch(target)
                }
            }

            val newIndex = CoreRepository.addRule(ruleJson(type, safeDomain, outbound))
            val next = _state.value.domainRules.map {
                if (it.id == id) it.copy(type = type, domain = safeDomain, outbound = outbound, coreIndex = if (newIndex >= 0) newIndex else null)
                else it
            }
            saveDomainRules(next)
            _state.value = _state.value.copy(
                domainRules = next,
                saving = false,
                warning = if (newIndex >= 0) null else "域名规则更新未写入内核，仅本地保存"
            )
            _toast.tryEmit(if (newIndex >= 0) "规则已更新" else "规则已更新（仅本地）")
        }
    }

    fun removeDomainRule(id: String) {
        viewModelScope.launch(Dispatchers.IO) {
            val target = _state.value.domainRules.firstOrNull { it.id == id } ?: return@launch
            _state.value = _state.value.copy(saving = true)
            val removed = target.coreIndex?.let { CoreRepository.removeRule(it) } ?: false
            if (!removed) {
                removeRuleByMatch(target)
            }
            val next = _state.value.domainRules.filterNot { it.id == id }
            saveDomainRules(next)
            _state.value = _state.value.copy(
                domainRules = next,
                saving = false,
                warning = if (removed || target.coreIndex == null) null else "规则已从本地删除，内核未找到对应规则"
            )
            _toast.tryEmit("规则已删除")
        }
    }

    private fun removeRuleByMatch(item: DomainRuleUi) {
        val rules = CoreRepository.listRules()
        val found = rules.firstOrNull {
            it.type.equals(item.type, ignoreCase = true) &&
                it.payload == item.domain &&
                it.outbound.equals(item.outbound, ignoreCase = true)
        }
        if (found != null) {
            CoreRepository.removeRule(found.index)
        }
    }

    fun setAppRoutingMode(mode: String) {
        val safe = if (mode == "blacklist") "blacklist" else "whitelist"
        saveAppRoutingMode(safe)
        ConfigManager.setProxyModeApps(
            getApplication(),
            if (safe == "whitelist") "only" else "bypass"
        )
        _state.value = _state.value.copy(appRoutingMode = safe, needsReconnectHint = true)
        _toast.tryEmit("应用分流模式已切换为 ${if (safe == "whitelist") "白名单" else "黑名单"}，重连后生效")
    }

    fun addAppRule(packageName: String, outbound: String) {
        val pkg = packageName.trim()
        if (pkg.isBlank()) {
            _toast.tryEmit("应用包名不能为空")
            return
        }
        val next = _state.value.appRules + AppRuleUi(
            id = "${System.currentTimeMillis()}_${pkg.hashCode()}",
            packageName = pkg,
            outbound = outbound
        )
        saveAppRules(next)
        syncAppRulesToProxyConfig(next)
        _state.value = _state.value.copy(appRules = next, needsReconnectHint = true)
        _toast.tryEmit("应用规则已添加，重连后生效")
    }

    fun updateAppRule(id: String, packageName: String, outbound: String) {
        val pkg = packageName.trim()
        if (pkg.isBlank()) {
            _toast.tryEmit("应用包名不能为空")
            return
        }
        val next = _state.value.appRules.map {
            if (it.id == id) it.copy(packageName = pkg, outbound = outbound) else it
        }
        saveAppRules(next)
        syncAppRulesToProxyConfig(next)
        _state.value = _state.value.copy(appRules = next, needsReconnectHint = true)
        _toast.tryEmit("应用规则已更新，重连后生效")
    }

    fun removeAppRule(id: String) {
        val next = _state.value.appRules.filterNot { it.id == id }
        saveAppRules(next)
        syncAppRulesToProxyConfig(next)
        _state.value = _state.value.copy(appRules = next, needsReconnectHint = true)
        _toast.tryEmit("应用规则已删除，重连后生效")
    }

    private fun ruleJson(type: String, domain: String, outbound: String): String {
        return "{\"type\":\"$type\",\"payload\":\"$domain\",\"outbound\":\"$outbound\"}"
    }

    private fun domainPrefs() = getApplication<Application>()
        .getSharedPreferences("routing_domain_rules", android.content.Context.MODE_PRIVATE)

    private fun appPrefs() = getApplication<Application>()
        .getSharedPreferences("routing_app_rules", android.content.Context.MODE_PRIVATE)

    private fun loadDomainRules(): List<DomainRuleUi> {
        val raw = domainPrefs().getString("domain_rules", "") ?: ""
        if (raw.isBlank()) return emptyList()
        return try {
            val type = object : TypeToken<List<DomainRuleUi>>() {}.type
            gson.fromJson(raw, type)
        } catch (_: Exception) {
            emptyList()
        }
    }

    private fun saveDomainRules(items: List<DomainRuleUi>) {
        domainPrefs().edit().putString("domain_rules", gson.toJson(items)).apply()
    }

    fun moveDomainRuleUp(id: String) {
        val list = _state.value.domainRules.toMutableList()
        val index = list.indexOfFirst { it.id == id }
        if (index <= 0) return
        val tmp = list[index - 1]
        list[index - 1] = list[index]
        list[index] = tmp
        saveDomainRules(list)
        _state.value = _state.value.copy(domainRules = list)
        _toast.tryEmit("规则优先级已上移")
    }

    fun moveDomainRuleDown(id: String) {
        val list = _state.value.domainRules.toMutableList()
        val index = list.indexOfFirst { it.id == id }
        if (index < 0 || index >= list.lastIndex) return
        val tmp = list[index + 1]
        list[index + 1] = list[index]
        list[index] = tmp
        saveDomainRules(list)
        _state.value = _state.value.copy(domainRules = list)
        _toast.tryEmit("规则优先级已下移")
    }

    fun previewDomainMatch(domain: String): String {
        val input = domain.trim().lowercase()
        if (input.isBlank()) return "请输入要预览的域名"

        val hit = _state.value.domainRules.firstOrNull { rule ->
            val payload = rule.domain.trim().lowercase()
            when (rule.type.lowercase()) {
                "full" -> input == payload
                "keyword" -> input.contains(payload)
                else -> input.endsWith(payload)
            }
        }

        return if (hit != null) {
            "命中：${hit.type.uppercase()} ${hit.domain} -> ${hit.outbound}"
        } else {
            "未命中自定义域名规则，将按默认路由处理"
        }
    }

    private fun loadAppRoutingMode(): String =
        appPrefs().getString("app_routing_mode", "whitelist") ?: "whitelist"

    private fun saveAppRoutingMode(mode: String) {
        appPrefs().edit().putString("app_routing_mode", mode).apply()
    }

    private fun loadAppRules(): List<AppRuleUi> {
        val raw = appPrefs().getString("app_rules", "") ?: ""
        if (raw.isBlank()) return emptyList()
        return try {
            val type = object : TypeToken<List<AppRuleUi>>() {}.type
            gson.fromJson(raw, type)
        } catch (_: Exception) {
            emptyList()
        }
    }

    private fun saveAppRules(items: List<AppRuleUi>) {
        appPrefs().edit().putString("app_rules", gson.toJson(items)).apply()
    }

    private fun syncAppRulesToProxyConfig(items: List<AppRuleUi>) {
        val packages = items.map { it.packageName.trim() }.filter { it.isNotBlank() }.toSet()
        ConfigManager.setBypassApps(getApplication(), packages)
    }

    fun setDefaultOutbound(tag: String) {
        val safeTag = tag.trim()
        if (safeTag.isBlank()) {
            _toast.tryEmit("默认出站不能为空")
            return
        }
        val ok = CoreRepository.selectOutbound(safeTag)
        if (ok) {
            _state.value = _state.value.copy(selectedOutbound = safeTag)
            _toast.tryEmit("默认策略已切换为 $safeTag")
        } else {
            _state.value = _state.value.copy(error = "默认策略切换失败：内核拒绝或无可用选择器")
            _toast.tryEmit("默认策略切换失败")
        }
    }

    fun clearError() {
        if (_state.value.error != null) {
            _state.value = _state.value.copy(error = null)
        }
    }
}
