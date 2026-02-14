package com.openworld.app.viewmodel

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.google.gson.Gson
import com.openworld.app.R
import com.openworld.app.model.AppSettings
import com.openworld.app.model.HubRuleSet
import com.openworld.app.model.GithubTreeResponse
import com.openworld.app.repository.RuleSetRepository
import com.openworld.app.repository.SettingsRepository
import com.openworld.app.util.NetworkClient
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import okhttp3.Request
import android.util.Log


class RuleSetViewModel(application: Application) : AndroidViewModel(application) {

    companion object {
        private const val TAG = "RuleSetViewModel"
    }

    private val ruleSetRepository = RuleSetRepository.getInstance(application)
    private val settingsRepository = SettingsRepository.getInstance(application)

    val settings: StateFlow<AppSettings> = settingsRepository.settings
        .stateIn(
            scope = viewModelScope,
            started = SharingStarted.WhileSubscribed(5000),
            initialValue = AppSettings()
        )

    private val _ruleSets = MutableStateFlow<List<HubRuleSet>>(emptyList())
    val ruleSets: StateFlow<List<HubRuleSet>> = _ruleSets.asStateFlow()

    private val _isLoading = MutableStateFlow(false)
    val isLoading: StateFlow<Boolean> = _isLoading.asStateFlow()

    private val _error = MutableStateFlow<String?>(null)
    val error: StateFlow<String?> = _error.asStateFlow()

    private val gson = Gson()

    fun isDownloaded(tag: String): Boolean {
        // Check if the rule set is already added in settings
        return settings.value.ruleSets.any { it.tag == tag }
    }

    init {
        // Initial fetch
        fetchRuleSets()
    }

    fun fetchRuleSets() {
        if (_isLoading.value) return

        viewModelScope.launch(Dispatchers.IO) {
            _isLoading.value = true
            _error.value = null
            try {
                val currentSettings = settingsRepository.settings.first()
                val sagerNetRules = fetchFromSagerNet(currentSettings)

                if (sagerNetRules.isEmpty()) {
                    Log.w(TAG, "Online results empty, using built-in rule sets")
                    val builtIn = getBuiltInRuleSets().sortedBy { it.name }
                    _ruleSets.value = builtIn
                } else {
                    _ruleSets.value = sagerNetRules.sortedBy { it.name }
                }
            } catch (e: Exception) {
                Log.e(TAG, "Failed to fetch rule sets", e)
                _error.value = getApplication<Application>().getString(R.string.ruleset_update_network_error)
                val current = _ruleSets.value
                if (current.isEmpty()) {
                    Log.w(TAG, "Current list empty, using built-in fallback")
                    _ruleSets.value = getBuiltInRuleSets().sortedBy { it.name }
                }
            } finally {
                _isLoading.value = false
            }
        }
    }

    private fun getBuiltInRuleSets(): List<HubRuleSet> {
        val githubUrl = "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set"
        val baseUrl = "https://ghp.ci/$githubUrl"
        val commonRules = listOf(
            "google", "youtube", "twitter", "facebook", "instagram", "tiktok",
            "telegram", "whatsapp", "discord", "github", "microsoft", "apple",
            "amazon", "netflix", "spotify", "bilibili", "zhihu", "baidu",
            "tencent", "alibaba", "jd", "taobao", "weibo", "douyin",
            "cn", "geolocation-cn", "geolocation-!cn", "private", "category-ads-all"
        )
        return commonRules.map { name ->
            val fullName = if (name == "category-ads-all") "geosite-category-ads-all" else "geosite-$name"
            HubRuleSet(
                name = fullName,
                ruleCount = 0,
                tags = listOf("Built-in", "geosite"),
                description = "Commonly used rule sets",
                sourceUrl = "$baseUrl/$fullName.json",
                binaryUrl = "$baseUrl/$fullName.srs"
            )
        }
    }

    private fun fetchFromSagerNet(currentSettings: AppSettings): List<HubRuleSet> {
        val rawUrl = "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set"
        val url = "https://api.github.com/repos/SagerNet/sing-geosite/git/trees/rule-set?recursive=1"
        return try {
            val request = Request.Builder()
                .url(url)
                .header("User-Agent", "OpenWorld-App")
                .build()

            val response = executeRequestWithFallback(request, currentSettings)
            parseSagerNetResponse(response, rawUrl)
        } catch (e: Exception) {
            Log.e(TAG, "[SagerNet] Exception: ${e.javaClass.simpleName} - ${e.message}", e)
            emptyList()
        }
    }

    private fun parseSagerNetResponse(response: okhttp3.Response?, rawUrl: String): List<HubRuleSet> {
        if (response == null) {
            Log.e(TAG, "[SagerNet] Request failed: no response")
            return emptyList()
        }

        return response.use { resp ->
            if (!resp.isSuccessful) {
                val errorBody = resp.body?.string() ?: ""
                Log.e(TAG, "[SagerNet] Request failed! Code=${resp.code}, Body=$errorBody")
                return@use emptyList()
            }

            val json = resp.body?.string() ?: "{}"
            val treeResponse: GithubTreeResponse = gson.fromJson(json, GithubTreeResponse::class.java)
                ?: return@use emptyList()

            val srsFiles = treeResponse.tree
                .filter { it.type == "blob" && it.path.endsWith(".srs") }

            srsFiles.map { file ->
                val fileName = file.path.substringAfterLast("/")
                val nameWithoutExt = fileName.substringBeforeLast(".srs")
                val sourcePath = file.path.replace(".srs", ".json")
                HubRuleSet(
                    name = nameWithoutExt,
                    ruleCount = 0,
                    tags = listOf("Official", "geosite"),
                    description = "SagerNet Official Rule Set",
                    sourceUrl = "https://ghp.ci/$rawUrl/$sourcePath",
                    binaryUrl = "https://ghp.ci/$rawUrl/${file.path}"
                )
            }
        }
    }

    private fun executeRequestWithFallback(
        request: Request,
        settings: AppSettings
    ): okhttp3.Response? {
        val proxyClient = getProxyClient(settings)
        if (proxyClient != null) {
            try {
                val response = proxyClient.newCall(request).execute()
                if (response.isSuccessful) {
                    return response
                }
                response.close()
            } catch (e: Exception) {
                // Ignore proxy error and fall back
            }
        }

        return try {
            getDirectClient().newCall(request).execute()
        } catch (e: Exception) {
            Log.e(TAG, "Direct request failed: ${e.message}")
            null
        }
    }

    private fun getDirectClient(): okhttp3.OkHttpClient {
        return NetworkClient.createClientWithTimeout(
            connectTimeoutSeconds = 10,
            readTimeoutSeconds = 10,
            writeTimeoutSeconds = 10
        )
    }

    private fun getProxyClient(settings: AppSettings): okhttp3.OkHttpClient? {
        // Simplified check: only check port. In real app, check VPN status ideally.
        if (settings.proxyPort <= 0) {
            return null
        }
        return NetworkClient.createClientWithProxy(
            proxyPort = settings.proxyPort,
            connectTimeoutSeconds = 10,
            readTimeoutSeconds = 10,
            writeTimeoutSeconds = 10
        )
    }
}
