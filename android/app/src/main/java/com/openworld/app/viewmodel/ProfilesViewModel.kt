package com.openworld.app.viewmodel

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.google.gson.JsonParser
import com.openworld.app.R
import com.openworld.app.config.ConfigManager
import com.openworld.app.model.ProfileType
import com.openworld.app.model.ProfileUi
import com.openworld.app.model.SubscriptionUpdateResult
import com.openworld.app.model.UpdateStatus
import com.openworld.app.repository.CoreRepository
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch

class ProfilesViewModel(application: Application) : AndroidViewModel(application) {

    private val _profiles = MutableStateFlow<List<ProfileUi>>(emptyList())
    val profiles: StateFlow<List<ProfileUi>> = _profiles.asStateFlow()

    private val _activeProfileId = MutableStateFlow<String?>(null)
    val activeProfileId: StateFlow<String?> = _activeProfileId.asStateFlow()

    private val _importState = MutableStateFlow<ImportState>(ImportState.Idle)
    val importState: StateFlow<ImportState> = _importState.asStateFlow()

    private val _updateStatus = MutableStateFlow<String?>(null)
    val updateStatus: StateFlow<String?> = _updateStatus.asStateFlow()

    private val _toastEvents = MutableSharedFlow<String>(extraBufferCapacity = 1)
    val toastEvents: SharedFlow<String> = _toastEvents.asSharedFlow()

    private var importJob: Job? = null

    init {
        refreshProfiles()
    }

    fun refreshProfiles() {
        viewModelScope.launch(Dispatchers.IO) {
            val list = ConfigManager.getProfiles(getApplication())
            _profiles.value = list
            _activeProfileId.value = ConfigManager.getActiveProfile(getApplication())
        }
    }

    fun setActiveProfile(profileId: String) {
        viewModelScope.launch(Dispatchers.IO) {
            ConfigManager.setActiveProfile(getApplication(), profileId)
            // CoreRepository.switchProfile(profileId) // If Core supports it directly, otherwise restart or reload
            // OpenWorld Core might need reload or generic reloadConfig.
            // ConfigManager.generateConfig() uses active profile.
            // So we reuse generateConfig and reload.
            val config = ConfigManager.generateConfig(getApplication())
            CoreRepository.reloadConfig(config)
            
            refreshProfiles()
            _toastEvents.tryEmit(getApplication<Application>().getString(R.string.profiles_updated))
        }
    }

    fun toggleProfileEnabled(profileId: String) {
        // In OpenWorld, only one profile is active. "Enabled" means active.
        // If we click toggle on a non-active profile, we make it active.
        // If we click toggle on active profile, do we disable it? (No profile?)
        // Usually we just select it.
        // KunBox logic was toggling 'enabled' field in metadata?
        // Node's have enabled state from profile?
        // For now, toggle = set active.
        val isActive = _activeProfileId.value == profileId
        if (!isActive) {
            setActiveProfile(profileId)
        } else {
            // Cannot disable the only active profile easily without a "stop" logic or "default" profile.
             _toastEvents.tryEmit("Cannot disable active profile directly. Switch to another one.")
        }
    }

    fun updateProfileMetadata(
        profileId: String,
        newName: String,
        newUrl: String?,
        autoUpdateInterval: Int = 0,
        dnsPreResolve: Boolean = false,
        dnsServer: String? = null
    ) {
         viewModelScope.launch(Dispatchers.IO) {
             // Rename logic is complex if ID = name.
             // If name changes, we need to rename file and update properties.
             val context = getApplication<Application>()
             
             if (profileId != newName) {
                 // Rename
                 val content = ConfigManager.loadProfile(context, profileId)
                 if (content != null) {
                     ConfigManager.saveProfile(context, newName, content)
                     ConfigManager.deleteProfile(context, profileId) // delete old
                     // Update sub url mapping if exists
                     val url = ConfigManager.getSubscriptionUrl(context, profileId)
                     if (url != null) {
                        ConfigManager.setSubscriptionUrl(context, newName, url)
                        ConfigManager.removeSubscriptionUrl(context, profileId)
                     }
                 }
             }

             if (newUrl != null) {
                 ConfigManager.setSubscriptionUrl(context, newName, newUrl)
             }
             
             // Auto update interval and dns settings are not yet fully implemented in ConfigManager metadata
             // storing them in subPrefs or separate metadata file would be ideal.
             // For now, we skip those or assume they are stored if implemented.
             
             refreshProfiles()
             _toastEvents.tryEmit(getApplication<Application>().getString(R.string.profiles_updated))
         }
    }

    fun updateProfile(profileId: String) {
        viewModelScope.launch(Dispatchers.IO) {
            _updateStatus.value = getApplication<Application>().getString(R.string.common_loading)
            val context = getApplication<Application>()
            val url = ConfigManager.getSubscriptionUrl(context, profileId)
            
            if (url != null) {
                try {
                    val fetchResult = com.openworld.core.OpenWorldCore.fetchUrl(url)
                    if (fetchResult.isNullOrBlank()) {
                        _updateStatus.value = "Failed: null response"
                        return@launch
                    }
                    val fetchJson = JsonParser.parseString(fetchResult).asJsonObject
                    if (fetchJson.has("error")) {
                        _updateStatus.value = "Failed: ${fetchJson.get("error").asString}"
                        return@launch
                    }
                    val rawContent = fetchJson.get("content")?.asString.orEmpty()
                    if (rawContent.isNotBlank()) {
                         val savedContent = convertViaZenOne(rawContent)
                         if (savedContent == null) {
                             _updateStatus.value = "Failed: ZenOne conversion failed"
                         } else {
                             ConfigManager.saveProfile(context, profileId, savedContent)
                             _updateStatus.value = "Updated"
                         }
                    } else {
                         _updateStatus.value = "Failed: Empty content"
                    }
                } catch (e: Exception) {
                    _updateStatus.value = "Failed: ${e.message}"
                }
            } else {
                _updateStatus.value = "Not a subscription"
            }
            
            delay(2000)
            _updateStatus.value = null
            refreshProfiles()
        }
    }

    fun deleteProfile(profileId: String) {
        viewModelScope.launch(Dispatchers.IO) {
            ConfigManager.deleteProfile(getApplication(), profileId)
            refreshProfiles()
            _toastEvents.tryEmit(getApplication<Application>().getString(R.string.profiles_deleted))
        }
    }

    fun importSubscription(
        name: String,
        url: String,
        autoUpdateInterval: Int = 0,
        dnsPreResolve: Boolean = false,
        dnsServer: String? = null
    ) {
        if (_importState.value is ImportState.Loading) return
        
        importJob = viewModelScope.launch(Dispatchers.IO) {
            _importState.value = ImportState.Loading("Downloading...")
            val context = getApplication<Application>()
            
            try {
                // 1. 用 FFI fetchUrl 下载订阅内容（不依赖内核运行）
                val fetchResult = com.openworld.core.OpenWorldCore.fetchUrl(url)
                if (fetchResult.isNullOrBlank()) {
                    _importState.value = ImportState.Error("Download failed: null response")
                    return@launch
                }
                val fetchJson = JsonParser.parseString(fetchResult).asJsonObject
                if (fetchJson.has("error")) {
                    _importState.value = ImportState.Error("Download failed: ${fetchJson.get("error").asString}")
                    return@launch
                }
                val rawContent = fetchJson.get("content")?.asString.orEmpty()
                if (rawContent.isBlank()) {
                    _importState.value = ImportState.Error("Subscription content is empty")
                    return@launch
                }

                _importState.value = ImportState.Loading("Converting via ZenOne...")

                // 2. 通过 ZenOne 转换订阅内容（不回退，失败直接报错）
                val zenoneResult = com.openworld.core.OpenWorldCore.convertSubscriptionToZenone(rawContent)
                if (zenoneResult.isNullOrBlank()) {
                    _importState.value = ImportState.Error("ZenOne conversion returned empty result")
                    return@launch
                }
                val zenoneJson = JsonParser.parseString(zenoneResult).asJsonObject
                if (zenoneJson.has("error")) {
                    val error = zenoneJson.get("error").asString
                    _importState.value = ImportState.Error("ZenOne conversion failed: $error")
                    return@launch
                }
                val zenoneYaml = zenoneJson.get("zenone_yaml")?.asString
                if (zenoneYaml.isNullOrBlank()) {
                    _importState.value = ImportState.Error("ZenOne returned no YAML content")
                    return@launch
                }
                val nodeCount = zenoneJson.get("node_count")?.asInt ?: 0
                android.util.Log.i("ProfilesVM", "ZenOne converted: $nodeCount nodes")
                ConfigManager.saveProfile(context, name, zenoneYaml)

                ConfigManager.setSubscriptionUrl(context, name, url)
                refreshProfiles()
                val profile = ConfigManager.getProfiles(context).find { it.name == name }
                if (profile != null) {
                    _importState.value = ImportState.Success(profile)
                } else {
                    _importState.value = ImportState.Error("Profile saved but not found")
                }
            } catch (e: Exception) {
                _importState.value = ImportState.Error(e.message ?: "Unknown error")
            }
        }
    }

    fun importFromContent(
        name: String,
        content: String,
        profileType: ProfileType = ProfileType.Imported
    ) {
         if (_importState.value is ImportState.Loading) return
         
         importJob = viewModelScope.launch(Dispatchers.IO) {
             _importState.value = ImportState.Loading("Converting via ZenOne...")
             val context = getApplication<Application>()
             
             try {
                 val savedContent = convertViaZenOne(content)
                 if (savedContent == null) {
                     _importState.value = ImportState.Error("ZenOne conversion failed")
                     return@launch
                 }
                 ConfigManager.saveProfile(context, name, savedContent)
                 refreshProfiles()
                 val profile = ConfigManager.getProfiles(context).find { it.name == name }
                 if (profile != null) {
                     _importState.value = ImportState.Success(profile)
                 } else {
                     _importState.value = ImportState.Error("Profile saved but not found")
                 }
             } catch (e: Exception) {
                 _importState.value = ImportState.Error(e.message ?: "Unknown error")
             }
         }
    }

    fun cancelImport() {
        importJob?.cancel()
        importJob = null
        _importState.value = ImportState.Idle
    }

    fun resetImportState() {
        importJob = null
        _importState.value = ImportState.Idle
    }

    fun getProfileInfo(profileName: String): ProfileEditInfo? {
        val profile = _profiles.value.find { it.name == profileName } ?: return null
        return ProfileEditInfo(
            subscriptionUrl = profile.url,
            autoUpdate = profile.autoUpdateInterval > 0,
            updateIntervalHours = if (profile.autoUpdateInterval > 0) profile.autoUpdateInterval / 60 else 24
        )
    }

    fun saveProfileSettings(
        originalName: String, 
        newName: String, 
        subscriptionUrl: String, 
        autoUpdate: Boolean, 
        updateIntervalHours: Int
    ) {
        val intervalMinutes = if (autoUpdate) updateIntervalHours * 60 else 0
        updateProfileMetadata(
            profileId = originalName, 
            newName = newName, 
            newUrl = subscriptionUrl, 
            autoUpdateInterval = intervalMinutes
        )
    }

    /**
     * 通过 ZenOne 转换订阅内容，返回 ZenOne YAML；失败返回 null（调用方回退用原始内容）
     */
    private fun convertViaZenOne(rawContent: String): String? {
        return try {
            val result = com.openworld.core.OpenWorldCore.convertSubscriptionToZenone(rawContent)
                ?: return null
            val json = JsonParser.parseString(result).asJsonObject
            if (json.has("error")) {
                android.util.Log.w("ProfilesVM", "ZenOne: ${json.get("error").asString}")
                null
            } else {
                val yaml = json.get("zenone_yaml")?.asString
                val count = json.get("node_count")?.asInt ?: 0
                android.util.Log.i("ProfilesVM", "ZenOne converted: $count nodes")
                yaml
            }
        } catch (e: Exception) {
            android.util.Log.w("ProfilesVM", "ZenOne exception: ${e.message}")
            null
        }
    }

    /**
     * 从 FFI 返回的 JSON 中提取 raw_content（原始订阅内容），
     * 如果解析失败则返回原始字符串。
     */
    private fun extractRawContent(ffiResponse: String): String {
        return try {
            val json = JsonParser.parseString(ffiResponse).asJsonObject
            json.get("raw_content")?.asString ?: ffiResponse
        } catch (_: Exception) {
            ffiResponse
        }
    }

    sealed class ImportState {
        data object Idle : ImportState()
        data class Loading(val message: String) : ImportState()
        data class Success(val profile: ProfileUi) : ImportState()
        data class Error(val message: String) : ImportState()
    }
}

data class ProfileEditInfo(
    val subscriptionUrl: String?,
    val autoUpdate: Boolean,
    val updateIntervalHours: Int
)
