package com.openworld.app.viewmodel

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.google.gson.JsonParser
import com.openworld.app.config.ConfigManager
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import java.io.File
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

class ProfilesViewModel(app: Application) : AndroidViewModel(app) {

    data class ProfileInfo(
        val name: String,
        val isActive: Boolean = false,
        val fileSize: Long = 0,
        val lastModified: Long = 0,
        val subscriptionUrl: String? = null,
        val autoUpdate: Boolean = false,
        val updateIntervalHours: Int = 24
    ) {
        val fileSizeText: String
            get() = when {
                fileSize < 1024 -> "${fileSize}B"
                fileSize < 1024 * 1024 -> "${fileSize / 1024}KB"
                else -> String.format("%.1fMB", fileSize / (1024.0 * 1024.0))
            }

        val lastModifiedText: String
            get() = if (lastModified > 0) {
                SimpleDateFormat("yyyy-MM-dd HH:mm", Locale.getDefault())
                    .format(Date(lastModified))
            } else ""
    }

    enum class ImportStage {
        IDLE,
        VALIDATING,
        DOWNLOADING,
        PARSING,
        SAVING,
        FINISHED,
        FAILED
    }

    data class UiState(
        val profiles: List<ProfileInfo> = emptyList(),
        val activeProfile: String = "default",
        val importing: Boolean = false,
        val importStage: ImportStage = ImportStage.IDLE,
        val importError: String? = null,
        val updating: Boolean = false,
        val updatingProfile: String = ""
    )

    private val _state = MutableStateFlow(UiState())
    val state: StateFlow<UiState> = _state.asStateFlow()

    private val _toastEvent = MutableSharedFlow<String>(extraBufferCapacity = 1)
    val toastEvent: SharedFlow<String> = _toastEvent.asSharedFlow()

    init {
        refresh()
    }

    fun refresh() {
        viewModelScope.launch(Dispatchers.IO) {
            val ctx = getApplication<Application>()
            val active = ConfigManager.getActiveProfile(ctx)
            val configDir = ConfigManager.configDir(ctx)

            val profiles = ConfigManager.listProfiles(ctx).map { name ->
                val file = findProfileFile(configDir, name)
                ProfileInfo(
                    name = name,
                    isActive = name == active,
                    fileSize = file?.length() ?: 0,
                    lastModified = file?.lastModified() ?: 0,
                    subscriptionUrl = readSubscriptionUrl(ctx, name),
                    autoUpdate = readAutoUpdate(ctx, name),
                    updateIntervalHours = readUpdateIntervalHours(ctx, name)
                )
            }
            _state.value = _state.value.copy(
                profiles = profiles,
                activeProfile = active
            )
        }
    }

    fun selectProfile(name: String) {
        viewModelScope.launch(Dispatchers.IO) {
            ConfigManager.setActiveProfile(getApplication(), name)
            refresh()
            _toastEvent.tryEmit("已切换: $name")
        }
    }

    fun importFromUrl(url: String, name: String) {
        viewModelScope.launch(Dispatchers.IO) {
            val safeName = name.trim()
            val safeUrl = url.trim()
            if (safeName.isBlank()) {
                _toastEvent.tryEmit("导入失败: 配置名称不能为空")
                return@launch
            }
            if (!(safeUrl.startsWith("http://") || safeUrl.startsWith("https://"))) {
                _state.value = _state.value.copy(importError = "URL 必须以 http:// 或 https:// 开头", importStage = ImportStage.FAILED)
                _toastEvent.tryEmit("导入失败: URL 格式不正确")
                return@launch
            }

            _state.value = _state.value.copy(importing = true, importStage = ImportStage.VALIDATING, importError = null)
            try {
                _state.value = _state.value.copy(importStage = ImportStage.DOWNLOADING)
                val client = okhttp3.OkHttpClient()
                val request = okhttp3.Request.Builder().url(safeUrl).build()
                val response = client.newCall(request).execute()
                if (!response.isSuccessful) throw Exception("HTTP ${response.code}")
                val body = response.body?.string() ?: throw Exception("空响应")

                _state.value = _state.value.copy(importStage = ImportStage.PARSING)
                validateProfileContent(body)

                _state.value = _state.value.copy(importStage = ImportStage.SAVING)
                val ctx = getApplication<Application>()
                ConfigManager.saveProfile(ctx, safeName, body)
                saveSubscriptionUrl(ctx, safeName, safeUrl)
                refresh()

                _state.value = _state.value.copy(importStage = ImportStage.FINISHED)
                _toastEvent.tryEmit("导入成功: $safeName")
            } catch (e: Exception) {
                _state.value = _state.value.copy(importStage = ImportStage.FAILED, importError = e.message ?: "未知错误")
                _toastEvent.tryEmit("导入失败: ${e.message}")
            } finally {
                _state.value = _state.value.copy(importing = false)
            }
        }
    }

    fun importFromClipboard(content: String, name: String) {
        viewModelScope.launch(Dispatchers.IO) {
            val safeName = name.trim()
            val safeContent = content.trim()
            if (safeName.isBlank()) {
                _toastEvent.tryEmit("导入失败: 配置名称不能为空")
                return@launch
            }
            if (safeContent.isBlank()) {
                _state.value = _state.value.copy(importError = "配置内容为空", importStage = ImportStage.FAILED)
                _toastEvent.tryEmit("导入失败: 配置内容为空")
                return@launch
            }

            _state.value = _state.value.copy(importing = true, importStage = ImportStage.VALIDATING, importError = null)
            try {
                _state.value = _state.value.copy(importStage = ImportStage.PARSING)
                validateProfileContent(safeContent)

                _state.value = _state.value.copy(importStage = ImportStage.SAVING)
                ConfigManager.saveProfile(getApplication(), safeName, safeContent)
                refresh()

                _state.value = _state.value.copy(importStage = ImportStage.FINISHED)
                _toastEvent.tryEmit("导入成功: $safeName")
            } catch (e: Exception) {
                _state.value = _state.value.copy(importStage = ImportStage.FAILED, importError = e.message ?: "未知错误")
                _toastEvent.tryEmit("导入失败: ${e.message}")
            } finally {
                _state.value = _state.value.copy(importing = false)
            }
        }
    }

    fun importFromQr(raw: String, name: String) {
        val text = raw.trim()
        if (text.startsWith("http://") || text.startsWith("https://")) {
            importFromUrl(text, name)
            return
        }
        importFromClipboard(text, name)
    }

    fun deleteProfile(name: String) {
        viewModelScope.launch(Dispatchers.IO) {
            val ctx = getApplication<Application>()
            ConfigManager.deleteProfile(ctx, name)
            deleteSubscriptionUrl(ctx, name)
            deleteUpdatePolicy(ctx, name)
            if (_state.value.activeProfile == name) {
                ConfigManager.setActiveProfile(ctx, "default")
            }
            refresh()
            _toastEvent.tryEmit("已删除: $name")
        }
    }

    fun getProfileInfo(name: String): ProfileInfo? = _state.value.profiles.firstOrNull { it.name == name }

    fun saveProfileSettings(
        originalName: String,
        newName: String,
        subscriptionUrl: String,
        autoUpdate: Boolean,
        updateIntervalHours: Int
    ) {
        viewModelScope.launch(Dispatchers.IO) {
            val ctx = getApplication<Application>()
            val safeNewName = newName.trim()
            if (safeNewName.isBlank()) {
                _toastEvent.tryEmit("配置名称不能为空")
                return@launch
            }

            val configDir = ConfigManager.configDir(ctx)
            val oldFile = findProfileFile(configDir, originalName)
            if (oldFile == null) {
                _toastEvent.tryEmit("配置文件不存在")
                return@launch
            }

            val targetFile = java.io.File(configDir, "$safeNewName.yaml")
            if (safeNewName != originalName && targetFile.exists()) {
                _toastEvent.tryEmit("目标配置名已存在")
                return@launch
            }

            if (safeNewName != originalName) {
                val moved = oldFile.copyTo(targetFile, overwrite = false)
                if (moved.exists()) {
                    oldFile.delete()
                }
                val oldUrl = readSubscriptionUrl(ctx, originalName)
                if (!oldUrl.isNullOrBlank()) {
                    saveSubscriptionUrl(ctx, safeNewName, oldUrl)
                }
                val oldAuto = readAutoUpdate(ctx, originalName)
                val oldInterval = readUpdateIntervalHours(ctx, originalName)
                saveAutoUpdate(ctx, safeNewName, oldAuto)
                saveUpdateIntervalHours(ctx, safeNewName, oldInterval)
                deleteSubscriptionUrl(ctx, originalName)
                deleteUpdatePolicy(ctx, originalName)
                if (_state.value.activeProfile == originalName) {
                    ConfigManager.setActiveProfile(ctx, safeNewName)
                }
            }

            if (subscriptionUrl.isBlank()) {
                deleteSubscriptionUrl(ctx, safeNewName)
            } else {
                saveSubscriptionUrl(ctx, safeNewName, subscriptionUrl.trim())
            }
            saveAutoUpdate(ctx, safeNewName, autoUpdate)
            saveUpdateIntervalHours(ctx, safeNewName, updateIntervalHours.coerceIn(1, 168))

            refresh()
            _toastEvent.tryEmit("配置已保存")
        }
    }

    fun updateSubscription(name: String) {
        viewModelScope.launch(Dispatchers.IO) {
            val ctx = getApplication<Application>()
            val url = readSubscriptionUrl(ctx, name)
            if (url.isNullOrBlank()) {
                _toastEvent.tryEmit("该配置无订阅 URL")
                return@launch
            }
            _state.value = _state.value.copy(updating = true, updatingProfile = name)
            try {
                val client = okhttp3.OkHttpClient()
                val request = okhttp3.Request.Builder().url(url).build()
                val response = client.newCall(request).execute()
                val body = response.body?.string() ?: throw Exception("空响应")
                ConfigManager.saveProfile(ctx, name, body)
                refresh()
                _toastEvent.tryEmit("更新成功: $name")
            } catch (e: Exception) {
                _toastEvent.tryEmit("更新失败: ${e.message}")
            } finally {
                _state.value = _state.value.copy(updating = false, updatingProfile = "")
            }
        }
    }

    fun updateAllSubscriptions() {
        viewModelScope.launch(Dispatchers.IO) {
            _state.value = _state.value.copy(updating = true)
            val ctx = getApplication<Application>()
            val profiles = _state.value.profiles.filter { !it.subscriptionUrl.isNullOrBlank() }
            var success = 0
            var failed = 0

            for (profile in profiles) {
                _state.value = _state.value.copy(updatingProfile = profile.name)
                try {
                    val client = okhttp3.OkHttpClient()
                    val request = okhttp3.Request.Builder().url(profile.subscriptionUrl!!).build()
                    val response = client.newCall(request).execute()
                    val body = response.body?.string() ?: throw Exception("空响应")
                    ConfigManager.saveProfile(ctx, profile.name, body)
                    success++
                } catch (_: Exception) {
                    failed++
                }
            }

            _state.value = _state.value.copy(updating = false, updatingProfile = "")
            refresh()
            _toastEvent.tryEmit("更新完成: $success 成功, $failed 失败")
        }
    }

    // ── 订阅 URL 持久化 ──

    private fun subscriptionPrefs(ctx: Application) =
        ctx.getSharedPreferences("profile_subscriptions", android.content.Context.MODE_PRIVATE)

    private fun updatePolicyPrefs(ctx: Application) =
        ctx.getSharedPreferences("profile_update_policy", android.content.Context.MODE_PRIVATE)

    private fun readSubscriptionUrl(ctx: Application, name: String): String? =
        subscriptionPrefs(ctx).getString("sub_url_$name", null)

    private fun saveSubscriptionUrl(ctx: Application, name: String, url: String) =
        subscriptionPrefs(ctx).edit().putString("sub_url_$name", url).apply()

    private fun deleteSubscriptionUrl(ctx: Application, name: String) =
        subscriptionPrefs(ctx).edit().remove("sub_url_$name").apply()

    private fun readAutoUpdate(ctx: Application, name: String): Boolean =
        updatePolicyPrefs(ctx).getBoolean("auto_update_$name", false)

    private fun saveAutoUpdate(ctx: Application, name: String, enabled: Boolean) =
        updatePolicyPrefs(ctx).edit().putBoolean("auto_update_$name", enabled).apply()

    private fun readUpdateIntervalHours(ctx: Application, name: String): Int =
        updatePolicyPrefs(ctx).getInt("update_interval_$name", 24)

    private fun saveUpdateIntervalHours(ctx: Application, name: String, hours: Int) =
        updatePolicyPrefs(ctx).edit().putInt("update_interval_$name", hours).apply()

    private fun deleteUpdatePolicy(ctx: Application, name: String) {
        updatePolicyPrefs(ctx).edit()
            .remove("auto_update_$name")
            .remove("update_interval_$name")
            .apply()
    }

    private fun findProfileFile(configDir: File, name: String): File? {
        val yaml = File(configDir, "$name.yaml")
        if (yaml.exists()) return yaml
        val json = File(configDir, "$name.json")
        if (json.exists()) return json
        val yml = File(configDir, "$name.yml")
        if (yml.exists()) return yml
        return null
    }

    private fun validateProfileContent(content: String) {
        val text = content.trim()
        if (text.isBlank()) throw IllegalArgumentException("配置内容为空")

        if (text.startsWith("{")) {
            runCatching { JsonParser.parseString(text) }
                .getOrElse { throw IllegalArgumentException("JSON 格式无效") }
            return
        }

        val hasSingBoxInbound = text.contains("inbounds:") || text.contains("\"inbounds\"")
        val hasSingBoxOutbound = text.contains("outbounds:") || text.contains("\"outbounds\"")
        val hasClashProxy = text.contains("proxies:") || text.contains("\"proxies\"")
        val hasClashGroups = text.contains("proxy-groups:") || text.contains("\"proxy-groups\"")

        val looksLikeSingBox = hasSingBoxInbound || hasSingBoxOutbound
        val looksLikeClash = hasClashProxy || hasClashGroups

        if (!looksLikeSingBox && !looksLikeClash) {
            throw IllegalArgumentException("配置缺少可识别字段（inbounds/outbounds 或 proxies/proxy-groups）")
        }
    }
}
