package com.openworld.app.repository.store

import android.content.Context
import android.util.Log
import com.google.gson.Gson
import com.google.gson.GsonBuilder
import com.openworld.app.database.AppDatabase
import com.openworld.app.database.entity.SettingsEntity
import com.openworld.app.model.AppSettings
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

/**
 * 设置存储 - 使用 Room 数据库存�? *
 * 设计优势:
 * - 单次读写整个设置对象 vs N 次键值对操作
 * - JSON 序列化类型安�?vs 字符串手动转�? * - Flow 实时观察 vs 手动刷新
 * - 内置版本控制支持迁移 vs 无版�? * - Room 数据库在重装后保�? * - 事务支持保证数据一致�? */
class SettingsStore private constructor(context: Context) {
    companion object {
        private const val TAG = "SettingsStore"

        @Volatile
        private var INSTANCE: SettingsStore? = null

        fun getInstance(context: Context): SettingsStore {
            return INSTANCE ?: synchronized(this) {
                INSTANCE ?: SettingsStore(context.applicationContext).also { INSTANCE = it }
            }
        }
    }

    private val database = AppDatabase.getInstance(context)
    private val settingsDao = database.settingsDao()

    private val gson: Gson = GsonBuilder()
        .serializeNulls()
        .create()

    private val writeMutex = Mutex()
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)

    private val _settings = MutableStateFlow(AppSettings())
    val settings: StateFlow<AppSettings> = _settings.asStateFlow()

    init {
        loadSettings()
    }

    @Suppress("NestedBlockDepth")
    private fun loadSettings() {
        try {
            val startTime = System.currentTimeMillis()

            // �?Room 加载设置
            val entity = settingsDao.getSettingsSync()
            if (entity != null) {
                val loaded = gson.fromJson(entity.data, AppSettings::class.java)
                if (loaded != null) {
                    val migrated = migrateIfNeeded(entity.version, loaded)
                    _settings.value = migrated
                    // Persist migration if we upgraded settings.
                    if (entity.version != SettingsEntity.CURRENT_VERSION) {
                        scope.launch {
                            saveSettingsInternal(migrated)
                        }
                    }
                    val elapsed = System.currentTimeMillis() - startTime
                    Log.i(TAG, "Settings loaded from Room in ${elapsed}ms")
                    return
                }
            }

            // 使用默认设置
            Log.i(TAG, "No existing settings, using defaults")
        } catch (e: Exception) {
            Log.e(TAG, "Failed to load settings", e)
        }
    }

    private fun migrateIfNeeded(version: Int, settings: AppSettings): AppSettings {
        var result = settings

        // v2: introduce tunMtuAuto and improved throughput defaults.
        // For existing installs, enable auto MTU by default to improve throughput while keeping manual MTU as fallback.
        if (version < 2) {
            result = result.copy(tunMtuAuto = true)
        }

        // v3: DNS 配置优化（去大厂 + 隐私增强�?        // 仅当用户使用的是旧默认值时才迁移，保留用户自定义配�?        if (version < 3) {
            // 旧版本可能的默认值列�?            val oldLocalDefaults = listOf(
                "https://dns.alidns.com/dns-query",
                "https://1.1.1.1/dns-query",
                "223.5.5.5",
                ""
            )
            val oldRemoteDefaults = listOf(
                "https://dns.google/dns-query",
                "https://1.1.1.1/dns-query",
                "8.8.8.8",
                "1.1.1.1",
                ""
            )

            var newLocal = result.localDns
            var newRemote = result.remoteDns

            // 如果是旧默认值，迁移到新默认�?            if (result.localDns in oldLocalDefaults) {
                newLocal = "local" // 系统/运营�?DNS
                Log.i(TAG, "Migrating localDns from '${result.localDns}' to 'local'")
            }
            if (result.remoteDns in oldRemoteDefaults) {
                newRemote = "https://1.1.1.1/dns-query" // Cloudflare DoH
                Log.i(TAG, "Migrating remoteDns from '${result.remoteDns}' to 'https://1.1.1.1/dns-query'")
            }

            result = result.copy(localDns = newLocal, remoteDns = newRemote)
        }

        return result
    }

    /**
     * 更新设置 - 同步更新内存，异步保存到数据�?     */
    fun updateSettings(update: (AppSettings) -> AppSettings) {
        val newSettings = update(_settings.value)
        _settings.value = newSettings

        // 异步保存
        scope.launch {
            saveSettingsInternal(newSettings)
        }
    }

    /**
     * 更新设置并等待保存完�?     */
    suspend fun updateSettingsAndWait(update: (AppSettings) -> AppSettings) {
        val newSettings = update(_settings.value)
        _settings.value = newSettings
        saveSettingsInternal(newSettings)
    }

    private suspend fun saveSettingsInternal(settings: AppSettings) {
        writeMutex.withLock {
            try {
                val startTime = System.currentTimeMillis()
                val json = gson.toJson(settings)
                val entity = SettingsEntity(
                    id = 1,
                    version = SettingsEntity.CURRENT_VERSION,
                    data = json,
                    updatedAt = System.currentTimeMillis()
                )
                settingsDao.saveSettings(entity)
                val elapsed = System.currentTimeMillis() - startTime
                Log.d(TAG, "Settings saved to Room in ${elapsed}ms")
            } catch (e: Exception) {
                Log.e(TAG, "Failed to save settings", e)
            }
        }
    }

    /**
     * 同步保存设置 (仅用于迁�?
     */
    private fun saveSettingsSync(settings: AppSettings) {
        try {
            val json = gson.toJson(settings)
            val entity = SettingsEntity(
                id = 1,
                version = SettingsEntity.CURRENT_VERSION,
                data = json,
                updatedAt = System.currentTimeMillis()
            )
            settingsDao.saveSettingsSync(entity)
        } catch (e: Exception) {
            Log.e(TAG, "Failed to save settings sync", e)
        }
    }

    /**
     * 获取当前设置快照
     */
    fun getCurrentSettings(): AppSettings = _settings.value

    /**
     * 强制重新加载设置
     */
    fun reload() {
        loadSettings()
    }

    /**
     * 检查是否有设置数据
     */
    fun hasSettings(): Boolean = settingsDao.hasSettingsSync()

    /**
     * 重置设置 (恢复默认)
     */
    suspend fun resetSettings() {
        writeMutex.withLock {
            try {
                settingsDao.deleteSettings()
                _settings.value = AppSettings()
                Log.i(TAG, "Settings reset to defaults")
            } catch (e: Exception) {
                Log.e(TAG, "Failed to reset settings", e)
            }
        }
    }
}







