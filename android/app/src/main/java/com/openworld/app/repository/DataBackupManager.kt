package com.openworld.app.repository

import android.content.Context
import android.net.Uri
import com.google.gson.Gson
import com.google.gson.reflect.TypeToken
import com.openworld.app.config.ConfigManager
import java.io.File

object DataBackupManager {

    private val gson = Gson()

    private val prefNames = listOf(
        "openworld_settings",
        "profile_subscriptions",
        "profile_update_policy",
        "routing_domain_rules",
        "routing_app_rules"
    )

    data class PrefItem(
        val key: String,
        val type: String,
        val value: String
    )

    data class PrefDump(
        val name: String,
        val items: List<PrefItem>
    )

    data class ProfileDump(
        val name: String,
        val ext: String,
        val content: String
    )

    data class BackupBundle(
        val version: Int = 1,
        val exportedAt: Long = System.currentTimeMillis(),
        val prefs: List<PrefDump> = emptyList(),
        val profiles: List<ProfileDump> = emptyList()
    )

    fun exportToUri(context: Context, uri: Uri) {
        val bundle = BackupBundle(
            prefs = dumpPrefs(context),
            profiles = dumpProfiles(context)
        )
        val text = gson.toJson(bundle)
        context.contentResolver.openOutputStream(uri)?.bufferedWriter()?.use { it.write(text) }
            ?: error("无法写入目标文件")
    }

    fun importFromUri(context: Context, uri: Uri) {
        val text = context.contentResolver.openInputStream(uri)?.bufferedReader()?.use { it.readText() }
            ?: error("无法读取备份文件")

        val bundle = runCatching { gson.fromJson(text, BackupBundle::class.java) }
            .getOrElse { throw IllegalArgumentException("备份文件格式无效") }

        if (bundle.version <= 0) {
            throw IllegalArgumentException("不支持的备份版本")
        }

        restorePrefs(context, bundle.prefs)
        restoreProfiles(context, bundle.profiles)

        val active = ConfigManager.getActiveProfile(context)
        if (!ConfigManager.listProfiles(context).contains(active)) {
            ConfigManager.setActiveProfile(context, "default")
        }
    }

    private fun dumpPrefs(context: Context): List<PrefDump> {
        return prefNames.map { name ->
            val all = context.getSharedPreferences(name, Context.MODE_PRIVATE).all
            val items = all.mapNotNull { (key, value) ->
                when (value) {
                    is String -> PrefItem(key, "string", value)
                    is Boolean -> PrefItem(key, "boolean", value.toString())
                    is Int -> PrefItem(key, "int", value.toString())
                    is Long -> PrefItem(key, "long", value.toString())
                    is Float -> PrefItem(key, "float", value.toString())
                    is Set<*> -> {
                        val stringSet = value.mapNotNull { it?.toString() }
                        PrefItem(key, "string_set", gson.toJson(stringSet))
                    }
                    else -> null
                }
            }
            PrefDump(name = name, items = items)
        }
    }

    private fun restorePrefs(context: Context, dumps: List<PrefDump>) {
        dumps.forEach { dump ->
            val prefs = context.getSharedPreferences(dump.name, Context.MODE_PRIVATE)
            val editor = prefs.edit().clear()
            dump.items.forEach { item ->
                when (item.type) {
                    "string" -> editor.putString(item.key, item.value)
                    "boolean" -> editor.putBoolean(item.key, item.value.toBoolean())
                    "int" -> editor.putInt(item.key, item.value.toIntOrNull() ?: 0)
                    "long" -> editor.putLong(item.key, item.value.toLongOrNull() ?: 0L)
                    "float" -> editor.putFloat(item.key, item.value.toFloatOrNull() ?: 0f)
                    "string_set" -> {
                        val type = object : TypeToken<List<String>>() {}.type
                        val list: List<String> = runCatching {
                            @Suppress("UNCHECKED_CAST")
                            (gson.fromJson(item.value, type) as? List<String>).orEmpty()
                        }.getOrDefault(emptyList())
                        editor.putStringSet(item.key, list.toSet())
                    }
                }
            }
            editor.apply()
        }
    }

    private fun dumpProfiles(context: Context): List<ProfileDump> {
        val dir = ConfigManager.configDir(context)
        return dir.listFiles()
            ?.filter { it.extension.lowercase() in listOf("yaml", "yml", "json") }
            ?.map { file ->
                ProfileDump(
                    name = file.nameWithoutExtension,
                    ext = file.extension,
                    content = file.readText()
                )
            }
            ?: emptyList()
    }

    private fun restoreProfiles(context: Context, profiles: List<ProfileDump>) {
        val dir = ConfigManager.configDir(context)
        dir.listFiles()?.forEach { file ->
            if (file.extension.lowercase() in listOf("yaml", "yml", "json")) {
                file.delete()
            }
        }

        profiles.forEach { profile ->
            val ext = if (profile.ext.lowercase() in listOf("yaml", "yml", "json")) profile.ext.lowercase() else "yaml"
            File(dir, "${profile.name}.$ext").writeText(profile.content)
        }
    }
}
