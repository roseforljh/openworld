package com.openworld.app.util

import android.content.Context
import android.content.res.Configuration
import com.openworld.app.repository.SettingsStore
import java.util.Locale

object LocaleManager {

    fun wrapContext(base: Context): Context {
        val language = SettingsStore.getAppLanguage(base)
        val locale = resolveLocale(language) ?: return base
        Locale.setDefault(locale)
        val config = Configuration(base.resources.configuration)
        config.setLocale(locale)
        return base.createConfigurationContext(config)
    }

    fun applyLocale(context: Context) {
        val language = SettingsStore.getAppLanguage(context)
        val locale = resolveLocale(language) ?: return
        Locale.setDefault(locale)
        val resources = context.resources
        val config = Configuration(resources.configuration)
        config.setLocale(locale)
        resources.updateConfiguration(config, resources.displayMetrics)
    }

    private fun resolveLocale(language: String): Locale? {
        return when (language.lowercase()) {
            "zh-cn" -> Locale.SIMPLIFIED_CHINESE
            "en" -> Locale.ENGLISH
            else -> null
        }
    }
}
