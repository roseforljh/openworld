package com.openworld.app

import android.app.Application
import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.ComponentCallbacks2
import android.content.Context
import android.os.Build
import com.openworld.app.util.LocaleManager
import com.openworld.core.OpenWorldCore

class OpenWorldApp : Application() {

    override fun attachBaseContext(base: Context) {
        super.attachBaseContext(LocaleManager.wrapContext(base))
    }

    override fun onCreate() {
        super.onCreate()
        LocaleManager.applyLocale(this)
        instance = this
        createNotificationChannels()
    }

    private fun createNotificationChannels() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_VPN,
                getString(R.string.vpn_notification_channel),
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                setShowBadge(false)
            }
            val nm = getSystemService(NotificationManager::class.java)
            nm.createNotificationChannel(channel)
        }
    }

    override fun onTrimMemory(level: Int) {
        super.onTrimMemory(level)
        if (level >= ComponentCallbacks2.TRIM_MEMORY_MODERATE) {
            try { OpenWorldCore.notifyMemoryLow() } catch (_: Exception) {}
        }
        if (level >= ComponentCallbacks2.TRIM_MEMORY_COMPLETE) {
            try { OpenWorldCore.gc() } catch (_: Exception) {}
        }
    }

    companion object {
        const val CHANNEL_VPN = "vpn_service"
        lateinit var instance: OpenWorldApp
            private set
    }
}
