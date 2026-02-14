package com.openworld.app

import android.app.ActivityManager
import android.app.Application
import android.net.ConnectivityManager
import android.os.Process
import androidx.work.Configuration
import androidx.work.WorkManager
import com.openworld.app.core.BoxWrapperManager
import com.openworld.app.lifecycle.AppLifecycleObserver
import com.openworld.app.repository.LogRepository
import com.openworld.app.repository.SettingsRepository
import com.openworld.app.service.RuleSetAutoUpdateWorker
import com.openworld.app.service.SubscriptionAutoUpdateWorker
import com.openworld.app.service.VpnKeepaliveWorker
import com.openworld.app.utils.DefaultNetworkListener
import com.tencent.mmkv.MMKV
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch

class OpenWorldApplication : Application(), Configuration.Provider {

    private val applicationScope = CoroutineScope(SupervisorJob() + Dispatchers.Main)

    override val workManagerConfiguration: Configuration
        get() = Configuration.Builder()
            .setMinimumLoggingLevel(android.util.Log.INFO)
            .build()

    override fun onCreate() {
        super.onCreate()

        // 初始�?MMKV - 必须在所有进程中初始�?        MMKV.initialize(this)

        // 手动初始�?WorkManager 以支持多进程
        if (!isWorkManagerInitialized()) {
            WorkManager.initialize(this, workManagerConfiguration)
        }

        LogRepository.init(this)

        // 检测并初始�?OpenWorld 内核
        BoxWrapperManager.detectOpenWorldKernel()

        // 清理遗留的临时数据库文件 (应对应用崩溃或强制停止的情况)
        cleanupOrphanedTempFiles()

// 只在主进程中调度自动更新任务
        if (isMainProcess()) {
            AppLifecycleObserver.register()

            applicationScope.launch {
                // 读取省电设置并传�?AppLifecycleObserver
                try {
                    val settings = SettingsRepository.getInstance(this@OpenWorldApplication).settings.value
                    AppLifecycleObserver.setBackgroundTimeout(settings.backgroundPowerSavingDelay.delayMs)
                } catch (e: Exception) {
                    android.util.Log.w("OpenWorldApp", "Failed to read power saving setting", e)
                }

                // 预缓存物理网�?                // VPN 启动时可直接使用已缓存的网络，避免应用二次加�?                val cm = getSystemService(CONNECTIVITY_SERVICE) as? ConnectivityManager
                if (cm != null) {
                    DefaultNetworkListener.start(cm, this@OpenWorldApplication) { network ->
                        android.util.Log.d("OpenWorldApp", "Underlying network updated: $network")
                    }
                }

                // 订阅自动更新
                SubscriptionAutoUpdateWorker.rescheduleAll(this@OpenWorldApplication)
                // 规则集自动更�?                RuleSetAutoUpdateWorker.rescheduleAll(this@OpenWorldApplication)
                // VPN 进程保活机制
                // 优化: 定期检查后台进程状�?防止系统杀死导�?VPN 意外断开
                VpnKeepaliveWorker.schedule(this@OpenWorldApplication)
            }
        }
    }

    private fun isWorkManagerInitialized(): Boolean {
        return try {
            WorkManager.getInstance(this)
            true
        } catch (e: IllegalStateException) {
            false
        }
    }

    private fun isMainProcess(): Boolean {
        val pid = Process.myPid()
        val activityManager = getSystemService(ACTIVITY_SERVICE) as ActivityManager
        val processName = activityManager.runningAppProcesses?.find { it.pid == pid }?.processName
        return processName == packageName
    }

    /**
     * 清理遗留的临时数据库文件
     * 在应用启动时执行,清理因崩溃或强制停止而残留的测试数据库文�?     */
    private fun cleanupOrphanedTempFiles() {
        try {
            val tempDir = java.io.File(cacheDir, "singbox_temp")
            if (!tempDir.exists() || !tempDir.isDirectory) return

            val cleaned = mutableListOf<String>()
            tempDir.listFiles()?.forEach { file ->
                // 清理所有测试数据库文件及其 WAL/SHM 辅助文件
                if (file.name.startsWith("test_") || file.name.startsWith("batch_test_")) {
                    if (file.delete()) {
                        cleaned.add(file.name)
                    }
                }
            }

            if (cleaned.isNotEmpty()) {
                android.util.Log.i("OpenWorldApp", "Cleaned ${cleaned.size} orphaned temp files: ${cleaned.take(5).joinToString()}")
            }
        } catch (e: Exception) {
            android.util.Log.w("OpenWorldApp", "Failed to cleanup orphaned temp files", e)
        }
    }
}







