package com.openworld.app.service

import android.app.ActivityManager
import android.content.Context
import android.content.Intent
import android.util.Log
import androidx.work.*
import com.openworld.app.ipc.VpnStateStore
import com.openworld.app.repository.SettingsRepository
import kotlinx.coroutines.flow.first
import java.util.concurrent.TimeUnit

/**
 * VPN 进程保活 Worker
 *
 * 功能:
 * 1. 定期检�?VPN 服务进程是否存活
 * 2. 检测到异常终止时尝试自动恢�? * 3. 避免用户感知�?VPN 中断
 *
 * 设计理由:
 * - Service 运行在独立进�?(:bg),系统可能在内存紧张时杀�? * - 用户期望 VPN 持续运行,意外断开影响体验
 * - WorkManager 提供系统级保活能�?即使应用被杀也能执行
 */
class VpnKeepaliveWorker(
    context: Context,
    params: WorkerParameters
) : CoroutineWorker(context, params) {

    companion object {
        private const val TAG = "VpnKeepaliveWorker"
        private const val WORK_NAME = "vpn_keepalive"

        // 检查间�? 15分钟一�?(WorkManager PeriodicWorkRequest 最小周�?
        private const val CHECK_INTERVAL_MINUTES = 15L

        /**
         * 调度保活任务
         *
         * 策略:
         * - 使用 PeriodicWorkRequest 定期执行
         * - 设置网络约束: 需要网络连�?VPN 本身需要网�?
         * - 设置电池约束: 非低电量模式才执行保�?         * - 允许在充电时运行
         */
        fun schedule(context: Context) {
            val constraints = Constraints.Builder()
                .setRequiredNetworkType(NetworkType.CONNECTED) // 需要网络连�?                .setRequiresBatteryNotLow(true) // 电量充足时运�?                .build()

            val workRequest = PeriodicWorkRequestBuilder<VpnKeepaliveWorker>(
                repeatInterval = CHECK_INTERVAL_MINUTES,
                repeatIntervalTimeUnit = TimeUnit.MINUTES
            )
                .setConstraints(constraints)
                .setInitialDelay(15, TimeUnit.MINUTES) // 周期任务对齐 15 分钟，避免启动后短时间唤�?                .build()

            WorkManager.getInstance(context).enqueueUniquePeriodicWork(
                WORK_NAME,
                ExistingPeriodicWorkPolicy.KEEP, // 保持现有任务,避免重复调度
                workRequest
            )

            Log.i(TAG, "VPN keepalive worker scheduled (interval: ${CHECK_INTERVAL_MINUTES}min)")
        }

        /**
         * 取消保活任务
         */
        fun cancel(context: Context) {
            WorkManager.getInstance(context).cancelUniqueWork(WORK_NAME)
            Log.i(TAG, "VPN keepalive worker cancelled")
        }

        /**
         * 检查后台进程是否存�?         */
        private fun isBackgroundProcessAlive(context: Context): Boolean {
            val activityManager = context.getSystemService(Context.ACTIVITY_SERVICE) as ActivityManager
            val processes = activityManager.runningAppProcesses ?: return false

            val bgProcessName = "${context.packageName}:bg"
            return processes.any { it.processName == bgProcessName }
        }
    }

    override suspend fun doWork(): Result {
        return try {

            // 1. 检查是否应该运�?VPN (用户未手动停�?
            val isManuallyStopped = VpnStateStore.isManuallyStopped()
            if (isManuallyStopped) {
                return Result.success()
            }

            // 2. 检查当�?VPN 模式
            val currentMode = VpnStateStore.getMode()
            if (currentMode == VpnStateStore.CoreMode.NONE) {
                return Result.success()
            }

            // 3. 检查后台进程是否存�?            val bgProcessAlive = isBackgroundProcessAlive(applicationContext)

            // 4. 如果进程死亡但应该运�?则尝试恢�?            if (!bgProcessAlive) {
                Log.w(TAG, "Detected background process died unexpectedly, attempting recovery...")
                attemptVpnRecovery(currentMode)
            } else {
                // 5. 进程存活,检查服务状态是否一�?                // 这里通过 OpenWorldRemote 检�?但由于是跨进�?可能有延�?                // 主要作为辅助验证
            }

            Result.success()
        } catch (e: Exception) {
            Log.e(TAG, "VPN keepalive check failed", e)
            // 失败时重�?最多重�?�?            if (runAttemptCount < 3) {
                Result.retry()
            } else {
                Result.failure()
            }
        }
    }

    /**
     * 尝试恢复 VPN 连接
     *
     * 策略:
     * 1. 读取上次的配置路�?     * 2. 使用相同配置重启 VPN 服务
     * 3. 记录恢复日志
     */
    private suspend fun attemptVpnRecovery(mode: VpnStateStore.CoreMode) {
        try {
            Log.i(TAG, "Attempting to recover VPN service (mode: $mode)...")

            // 获取配置路径
            val settingsRepo = SettingsRepository.getInstance(applicationContext)
            val settings = settingsRepo.settings.first()

            // 准备重启 Intent
            val intent = when (mode) {
                VpnStateStore.CoreMode.VPN -> {
                    Intent(applicationContext, OpenWorldService::class.java).apply {
                        action = OpenWorldService.ACTION_START
                        putExtra(OpenWorldService.EXTRA_CONFIG_PATH,
                            applicationContext.filesDir.resolve("config.json").absolutePath)
                    }
                }
                VpnStateStore.CoreMode.PROXY -> {
                    Intent(applicationContext, ProxyOnlyService::class.java).apply {
                        action = ProxyOnlyService.ACTION_START
                        putExtra(ProxyOnlyService.EXTRA_CONFIG_PATH,
                            applicationContext.filesDir.resolve("config.json").absolutePath)
                    }
                }
                else -> {
                    Log.w(TAG, "Unknown mode: $mode, skip recovery")
                    return
                }
            }

            // 启动服务
            try {
                if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.O) {
                    applicationContext.startForegroundService(intent)
                } else {
                    applicationContext.startService(intent)
                }
                Log.i(TAG, "VPN service recovery triggered successfully")
            } catch (e: Exception) {
                Log.e(TAG, "Failed to start VPN service during recovery", e)

                // 如果启动失败,清除状态避免无限重�?                VpnStateStore.setMode(VpnStateStore.CoreMode.NONE)
                VpnTileService.persistVpnState(applicationContext, false)
            }
        } catch (e: Exception) {
            Log.e(TAG, "VPN recovery failed", e)
        }
    }
}







