package com.openworld.app.service

import android.content.Context
import android.util.Log
import androidx.work.*
import com.openworld.app.model.RuleSetType
import com.openworld.app.repository.RuleSetRepository
import com.openworld.app.repository.SettingsRepository
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.withContext
import java.util.concurrent.TimeUnit

/**
 * 规则集自动更�?Worker
 * 使用 WorkManager 在后台定期更新所有远程规则集
 */
class RuleSetAutoUpdateWorker(
    context: Context,
    workerParams: WorkerParameters
) : CoroutineWorker(context, workerParams) {

    companion object {
        private const val TAG = "RuleSetAutoUpdate"
        private const val WORK_NAME = "ruleset_global_auto_update"

        /**
         * 调度全局规则集自动更新任�?         * @param context Context
         * @param intervalMinutes 更新间隔（分钟）�? 表示禁用
         */
        fun schedule(context: Context, intervalMinutes: Int) {
            val workManager = WorkManager.getInstance(context)

            if (intervalMinutes <= 0) {
                // 禁用自动更新，取消现有任�?                workManager.cancelUniqueWork(WORK_NAME)
                return
            }

            // 创建周期性工作请�?            val constraints = Constraints.Builder()
                .setRequiredNetworkType(NetworkType.CONNECTED)
                .build()

            val workRequest = PeriodicWorkRequestBuilder<RuleSetAutoUpdateWorker>(
                intervalMinutes.toLong(),
                TimeUnit.MINUTES
            )
                .setConstraints(constraints)
                .setBackoffCriteria(
                    BackoffPolicy.EXPONENTIAL,
                    10,
                    TimeUnit.MINUTES
                )
                .build()

            // 使用 REPLACE 策略，如果已有相同名称的任务则替�?            workManager.enqueueUniquePeriodicWork(
                WORK_NAME,
                ExistingPeriodicWorkPolicy.REPLACE,
                workRequest
            )
        }

        /**
         * 取消全局规则集自动更新任�?         */
        fun cancel(context: Context) {
            val workManager = WorkManager.getInstance(context)
            workManager.cancelUniqueWork(WORK_NAME)
        }

        /**
         * 根据已保存的设置重新调度自动更新任务
         * 在应用启动时调用
         */
        suspend fun rescheduleAll(context: Context) = withContext(Dispatchers.IO) {
            try {
                val settingsRepository = SettingsRepository.getInstance(context)
                val settings = settingsRepository.settings.first()

                if (settings.ruleSetAutoUpdateEnabled && settings.ruleSetAutoUpdateInterval > 0) {
                    schedule(context, settings.ruleSetAutoUpdateInterval)
                } else {
                    cancel(context)
                }
            } catch (e: Exception) {
                Log.e(TAG, "Failed to reschedule auto-update task", e)
            }
        }
    }

    override suspend fun doWork(): Result = withContext(Dispatchers.IO) {

        try {
            val settingsRepository = SettingsRepository.getInstance(applicationContext)
            val ruleSetRepository = RuleSetRepository.getInstance(applicationContext)

            // 检查是否仍然启用自动更�?            val settings = settingsRepository.settings.first()

            if (!settings.ruleSetAutoUpdateEnabled) {
                cancel(applicationContext)
                return@withContext Result.success()
            }

            // 获取所有远程规则集并更�?            val remoteRuleSets = settings.ruleSets.filter {
                it.type == RuleSetType.REMOTE && it.enabled
            }

            if (remoteRuleSets.isEmpty()) {
                return@withContext Result.success()
            }

            var successCount = 0
            var failCount = 0

            remoteRuleSets.forEach { ruleSet ->
                try {
                    val success = ruleSetRepository.prefetchRuleSet(
                        ruleSet = ruleSet,
                        forceUpdate = true,
                        allowNetwork = true
                    )
                    if (success) {
                        successCount++
                    } else {
                        failCount++
                        Log.w(TAG, "Failed to update rule set: ${ruleSet.tag}")
                    }
                } catch (e: Exception) {
                    failCount++
                    Log.e(TAG, "Error updating rule set: ${ruleSet.tag}", e)
                }
            }

            Result.success()
        } catch (e: Exception) {
            Log.e(TAG, "Auto-update failed", e)

            // 如果失败，返�?retry �?WorkManager 根据退避策略重�?            Result.retry()
        }
    }
}







