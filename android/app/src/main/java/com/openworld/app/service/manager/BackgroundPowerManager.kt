package com.openworld.app.service.manager

import android.os.SystemClock
import android.util.Log
import com.openworld.app.repository.LogRepository
import kotlinx.coroutines.CoroutineScope

/**
 * 后台省电管理器（降级为状态记录器）
 *
 * 说明：
 * - 保留原有 API 形状与调用入口，兼容现有调用方。
 * - 不再执行任何会影响连接稳定性的省电动作。
 * - 主进程后台超时自杀由 AppLifecycleObserver 负责，这里仅记录状态。
 */
class BackgroundPowerManager(
    @Suppress("unused")
    private val serviceScope: CoroutineScope
) {
    companion object {
        private const val TAG = "BackgroundPowerManager"

        /** 默认后台省电阈值: 30 分钟 */
        const val DEFAULT_BACKGROUND_THRESHOLD_MS = 30 * 60 * 1000L

        /** 最小阈值: 5 分钟 (防止过于激进) */
        const val MIN_THRESHOLD_MS = 5 * 60 * 1000L

        /** 最大阈值: 2 小时 */
        const val MAX_THRESHOLD_MS = 2 * 60 * 60 * 1000L

        /** 恢复触发最小离开时长: 3 秒（避免过度触发） */
        private const val MIN_RECOVERY_AWAY_MS = 3_000L
    }

    /**
     * 省电模式状态（兼容保留）
     */
    enum class PowerMode {
        NORMAL,
        POWER_SAVING
    }

    /**
     * 回调接口 - 由 SingBoxService 实现（兼容保留）
     */
    interface Callbacks {
        /** VPN 是否正在运行 */
        val isVpnRunning: Boolean

        /** 暂停非核心进程 (进入省电模式) */
        fun suspendNonEssentialProcesses()

        /** 恢复非核心进程 (退出省电模式) */
        fun resumeNonEssentialProcesses()

        /** 请求核心网络恢复（由 Service 网关统一决策） */
        fun requestCoreNetworkRecovery(reason: String, force: Boolean = false)
    }

    private var callbacks: Callbacks? = null
    private var backgroundThresholdMs: Long = DEFAULT_BACKGROUND_THRESHOLD_MS

    @Volatile
    private var currentMode: PowerMode = PowerMode.NORMAL

    @Volatile
    private var userAwayAtMs: Long = 0L

    // 双信号状态
    @Volatile
    private var isAppInBackground: Boolean = false

    @Volatile
    private var isScreenOff: Boolean = false

    @Volatile
    private var backgroundStartTimeMs: Long = 0L

    private val logRepo by lazy { LogRepository.getInstance() }

    private fun logState(message: String) {
        Log.i(TAG, message)
        runCatching { logRepo.addLog("INFO [Power] $message") }
    }

    /**
     * 当前省电模式
     */
    val powerMode: PowerMode get() = currentMode

    /**
     * 是否处于省电模式
     */
    val isPowerSaving: Boolean get() = currentMode == PowerMode.POWER_SAVING

    /**
     * 用户是否离开 (后台或息屏)
     */
    private val isUserAway: Boolean get() = isAppInBackground || isScreenOff

    /**
     * 初始化管理器
     */
    fun init(callbacks: Callbacks, thresholdMs: Long = DEFAULT_BACKGROUND_THRESHOLD_MS) {
        this.callbacks = callbacks
        this.backgroundThresholdMs = if (thresholdMs == Long.MAX_VALUE) {
            Long.MAX_VALUE
        } else {
            thresholdMs.coerceIn(MIN_THRESHOLD_MS, MAX_THRESHOLD_MS)
        }
        val thresholdDisplay = if (backgroundThresholdMs == Long.MAX_VALUE) "NEVER" else "${backgroundThresholdMs / 1000 / 60}min"
        Log.i(TAG, "BackgroundPowerManager initialized as state-recorder only (threshold=$thresholdDisplay)")
    }

    /**
     * 更新后台省电阈值
     */
    fun setThreshold(thresholdMs: Long) {
        backgroundThresholdMs = if (thresholdMs == Long.MAX_VALUE) {
            Long.MAX_VALUE
        } else {
            thresholdMs.coerceIn(MIN_THRESHOLD_MS, MAX_THRESHOLD_MS)
        }
        val thresholdDisplay = if (backgroundThresholdMs == Long.MAX_VALUE) "NEVER" else "${backgroundThresholdMs / 1000 / 60}min"
        Log.i(TAG, "Threshold updated to $thresholdDisplay")
    }

    // ==================== 信号1: 主进程 IPC 通知 ====================

    /**
     * App 进入后台 (来自主进程 IPC)
     */
    fun onAppBackground() {
        if (isAppInBackground) return
        isAppInBackground = true
        backgroundStartTimeMs = SystemClock.elapsedRealtime()
        Log.i(TAG, "[IPC] App entered background at $backgroundStartTimeMs")
        evaluateUserPresence()
    }

    /**
     * App 返回前台 (来自主进程 IPC)
     */
    fun onAppForeground() {
        if (!isAppInBackground) {
            logState("[IPC] App foreground ignored: state mismatch (isAppInBackground=false)")
            return
        }

        val now = SystemClock.elapsedRealtime()
        val backgroundDuration = if (backgroundStartTimeMs > 0) {
            now - backgroundStartTimeMs
        } else {
            0L
        }
        val awayDuration = if (userAwayAtMs > 0) {
            now - userAwayAtMs
        } else {
            0L
        }

        isAppInBackground = false

        maybeRequestRecoveryOnReturn(
            source = "app_foreground",
            eventLabel = "[IPC] App returned to foreground",
            eventDurationMs = backgroundDuration,
            awayDurationMs = awayDuration
        )

        backgroundStartTimeMs = 0L
        evaluateUserPresence()
    }

    // ==================== 信号2: 屏幕状态 ====================

    /**
     * 屏幕关闭 (来自 ScreenStateManager)
     */
    fun onScreenOff() {
        if (isScreenOff) return
        isScreenOff = true
        Log.i(TAG, "[Screen] Screen turned OFF")
        evaluateUserPresence()
    }

    /**
     * 屏幕点亮 (来自 ScreenStateManager)
     */
    fun onScreenOn() {
        if (!isScreenOff) return

        val now = SystemClock.elapsedRealtime()
        val awayDuration = if (userAwayAtMs > 0) {
            now - userAwayAtMs
        } else {
            0L
        }

        isScreenOff = false

        maybeRequestRecoveryOnReturn(
            source = "screen_on",
            eventLabel = "[Screen] Screen turned ON",
            eventDurationMs = awayDuration,
            awayDurationMs = awayDuration
        )

        evaluateUserPresence()
    }

    // ==================== 统一判断逻辑（状态记录 + 轻量恢复桥接） ====================

    /**
     * 在用户回到可交互态时按需触发核心网络恢复
     */
    private fun maybeRequestRecoveryOnReturn(
        source: String,
        eventLabel: String,
        eventDurationMs: Long,
        awayDurationMs: Long
    ) {
        val cb = callbacks
        if (cb == null) {
            logState("$eventLabel after ${eventDurationMs / 1000}s, skip recovery: callbacks is null")
            return
        }

        if (!cb.isVpnRunning) {
            logState("$eventLabel after ${eventDurationMs / 1000}s, skip recovery: vpn not running")
            return
        }

        if (awayDurationMs < MIN_RECOVERY_AWAY_MS) {
            logState(
                "$eventLabel after ${eventDurationMs / 1000}s, skip recovery: " +
                    "away ${awayDurationMs}ms < ${MIN_RECOVERY_AWAY_MS}ms"
            )
            return
        }

        logState(
            "$eventLabel after ${eventDurationMs / 1000}s, " +
                "request recovery(source=$source, force=${awayDurationMs > 30_000L}, away=${awayDurationMs}ms)"
        )
        // 离开超过 30 秒，强制恢复（跳过所有防抖），避免恢复被合并/跳过
        val forceRecovery = awayDurationMs > 30_000L
        cb.requestCoreNetworkRecovery(source, force = forceRecovery)
    }

    /**
     * 评估用户状态（仅状态记录）
     */
    private fun evaluateUserPresence() {
        if (isUserAway) {
            if (userAwayAtMs == 0L) {
                userAwayAtMs = SystemClock.elapsedRealtime()
                val thresholdDisplay = if (backgroundThresholdMs == Long.MAX_VALUE) {
                    "NEVER"
                } else {
                    "${backgroundThresholdMs / 1000 / 60}min"
                }
                Log.i(
                    TAG,
                    "User away (background=$isAppInBackground, " +
                        "screenOff=$isScreenOff), threshold=$thresholdDisplay (state-only)"
                )
            }
            return
        }

        val wasAway = userAwayAtMs > 0
        if (wasAway) {
            val awayDuration = SystemClock.elapsedRealtime() - userAwayAtMs
            Log.i(TAG, "User returned after ${awayDuration / 1000}s (state-only)")
        }
        userAwayAtMs = 0L

        // 兼容兜底：若旧状态残留为 POWER_SAVING，则复位为 NORMAL，但不触发任何恢复动作
        if (currentMode == PowerMode.POWER_SAVING) {
            Log.i(TAG, "Resetting legacy POWER_SAVING state to NORMAL (no-op)")
            currentMode = PowerMode.NORMAL
        }
    }

    /**
     * 进入省电模式（兼容保留，no-op）
     */
    private fun enterPowerSavingMode() {
        Log.d(TAG, "enterPowerSavingMode ignored: state-recorder-only mode")
    }

    /**
     * 退出省电模式（兼容保留，no-op）
     */
    private fun exitPowerSavingMode() {
        Log.d(TAG, "exitPowerSavingMode ignored: state-recorder-only mode")
    }

    /**
     * 强制进入省电模式 (用于测试或手动触发)
     */
    fun forceEnterPowerSaving() {
        enterPowerSavingMode()
    }

    /**
     * 强制退出省电模式
     */
    fun forceExitPowerSaving() {
        exitPowerSavingMode()
    }

    /**
     * 清理资源
     */
    fun cleanup() {
        currentMode = PowerMode.NORMAL
        isAppInBackground = false
        isScreenOff = false
        userAwayAtMs = 0L
        backgroundStartTimeMs = 0L
        callbacks = null
        Log.i(TAG, "BackgroundPowerManager cleaned up")
    }

    /**
     * 获取统计信息 (用于调试)
     */
    fun getStats(): Map<String, Any> {
        return mapOf(
            "currentMode" to currentMode.name,
            "isAppInBackground" to isAppInBackground,
            "isScreenOff" to isScreenOff,
            "isUserAway" to isUserAway,
            "thresholdMin" to if (backgroundThresholdMs == Long.MAX_VALUE) {
                Long.MAX_VALUE
            } else {
                backgroundThresholdMs / 1000 / 60
            },
            "awayDurationSec" to if (userAwayAtMs > 0) {
                (SystemClock.elapsedRealtime() - userAwayAtMs) / 1000
            } else {
                0L
            },
            "backgroundDurationSec" to if (backgroundStartTimeMs > 0) {
                (SystemClock.elapsedRealtime() - backgroundStartTimeMs) / 1000
            } else {
                0L
            }
        )
    }
}
