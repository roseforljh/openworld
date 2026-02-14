package com.openworld.app.service.manager

import android.app.Application
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.os.Build
import android.os.PowerManager
import android.os.SystemClock
import android.util.Log
import com.openworld.app.core.BoxWrapperManager
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.launch

/**
 * 屏幕和设备状态管理器
 * 负责屏幕状态监听、设备空闲处理和 Activity 生命周期回调
 * 屏幕状态变化会通知 BackgroundPowerManager 触发省电模式
 */
class ScreenStateManager(
    private val context: Context,
    private val serviceScope: CoroutineScope
) {
    companion object {
        private const val TAG = "ScreenStateManager"
        private const val DOZE_EXIT_RECOVERY_DEBOUNCE_MS = 5_000L
        private const val ACTIVITY_RESUME_RECOVERY_MIN_AWAY_MS = 3_000L
    }

    interface Callbacks {
        val isRunning: Boolean

        /**
         * 通知远程 UI 强制刷新状�?         * 用于 Doze 唤醒后确�?IPC 状态同�?         */
        fun notifyRemoteStateUpdate(force: Boolean)

        /**
         * 请求核心网络恢复（由 Service 网关统一决策�?         */
        fun requestCoreNetworkRecovery(reason: String, force: Boolean = false)
    }

    private var callbacks: Callbacks? = null
    private var screenStateReceiver: BroadcastReceiver? = null
    private var activityLifecycleCallbacks: Application.ActivityLifecycleCallbacks? = null
    private var powerManager: BackgroundPowerManager? = null

    @Volatile private var lastDozeExitRecoveryAtMs: Long = 0L
    @Volatile private var screenOffAtMs: Long = 0L
    @Volatile private var appBackgroundAtMs: Long = 0L

    @Volatile var isScreenOn: Boolean = true
        private set
    @Volatile var isAppInForeground: Boolean = true
        private set

    fun init(callbacks: Callbacks) {
        this.callbacks = callbacks
    }

    /**
     * 设置省电管理器引�?     */
    fun setPowerManager(manager: BackgroundPowerManager?) {
        powerManager = manager
        Log.d(TAG, "PowerManager ${if (manager != null) "set" else "cleared"}")
    }

    /**
     * 注册屏幕状态监听器
     */
    fun registerScreenStateReceiver() {
        try {
            if (screenStateReceiver != null) return

            screenStateReceiver = object : BroadcastReceiver() {
                override fun onReceive(ctx: Context, intent: Intent) {
                    when (intent.action) {
                        Intent.ACTION_SCREEN_ON -> handleScreenOn()
                        Intent.ACTION_SCREEN_OFF -> handleScreenOff()
                        Intent.ACTION_USER_PRESENT -> handleUserPresent()
                        PowerManager.ACTION_DEVICE_IDLE_MODE_CHANGED -> handleDeviceIdleModeChanged(ctx)
                    }
                }

                private fun handleScreenOn() {
                    Log.i(TAG, "Screen ON detected")
                    isScreenOn = true
                    screenOffAtMs = 0L
                    // BackgroundPowerManager.onScreenOn() 统一处理网络恢复
                    powerManager?.onScreenOn()
                }

                private fun handleScreenOff() {
                    Log.i(TAG, "Screen OFF detected")
                    isScreenOn = false
                    screenOffAtMs = SystemClock.elapsedRealtime()
                    powerManager?.onScreenOff()
                }

                private fun handleUserPresent() {
                    Log.i(TAG, "[Unlock] User unlocked device")
                }

                private fun handleDeviceIdleModeChanged(ctx: Context) {
                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                        val pm = ctx.getSystemService(Context.POWER_SERVICE) as? PowerManager
                        val isIdleMode = pm?.isDeviceIdleMode == true

                        if (isIdleMode) {
                            Log.i(TAG, "[Doze Enter] Device entering idle mode")
                            serviceScope.launch { handleDeviceIdle() }
                        } else {
                            Log.i(TAG, "[Doze Exit] Device exiting idle mode")
                            serviceScope.launch { handleDeviceWake() }
                        }
                    }
                }
            }

            val filter = IntentFilter().apply {
                addAction(Intent.ACTION_SCREEN_ON)
                addAction(Intent.ACTION_SCREEN_OFF)
                addAction(Intent.ACTION_USER_PRESENT)
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                    addAction(PowerManager.ACTION_DEVICE_IDLE_MODE_CHANGED)
                }
            }

            context.registerReceiver(screenStateReceiver, filter)
            Log.i(TAG, "Screen state receiver registered")
        } catch (e: Exception) {
            Log.e(TAG, "Failed to register screen state receiver", e)
        }
    }

    /**
     * 注销屏幕状态监听器
     */
    fun unregisterScreenStateReceiver() {
        try {
            screenStateReceiver?.let {
                context.unregisterReceiver(it)
                screenStateReceiver = null
                Log.i(TAG, "Screen state receiver unregistered")
            }
        } catch (e: Exception) {
            Log.w(TAG, "Failed to unregister screen state receiver", e)
        }
    }

    /**
     * 注册 Activity 生命周期回调
     *
     * 注意：此方法�?VPN 进程 (:vpn_service) 中运行，只能监听同进程内�?Activity
     * (�?ShortcutActivity)。主进程�?MainActivity 生命周期�?IPC 路径
     * (AppLifecycleObserver -> OpenWorldIpcHub -> BackgroundPowerManager) 处理�?     */
    @Suppress("CognitiveComplexMethod")
    fun registerActivityLifecycleCallbacks(application: Application?) {
        try {
            if (activityLifecycleCallbacks != null) return

            val app = application ?: return

            activityLifecycleCallbacks = object : Application.ActivityLifecycleCallbacks {
                override fun onActivityResumed(activity: android.app.Activity) {
                    if (!isAppInForeground) {
                        Log.i(TAG, "App returned to FOREGROUND (${activity.localClassName})")
                        val wasInBackground = !isAppInForeground
                        isAppInForeground = true

                        val backgroundDuration = if (appBackgroundAtMs > 0) {
                            SystemClock.elapsedRealtime() - appBackgroundAtMs
                        } else 0L

                        // 网络恢复�?BackgroundPowerManager 统一处理（通过 IPC 路径�?                        // 此处不再重复触发，避免多�?wakeAndResetNetwork 导致连接中断
                        if (wasInBackground && backgroundDuration >= ACTIVITY_RESUME_RECOVERY_MIN_AWAY_MS) {
                            val seconds = backgroundDuration / 1000
                            Log.i(TAG, "[ActivityResume] Background ${seconds}s, recovery delegated to PowerManager")
                        }

                        appBackgroundAtMs = 0L
                        callbacks?.notifyRemoteStateUpdate(true)
                    }
                }

                override fun onActivityPaused(activity: android.app.Activity) {}
                override fun onActivityStarted(activity: android.app.Activity) {}
                override fun onActivityStopped(activity: android.app.Activity) {
                    if (isAppInForeground) {
                        isAppInForeground = false
                        appBackgroundAtMs = SystemClock.elapsedRealtime()
                        Log.d(TAG, "App moved to BACKGROUND at $appBackgroundAtMs")
                    }
                }
                override fun onActivityCreated(activity: android.app.Activity, savedInstanceState: android.os.Bundle?) {}
                override fun onActivityDestroyed(activity: android.app.Activity) {}
                override fun onActivitySaveInstanceState(activity: android.app.Activity, outState: android.os.Bundle) {}
            }

            app.registerActivityLifecycleCallbacks(activityLifecycleCallbacks)
            Log.i(TAG, "Activity lifecycle callbacks registered")
        } catch (e: Exception) {
            Log.e(TAG, "Failed to register activity lifecycle callbacks", e)
        }
    }

    /**
     * 注销 Activity 生命周期回调
     */
    fun unregisterActivityLifecycleCallbacks(application: Application?) {
        try {
            activityLifecycleCallbacks?.let { cb ->
                application?.unregisterActivityLifecycleCallbacks(cb)
                activityLifecycleCallbacks = null
                Log.i(TAG, "Activity lifecycle callbacks unregistered")
            }
        } catch (e: Exception) {
            Log.w(TAG, "Failed to unregister activity lifecycle callbacks", e)
        }
    }

    /**
     * 处理应用进入后台
     */
    fun onAppBackground() {
        Log.i(TAG, "App moved to BACKGROUND")
        isAppInForeground = false
    }

    /**
     * 设备进入空闲模式
     */
    private suspend fun handleDeviceIdle() {
        if (callbacks?.isRunning != true) return
        Log.i(TAG, "[Doze] Device idle, sleeping core")
        BoxWrapperManager.sleep()
    }

    /**
     * 设备退出空闲模�?     */
    private suspend fun handleDeviceWake() {
        if (callbacks?.isRunning != true) return

        try {
            val now = SystemClock.elapsedRealtime()
            val elapsed = now - lastDozeExitRecoveryAtMs
            if (elapsed < DOZE_EXIT_RECOVERY_DEBOUNCE_MS) {
                Log.d(TAG, "[Doze] Wake recovery skipped (debounce)")
                callbacks?.notifyRemoteStateUpdate(true)
                return
            }

            lastDozeExitRecoveryAtMs = now

            Log.i(TAG, "[Doze] Device wake, request recovery")
            callbacks?.requestCoreNetworkRecovery(reason = "doze_exit", force = false)
            callbacks?.notifyRemoteStateUpdate(true)
        } catch (e: Exception) {
            Log.e(TAG, "[Doze] handleDeviceWake failed", e)
        }
    }

    fun cleanup() {
        unregisterScreenStateReceiver()
        callbacks = null
    }
}







