package com.openworld.app.service.notification

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.os.Build
import android.os.SystemClock
import android.util.Log
import com.openworld.app.MainActivity
import com.openworld.app.R
import com.openworld.app.service.OpenWorldService
import com.openworld.app.service.OpenWorldService.Companion.ACTION_STOP
import com.openworld.app.service.OpenWorldService.Companion.ACTION_SWITCH_NODE
import com.openworld.app.service.OpenWorldService.Companion.ACTION_RESET_CONNECTIONS
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicLong

/**
 * VPN 通知管理�? * 负责 VPN 服务通知的创建、更新和生命周期管理
 */
class VpnNotificationManager(
    private val context: Context,
    private val serviceScope: CoroutineScope
) {
    companion object {
        private const val TAG = "VpnNotificationManager"
        const val NOTIFICATION_ID = 1
        const val CHANNEL_ID = "singbox_vpn_service_silent"
        private const val LEGACY_CHANNEL_ID = "singbox_vpn_service"
        private const val UPDATE_DEBOUNCE_MS = 3000L
    }

    private val notificationManager: NotificationManager by lazy {
        context.getSystemService(NotificationManager::class.java)
    }

    private val lastUpdateAtMs = AtomicLong(0L)
    private val hasForegroundStarted = AtomicBoolean(false)

    @Volatile
    private var updateJob: Job? = null

    @Volatile
    private var suppressUpdates = false

    @Volatile
    private var lastTextLogged: String? = null

    /**
     * 通知状态数�?     */
    data class NotificationState(
        val isRunning: Boolean = false,
        val isStopping: Boolean = false,
        val activeNodeName: String? = null,
        val showSpeed: Boolean = true,
        val uploadSpeed: Long = 0L,
        val downloadSpeed: Long = 0L
    )

    /**
     * 创建通知渠道 (Android 8.0+)
     */
    fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            // 清理旧渠�?            runCatching { notificationManager.deleteNotificationChannel("singbox_vpn") }
            runCatching { notificationManager.deleteNotificationChannel(LEGACY_CHANNEL_ID) }

            val channel = NotificationChannel(
                CHANNEL_ID,
                "OpenWorld VPN",
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = "VPN Service Notification"
                setShowBadge(false)
                enableVibration(false)
                enableLights(false)
                setSound(null, null)
                lockscreenVisibility = Notification.VISIBILITY_PUBLIC
            }
            notificationManager.createNotificationChannel(channel)
        }
    }

    /**
     * 更新通知
     * @param state 当前通知状�?     * @param service VPN 服务实例 (用于 startForeground)
     */
    fun updateNotification(state: NotificationState, service: OpenWorldService) {
        val notification = createNotification(state)

        val text = runCatching {
            notification.extras?.getCharSequence(Notification.EXTRA_TEXT)?.toString()
        }.getOrNull()

        if (!text.isNullOrBlank() && text != lastTextLogged) {
            lastTextLogged = text
            Log.i(TAG, "Notification content: $text")
        }

        // 修复华为设备提示音问�? 只在首次调用 startForeground, 后续使用 notify
        if (!hasForegroundStarted.get()) {
            runCatching {
                service.startForeground(NOTIFICATION_ID, notification)
                hasForegroundStarted.set(true)
            }.onFailure { e ->
                Log.w(TAG, "Failed to call startForeground, fallback to notify()", e)
                notificationManager.notify(NOTIFICATION_ID, notification)
            }
        } else {
            runCatching {
                notificationManager.notify(NOTIFICATION_ID, notification)
            }.onFailure { e ->
                Log.w(TAG, "Failed to update notification via notify()", e)
            }
        }
    }

    /**
     * 请求更新通知 (带防�?
     * @param state 当前通知状�?     * @param service VPN 服务实例
     * @param force 是否强制立即更新
     */
    fun requestNotificationUpdate(
        state: NotificationState,
        service: OpenWorldService,
        force: Boolean = false
    ) {
        if (suppressUpdates) return
        if (state.isStopping) return

        val now = SystemClock.elapsedRealtime()
        val last = lastUpdateAtMs.get()

        if (force) {
            lastUpdateAtMs.set(now)
            updateJob?.cancel()
            updateJob = null
            updateNotification(state, service)
            return
        }

        val delayMs = (UPDATE_DEBOUNCE_MS - (now - last)).coerceAtLeast(0L)
        if (delayMs <= 0L) {
            lastUpdateAtMs.set(now)
            updateJob?.cancel()
            updateJob = null
            updateNotification(state, service)
            return
        }

        if (updateJob?.isActive == true) return
        updateJob = serviceScope.launch {
            delay(delayMs)
            lastUpdateAtMs.set(SystemClock.elapsedRealtime())
            updateNotification(state, service)
        }
    }

    /**
     * 创建通知
     */
    fun createNotification(state: NotificationState): Notification {
        // 停止中状态显示简化通知
        if (state.isStopping) {
            return buildNotificationBuilder()
                .setContentTitle("OpenWorld VPN")
                .setContentText(context.getString(R.string.connection_disconnecting))
                .setSmallIcon(android.R.drawable.ic_lock_idle_low_battery)
                .setOngoing(true)
                .build()
        }

        // 主界�?PendingIntent
        val mainIntent = Intent(context, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_CLEAR_TOP or Intent.FLAG_ACTIVITY_SINGLE_TOP
        }
        val mainPendingIntent = PendingIntent.getActivity(
            context, 0, mainIntent,
            PendingIntent.FLAG_IMMUTABLE
        )

        // 切换节点按钮
        val switchIntent = Intent(context, OpenWorldService::class.java).apply {
            action = ACTION_SWITCH_NODE
        }
        val switchPendingIntent = PendingIntent.getService(
            context, 1, switchIntent,
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )

        // 断开连接按钮
        val stopIntent = Intent(context, OpenWorldService::class.java).apply {
            action = ACTION_STOP
        }
        val stopPendingIntent = PendingIntent.getService(
            context, 2, stopIntent,
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )

        // 重置连接按钮
        val resetIntent = Intent(context, OpenWorldService::class.java).apply {
            action = ACTION_RESET_CONNECTIONS
        }
        val resetPendingIntent = PendingIntent.getService(
            context, 3, resetIntent,
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )

        // 节点名称
        val nodeName = state.activeNodeName ?: context.getString(R.string.connection_connected)

        // 内容文本
        val contentText = if (state.showSpeed) {
            val uploadStr = formatSpeed(state.uploadSpeed)
            val downloadStr = formatSpeed(state.downloadSpeed)
            context.getString(R.string.notification_speed_format, uploadStr, downloadStr)
        } else {
            context.getString(R.string.connection_connected)
        }

        return buildNotificationBuilder()
            .setContentTitle("OpenWorld VPN - $nodeName")
            .setContentText(contentText)
            .setSmallIcon(android.R.drawable.ic_lock_lock)
            .setContentIntent(mainPendingIntent)
            .setOngoing(true)
            .addAction(
                Notification.Action.Builder(
                    android.R.drawable.ic_menu_revert,
                    context.getString(R.string.notification_switch_node),
                    switchPendingIntent
                ).build()
            )
            .addAction(
                Notification.Action.Builder(
                    android.R.drawable.ic_menu_rotate,
                    context.getString(R.string.notification_reset_connections),
                    resetPendingIntent
                ).build()
            )
            .addAction(
                Notification.Action.Builder(
                    android.R.drawable.ic_menu_close_clear_cancel,
                    context.getString(R.string.notification_disconnect),
                    stopPendingIntent
                ).build()
            )
            .build()
    }

    /**
     * 创建启动中通知
     */
    fun createStartingNotification(message: String): Notification {
        return buildNotificationBuilder()
            .setContentTitle("OpenWorld VPN")
            .setContentText(message)
            .setSmallIcon(android.R.drawable.ic_popup_sync)
            .setOngoing(true)
            .build()
    }

    /**
     * 显示临时通知
     */
    fun showTemporaryNotification(id: Int, notification: Notification) {
        notificationManager.notify(NOTIFICATION_ID + id, notification)
    }

    /**
     * 取消通知
     */
    fun cancelNotification(id: Int = NOTIFICATION_ID) {
        notificationManager.cancel(id)
    }

    /**
     * 设置是否抑制更新
     */
    fun setSuppressUpdates(suppress: Boolean) {
        suppressUpdates = suppress
    }

    /**
     * 重置状�?     * �?VPN 停止时调�?     */
    fun resetState() {
        updateJob?.cancel()
        updateJob = null
        hasForegroundStarted.set(false)
        suppressUpdates = false
        lastTextLogged = null
    }

    /**
     * 检查是否已调用�?startForeground
     */
    fun hasForegroundStarted(): Boolean = hasForegroundStarted.get()

    /**
     * 设置已启动前台服�?     */
    fun markForegroundStarted() {
        hasForegroundStarted.set(true)
    }

    private fun buildNotificationBuilder(): Notification.Builder {
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            Notification.Builder(context, CHANNEL_ID)
        } else {
            @Suppress("DEPRECATION")
            Notification.Builder(context)
        }
    }

    private fun formatSpeed(bytesPerSecond: Long): String {
        return android.text.format.Formatter.formatFileSize(context, bytesPerSecond) + "/s"
    }
}







