package com.openworld.app.ipc

import android.app.Service
import android.content.Intent
import android.os.IBinder
import com.openworld.app.aidl.IOpenWorldService
import com.openworld.app.aidl.IOpenWorldServiceCallback

class OpenWorldIpcService : Service() {

    private val binder = object : IOpenWorldService.Stub() {
        override fun getState(): Int = OpenWorldIpcHub.getStateOrdinal()

        override fun getActiveLabel(): String = OpenWorldIpcHub.getActiveLabel()

        override fun getLastError(): String = OpenWorldIpcHub.getLastError()

        override fun isManuallyStopped(): Boolean = OpenWorldIpcHub.isManuallyStopped()

        override fun registerCallback(callback: IOpenWorldServiceCallback?) {
            if (callback == null) return
            OpenWorldIpcHub.registerCallback(callback)
        }

        override fun unregisterCallback(callback: IOpenWorldServiceCallback?) {
            if (callback == null) return
            OpenWorldIpcHub.unregisterCallback(callback)
        }

        override fun notifyAppLifecycle(isForeground: Boolean) {
            OpenWorldIpcHub.onAppLifecycle(isForeground)
        }

        override fun hotReloadConfig(configContent: String?): Int {
            if (configContent.isNullOrEmpty()) {
                return OpenWorldIpcHub.HotReloadResult.UNKNOWN_ERROR
            }
            return OpenWorldIpcHub.hotReloadConfig(configContent)
        }
    }

    override fun onBind(intent: Intent?): IBinder = binder
}







