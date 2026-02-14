package com.openworld.app.ipc

import android.app.Service
import android.content.Intent
import android.os.IBinder
import com.openworld.app.aidl.ISingBoxService
import com.openworld.app.aidl.ISingBoxServiceCallback

class SingBoxIpcService : Service() {

    private val binder = object : ISingBoxService.Stub() {
        override fun getState(): Int = SingBoxIpcHub.getStateOrdinal()

        override fun getActiveLabel(): String = SingBoxIpcHub.getActiveLabel()

        override fun getLastError(): String = SingBoxIpcHub.getLastError()

        override fun isManuallyStopped(): Boolean = SingBoxIpcHub.isManuallyStopped()

        override fun registerCallback(callback: ISingBoxServiceCallback?) {
            if (callback == null) return
            SingBoxIpcHub.registerCallback(callback)
        }

        override fun unregisterCallback(callback: ISingBoxServiceCallback?) {
            if (callback == null) return
            SingBoxIpcHub.unregisterCallback(callback)
        }

        override fun notifyAppLifecycle(isForeground: Boolean) {
            SingBoxIpcHub.onAppLifecycle(isForeground)
        }

        override fun hotReloadConfig(configContent: String?): Int {
            if (configContent.isNullOrEmpty()) {
                return SingBoxIpcHub.HotReloadResult.UNKNOWN_ERROR
            }
            return SingBoxIpcHub.hotReloadConfig(configContent)
        }
    }

    override fun onBind(intent: Intent?): IBinder = binder
}
