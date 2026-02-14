package com.openworld.app.core

import android.util.Log
import com.openworld.app.core.bridge.Libbox
import java.lang.reflect.Method

/**
 * Libbox 兼容层 - 提供对不同版本 libbox 的兼容性支持
 *
 * 注意: 新代码应优先使用 BoxWrapperManager，本类作为回退方案
 */
object LibboxCompat {
    private const val TAG = "LibboxCompat"

    private var resetAllConnectionsMethod: Method? = null
    private var resetAllConnectionsChecked = false

    @Volatile
    var hasResetAllConnections: Boolean = false
        private set

    @Volatile
    var hasExtensionApi: Boolean = false
        private set

    init {
        detectAvailableApis()
    }

    private fun detectAvailableApis() {
        // 检测 resetAllConnections
        resetAllConnectionsMethod = try {
            Libbox::class.java.getMethod("resetAllConnections", Boolean::class.javaPrimitiveType).also {
                hasResetAllConnections = true
                Log.i(TAG, "Detected Libbox.resetAllConnections(boolean)")
            }
        } catch (e: NoSuchMethodException) {
            try {
                Libbox::class.java.getMethod("ResetAllConnections", Boolean::class.javaPrimitiveType).also {
                    hasResetAllConnections = true
                    Log.i(TAG, "Detected Libbox.ResetAllConnections(boolean)")
                }
            } catch (e2: NoSuchMethodException) {
                Log.d(TAG, "Libbox.resetAllConnections not available")
                null
            }
        } catch (e: Exception) {
            Log.w(TAG, "Error detecting resetAllConnections: ${e.message}")
            null
        }
        resetAllConnectionsChecked = true

        // 检测扩展 API (自定义方法)
        hasExtensionApi = try {
            Libbox::class.java.getMethod("getOpenWorldVersion")
            Log.i(TAG, "Detected extension API")
            true
        } catch (e: Exception) {
            Log.d(TAG, "Extension API not available")
            false
        }
    }

    /**
     * 重置所有连接，直接调用 sing-box 内核的 conntrack.Close()
     * @param system true=关闭系统级连接表(推荐), false=仅用户级连接
     * @return true 如果成功调用原生方法
     */
    fun resetAllConnections(system: Boolean = true): Boolean {
        // 优先使用 BoxWrapperManager
        if (BoxWrapperManager.isAvailable()) {
            return BoxWrapperManager.resetAllConnections(system)
        }

        val method = resetAllConnectionsMethod ?: return false

        return try {
            method.invoke(null, system)
            Log.i(TAG, "Called Libbox.resetAllConnections($system)")
            true
        } catch (e: Exception) {
            Log.w(TAG, "Failed to call resetAllConnections: ${e.message}")
            false
        }
    }

    fun getVersion(): String {
        return try {
            Libbox.version()
        } catch (e: Exception) {
            "unknown"
        }
    }

    /**
     * 获取扩展版本
     */
    fun getExtensionVersion(): String {
        return try {
            Libbox.getOpenWorldVersion()
        } catch (e: Exception) {
            "N/A"
        }
    }

    fun hasExtendedLibbox(): Boolean = hasResetAllConnections

    /**
     * 检查是否支持扩展 API
     */
    fun hasOpenWorldExtension(): Boolean = hasExtensionApi

    fun printDiagnostics() {
        Log.i(TAG, "LibboxCompat: version=${getVersion()}, extensionVersion=${getExtensionVersion()}, hasResetAllConnections=$hasResetAllConnections, hasExtensionApi=$hasExtensionApi")
    }
}
