package com.openworld.app.core

import android.util.Log
import com.openworld.core.OpenWorldCore

/**
 * Libbox 兼容�?- 现在仅提�?OpenWorld 内核的适配
 *
 * 注意: 所有功能已迁移�?BoxWrapperManager
 * 本类保留用于兼容性接�? */
object LibboxCompat {
    private const val TAG = "LibboxCompat"

    /**
     * 是否�?resetAllConnections 功能
     */
    var hasResetAllConnections: Boolean = true
        private set

    /**
     * 重置所有连�?     */
    fun resetAllConnections(system: Boolean = true): Boolean {
        return BoxWrapperManager.resetAllConnections(system)
    }

    fun getVersion(): String {
        return try {
            OpenWorldCore.version()
        } catch (e: Exception) {
            "unknown"
        }
    }

    fun getExtensionVersion(): String {
        return try {
            OpenWorldCore.version()
        } catch (e: Exception) {
            "N/A"
        }
    }

    fun hasExtendedLibbox(): Boolean = BoxWrapperManager.isOpenWorldAvailable

    fun hasOpenWorldExtension(): Boolean = BoxWrapperManager.isOpenWorldAvailable

    fun printDiagnostics() {
        val version = try {
            OpenWorldCore.version()
        } catch (e: Exception) {
            "N/A"
        }
        Log.i(TAG, "LibboxCompat: version=$version, useOpenWorld=${BoxWrapperManager.isOpenWorldAvailable}")
    }
}







