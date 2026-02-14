package com.openworld.app.utils

import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.os.PowerManager
import android.provider.Settings
import android.util.Log

/**
 * 电池优化帮助�? * 用于检测和引导用户关闭电池优化,防止 VPN 服务在息屏时被系统杀�? */
object BatteryOptimizationHelper {
    private const val TAG = "BatteryOptHelper"

    /**
     * 检查应用是否在电池优化白名单中
     * @return true = 已豁�?不受电池优化限制), false = 受限�?     */
    fun isIgnoringBatteryOptimizations(context: Context): Boolean {
        return if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            val pm = context.getSystemService(Context.POWER_SERVICE) as? PowerManager
            pm?.isIgnoringBatteryOptimizations(context.packageName) ?: false
        } else {
            // Android 6.0 以下没有 Doze 模式,默认不受限制
            true
        }
    }

    /**
     * 请求电池优化豁免
     * 会弹出系统对话框让用户选择
     */
    fun requestIgnoreBatteryOptimizations(context: Context): Boolean {
        return try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                if (!isIgnoringBatteryOptimizations(context)) {
                    val intent = Intent(Settings.ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZATIONS).apply {
                        data = Uri.parse("package:${context.packageName}")
                        addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                    }
                    context.startActivity(intent)
                    Log.i(TAG, "Requested battery optimization exemption")
                    true
                } else {
                    Log.i(TAG, "Already ignoring battery optimizations")
                    false
                }
            } else {
                false
            }
        } catch (e: Exception) {
            Log.e(TAG, "Failed to request battery optimization exemption", e)
            // 降级方案: 打开电池优化设置页面让用户手动设�?            try {
                openBatteryOptimizationSettings(context)
                true
            } catch (e2: Exception) {
                Log.e(TAG, "Failed to open battery settings", e2)
                false
            }
        }
    }

    /**
     * 打开电池优化设置页面
     * 用于引导用户手动关闭电池优化
     */
    fun openBatteryOptimizationSettings(context: Context) {
        try {
            val intent = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                Intent(Settings.ACTION_IGNORE_BATTERY_OPTIMIZATION_SETTINGS).apply {
                    addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                }
            } else {
                // 旧版本打开应用详情�?                Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS).apply {
                    data = Uri.parse("package:${context.packageName}")
                    addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                }
            }
            context.startActivity(intent)
            Log.i(TAG, "Opened battery optimization settings")
        } catch (e: Exception) {
            Log.e(TAG, "Failed to open battery optimization settings", e)
        }
    }

    /**
     * 获取厂商定制的电池管理页�?Intent
     * 不同厂商的电池优化设置页面路径不�?     */
    fun getManufacturerBatteryIntent(context: Context): Intent? {
        val packageName = context.packageName
        val manufacturer = Build.MANUFACTURER.lowercase()

        return try {
            when {
                // 小米 MIUI
                manufacturer.contains("xiaomi") || manufacturer.contains("redmi") -> {
                    Intent().apply {
                        component = android.content.ComponentName(
                            "com.miui.powerkeeper",
                            "com.miui.powerkeeper.ui.HiddenAppsConfigActivity"
                        )
                        putExtra("package_name", packageName)
                        putExtra("package_label", context.applicationInfo.loadLabel(context.packageManager))
                        addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                    }
                }
                // 华为 EMUI
                manufacturer.contains("huawei") || manufacturer.contains("honor") -> {
                    Intent().apply {
                        component = android.content.ComponentName(
                            "com.huawei.systemmanager",
                            "com.huawei.systemmanager.startupmgr.ui.StartupNormalAppListActivity"
                        )
                        addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                    }
                }
                // OPPO ColorOS
                manufacturer.contains("oppo") -> {
                    Intent().apply {
                        component = android.content.ComponentName(
                            "com.coloros.safecenter",
                            "com.coloros.safecenter.permission.startup.StartupAppListActivity"
                        )
                        addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                    }
                }
                // vivo
                manufacturer.contains("vivo") -> {
                    Intent().apply {
                        component = android.content.ComponentName(
                            "com.iqoo.secure",
                            "com.iqoo.secure.ui.phoneoptimize.AddWhiteListActivity"
                        )
                        addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                    }
                }
                // 三星
                manufacturer.contains("samsung") -> {
                    Intent().apply {
                        component = android.content.ComponentName(
                            "com.samsung.android.lool",
                            "com.samsung.android.sm.ui.battery.BatteryActivity"
                        )
                        addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
                    }
                }
                else -> null
            }
        } catch (e: Exception) {
            Log.e(TAG, "Failed to create manufacturer battery intent for $manufacturer", e)
            null
        }
    }

    /**
     * 检测并引导用户关闭电池优化
     * @return true = 需要用户操�? false = 已豁免或操作失败
     */
    fun checkAndRequestBatteryOptimization(context: Context): Boolean {
        if (isIgnoringBatteryOptimizations(context)) {
            Log.i(TAG, "App is already exempt from battery optimizations")
            return false
        }

        Log.w(TAG, "App is subject to battery optimizations, requesting exemption")
        return requestIgnoreBatteryOptimizations(context)
    }
}







