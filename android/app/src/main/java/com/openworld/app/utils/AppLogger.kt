package com.openworld.app.utils

import android.util.Log

/**
 * 应用日志工具�? *
 * 优化说明:
 * - Release 构建默认关闭 DEBUG/VERBOSE 级别日志
 * - 减少字符串拼接和日志输出开销
 * - 支持动态调整日志级�? */
object AppLogger {

    /**
     * 日志级别
     */
    enum class Level(val priority: Int) {
        VERBOSE(Log.VERBOSE),
        DEBUG(Log.DEBUG),
        INFO(Log.INFO),
        WARN(Log.WARN),
        ERROR(Log.ERROR),
        NONE(Int.MAX_VALUE)
    }

    /**
     * 当前最低日志级�?     * 可通过 Application 初始化时根据 BuildConfig.DEBUG 设置
     */
    @Volatile
    var minLevel: Level = Level.INFO

    /**
     * 是否启用日志（总开关）
     */
    @Volatile
    var enabled: Boolean = true

    /**
     * 检查指定级别是否可以输�?     * 使用 @PublishedApi 允许 inline 函数访问
     */
    @PublishedApi
    internal fun isLoggable(level: Level): Boolean {
        return enabled && level.priority >= minLevel.priority
    }

    /**
     * VERBOSE 级别日志
     */
    inline fun v(tag: String, message: () -> String) {
        if (isLoggable(Level.VERBOSE)) {
            Log.v(tag, message())
        }
    }

    /**
     * DEBUG 级别日志
     */
    inline fun d(tag: String, message: () -> String) {
        if (isLoggable(Level.DEBUG)) {
            Log.d(tag, message())
        }
    }

    /**
     * INFO 级别日志
     */
    inline fun i(tag: String, message: () -> String) {
        if (isLoggable(Level.INFO)) {
            Log.i(tag, message())
        }
    }

    /**
     * WARN 级别日志
     */
    inline fun w(tag: String, message: () -> String) {
        if (isLoggable(Level.WARN)) {
            Log.w(tag, message())
        }
    }

    /**
     * WARN 级别日志（带异常�?     */
    inline fun w(tag: String, throwable: Throwable?, message: () -> String) {
        if (isLoggable(Level.WARN)) {
            Log.w(tag, message(), throwable)
        }
    }

    /**
     * ERROR 级别日志
     */
    inline fun e(tag: String, message: () -> String) {
        if (isLoggable(Level.ERROR)) {
            Log.e(tag, message())
        }
    }

    /**
     * ERROR 级别日志（带异常�?     */
    inline fun e(tag: String, throwable: Throwable?, message: () -> String) {
        if (isLoggable(Level.ERROR)) {
            Log.e(tag, message(), throwable)
        }
    }

    /**
     * 直接输出日志（兼容旧代码，不推荐使用�?     */
    fun v(tag: String, message: String) {
        if (isLoggable(Level.VERBOSE)) Log.v(tag, message)
    }

    fun d(tag: String, message: String) {
        if (isLoggable(Level.DEBUG)) Log.d(tag, message)
    }

    fun i(tag: String, message: String) {
        if (isLoggable(Level.INFO)) Log.i(tag, message)
    }

    fun w(tag: String, message: String) {
        if (isLoggable(Level.WARN)) Log.w(tag, message)
    }

    fun w(tag: String, message: String, throwable: Throwable?) {
        if (isLoggable(Level.WARN)) Log.w(tag, message, throwable)
    }

    fun e(tag: String, message: String) {
        if (isLoggable(Level.ERROR)) Log.e(tag, message)
    }

    fun e(tag: String, message: String, throwable: Throwable?) {
        if (isLoggable(Level.ERROR)) Log.e(tag, message, throwable)
    }
}







