package com.openworld.app.utils

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

/**
 * 深度链接处理�?- 用于�?MainActivity �?ProfilesScreen 之间传�?URL Scheme 数据
 */
object DeepLinkHandler {

    data class SubscriptionImportData(
        val name: String,
        val url: String,
        val autoUpdateInterval: Int
    )

    private val _pendingSubscriptionImport = MutableStateFlow<SubscriptionImportData?>(null)
    val pendingSubscriptionImport: StateFlow<SubscriptionImportData?> = _pendingSubscriptionImport.asStateFlow()

    /**
     * 设置待处理的订阅导入数据
     */
    fun setPendingSubscriptionImport(name: String, url: String, interval: Int) {
        _pendingSubscriptionImport.value = SubscriptionImportData(name, url, interval)
    }

    /**
     * 清除待处理的订阅导入数据
     */
    fun clearPendingSubscriptionImport() {
        _pendingSubscriptionImport.value = null
    }
}







