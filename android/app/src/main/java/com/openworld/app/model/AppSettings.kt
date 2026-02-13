package com.openworld.app.model

data class AppSettings(
    val appTheme: AppThemeMode = AppThemeMode.SYSTEM,
    val routingMode: String = "rule",
    val dnsLocal: String = "223.5.5.5",
    val dnsRemote: String = "tls://8.8.8.8",
    val debugLogging: Boolean = false
)
