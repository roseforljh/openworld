package com.openworld.app.model

data class ProfileUi(
    val name: String,
    val isActive: Boolean = false,
    val lastUpdated: String = "",
    val subscriptionUrl: String = "",
    val isUpdating: Boolean = false
)
