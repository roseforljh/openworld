package com.openworld.app.model

data class NodeUi(
    val tag: String,
    val name: String,
    val type: String = "",
    val groupName: String = "",
    val latency: Int = -1,
    val isSelected: Boolean = false,
    val isTesting: Boolean = false
)
