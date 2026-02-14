package com.openworld.app.database.entity

import androidx.room.Entity
import androidx.room.PrimaryKey

/**
 * 活跃状态实�? *
 * 存储当前活跃�?Profile �?Node ID
 * 使用单例模式（固�?ID = 1�? */
@Entity(tableName = "active_state")
data class ActiveStateEntity(
    @PrimaryKey
    val id: Int = 1,
    val activeProfileId: String?,
    val activeNodeId: String?
)







