package com.openworld.app.database.entity

import androidx.room.Entity
import androidx.room.PrimaryKey

/**
 * 设置实体 - 单行存储整个 AppSettings
 *
 * 设计优势:
 * - 单次读写 vs N 次读�? * - 类型安全 vs 字符串转�? * - Flow 实时观察 vs 手动刷新
 * - 内置版本控制 vs 无版�? */
@Entity(tableName = "settings")
data class SettingsEntity(
    @PrimaryKey
    val id: Int = 1, // 始终只有一�?
    /**
     * 数据版本号，用于迁移
     */
    val version: Int = CURRENT_VERSION,

    /**
     * 序列化的 AppSettings JSON
     */
    val data: String,

    /**
     * 最后更新时间戳
     */
    val updatedAt: Long = System.currentTimeMillis()
) {
    companion object {
        const val CURRENT_VERSION = 3
    }
}







