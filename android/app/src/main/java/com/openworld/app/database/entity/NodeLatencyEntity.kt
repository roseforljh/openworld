package com.openworld.app.database.entity

import androidx.room.Entity
import androidx.room.Index
import androidx.room.PrimaryKey

/**
 * 节点延迟缓存实体
 *
 * 存储节点的延迟测试结果，用于快速查询
 */
@Entity(
    tableName = "node_latencies",
    indices = [Index(value = ["nodeId"])]
)
data class NodeLatencyEntity(
    @PrimaryKey
    val nodeId: String,
    val latencyMs: Long,
    val testedAt: Long = System.currentTimeMillis()
)
