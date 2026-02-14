package com.openworld.app.database.dao

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query
import com.openworld.app.database.entity.NodeLatencyEntity
import kotlinx.coroutines.flow.Flow

/**
 * 节点延迟缓存数据访问对象
 *
 * 管理节点的延迟测试结�? */
@Dao
interface NodeLatencyDao {

    @Query("SELECT * FROM node_latencies WHERE nodeId = :nodeId")
    suspend fun getByNodeId(nodeId: String): NodeLatencyEntity?

    @Query("SELECT * FROM node_latencies")
    suspend fun getAll(): List<NodeLatencyEntity>

    @Query("SELECT * FROM node_latencies")
    fun getAllSync(): List<NodeLatencyEntity>

    @Query("SELECT * FROM node_latencies")
    fun getAllFlow(): Flow<List<NodeLatencyEntity>>

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insert(latency: NodeLatencyEntity)

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertAll(latencies: List<NodeLatencyEntity>)

    @Query("DELETE FROM node_latencies WHERE nodeId = :nodeId")
    suspend fun deleteByNodeId(nodeId: String)

    @Query("DELETE FROM node_latencies WHERE testedAt < :before")
    suspend fun deleteOlderThan(before: Long)

    @Query("DELETE FROM node_latencies")
    suspend fun deleteAll()

    /**
     * 批量更新延迟
     * 使用 INSERT OR REPLACE 策略
     */
    @Query("INSERT OR REPLACE INTO node_latencies (nodeId, latencyMs, testedAt) VALUES (:nodeId, :latencyMs, :testedAt)")
    suspend fun upsert(nodeId: String, latencyMs: Long, testedAt: Long = System.currentTimeMillis())
}







