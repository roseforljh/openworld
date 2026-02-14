package com.openworld.app.database.dao

import androidx.room.Dao
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query
import com.openworld.app.database.entity.SettingsEntity
import kotlinx.coroutines.flow.Flow

/**
 * 设置 DAO - 高效的单行设置存储
 *
 * 特点:
 * - Flow 实时观察设置变化
 * - 单次读写整个设置对象
 * - 异步操作，不阻塞主线程
 */
@Dao
interface SettingsDao {

    /**
     * 观察设置变化 (Flow)
     */
    @Query("SELECT * FROM settings WHERE id = 1")
    fun observeSettings(): Flow<SettingsEntity?>

    /**
     * 获取当前设置 (挂起函数)
     */
    @Query("SELECT * FROM settings WHERE id = 1")
    suspend fun getSettings(): SettingsEntity?

    /**
     * 同步获取当前设置 (仅用于初始化)
     */
    @Query("SELECT * FROM settings WHERE id = 1")
    fun getSettingsSync(): SettingsEntity?

    /**
     * 保存设置 (覆盖)
     */
    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun saveSettings(settings: SettingsEntity)

    /**
     * 同步保存设置 (仅用于迁移)
     */
    @Insert(onConflict = OnConflictStrategy.REPLACE)
    fun saveSettingsSync(settings: SettingsEntity)

    /**
     * 删除设置 (重置)
     */
    @Query("DELETE FROM settings")
    suspend fun deleteSettings()

    /**
     * 检查设置是否存在
     */
    @Query("SELECT EXISTS(SELECT 1 FROM settings WHERE id = 1)")
    suspend fun hasSettings(): Boolean

    /**
     * 同步检查设置是否存在
     */
    @Query("SELECT EXISTS(SELECT 1 FROM settings WHERE id = 1)")
    fun hasSettingsSync(): Boolean
}
