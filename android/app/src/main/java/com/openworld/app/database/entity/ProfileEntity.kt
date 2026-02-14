package com.openworld.app.database.entity

import androidx.room.Entity
import androidx.room.PrimaryKey
import com.openworld.app.model.ProfileType
import com.openworld.app.model.ProfileUi
import com.openworld.app.model.UpdateStatus

/**
 * Profile 数据库实�? *
 * 对应 ProfileUi，使�?Room 存储以提升查询性能
 */
@Entity(tableName = "profiles")
data class ProfileEntity(
    @PrimaryKey
    val id: String,
    val name: String,
    val type: ProfileType,
    val url: String?,
    val lastUpdated: Long,
    val enabled: Boolean,
    val autoUpdateInterval: Int = 0,
    val updateStatus: UpdateStatus = UpdateStatus.Idle,
    val expireDate: Long = 0,
    val totalTraffic: Long = 0,
    val usedTraffic: Long = 0,
    val sortOrder: Int = 0,
    // DNS 预解析设�?    val dnsPreResolve: Boolean = false,
    val dnsServer: String? = null
) {
    /**
     * 转换�?UI 模型
     */
    fun toUiModel(): ProfileUi = ProfileUi(
        id = id,
        name = name,
        type = type,
        url = url,
        lastUpdated = lastUpdated,
        enabled = enabled,
        autoUpdateInterval = autoUpdateInterval,
        updateStatus = updateStatus,
        expireDate = expireDate,
        totalTraffic = totalTraffic,
        usedTraffic = usedTraffic,
        dnsPreResolve = dnsPreResolve,
        dnsServer = dnsServer
    )

    companion object {
        /**
         * �?UI 模型创建实体
         */
        fun fromUiModel(ui: ProfileUi, sortOrder: Int = 0): ProfileEntity = ProfileEntity(
            id = ui.id,
            name = ui.name,
            type = ui.type,
            url = ui.url,
            lastUpdated = ui.lastUpdated,
            enabled = ui.enabled,
            autoUpdateInterval = ui.autoUpdateInterval,
            updateStatus = ui.updateStatus,
            expireDate = ui.expireDate,
            totalTraffic = ui.totalTraffic,
            usedTraffic = ui.usedTraffic,
            sortOrder = sortOrder,
            dnsPreResolve = ui.dnsPreResolve,
            dnsServer = ui.dnsServer
        )
    }
}







