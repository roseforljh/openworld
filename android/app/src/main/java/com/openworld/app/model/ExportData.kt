package com.openworld.app.model

import androidx.annotation.Keep
import com.google.gson.annotations.SerializedName

/**
 * 导出数据的根模型
 * 用于应用数据的备份和恢复
 */
@Keep
data class ExportData(
    @SerializedName("version") val version: Int = 1, // 数据格式版本�?    @SerializedName("exportTime") val exportTime: Long, // 导出时间�?    @SerializedName("appVersion") val appVersion: String, // 应用版本�?    @SerializedName("settings") val settings: AppSettings, // 应用设置
    @SerializedName("profiles") val profiles: List<ProfileExportData>, // 配置列表
    @SerializedName("activeProfileId") val activeProfileId: String?, // 活跃配置 ID
    @SerializedName("activeNodeId") val activeNodeId: String? // 活跃节点 ID
)

/**
 * 配置导出数据
 * 包含配置元数据和完整的节点配�? */
@Keep
data class ProfileExportData(
    @SerializedName("profile") val profile: ProfileUi, // 配置元数�?    @SerializedName("config") val config: OpenWorldConfig // 完整的节点配�?)

/**
 * 导入选项
 */
@Keep
data class ImportOptions(
    val overwriteExisting: Boolean = true, // 是否覆盖现有数据（默认覆盖）
    val importSettings: Boolean = true, // 是否导入设置
    val importProfiles: Boolean = true, // 是否导入配置
    val importRules: Boolean = true // 是否导入规则
)

/**
 * 导入结果
 */
@Keep
sealed class ImportResult {
    /**
     * 导入成功
     */
    data class Success(
        val profilesImported: Int,
        val nodesImported: Int,
        val settingsImported: Boolean
    ) : ImportResult()

    /**
     * 部分成功
     */
    data class PartialSuccess(
        val profilesImported: Int,
        val profilesFailed: Int,
        val errors: List<String>
    ) : ImportResult()

    /**
     * 导入失败
     */
    data class Failed(val error: String) : ImportResult()
}

/**
 * 导出数据摘要
 * 用于在导入前展示给用户确�? */
@Keep
data class ExportDataSummary(
    val version: Int,
    val exportTime: Long,
    val appVersion: String,
    val profileCount: Int,
    val totalNodeCount: Int,
    val hasSettings: Boolean,
    val hasCustomRules: Boolean,
    val hasRuleSets: Boolean,
    val hasAppRules: Boolean
)







