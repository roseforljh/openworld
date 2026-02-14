package com.openworld.app.core

import android.util.Log
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

/**
 * Selector 热切换管理器
 *
 * 负责跟踪当前配置�?selector 结构，判断是否支持热切换�? *
 * 热切换条�?
 * 1. VPN 正在运行
 * 2. 当前配置�?selector 类型的出�? * 3. 新节点在同一 selector group �?(签名匹配)
 *
 * 使用流程:
 * 1. VPN 启动后，调用 recordSelectorSignature() 记录当前 selector �?outbound 列表签名
 * 2. 切换节点前，调用 canHotSwitch() 检查新节点是否在同一 selector group
 * 3. 如果可以热切换，调用 selectOutbound() 执行切换
 * 4. VPN 停止时，调用 clear() 清除状�? *
 * 现在使用 OpenWorld 内核 (BoxWrapperManager)
 */
object SelectorManager {
    private const val TAG = "SelectorManager"

    // 当前配置�?selector group 签名 (outbounds 列表�?hash)
    @Volatile
    private var currentSelectorSignature: String? = null

    // 当前 selector �?outbound tags 列表
    @Volatile
    private var currentOutboundTags: List<String> = emptyList()

    // 当前选中的节�?tag
    private val _selectedOutbound = MutableStateFlow<String?>(null)
    val selectedOutbound: StateFlow<String?> = _selectedOutbound.asStateFlow()

    // 是否支持热切�?    private val _canHotSwitch = MutableStateFlow(false)
    val canHotSwitchFlow: StateFlow<Boolean> = _canHotSwitch.asStateFlow()

    /**
     * 记录当前配置�?selector 签名
     *
     * �?VPN 启动成功后调用，传入 PROXY selector �?outbounds 列表
     *
     * @param outboundTags PROXY selector 包含的所�?outbound tags
     * @param selectedTag 当前选中�?outbound tag
     */
    fun recordSelectorSignature(outboundTags: List<String>, selectedTag: String? = null) {
        currentOutboundTags = outboundTags.toList()
        currentSelectorSignature = computeSignature(outboundTags)
        _canHotSwitch.value = outboundTags.isNotEmpty()
        if (selectedTag != null) {
            _selectedOutbound.value = selectedTag
        }
        Log.d(TAG, "Recorded selector: ${outboundTags.size} outbounds, sig=$currentSelectorSignature, selected=$selectedTag")
    }

    /**
     * 检查新配置是否与当前配置兼容（可热切换�?     *
     * 判断条件�?     * 1. 当前有有效的 selector 签名
     * 2. 新配置的 outbound 列表签名与当前相�?     *
     * @param newOutboundTags 新配置的 outbound tags
     * @return true 如果可以热切�?     */
    fun canHotSwitch(newOutboundTags: List<String>): Boolean {
        val currentSig = currentSelectorSignature ?: return false
        val newSig = computeSignature(newOutboundTags)
        val canSwitch = currentSig == newSig
        Log.d(TAG, "canHotSwitch: current=$currentSig, new=$newSig, result=$canSwitch")
        return canSwitch
    }

    /**
     * 检查指定节点是否在当前 selector group �?     *
     * @param nodeTag 节点 tag
     * @return true 如果节点在当�?selector �?outbounds 列表�?     */
    fun isNodeInCurrentSelector(nodeTag: String): Boolean {
        return currentOutboundTags.contains(nodeTag)
    }

    /**
     * 通过 BoxWrapperManager 执行热切�?     *
     * @param outboundTag 目标 outbound �?tag
     * @return true if successful
     */
    fun selectOutbound(outboundTag: String): Boolean {
        return selectOutboundViaWrapper(outboundTag)
    }

    /**
     * 通过 BoxWrapperManager 执行热切�?(主要方案)
     *
     * @param outboundTag 目标 outbound �?tag
     * @return true if successful
     */
    fun selectOutboundViaWrapper(outboundTag: String): Boolean {
        val success = BoxWrapperManager.selectOutbound(outboundTag)
        if (success) {
            _selectedOutbound.value = outboundTag
            Log.i(TAG, "Hot switch via BoxWrapper: -> $outboundTag")
        }
        return success
    }

    /**
     * 获取当前选中�?outbound tag
     */
    fun getSelectedOutbound(): String? = _selectedOutbound.value

    /**
     * 获取当前 selector 的所�?outbound tags
     */
    fun getCurrentOutboundTags(): List<String> = currentOutboundTags

    /**
     * 检查是否有有效�?selector 记录
     */
    fun hasSelector(): Boolean = currentSelectorSignature != null && currentOutboundTags.isNotEmpty()

    /**
     * 清除状态（VPN 停止时调用）
     */
    fun clear() {
        currentSelectorSignature = null
        currentOutboundTags = emptyList()
        _selectedOutbound.value = null
        _canHotSwitch.value = false
        Log.d(TAG, "Selector state cleared")
    }

    /**
     * 计算 outbound tags 列表的签�?     * 使用排序后的 hashCode 确保顺序无关
     */
    private fun computeSignature(tags: List<String>): String {
        return tags.sorted().hashCode().toString()
    }
}







