package com.openworld.app.viewmodel.shared

import android.content.Context
import androidx.lifecycle.ProcessLifecycleOwner
import androidx.lifecycle.lifecycleScope
import com.openworld.app.model.NodeFilter
import com.openworld.app.model.NodeSortType
import com.openworld.app.repository.SettingsRepository
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.stateIn

/**
 * 节点显示设置的共享状态容器
 *
 * DashboardViewModel 和 NodesViewModel 都需要收集 nodeFilter/sortType/customOrder，
 * 这里使用 stateIn 将 Flow 转为 StateFlow 并在多个 ViewModel 间共享，
 * 避免每个 ViewModel 各自启动独立的收集协程造成资源浪费。
 */
class NodeDisplaySettings private constructor(
    settingsRepository: SettingsRepository,
    scope: CoroutineScope
) {
    companion object {
        @Volatile
        private var instance: NodeDisplaySettings? = null

        // 使用 ProcessLifecycleOwner.lifecycleScope，生命周期与应用进程绑定
        // 不再依赖 ViewModel 的 scope，避免 ViewModel 销毁后 StateFlow 停止更新
        fun getInstance(context: Context): NodeDisplaySettings {
            return instance ?: synchronized(this) {
                instance ?: NodeDisplaySettings(
                    SettingsRepository.getInstance(context),
                    ProcessLifecycleOwner.get().lifecycleScope
                ).also { instance = it }
            }
        }

        fun clearInstance() {
            instance = null
        }
    }

    val nodeFilter: StateFlow<NodeFilter> = settingsRepository.getNodeFilterFlow()
        .stateIn(scope, SharingStarted.Eagerly, NodeFilter())

    val sortType: StateFlow<NodeSortType> = settingsRepository.getNodeSortType()
        .stateIn(scope, SharingStarted.Eagerly, NodeSortType.DEFAULT)

    val customOrder: StateFlow<List<String>> = settingsRepository.getCustomNodeOrder()
        .stateIn(scope, SharingStarted.Eagerly, emptyList())
}
