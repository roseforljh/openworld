package com.openworld.app.service.manager

import android.content.Context
import android.content.Intent
import android.util.Log
import com.openworld.app.ipc.VpnStateStore
import com.openworld.app.repository.ConfigRepository
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.launch

/**
 * 节点切换管理�? * 负责热切换和下一节点切换逻辑
 */
class NodeSwitchManager(
    private val context: Context,
    private val serviceScope: CoroutineScope
) {
    companion object {
        private const val TAG = "NodeSwitchManager"
        private const val SWITCH_DEBOUNCE_MS = 800L // 防抖间隔
    }

    // 防抖：上次切换时间戳
    @Volatile
    private var lastSwitchTimeMs: Long = 0

    // 防抖：是否正在切换中
    @Volatile
    private var isSwitching: Boolean = false

    interface Callbacks {
        val isRunning: Boolean
        suspend fun hotSwitchNode(nodeTag: String): Boolean
        fun getConfigPath(): String
        fun setRealTimeNodeName(name: String?)
        fun requestNotificationUpdate(force: Boolean)
        fun notifyRemoteStateUpdate(force: Boolean)
        fun startServiceIntent(intent: Intent)
    }

    private var callbacks: Callbacks? = null

    fun init(callbacks: Callbacks) {
        this.callbacks = callbacks
    }

    /**
     * 执行热切�?     */
    fun performHotSwitch(
        nodeId: String,
        outboundTag: String?,
        serviceClass: Class<*>,
        actionStart: String,
        extraConfigPath: String
    ) {
        serviceScope.launch {
            val configRepository = ConfigRepository.getInstance(context)
            val node = configRepository.getNodeById(nodeId)

            val nodeTag = outboundTag ?: node?.name

            if (nodeTag == null) {
                Log.w(TAG, "Hot switch failed: node not found $nodeId and no outboundTag provided")
                return@launch
            }

            val success = callbacks?.hotSwitchNode(nodeTag) == true

            if (success) {
                Log.i(TAG, "Hot switch successful for $nodeTag")
                val displayName = node?.name ?: nodeTag
                // 2025-fix: 持久�?activeLabel �?VpnStateStore，确保跨进程/重启后通知栏显示正�?                VpnStateStore.setActiveLabel(displayName)
                callbacks?.setRealTimeNodeName(displayName)
                runCatching { configRepository.syncActiveNodeFromProxySelection(displayName) }
                callbacks?.requestNotificationUpdate(force = false)
                callbacks?.notifyRemoteStateUpdate(force = true)
            } else {
                Log.w(TAG, "Hot switch failed for $nodeTag, falling back to restart")
                val configPath = callbacks?.getConfigPath() ?: return@launch
                val restartIntent = Intent(context, serviceClass).apply {
                    action = actionStart
                    putExtra(extraConfigPath, configPath)
                }
                callbacks?.startServiceIntent(restartIntent)
            }
        }
    }

    /**
     * 切换到下一个节�?     * 优化：直接使用内存中的节点列表，先执行切换再异步更新状�?     */
    fun switchNextNode(
        serviceClass: Class<*>,
        actionStart: String,
        extraConfigPath: String
    ) {
        if (callbacks?.isRunning != true) {
            Log.w(TAG, "switchNextNode: VPN not running, skip")
            return
        }

        // 防抖检查：如果正在切换中或距离上次切换时间太短，忽略请�?        val now = System.currentTimeMillis()
        if (isSwitching) {
            Log.d(TAG, "switchNextNode: already switching, ignored")
            return
        }
        if (now - lastSwitchTimeMs < SWITCH_DEBOUNCE_MS) {
            Log.d(TAG, "switchNextNode: debounce, ignored (${now - lastSwitchTimeMs}ms < ${SWITCH_DEBOUNCE_MS}ms)")
            return
        }

        // 同步获取节点信息（从内存），避免协程切换开销
        val configRepository = ConfigRepository.getInstance(context)
        val nodes = configRepository.nodes.value
        if (nodes.isEmpty()) {
            Log.w(TAG, "switchNextNode: no nodes available")
            return
        }

        val activeNodeId = configRepository.activeNodeId.value
        val currentIndex = nodes.indexOfFirst { it.id == activeNodeId }
        val nextIndex = (currentIndex + 1) % nodes.size
        val nextNode = nodes[nextIndex]

        Log.i(TAG, "switchNextNode: switching from ${nodes.getOrNull(currentIndex)?.name} to ${nextNode.name}")

        isSwitching = true
        lastSwitchTimeMs = now

        serviceScope.launch {
            try {
                val success = callbacks?.hotSwitchNode(nextNode.name) == true
                if (success) {
                    // 2025-fix: 持久�?activeLabel �?VpnStateStore，确保跨进程/重启后通知栏显示正�?                    VpnStateStore.setActiveLabel(nextNode.name)
                    callbacks?.setRealTimeNodeName(nextNode.name)
                    callbacks?.requestNotificationUpdate(force = true)
                    callbacks?.notifyRemoteStateUpdate(force = true)
                    // 异步更新持久化状态，不阻塞切�?                    runCatching {
                        configRepository.setActiveNodeIdOnly(nextNode.id)
                        configRepository.syncActiveNodeFromProxySelection(nextNode.name)
                    }
                    Log.i(TAG, "switchNextNode: hot switch successful")
                } else {
                    Log.w(TAG, "switchNextNode: hot switch failed, falling back to restart")
                    val configPath = callbacks?.getConfigPath() ?: return@launch
                    val restartIntent = Intent(context, serviceClass).apply {
                        action = actionStart
                        putExtra(extraConfigPath, configPath)
                    }
                    callbacks?.startServiceIntent(restartIntent)
                }
            } finally {
                isSwitching = false
            }
        }
    }

    fun cleanup() {
        callbacks = null
    }
}







