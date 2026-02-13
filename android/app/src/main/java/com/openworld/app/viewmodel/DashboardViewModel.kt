package com.openworld.app.viewmodel

import android.app.Application
import android.net.VpnService
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.openworld.app.config.ConfigManager
import com.openworld.app.repository.CoreRepository
import com.openworld.app.service.OpenWorldVpnService
import com.openworld.core.OpenWorldCore
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch

class DashboardViewModel(app: Application) : AndroidViewModel(app) {

    data class UiState(
        val connected: Boolean = false,
        val connecting: Boolean = false,
        val mode: String = "rule",
        val uploadRate: Long = 0,
        val downloadRate: Long = 0,
        val totalUpload: Long = 0,
        val totalDownload: Long = 0,
        val connectionCount: Int = 0,
        val ping: Int = -1,
        val coreVersion: String = "",
        // 配置
        val profiles: List<String> = emptyList(),
        val activeProfile: String = "default",
        // 节点
        val groups: List<CoreRepository.ProxyGroup> = emptyList(),
        val activeNodeTag: String = "",
        // 操作状态
        val updatingSubscription: Boolean = false,
        val testingLatency: Boolean = false
    )

    private val _state = MutableStateFlow(UiState())
    val state: StateFlow<UiState> = _state.asStateFlow()

    private val _vpnPermissionNeeded = MutableStateFlow(false)
    val vpnPermissionNeeded: StateFlow<Boolean> = _vpnPermissionNeeded.asStateFlow()

    private val _toastEvent = MutableSharedFlow<String>(extraBufferCapacity = 1)
    val toastEvent: SharedFlow<String> = _toastEvent.asSharedFlow()

    init {
        loadProfiles()
        loadGroups()
        startPolling()
        viewModelScope.launch(Dispatchers.IO) {
            try {
                _state.value = _state.value.copy(coreVersion = OpenWorldCore.version())
            } catch (_: Exception) {}
        }
    }

    // ── 连接控制 ──

    fun toggleConnection() {
        val ctx = getApplication<Application>()
        if (_state.value.connected) {
            OpenWorldVpnService.stop(ctx)
            _state.value = _state.value.copy(connected = false, connecting = false)
        } else {
            val intent = VpnService.prepare(ctx)
            if (intent != null) {
                _vpnPermissionNeeded.value = true
                return
            }
            _state.value = _state.value.copy(connecting = true)
            OpenWorldVpnService.start(ctx)
        }
    }

    fun onVpnPermissionGranted() {
        _vpnPermissionNeeded.value = false
        val ctx = getApplication<Application>()
        _state.value = _state.value.copy(connecting = true)
        OpenWorldVpnService.start(ctx)
    }

    fun onVpnPermissionDenied() {
        _vpnPermissionNeeded.value = false
    }

    // ── 模式切换 ──

    fun setMode(mode: String) {
        viewModelScope.launch(Dispatchers.IO) {
            try {
                OpenWorldCore.setClashMode(mode)
                ConfigManager.setRoutingMode(getApplication(), mode)
                _state.value = _state.value.copy(mode = mode)
            } catch (e: Exception) {
                _toastEvent.tryEmit("模式切换失败: ${e.message}")
            }
        }
    }

    // ── 配置管理 ──

    fun loadProfiles() {
        viewModelScope.launch(Dispatchers.IO) {
            val ctx = getApplication<Application>()
            val profiles = ConfigManager.listProfiles(ctx)
            val active = ConfigManager.getActiveProfile(ctx)
            _state.value = _state.value.copy(
                profiles = profiles,
                activeProfile = active
            )
        }
    }

    fun setActiveProfile(name: String) {
        viewModelScope.launch(Dispatchers.IO) {
            ConfigManager.setActiveProfile(getApplication(), name)
            _state.value = _state.value.copy(activeProfile = name)
            _toastEvent.tryEmit("已切换配置: $name")
        }
    }

    // ── 节点管理 ──

    fun loadGroups() {
        viewModelScope.launch(Dispatchers.IO) {
            val groups = CoreRepository.getProxyGroups()
            val activeTag = groups.firstOrNull()?.selected ?: ""
            _state.value = _state.value.copy(
                groups = groups,
                activeNodeTag = activeTag
            )
        }
    }

    fun setActiveNode(groupName: String, nodeName: String) {
        viewModelScope.launch(Dispatchers.IO) {
            try {
                OpenWorldCore.setGroupSelected(groupName, nodeName)
                _state.value = _state.value.copy(activeNodeTag = nodeName)
                loadGroups()
                _toastEvent.tryEmit("已切换节点: $nodeName")
            } catch (e: Exception) {
                _toastEvent.tryEmit("切换节点失败: ${e.message}")
            }
        }
    }

    // ── 批量操作 ──

    fun updateAllSubscriptions() {
        viewModelScope.launch(Dispatchers.IO) {
            _state.value = _state.value.copy(updatingSubscription = true)
            try {
                // 遍历配置文件，尝试更新订阅
                val ctx = getApplication<Application>()
                val profiles = ConfigManager.listProfiles(ctx)
                var updated = 0
                for (name in profiles) {
                    try {
                        val content = ConfigManager.loadProfile(ctx, name)
                        if (content != null && content.contains("subscription_url")) {
                            // 有订阅 URL 的配置才尝试更新
                            updated++
                        }
                    } catch (_: Exception) {}
                }
                _toastEvent.tryEmit("订阅更新完成")
            } catch (e: Exception) {
                _toastEvent.tryEmit("订阅更新失败: ${e.message}")
            } finally {
                _state.value = _state.value.copy(updatingSubscription = false)
                loadProfiles()
            }
        }
    }

    fun testAllNodesLatency() {
        viewModelScope.launch(Dispatchers.IO) {
            _state.value = _state.value.copy(testingLatency = true)
            try {
                val groups = CoreRepository.getProxyGroups()
                for (group in groups) {
                    CoreRepository.testGroupDelay(
                        group.name,
                        "https://www.gstatic.com/generate_204",
                        5000
                    )
                }
                _toastEvent.tryEmit("全部测速完成")
            } catch (e: Exception) {
                _toastEvent.tryEmit("测速失败: ${e.message}")
            } finally {
                _state.value = _state.value.copy(testingLatency = false)
                loadGroups()
            }
        }
    }

    // ── 轮询 ──

    private fun startPolling() {
        viewModelScope.launch(Dispatchers.IO) {
            while (isActive) {
                val running = try { OpenWorldCore.isRunning() } catch (_: Exception) { false }
                val rate = CoreRepository.pollTrafficRate()
                val status = CoreRepository.getStatus()

                _state.value = _state.value.copy(
                    connected = running,
                    connecting = if (running) false else _state.value.connecting,
                    mode = status.mode,
                    uploadRate = rate.up_rate,
                    downloadRate = rate.down_rate,
                    totalUpload = rate.total_up,
                    totalDownload = rate.total_down,
                    connectionCount = status.connections
                )
                delay(1000)
            }
        }
    }
}
