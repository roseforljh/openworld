package com.openworld.app.viewmodel

import com.openworld.app.R
import android.app.Application
import android.content.Context
import android.content.Intent
import android.net.TrafficStats
import android.net.VpnService
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.os.Build
import android.os.Process
import android.os.SystemClock
import android.util.Log
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.openworld.app.model.ConnectionState
import com.openworld.app.model.ConnectionStats
import com.openworld.app.model.AppSettings
import com.openworld.app.model.FilterMode
import com.openworld.app.model.NodeFilter
import com.openworld.app.model.NodeSortType
import com.openworld.app.model.NodeUi
import com.openworld.app.model.ProfileUi
import com.openworld.app.repository.SettingsRepository
import com.openworld.app.ipc.OpenWorldRemote
import com.openworld.app.ipc.VpnStateStore
import com.openworld.app.service.OpenWorldService
import com.openworld.app.service.ServiceState
import com.openworld.app.service.ProxyOnlyService
import com.openworld.app.service.VpnTileService
import com.openworld.app.core.OpenWorldCore
import com.openworld.app.core.BoxWrapperManager
import com.openworld.app.repository.ConfigRepository
import com.openworld.app.viewmodel.shared.NodeDisplaySettings
import kotlinx.coroutines.Job
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.distinctUntilChanged
import kotlinx.coroutines.flow.drop
import kotlinx.coroutines.flow.filter
import kotlinx.coroutines.flow.flatMapLatest
import kotlinx.coroutines.flow.flow
import kotlinx.coroutines.flow.flowOf
import kotlinx.coroutines.flow.filterNotNull
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.TimeoutCancellationException
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.withTimeoutOrNull

class DashboardViewModel(application: Application) : AndroidViewModel(application) {

    companion object {
        private const val TAG = "DashboardViewModel"
    }

    private val configRepository = ConfigRepository.getInstance(application)
    private val settingsRepository = SettingsRepository.getInstance(application)
    private val singBoxCore = OpenWorldCore.getInstance(application)

    // 使用共享的设置状态，�?NodesViewModel 共享同一份数�?    private val displaySettings = NodeDisplaySettings.getInstance(application)

    // Connection state
    private val _connectionState = MutableStateFlow(ConnectionState.Idle)
    val connectionState: StateFlow<ConnectionState> = _connectionState.asStateFlow()

    // Stats
    private val _statsBase = MutableStateFlow(ConnectionStats(0, 0, 0, 0, 0))
    private val _connectedAtElapsedMs = MutableStateFlow<Long?>(null)

    private val durationMsFlow: Flow<Long> = connectionState.flatMapLatest { state ->
        if (state == ConnectionState.Connected) {
            flow {
                while (true) {
                    val start = _connectedAtElapsedMs.value
                    emit(if (start != null) SystemClock.elapsedRealtime() - start else 0L)
                    delay(1000)
                }
            }
        } else {
            flowOf(0L)
        }
    }

    fun setActiveProfile(profileId: String) {
        configRepository.setActiveProfile(profileId)
        val name = profiles.value.find { it.id == profileId }?.name
        if (!name.isNullOrBlank()) {
            viewModelScope.launch {
                val msg = getApplication<Application>().getString(R.string.node_switch_success, name)
                _actionStatus.value = msg
                delay(1500)
                if (_actionStatus.value == msg) {
                    _actionStatus.value = null
                }
            }
        }

        // 2025-fix: 如果VPN正在运行，切换配置后需要触发热切换/重启以加载新配置
        // 否则VPN仍然使用旧配置，导致用户看到"选中"了新配置的节点但实际没网
        if (OpenWorldRemote.isRunning.value || OpenWorldRemote.isStarting.value) {
            viewModelScope.launch {
                // 等待配置切换完成（setActiveProfile 内部可能有异步加载）
                delay(100)
                // 获取新配置的当前选中节点
                val currentNodeId = configRepository.activeNodeId.value
                if (currentNodeId != null) {
                    Log.i(TAG, "Profile switched while VPN running, triggering node switch for: $currentNodeId")
                    configRepository.setActiveNodeWithResult(currentNodeId)
                }
            }
        }
    }

    fun setActiveNode(nodeId: String) {
        // 2025-fix: 先同步更�?activeNodeId，避免竞态条�?        configRepository.setActiveNodeIdOnly(nodeId)

        viewModelScope.launch {
            val node = nodes.value.find { it.id == nodeId }
            val result = configRepository.setActiveNodeWithResult(nodeId)

            if (OpenWorldRemote.isRunning.value && node != null) {
                val msg = when (result) {
                    is ConfigRepository.NodeSwitchResult.Success,
                    is ConfigRepository.NodeSwitchResult.NotRunning -> getApplication<Application>().getString(R.string.node_switch_success, node.name)

                    is ConfigRepository.NodeSwitchResult.Failed ->
                        getApplication<Application>().getString(R.string.node_switch_failed, node.name)
                }
                _actionStatus.value = msg
                delay(1500)
                if (_actionStatus.value == msg) {
                    _actionStatus.value = null
                }
            }
        }
    }

    val stats: StateFlow<ConnectionStats> = combine(_statsBase, durationMsFlow) { base, duration ->
        base.copy(duration = duration)
    }.stateIn(
        scope = viewModelScope,
        started = SharingStarted.WhileSubscribed(5000),
        initialValue = ConnectionStats(0, 0, 0, 0, 0)
    )

    // 当前节点的实时延迟（VPN启动后测得的�?    // null = 未测�? -1 = 测试失败/超时, >0 = 实际延迟
    private val _currentNodePing = MutableStateFlow<Long?>(null)
    val currentNodePing: StateFlow<Long?> = _currentNodePing.asStateFlow()

    // Ping 测试状态：true = 正在测试�?    private val _isPingTesting = MutableStateFlow(false)
    val isPingTesting: StateFlow<Boolean> = _isPingTesting.asStateFlow()

    private var pingTestJob: Job? = null
    private var lastErrorToastJob: Job? = null
    private var startMonitorJob: Job? = null

    // 用于平滑流量显示的缓�?    private var lastUploadSpeed: Long = 0
    private var lastDownloadSpeed: Long = 0

    // Active profile and node from ConfigRepository
    val activeProfileId: StateFlow<String?> = configRepository.activeProfileId
        .stateIn(
            scope = viewModelScope,
            started = SharingStarted.WhileSubscribed(5000),
            initialValue = null
        )

    val activeNodeId: StateFlow<String?> = configRepository.activeNodeId
        .stateIn(
            scope = viewModelScope,
            started = SharingStarted.WhileSubscribed(5000),
            initialValue = null
        )

    val activeNodeLatency = kotlinx.coroutines.flow.combine(configRepository.nodes, activeNodeId) { nodes, id ->
        nodes.find { it.id == id }?.latencyMs
    }.stateIn(
        scope = viewModelScope,
        started = SharingStarted.WhileSubscribed(5000),
        initialValue = null
    )

    val profiles: StateFlow<List<ProfileUi>> = configRepository.profiles
        .stateIn(
            scope = viewModelScope,
            started = SharingStarted.WhileSubscribed(5000),
            initialValue = emptyList()
        )

    val nodes: StateFlow<List<NodeUi>> = combine(
        configRepository.nodes,
        displaySettings.nodeFilter,
        displaySettings.sortType,
        displaySettings.customOrder,
        configRepository.activeNodeId
    ) { nodes: List<NodeUi>, filter: NodeFilter, sortType: NodeSortType, customOrder: List<String>, _ ->
        val filtered = when (filter.filterMode) {
            FilterMode.NONE -> nodes
            FilterMode.INCLUDE -> {
                val keywords = filter.effectiveIncludeKeywords
                if (keywords.isEmpty()) nodes
                else nodes.filter { node -> keywords.any { keyword -> node.displayName.contains(keyword, ignoreCase = true) } }
            }
            FilterMode.EXCLUDE -> {
                val keywords = filter.effectiveExcludeKeywords
                if (keywords.isEmpty()) nodes
                else nodes.filter { node -> keywords.none { keyword -> node.displayName.contains(keyword, ignoreCase = true) } }
            }
        }

        // 应用排序
        val sorted = when (sortType) {
            NodeSortType.DEFAULT -> filtered
            NodeSortType.LATENCY -> filtered.sortedWith(compareBy<NodeUi> {
                val l = it.latencyMs
                // 将未测试(null)和超�?失败(<=0)的节点排到最�?                if (l == null || l <= 0) Long.MAX_VALUE else l
            })
            NodeSortType.NAME -> filtered.sortedBy { it.name }
            NodeSortType.REGION -> filtered.sortedWith(compareBy<NodeUi> {
                getRegionWeight(it.regionFlag)
            }.thenBy { it.name })
            NodeSortType.CUSTOM -> {
                val orderMap = customOrder.withIndex().associate { it.value to it.index }
                filtered.sortedBy { orderMap[it.id] ?: Int.MAX_VALUE }
            }
        }

        sorted
    }.stateIn(
        scope = viewModelScope,
        started = SharingStarted.WhileSubscribed(5000),
        initialValue = emptyList()
    )

    private var trafficSmoothingJob: Job? = null
    private var trafficBaseTxBytes: Long = 0
    private var trafficBaseRxBytes: Long = 0
    private var lastTrafficTxBytes: Long = 0
    private var lastTrafficRxBytes: Long = 0
    private var lastTrafficSampleAtElapsedMs: Long = 0

    // Status
    private val _updateStatus = MutableStateFlow<String?>(null)
    val updateStatus: StateFlow<String?> = _updateStatus.asStateFlow()

    private val _testStatus = MutableStateFlow<String?>(null)
    val testStatus: StateFlow<String?> = _testStatus.asStateFlow()

    private val _actionStatus = MutableStateFlow<String?>(null)
    val actionStatus: StateFlow<String?> = _actionStatus.asStateFlow()

    // VPN 权限请求结果
    private val _vpnPermissionNeeded = MutableStateFlow(false)
    val vpnPermissionNeeded: StateFlow<Boolean> = _vpnPermissionNeeded.asStateFlow()

    // 2025-fix-v12: 用于确保状态监听器只启动一�?    // 使用 @Volatile 保证多线程可见�?    @Volatile private var stateCollectorStarted = false

    // 2025-fix: 标记是否在启动时检测到了系�?VPN
    // 用于过滤 IPC 连接初期的虚�?STOPPED 状�?    private var systemVpnDetectedOnBoot = false

    // 2025-fix: 使用更健壮的 IPC 绑定逻辑
    // 原因: 原来的等待只�?1000ms，在系统负载高时可能不够
    // 改进: 增加重试次数 + 每次重试前先尝试 ensureBound
    init {
        viewModelScope.launch {
            // 第一阶段：确�?IPC 绑定（带重试�?            for (attempt in 1..5) {
                runCatching { OpenWorldRemote.ensureBound(getApplication()) }
                delay(300) // 每次等待 300ms，总共最�?1500ms
                if (OpenWorldRemote.isBound()) {
                    Log.i(TAG, "IPC bound successfully on attempt $attempt")
                    break
                }
                Log.w(TAG, "IPC not bound, attempt $attempt/5")
            }

            // 第二阶段：同步初始状态（�?MMKV 兜底�?            runCatching {
                val context = getApplication<Application>()
                val cm = context.getSystemService(ConnectivityManager::class.java)
                val hasSystemVpn = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                    cm?.allNetworks?.any { network ->
                        val caps = cm.getNetworkCapabilities(network) ?: return@any false
                        caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)
                    } == true
                } else {
                    false
                }

                if (hasSystemVpn) {
                    systemVpnDetectedOnBoot = true
                }

                val persisted = context.getSharedPreferences("vpn_state", Context.MODE_PRIVATE)
                    .getBoolean("vpn_active", false)

                if (!hasSystemVpn && persisted) {
                    VpnTileService.persistVpnState(context, false)
                }

                if (hasSystemVpn && persisted) {
                    _connectionState.value = ConnectionState.Connected
                    _connectedAtElapsedMs.value = SystemClock.elapsedRealtime()
                } else if (!OpenWorldRemote.isStarting.value) {
                    _connectionState.value = ConnectionState.Idle
                }
            }

            // 第三阶段：确保状态收集器启动（关键修复）
            // 原来只在绑定成功后才启动，现在无论绑定是否成功都启动
            // 这样即使 IPC 绑定失败，MMKV 状态也能持续更�?UI
            startStateCollector()
        }

        // Surface service-level startup errors on UI
        viewModelScope.launch {
            OpenWorldRemote.lastError.collect { err ->
                if (!err.isNullOrBlank()) {
                    _testStatus.value = err
                    lastErrorToastJob?.cancel()
                    lastErrorToastJob = viewModelScope.launch {
                        delay(3000)
                        if (_testStatus.value == err) {
                            _testStatus.value = null
                        }
                    }
                }
            }
        }
    }

    /**
     * 2025-fix-v12: 启动状态监听器
     * 确保只在 IPC 绑定完成后调用一�?     * 注意: 现在允许重复调用（幂等），内部会检查是否已启动
     */
    // 2025-fix: 用于处理连接状态变更的防抖 Job
    private var pendingIdleJob: Job? = null
    private var startGraceUntilElapsedMs: Long? = null

    /**
     * 启动状态收集器（幂等方法）
     * 2025-fix-v12: 确保只启动一次，但保证在 init �?refreshState 中都会被调用
     * 关键修复: 使用 synchronized 确保线程安全，同时允许在必要时重新启�?     */
    private fun startStateCollector() {
        // 使用 synchronized 确保只启动一�?        if (stateCollectorStarted) {
            Log.d(TAG, "startStateCollector: already started, skipping")
            return
        }

        synchronized(this) {
            if (stateCollectorStarted) return
            stateCollectorStarted = true
        }

        // 收集�?: 监听 OpenWorldService 状态变�?        val stateFlow = OpenWorldRemote.state
        viewModelScope.launch {
            stateFlow.collect { state ->
                when (state) {
                    ServiceState.RUNNING -> {
                        systemVpnDetectedOnBoot = false
                        setConnectionState(ConnectionState.Connected)
                    }
                    ServiceState.STARTING -> {
                        systemVpnDetectedOnBoot = false
                        setConnectionState(ConnectionState.Connecting)
                    }
                    ServiceState.STOPPING -> {
                        systemVpnDetectedOnBoot = false
                        setConnectionState(ConnectionState.Disconnecting)
                    }
                    ServiceState.STOPPED -> {
                        setConnectionState(ConnectionState.Idle)
                    }
                }
            }
        }

        // 收集�?: 监听服务端节点切换，同步更新主进程的 activeNodeId
        // 解决通知栏切换节点后首页显示旧节点的问题
        viewModelScope.launch {
            OpenWorldRemote.activeLabel
                .filter { it.isNotBlank() }
                .distinctUntilChanged()
                .collect { nodeName ->
                    Log.d(TAG, "activeLabel changed from service: $nodeName")
                    configRepository.syncActiveNodeFromProxySelection(nodeName)
                }
        }

        Log.i(TAG, "startStateCollector: collectors launched")
    }

    /**
     * 统一管理连接状态更新，内置防抖逻辑防止 UI 闪烁
     */
    private fun setConnectionState(newState: ConnectionState) {
        if (newState == ConnectionState.Disconnecting && _connectionState.value == ConnectionState.Connecting) {
            val graceUntil = startGraceUntilElapsedMs
            if (graceUntil != null && SystemClock.elapsedRealtime() < graceUntil) {
                return
            }
        }
        when (newState) {
            ConnectionState.Connected -> {
                // 如果有挂起的"变更为Idle"的任务，立即取消，说明是虚惊一�?                pendingIdleJob?.cancel()
                pendingIdleJob = null
                startGraceUntilElapsedMs = null

                if (_connectionState.value != ConnectionState.Connected) {
                    _connectionState.value = ConnectionState.Connected
                    _connectedAtElapsedMs.value = SystemClock.elapsedRealtime()
                    startTrafficMonitor()
                }
            }
            ConnectionState.Idle -> {
                // 如果当前是已连接，不要立即断开，而是延迟执行
                if (_connectionState.value == ConnectionState.Connected) {
                    // 如果已经在等待断开，不要重复创�?                    if (pendingIdleJob?.isActive == true) return

                    pendingIdleJob = viewModelScope.launch {
                        // 2025-fix-v7: 如果 MMKV 记录 VPN 正在运行，给更长宽限期等 IPC 恢复
                        // 避免 IPC 还在绑定中时误触发断连（�?300ms 延长�?3000ms�?                        val delayTime = when {
                            VpnStateStore.getActive() -> 3000L
                            systemVpnDetectedOnBoot -> 1000L
                            else -> 300L
                        }
                        delay(delayTime)

                        // 宽限期过，再次检�?OpenWorldRemote 状�?                        // 只有当服务端依然坚持�?STOPPED 时，才真正断开 UI
                        if (OpenWorldRemote.state.value == ServiceState.STOPPED) {
                            performDisconnect()
                        }
                        // 宽限期结束，标记失效
                        systemVpnDetectedOnBoot = false
                        pendingIdleJob = null
                    }
                } else if (_connectionState.value == ConnectionState.Connecting) {
                    val graceUntil = startGraceUntilElapsedMs
                    if (graceUntil != null) {
                        val now = SystemClock.elapsedRealtime()
                        val remaining = graceUntil - now
                        if (remaining > 0) {
                            if (pendingIdleJob?.isActive == true) return
                            pendingIdleJob = viewModelScope.launch {
                                delay(remaining)
                                if (OpenWorldRemote.state.value == ServiceState.STOPPED) {
                                    performDisconnect()
                                }
                                pendingIdleJob = null
                            }
                            return
                        }
                    }
                    performDisconnect()
                } else {
                    // 当前不是连接状态，直接更新
                    performDisconnect()
                }
            }
            else -> {
                // 其他状态（Connecting/Disconnecting/Error）直接更�?                pendingIdleJob?.cancel()
                if (newState == ConnectionState.Connecting) {
                    startGraceUntilElapsedMs = SystemClock.elapsedRealtime() + 800L
                } else {
                    startGraceUntilElapsedMs = null
                }
                if (_connectionState.value != newState) {
                    _connectionState.value = newState
                }
            }
        }
    }

    private fun performDisconnect() {
        if (_connectionState.value != ConnectionState.Idle) {
            _connectionState.value = ConnectionState.Idle
            _connectedAtElapsedMs.value = null
            stopTrafficMonitor()
            stopPingTest()
            _statsBase.value = ConnectionStats(0, 0, 0, 0, 0)
            _currentNodePing.value = null
        }
    }

    /**
     * 2025-fix-v12: 刷新 VPN 状�?(三阶段恢�?
     *
     * Phase 1: 即时恢复 (< 1ms)
     * - �?MMKV 读取 VPN 状态，立即更新 UI
     * - 异步验证/重建 IPC（不阻塞，不强制 rebind�?     *
     * Phase 2: 异步精确同步 (后台完成，用户无�?
     * - 等待 IPC 绑定完成
     * - 仅当 AIDL 返回的状态与 MMKV 一致或更可信时才覆�?UI
     * - 如果 IPC 超时未绑定但 MMKV 显示 active，保�?Connected 不回退
     *
     * Phase 3: 强制确保状态收集器启动 (关键修复)
     * - 无论 IPC 是否绑定成功，确�?startStateCollector() 被调�?     * - 防止 init 块超时导致状态监听器永不启动
     */
    fun refreshState() {
        viewModelScope.launch {
            val context = getApplication<Application>()

            // Phase 1: 即时恢复 (< 1ms，从 MMKV 读状�?+ 异步验证 IPC)
            OpenWorldRemote.instantRecovery(context)

            // 立即�?MMKV 状态更�?UI（不�?IPC�?            val isActive = VpnStateStore.getActive()
            val phase1State = when {
                isActive -> ConnectionState.Connected
                OpenWorldRemote.isStarting.value -> ConnectionState.Connecting
                else -> ConnectionState.Idle
            }
            setConnectionState(phase1State)

            // Phase 2: IPC 就绪后精确同步（后台静默完成，用户无感）
            // 2025-fix-v12: 增加等待次数，从 50 次增加到 80 次（总共 8 秒）
            // 原因: 在低性能设备或系统负载高时，IPC 绑定可能需要更长时�?            launch {
                var retries = 0
                val maxRetries = 80 // 80 * 100ms = 8 �?                while (!OpenWorldRemote.isBound() && retries < maxRetries) {
                    delay(100)
                    retries++
                }

                if (OpenWorldRemote.isBound()) {
                    val state = OpenWorldRemote.state.value
                    Log.i(TAG, "refreshState Phase 2: state=$state, bound=true, retries=$retries")
                    when (state) {
                        ServiceState.RUNNING -> setConnectionState(ConnectionState.Connected)
                        ServiceState.STARTING -> setConnectionState(ConnectionState.Connecting)
                        ServiceState.STOPPING -> setConnectionState(ConnectionState.Disconnecting)
                        ServiceState.STOPPED -> {
                            // 关键保护：如�?MMKV 仍然显示 active，说�?AIDL 可能还没同步完成
                            // （刚 rebind �?onServiceConnected 的初始同步可能还没到达）
                            // 此时不要回退�?Idle，等后续回调自然更新
                            if (VpnStateStore.getActive()) {
                                Log.w(
                                    TAG,
                                    "refreshState Phase 2: AIDL says STOPPED but MMKV says active, " +
                                        "keeping Connected (wait for callback)"
                                )
                            } else {
                                setConnectionState(ConnectionState.Idle)
                            }
                        }
                    }
                } else {
                    // IPC 超时未绑定，但如�?MMKV 显示 active，保�?Connected
                    if (isActive) {
                        Log.w(TAG, "refreshState Phase 2: IPC not bound but MMKV active, keeping Connected")
                    } else {
                        Log.w(TAG, "refreshState Phase 2: IPC not bound and MMKV inactive")
                        // 2025-fix-v12: 超时后明确设置为 Idle，避�?UI 卡住
                        setConnectionState(ConnectionState.Idle)
                    }
                }
            }

            // Phase 3: 强制确保状态收集器启动 (关键修复)
            // 无论 IPC 绑定是否成功，都要确�?startStateCollector 被调�?            // 这样即使所有等待都超时，MMKV 状态更新也能正确传递到 UI
            startStateCollector()
        }
    }

    /**
     * 检查系统是否有活跃�?VPN 连接
     */
    private fun checkSystemVpn(context: Context): Boolean {
        return try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                val cm = context.getSystemService(ConnectivityManager::class.java)
                cm?.allNetworks?.any { network ->
                    val caps = cm.getNetworkCapabilities(network) ?: return@any false
                    caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN)
                } == true
            } else {
                false
            }
        } catch (e: Exception) {
            Log.w(TAG, "Failed to check system VPN", e)
            false
        }
    }

    fun toggleConnection() {
        viewModelScope.launch {
            when (_connectionState.value) {
                ConnectionState.Idle, ConnectionState.Error -> {
                    // P0 Optimization: Optimistic UI
                    startGraceUntilElapsedMs = SystemClock.elapsedRealtime() + 800L
                    _connectionState.value = ConnectionState.Connecting
                    startCore()
                }
                ConnectionState.Connecting -> {
                    // P0 Optimization: Optimistic UI
                    startGraceUntilElapsedMs = null
                    _connectionState.value = ConnectionState.Disconnecting
                    stopVpn()
                }
                ConnectionState.Connected, ConnectionState.Disconnecting -> {
                    // P0 Optimization: Optimistic UI
                    startGraceUntilElapsedMs = null
                    _connectionState.value = ConnectionState.Disconnecting
                    stopVpn()
                }
            }
        }
    }

    fun restartVpn() {
        viewModelScope.launch {
            val context = getApplication<Application>()

            val settings = SettingsRepository.getInstance(context).settings.first()
            if (settings.tunEnabled) {
                val prepareIntent = VpnService.prepare(context)
                if (prepareIntent != null) {
                    _vpnPermissionNeeded.value = true
                    return@launch
                }
            }

            val configResult = withContext(Dispatchers.IO) {
                val settingsRepository = SettingsRepository.getInstance(context)
                settingsRepository.checkAndMigrateRuleSets()
                configRepository.generateConfigFile()
            }

            if (configResult == null) {
                _testStatus.value = getApplication<Application>().getString(R.string.dashboard_config_generation_failed)
                delay(2000)
                _testStatus.value = null
                return@launch
            }

            val useTun = settings.tunEnabled
            val perAppSettingsChanged = VpnStateStore.hasPerAppVpnSettingsChanged(
                appMode = settings.vpnAppMode.name,
                allowlist = settings.vpnAllowlist,
                blocklist = settings.vpnBlocklist
            )

            logRestartDebugInfo(settings)

            val tunSettingsChanged = VpnStateStore.hasTunSettingsChanged(
                tunStack = settings.tunStack.name,
                tunMtu = settings.tunMtu,
                autoRoute = settings.autoRoute,
                strictRoute = settings.strictRoute,
                proxyPort = settings.proxyPort
            )

            val requiresFullRestart = perAppSettingsChanged || tunSettingsChanged

            if (useTun && OpenWorldRemote.isRunning.value && !requiresFullRestart) {
                Log.i(TAG, "Settings are hot-reloadable, attempting kernel hot reload")
                if (tryHotReload(configResult.path)) {
                    Log.i(TAG, "Hot reload succeeded, settings applied without VPN reconnection")
                    return@launch
                }
                Log.w(TAG, "Hot reload failed, falling back to full restart")
            } else {
                if (requiresFullRestart) {
                    Log.i(
                        TAG,
                        "Full restart required: perAppChanged=$perAppSettingsChanged, tunChanged=$tunSettingsChanged"
                    )
                }
            }

            performRestart(context, configResult.path, useTun, perAppSettingsChanged)
        }
    }

    private fun logRestartDebugInfo(settings: AppSettings) {
        Log.d(
            TAG,
            "restartVpn: useTun=${settings.tunEnabled}, isRunning=${OpenWorldRemote.isRunning.value}"
        )
        Log.d(
            TAG,
            "restartVpn: currentMode=${settings.vpnAppMode.name}, " +
                "allowlist=${settings.vpnAllowlist.take(100)}, blocklist=${settings.vpnBlocklist.take(100)}"
        )
    }

    private suspend fun tryHotReload(configPath: String): Boolean {
        val configContent = withContext(Dispatchers.IO) {
            runCatching { java.io.File(configPath).readText() }.getOrNull()
        }

        if (!configContent.isNullOrEmpty()) {
            Log.i(TAG, "Attempting kernel hot reload via IPC...")

            val result = withContext(Dispatchers.IO) {
                OpenWorldRemote.hotReloadConfig(configContent)
            }

            when (result) {
                OpenWorldRemote.HotReloadResult.SUCCESS -> {
                    Log.i(TAG, "Hot reload succeeded via IPC")
                    return true
                }
                OpenWorldRemote.HotReloadResult.IPC_ERROR -> {
                    Log.w(TAG, "Hot reload IPC failed, falling back to traditional restart")
                }
                else -> {
                    Log.w(TAG, "Hot reload failed (code=$result), falling back to traditional restart")
                }
            }
        }
        return false
    }

    private suspend fun performRestart(
        context: Context,
        configPath: String,
        useTun: Boolean,
        perAppSettingsChanged: Boolean
    ) {
        if (perAppSettingsChanged && useTun && OpenWorldRemote.isRunning.value) {
            Log.i(TAG, "Per-app settings changed, using full restart to rebuild TUN")
            val intent = Intent(context, OpenWorldService::class.java).apply {
                action = OpenWorldService.ACTION_FULL_RESTART
                putExtra(OpenWorldService.EXTRA_CONFIG_PATH, configPath)
            }
            startServiceCompat(context, intent)
            return
        }

        runCatching {
            if (!com.openworld.app.ipc.VpnStateStore.shouldTriggerPrepareRestart(1500L)) {
                Log.d(TAG, "PREPARE_RESTART suppressed (sender throttle)")
            } else {
                context.startService(Intent(context, OpenWorldService::class.java).apply {
                    action = OpenWorldService.ACTION_PREPARE_RESTART
                    putExtra(
                        OpenWorldService.EXTRA_PREPARE_RESTART_REASON,
                        "DashboardViewModel:restartVpn"
                    )
                })
            }
        }

        delay(150)

        val intent = if (useTun) {
            Intent(context, OpenWorldService::class.java).apply {
                action = OpenWorldService.ACTION_START
                putExtra(OpenWorldService.EXTRA_CONFIG_PATH, configPath)
                putExtra(OpenWorldService.EXTRA_CLEAN_CACHE, true)
            }
        } else {
            Intent(context, ProxyOnlyService::class.java).apply {
                action = ProxyOnlyService.ACTION_START
                putExtra(ProxyOnlyService.EXTRA_CONFIG_PATH, configPath)
                putExtra(OpenWorldService.EXTRA_CLEAN_CACHE, true)
            }
        }

        startServiceCompat(context, intent)
    }

    private fun startServiceCompat(context: Context, intent: Intent) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            context.startForegroundService(intent)
        } else {
            context.startService(intent)
        }
    }

    private fun startCore() {
        viewModelScope.launch {
            val context = getApplication<Application>()

            val settings = runCatching {
                SettingsRepository.getInstance(context).settings.first()
            }.getOrNull()

            val desiredMode = if (settings?.tunEnabled == true) {
                VpnStateStore.CoreMode.VPN
            } else {
                VpnStateStore.CoreMode.PROXY
            }

            if (settings?.tunEnabled == true) {
                val prepareIntent = VpnService.prepare(context)
                if (prepareIntent != null) {
                    _vpnPermissionNeeded.value = true
                    return@launch
                }
            }

            _connectionState.value = ConnectionState.Connecting

            // Ensure only one core instance is running at a time to avoid local port conflicts.
            // Do not rely on VpnStateStore here (multi-process timing); just stop the opposite service.
            val needToStopOpposite = when (desiredMode) {
                VpnStateStore.CoreMode.VPN -> {
                    runCatching {
                        context.startService(Intent(context, ProxyOnlyService::class.java).apply {
                            action = ProxyOnlyService.ACTION_STOP
                        })
                    }
                    true
                }
                VpnStateStore.CoreMode.PROXY -> {
                    runCatching {
                        context.startService(Intent(context, OpenWorldService::class.java).apply {
                            action = OpenWorldService.ACTION_STOP
                        })
                    }
                    true
                }
                else -> false
            }

            // 如果需要停止对立服务，等待其完全停�?            if (needToStopOpposite) {
                // 先检查对立服务是否正在运�?                val oppositeWasRunning = OpenWorldRemote.isRunning.value || OpenWorldRemote.isStarting.value
                if (oppositeWasRunning) {
                    try {
                        // 增加超时时间：BoxService.close() 可能需要较长时间释放端�?                        withTimeout(8000L) {
                            // 使用 drop(1) 跳过当前值，等待真正的状态变�?                            OpenWorldRemote.state
                                .drop(1)
                                .first { it == ServiceState.STOPPED }
                        }
                    } catch (e: TimeoutCancellationException) {
                        Log.w(TAG, "Timeout waiting for opposite service to stop")
                    }
                }
                // 增加缓冲时间：确保端口完全释�?                // 原因: BoxService.close() 后端口释放可能有延迟
                delay(500)
            }

            // 生成配置文件并启�?VPN 服务
            try {
                // 在生成配置前先执行强制迁移，修复可能导致 404 的旧配置
                val configResult = withContext(Dispatchers.IO) {
                    val settingsRepository = com.openworld.app.repository.SettingsRepository.getInstance(context)
                    settingsRepository.checkAndMigrateRuleSets()
                    configRepository.generateConfigFile()
                }
                if (configResult == null) {
                    _connectionState.value = ConnectionState.Error
                    _testStatus.value = getApplication<Application>().getString(R.string.dashboard_config_generation_failed)
                    delay(2000)
                    _testStatus.value = null
                    return@launch
                }

                val useTun = desiredMode == VpnStateStore.CoreMode.VPN
                val intent = if (useTun) {
                    Intent(context, OpenWorldService::class.java).apply {
                        action = OpenWorldService.ACTION_START
                        putExtra(OpenWorldService.EXTRA_CONFIG_PATH, configResult.path)
                        // 从停止状态启动时，强制清理缓存，确保使用配置文件中选中的节�?                        // 修复 bug: App 更新�?cache.db 保留了旧的选中节点，导�?UI 上选中的新节点无效
                        putExtra(OpenWorldService.EXTRA_CLEAN_CACHE, true)
                    }
                } else {
                    Intent(context, ProxyOnlyService::class.java).apply {
                        action = ProxyOnlyService.ACTION_START
                        putExtra(ProxyOnlyService.EXTRA_CONFIG_PATH, configResult.path)
                        // 同理，Proxy 模式也需要清理缓�?                        putExtra(OpenWorldService.EXTRA_CLEAN_CACHE, true)
                    }
                }
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                    context.startForegroundService(intent)
                } else {
                    context.startService(intent)
                }

                // 1) 1000ms 内给出反馈：仍未 running 则提示“启动中”，但不判失�?                // 2) 后续只在服务端明确失败（lastErrorFlow）或服务异常退出时才置 Error
                startMonitorJob?.cancel()
                startMonitorJob = viewModelScope.launch {
                    val startTime = System.currentTimeMillis()
                    val quickFeedbackMs = 1000L
                    var showedStartingHint = false

                    while (true) {
                        if (OpenWorldRemote.isRunning.value) {
                            _connectionState.value = ConnectionState.Connected
                            startTrafficMonitor()
                            return@launch
                        }

                        val err = OpenWorldRemote.lastError.value
                        if (!err.isNullOrBlank()) {
                            _connectionState.value = ConnectionState.Error
                            _testStatus.value = err
                            delay(3000)
                            _testStatus.value = null
                            return@launch
                        }

                        val elapsed = System.currentTimeMillis() - startTime
                        if (!showedStartingHint && elapsed >= quickFeedbackMs) {
                            showedStartingHint = true
                            _testStatus.value = getApplication<Application>().getString(R.string.connection_connecting)
                            lastErrorToastJob?.cancel()
                            lastErrorToastJob = viewModelScope.launch {
                                delay(1200)
                                if (_testStatus.value == getApplication<Application>().getString(R.string.connection_connecting)) {
                                    _testStatus.value = null
                                }
                            }
                        }

                        val intervalMs = when {
                            elapsed < 10_000L -> 200L
                            elapsed < 60_000L -> 1000L
                            else -> 5000L
                        }
                        delay(intervalMs)
                    }
                }
            } catch (e: Exception) {
                _connectionState.value = ConnectionState.Error
                _testStatus.value = getApplication<Application>().getString(R.string.node_start_failed, e.message ?: "")
                delay(2000)
                _testStatus.value = null
            }
        }
    }

    private fun stopVpn() {
        val context = getApplication<Application>()
        startMonitorJob?.cancel()
        startMonitorJob = null
        stopTrafficMonitor()
        stopPingTest()
        // Immediately set to Idle for responsive UI
        _connectionState.value = ConnectionState.Idle
        _connectedAtElapsedMs.value = null
        _statsBase.value = ConnectionStats(0, 0, 0, 0, 0)
        _currentNodePing.value = null

        val mode = VpnStateStore.getMode()
        val intent = when (mode) {
            VpnStateStore.CoreMode.PROXY -> Intent(context, ProxyOnlyService::class.java).apply {
                action = ProxyOnlyService.ACTION_STOP
            }
            else -> Intent(context, OpenWorldService::class.java).apply {
                action = OpenWorldService.ACTION_STOP
            }
        }
        context.startService(intent)
    }

    /**
     * 启动当前节点的延迟测�?     * 使用5秒超时限制，测不出来就终止并显示超时状�?     */
    private fun startPingTest() {
        // Prevent redundant testing if we already have a valid ping result
        // This stops the test from re-running every time the dashboard is opened/recomposed
        // UNLESS the ping is currently null (not tested) or being manually refreshed
        if (_connectionState.value == ConnectionState.Connected &&
            _currentNodePing.value != null &&
            _currentNodePing.value != -1L &&
            !_isPingTesting.value) {
            return
        }

        stopPingTest()

        _isPingTesting.value = true
        // Only clear current ping if we are manually retesting or it was failed/null.
        // If it was valid, keep showing old value until new one arrives?
        // No, UI usually shows spinner. Let's clear to indicate "refreshing".
        _currentNodePing.value = null

        pingTestJob = viewModelScope.launch {
            try {
                // 设置测试中状�?                _isPingTesting.value = true
                _currentNodePing.value = null

                // 等待一小段时间确保 VPN 完全启动
                delay(1000)

                // 检�?VPN 是否还在运行
                if (_connectionState.value != ConnectionState.Connected) {
                    _isPingTesting.value = false
                    return@launch
                }

                val activeNodeId = activeNodeId.value ?: withTimeoutOrNull(1500L) {
                    this@DashboardViewModel.activeNodeId.filterNotNull().first()
                }
                if (activeNodeId.isNullOrBlank()) {
                    Log.w(TAG, "No active node to test ping")
                    _isPingTesting.value = false
                    _currentNodePing.value = -1L // 标记为失�?                    return@launch
                }

                val nodeName = configRepository.getNodeById(activeNodeId)?.name
                if (nodeName == null) {
                    Log.w(TAG, "Node name not found for id: $activeNodeId")
                    _isPingTesting.value = false
                    _currentNodePing.value = -1L // 标记为失�?                    return@launch
                }

                // 使用5秒超时包装整个测试过�?                val delay = configRepository.testNodeLatency(activeNodeId)

                // 测试完成，更新状�?                _isPingTesting.value = false

                // 再次检�?VPN 是否还在运行（测试可能需要一些时间）
                if (_connectionState.value == ConnectionState.Connected && pingTestJob?.isActive == true) {
                    if (delay != null && delay > 0) {
                        _currentNodePing.value = delay
                    } else {
                        // 超时或失败，设置�?-1 表示超时
                        _currentNodePing.value = -1L
                        Log.w(TAG, "Ping test failed or timed out")
                    }
                }
            } catch (e: Exception) {
                Log.e(TAG, "Error during ping test", e)
                _isPingTesting.value = false
                _currentNodePing.value = -1L // 标记为失�?            }
        }
    }

    /**
     * 停止延迟测试
     */
    private fun stopPingTest() {
        pingTestJob?.cancel()
        pingTestJob = null
        _isPingTesting.value = false
    }

    fun retestCurrentNodePing() {
        if (_connectionState.value != ConnectionState.Connected) return
        if (_isPingTesting.value) return
        // Force test by clearing previous value to bypass the check in startPingTest
        _currentNodePing.value = null
        startPingTest()
    }

    fun onVpnPermissionResult(granted: Boolean) {
        _vpnPermissionNeeded.value = false
        if (granted) {
            startCore()
        }
    }

    fun updateAllSubscriptions() {
        viewModelScope.launch {
            _updateStatus.value = getApplication<Application>().getString(R.string.common_loading)

            val result = configRepository.updateAllProfiles()

            // 根据结果显示不同的提�?            _updateStatus.value = result.toDisplayMessage(getApplication())
            delay(2500)
            _updateStatus.value = null
        }
    }

    fun testAllNodesLatency() {
        viewModelScope.launch {
            _testStatus.value = getApplication<Application>().getString(R.string.common_loading)
            val targetIds = nodes.value.map { it.id }
            configRepository.testAllNodesLatency(targetIds)
            _testStatus.value = getApplication<Application>().getString(R.string.dashboard_test_complete)
            delay(2000)
            _testStatus.value = null
        }
    }

    private fun startTrafficMonitor() {
        stopTrafficMonitor()

        // 重置平滑缓存
        lastUploadSpeed = 0
        lastDownloadSpeed = 0

        val uid = Process.myUid()
        val tx0 = TrafficStats.getUidTxBytes(uid).let { if (it > 0) it else 0L }
        val rx0 = TrafficStats.getUidRxBytes(uid).let { if (it > 0) it else 0L }
        trafficBaseTxBytes = tx0
        trafficBaseRxBytes = rx0
        lastTrafficTxBytes = tx0
        lastTrafficRxBytes = rx0
        lastTrafficSampleAtElapsedMs = SystemClock.elapsedRealtime()

        // 记录 BoxWrapper 初始流量�?(用于计算本次会话流量)
        wrapperBaseUpload = BoxWrapperManager.getUploadTotal().let { if (it >= 0) it else 0L }
        wrapperBaseDownload = BoxWrapperManager.getDownloadTotal().let { if (it >= 0) it else 0L }

        trafficSmoothingJob = viewModelScope.launch(Dispatchers.Default) {
            while (true) {
                delay(1000)

                val nowElapsed = SystemClock.elapsedRealtime()

                // 双源流量统计: 优先使用 BoxWrapper (内核�?, 回退�?TrafficStats (系统�?
                val (tx, rx, totalTx, totalRx) = if (BoxWrapperManager.isAvailable()) {
                    // 使用 BoxWrapper 内核级流量统�?(更准�?
                    val wrapperUp = BoxWrapperManager.getUploadTotal()
                    val wrapperDown = BoxWrapperManager.getDownloadTotal()
                    if (wrapperUp >= 0 && wrapperDown >= 0) {
                        // 计算本次会话流量
                        val sessionUp = (wrapperUp - wrapperBaseUpload).coerceAtLeast(0L)
                        val sessionDown = (wrapperDown - wrapperBaseDownload).coerceAtLeast(0L)
                        Quadruple(wrapperUp, wrapperDown, sessionUp, sessionDown)
                    } else {
                        // BoxWrapper 返回无效值，回退�?TrafficStats
                        val sysTx = TrafficStats.getUidTxBytes(uid).let { if (it > 0) it else 0L }
                        val sysRx = TrafficStats.getUidRxBytes(uid).let { if (it > 0) it else 0L }
                        Quadruple(sysTx, sysRx, (sysTx - trafficBaseTxBytes).coerceAtLeast(0L), (sysRx - trafficBaseRxBytes).coerceAtLeast(0L))
                    }
                } else {
                    // BoxWrapper 不可用，使用 TrafficStats
                    val sysTx = TrafficStats.getUidTxBytes(uid).let { if (it > 0) it else 0L }
                    val sysRx = TrafficStats.getUidRxBytes(uid).let { if (it > 0) it else 0L }
                    Quadruple(sysTx, sysRx, (sysTx - trafficBaseTxBytes).coerceAtLeast(0L), (sysRx - trafficBaseRxBytes).coerceAtLeast(0L))
                }

                val dtMs = (nowElapsed - lastTrafficSampleAtElapsedMs).coerceAtLeast(1L)
                val dTx = (tx - lastTrafficTxBytes).coerceAtLeast(0L)
                val dRx = (rx - lastTrafficRxBytes).coerceAtLeast(0L)

                val up = (dTx * 1000L) / dtMs
                val down = (dRx * 1000L) / dtMs

                // 优化: 使用自适应平滑因子，根据速度变化幅度动态调�?                // 优势: 大幅变化时快速响�?小幅变化时平滑显示，兼顾响应性和稳定�?                val uploadSmoothFactor = calculateAdaptiveSmoothFactor(up, lastUploadSpeed)
                val downloadSmoothFactor = calculateAdaptiveSmoothFactor(down, lastDownloadSpeed)

                val smoothedUp = if (lastUploadSpeed == 0L) up
                else (lastUploadSpeed * (1 - uploadSmoothFactor) + up * uploadSmoothFactor).toLong()
                val smoothedDown = if (lastDownloadSpeed == 0L) down
                else (lastDownloadSpeed * (1 - downloadSmoothFactor) + down * downloadSmoothFactor).toLong()

                lastUploadSpeed = smoothedUp
                lastDownloadSpeed = smoothedDown

                _statsBase.update { current ->
                    current.copy(
                        uploadSpeed = smoothedUp,
                        downloadSpeed = smoothedDown,
                        uploadTotal = totalTx,
                        downloadTotal = totalRx
                    )
                }

                lastTrafficTxBytes = tx
                lastTrafficRxBytes = rx
                lastTrafficSampleAtElapsedMs = nowElapsed
            }
        }
    }

    // 用于双源流量统计的辅助数据类
    private data class Quadruple(val tx: Long, val rx: Long, val totalTx: Long, val totalRx: Long)

    // BoxWrapper 流量基准�?(用于计算本次会话流量)
    private var wrapperBaseUpload: Long = 0
    private var wrapperBaseDownload: Long = 0

    private fun stopTrafficMonitor() {
        trafficSmoothingJob?.cancel()
        trafficSmoothingJob = null
        lastUploadSpeed = 0
        lastDownloadSpeed = 0
        trafficBaseTxBytes = 0
        trafficBaseRxBytes = 0
        lastTrafficTxBytes = 0
        lastTrafficRxBytes = 0
        lastTrafficSampleAtElapsedMs = 0
        wrapperBaseUpload = 0
        wrapperBaseDownload = 0
    }

    /**
     * 计算自适应平滑因子
     * @param current 当前速度
     * @param previous 上一次速度
     * @return 平滑因子 (0.0-1.0),值越大响应越�?     */
    private fun calculateAdaptiveSmoothFactor(current: Long, previous: Long): Double {
        // 处理零值情�?        if (previous <= 0) return 1.0

        // 计算变化幅度比例
        val change = kotlin.math.abs(current - previous).toDouble()
        val ratio = change / previous

        // 根据变化幅度返回不同的平滑因�?        return when {
            ratio > 2.0 -> 0.7 // 大幅变化(200%+),快速响�?            ratio > 0.5 -> 0.4 // 中等变化(50%-200%),平衡响应
            ratio > 0.1 -> 0.25 // 小幅变化(10%-50%),适度平滑
            else -> 0.15 // 微小变化(<10%),高度平滑
        }
    }

    private fun getRegionWeight(flag: String?): Int {
        if (flag.isNullOrBlank()) return 9999
        // Priority order: CN, HK, MO, TW, JP, KR, SG, US, Others
        return when (flag) {
            "🇨🇳" -> 0 // China
            "🇭🇰" -> 1 // Hong Kong
            "🇲🇴" -> 2 // Macau
            "🇹🇼" -> 3 // Taiwan
            "🇯🇵" -> 4 // Japan
            "🇰🇷" -> 5 // South Korea
            "🇸🇬" -> 6 // Singapore
            "🇺🇸" -> 7 // USA
            "🇻🇳" -> 8 // Vietnam
            "🇹🇭" -> 9 // Thailand
            "🇵🇭" -> 10 // Philippines
            "🇲🇾" -> 11 // Malaysia
            "🇮🇩" -> 12 // Indonesia
            "🇮🇳" -> 13 // India
            "🇷🇺" -> 14 // Russia
            "🇹🇷" -> 15 // Turkey
            "🇮🇹" -> 16 // Italy
            "🇩🇪" -> 17 // Germany
            "🇫🇷" -> 18 // France
            "🇳🇱" -> 19 // Netherlands
            "🇬🇧" -> 20 // UK
            "🇦🇺" -> 21 // Australia
            "🇨🇦" -> 22 // Canada
            "🇧🇷" -> 23 // Brazil
            "🇦🇷" -> 24 // Argentina
            else -> 1000 // Others
        }
    }

    /**
     * 获取活跃配置的名�?     */
    fun getActiveProfileName(): String? {
        val activeId = activeProfileId.value ?: return null
        return profiles.value.find { it.id == activeId }?.name
    }

    /**
     * 获取活跃节点的名�?     * 使用改进�?getNodeById 方法确保即使配置切换或节点列表未完全加载时也能正确显�?     */
    fun getActiveNodeName(): String? {
        val activeId = activeNodeId.value ?: return null
        return configRepository.getNodeById(activeId)?.displayName
    }

    override fun onCleared() {
        super.onCleared()
        startMonitorJob?.cancel()
        startMonitorJob = null
        stopTrafficMonitor()
        stopPingTest()
    }
}







