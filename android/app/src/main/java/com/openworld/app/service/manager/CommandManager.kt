package com.openworld.app.service.manager

import android.app.NotificationManager
import android.content.Context
import android.os.SystemClock
import android.util.Log
import com.openworld.app.core.BoxWrapperManager
import com.openworld.app.core.bridge.*
import com.openworld.app.ipc.VpnStateStore
import com.openworld.app.repository.ConfigRepository
import com.openworld.app.repository.LogRepository
import com.openworld.app.repository.TrafficRepository
import com.openworld.app.service.notification.VpnNotificationManager
import kotlinx.coroutines.*
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.util.concurrent.ConcurrentHashMap

/**
 * Command Server/Client 管理�? * 负责�?libbox 的命令交互，包括�? * - 日志收集
 * - 状态监�? * - 连接追踪
 * - 节点组管�? *
 * libbox v1.12.20 API:
 * - BoxService 通过 Libbox.newService(configContent, platformInterface) 创建
 * - BoxService.start() 启动服务
 * - BoxService.close() 关闭服务
 * - CommandServer 通过 Libbox.newCommandServer(handler, maxLines) 创建
 * - CommandServer.setService(boxService) 关联服务
 */
@Suppress("TooManyFunctions")
class CommandManager(
    private val context: Context,
    private val serviceScope: CoroutineScope
) {
    companion object {
        private const val TAG = "CommandManager"
        private const val MAX_LOG_LINES = 300
        private const val PORT_RELEASE_TIMEOUT_MS = 10000L
        private const val PORT_CHECK_INTERVAL_MS = 50L
    }

    // Command Server/Client
    private var commandServer: CommandServer? = null
    private var boxService: BoxService? = null
    private var commandClient: CommandClient? = null
    private var commandClientGroup: CommandClient? = null
    private var commandClientLogs: CommandClient? = null
    private var commandClientConnections: CommandClient? = null

    // 2025-fix: 保持 handler 引用，防止被 GC 回收导致 gomobile 引用失效
    @Volatile
    private var clientHandler: CommandClientHandler? = null

    @Volatile
    private var isNonEssentialSuspended: Boolean = false

    // 状�?    private val groupSelectedOutbounds = ConcurrentHashMap<String, String>()
    @Volatile var realTimeNodeName: String? = null
        private set
    @Volatile var activeConnectionNode: String? = null
        private set
    @Volatile var activeConnectionLabel: String? = null
        private set
    var recentConnectionIds: List<String> = emptyList()
        private set

    // URL 测试相关状�?    private val urlTestResults = ConcurrentHashMap<String, Int>() // tag -> delay (ms)
    private val urlTestMutex = Mutex()
    @Volatile private var pendingUrlTestGroupTag: String? = null
    @Volatile private var urlTestCompletionCallback: ((Map<String, Int>) -> Unit)? = null

    // 流量统计
    private var lastUplinkTotal: Long = 0
    private var lastDownlinkTotal: Long = 0
    private var lastSpeedUpdateTime: Long = 0L
    private var lastConnectionsLabelLogged: String? = null

    /**
     * 回调接口
     */
    interface Callbacks {
        fun requestNotificationUpdate(force: Boolean)
        fun resolveEgressNodeName(tagOrSelector: String?): String?
        fun onServiceStop(): Unit
        fun onServiceReload(): Unit
    }

    private var callbacks: Callbacks? = null

    fun init(callbacks: Callbacks) {
        this.callbacks = callbacks
    }

    /**
     * 创建 CommandServer 并启动服�?     */
    @Suppress("UNUSED_PARAMETER")
    fun createServer(platformInterface: PlatformInterface): Result<CommandServer> = runCatching {
        val serverHandler = object : CommandServerHandler {
            override fun postServiceClose() {
                Log.i(TAG, "postServiceClose requested")
                callbacks?.onServiceStop()
            }

            override fun serviceReload() {
                Log.i(TAG, "serviceReload requested")
                callbacks?.onServiceReload()
            }

            override fun getSystemProxyStatus(): SystemProxyStatus? = null

            override fun setSystemProxyEnabled(isEnabled: Boolean) {}
        }

        // 创建 CommandServer (v1.12.20 API: newCommandServer(handler, maxLines))
        val server = Libbox.newCommandServer(serverHandler, MAX_LOG_LINES)
        commandServer = server
        Log.i(TAG, "CommandServer created")
        server
    }

    /**
     * 启动 CommandServer
     */
    fun startServer(): Result<Unit> = runCatching {
        commandServer?.start() ?: throw IllegalStateException("CommandServer not created")
        Log.i(TAG, "CommandServer started")

        // 初始�?BoxWrapperManager
        commandServer?.let { server ->
            BoxWrapperManager.init(server)
        }
    }

    /**
     * 启动服务配置 (v1.12.20: 使用 BoxService)
     */
    fun startService(configContent: String, platformInterface: PlatformInterface): Result<Unit> = runCatching {
        // 创建并启�?BoxService
        val service = Libbox.newService(configContent, platformInterface)
        service.start()
        boxService = service

        // 关联�?CommandServer
        commandServer?.setService(service)
        Log.i(TAG, "BoxService started and linked to CommandServer")
    }

    /**
     * 关闭服务
     */
    fun closeService(): Result<Unit> = runCatching {
        boxService?.close()
        boxService = null
        Log.i(TAG, "BoxService closed")
    }

    /**
     * 获取 BoxService
     */
    fun getBoxService(): BoxService? = boxService

    /**
     * 启动 Command Clients
     */
    fun startClients(): Result<Unit> = runCatching {
        // 2025-fix: 存储 handler 到类字段，防止被 GC 回收
        val handler = createClientHandler()
        clientHandler = handler

        // 启动 CommandClient (Status + Group)
        // v1.12.20: 需要订�?Group 命令才能接收 URL 测试结果
        val optionsStatus = CommandClientOptions()
        optionsStatus.command = Libbox.CommandStatus
        optionsStatus.statusInterval = 3000L * 1000L * 1000L // 3s
        commandClient = Libbox.newCommandClient(handler, optionsStatus)
        commandClient?.connect()
        Log.i(TAG, "CommandClient connected (Status, interval=3s)")

        // 启动 CommandClient (Group) - 用于接收 URL 测试结果
        val optionsGroup = CommandClientOptions()
        optionsGroup.command = Libbox.CommandGroup
        optionsGroup.statusInterval = 3000L * 1000L * 1000L // 3s
        commandClientGroup = Libbox.newCommandClient(handler, optionsGroup)
        commandClientGroup?.connect()
        Log.i(TAG, "CommandClient connected (Group, interval=3s)")

        // 验证回调
        serviceScope.launch {
            delay(3500)
            val groupsSize = groupSelectedOutbounds.size
            val label = activeConnectionLabel
            if (groupsSize == 0 && label.isNullOrBlank()) {
                Log.w(TAG, "Command callbacks not observed yet")
            } else {
                Log.i(TAG, "Command callbacks OK (groups=$groupsSize)")
            }
        }
    }

    /**
     * 停止所�?Command Server/Client
     * @param proxyPort 需要等待释放的代理端口，传 0 或负数则不等�?     */
    @Suppress("CognitiveComplexMethod")
    suspend fun stopAndWaitPortRelease(
        proxyPort: Int,
        waitTimeoutMs: Long = PORT_RELEASE_TIMEOUT_MS,
        forceKillOnTimeout: Boolean = true,
        enforceReleaseOnTimeout: Boolean = false
    ): Result<Unit> = runCatching {
        Log.i(TAG, "stopAndWaitPortRelease: port=$proxyPort, timeout=${waitTimeoutMs}ms, forceKill=$forceKillOnTimeout")

        commandClient?.disconnect()
        commandClient = null
        commandClientGroup?.disconnect()
        commandClientGroup = null
        commandClientLogs?.disconnect()
        commandClientLogs = null
        commandClientConnections?.disconnect()
        commandClientConnections = null

        // 2025-fix: 必须�?clients 断开后再清理 handler，确�?Go 侧引用有�?        clientHandler = null

        BoxWrapperManager.release()

        // 必须先关�?BoxService (释放端口和连�?，再关闭 server
        val closeStart = SystemClock.elapsedRealtime()
        val hasBoxService = boxService != null
        Log.i(TAG, "Closing BoxService (exists=$hasBoxService)...")
        runCatching { boxService?.close() }
            .onFailure { Log.w(TAG, "BoxService.close failed: ${it.message}") }
        boxService = null
        Log.i(TAG, "BoxService closed in ${SystemClock.elapsedRealtime() - closeStart}ms")

        commandServer?.close()
        commandServer = null

        // 在端口等待之前先清除通知，防止端口等待超�?killProcess 后通知残留
        runCatching {
            val nm = context.getSystemService(NotificationManager::class.java)
            nm?.cancel(VpnNotificationManager.NOTIFICATION_ID)
            nm?.cancel(11) // ProxyOnlyService NOTIFICATION_ID
        }

        // 关键修复：主动等待端口释�?        if (proxyPort > 0) {
            Log.i(TAG, "Waiting for port $proxyPort to be released (timeout=${waitTimeoutMs}ms)...")
            val portReleased = waitForPortRelease(proxyPort, waitTimeoutMs)
            val elapsed = SystemClock.elapsedRealtime() - closeStart
            if (portReleased) {
                Log.i(TAG, "Port $proxyPort released in ${elapsed}ms")
            } else {
                if (forceKillOnTimeout) {
                    // 端口释放失败，强制杀死进程让系统回收端口
                    // 通知已在端口等待之前清除
                    Log.e(TAG, "Port $proxyPort NOT released after ${elapsed}ms, killing process to force release")
                    android.os.Process.killProcess(android.os.Process.myPid())
                } else {
                    if (enforceReleaseOnTimeout) {
                        throw IllegalStateException(
                            "Port $proxyPort NOT released after ${elapsed}ms in strict-stop mode"
                        )
                    }
                    Log.w(TAG, "Port $proxyPort NOT released after ${elapsed}ms, " +
                        "skip force kill (forceKillOnTimeout=false)")
                }
            }
        } else {
            Log.i(TAG, "Command Server/Client stopped (no port to wait)")
        }
    }

    /**
     * 停止所�?Command Server/Client（兼容旧调用，不等待端口�?     */
    fun stop(): Result<Unit> = runCatching {
        commandClient?.disconnect()
        commandClient = null
        commandClientGroup?.disconnect()
        commandClientGroup = null
        commandClientLogs?.disconnect()
        commandClientLogs = null
        commandClientConnections?.disconnect()
        commandClientConnections = null

        // 2025-fix: 必须�?clients 断开后再清理 handler，确�?Go 侧引用有�?        clientHandler = null

        BoxWrapperManager.release()

        // 必须先关�?BoxService (释放端口和连�?，再关闭 server
        runCatching { boxService?.close() }
            .onFailure { Log.w(TAG, "BoxService.close failed: ${it.message}") }
        boxService = null

        commandServer?.close()
        commandServer = null
        Log.i(TAG, "Command Server/Client stopped")
    }

    /**
     * 等待端口释放
     */
    private suspend fun waitForPortRelease(port: Int, timeoutMs: Long): Boolean {
        val startTime = SystemClock.elapsedRealtime()
        while (SystemClock.elapsedRealtime() - startTime < timeoutMs) {
            if (isPortAvailable(port)) {
                return true
            }
            delay(PORT_CHECK_INTERVAL_MS)
        }
        return false
    }

    /**
     * 检测端口是否可�?     */
    private fun isPortAvailable(port: Int): Boolean {
        return try {
            ServerSocket().use { socket ->
                socket.reuseAddress = true
                socket.bind(InetSocketAddress("127.0.0.1", port))
                true
            }
        } catch (@Suppress("SwallowedException") e: Exception) {
            false
        }
    }

    /**
     * 获取 CommandServer
     */
    fun getCommandServer(): CommandServer? = commandServer

    /**
     * 获取 CommandClient (用于连接管理)
     */
    fun getCommandClient(): CommandClient? = commandClient
    fun getConnectionsClient(): CommandClient? = commandClientConnections

    /**
     * 获取指定 group 的选中 outbound
     */
    fun getSelectedOutbound(groupTag: String): String? = groupSelectedOutbounds[groupTag]

    /**
     * 获取所�?group 选中状态的数量
     */
    fun getGroupsCount(): Int = groupSelectedOutbounds.size

    /**
     * 关闭所有连�?     */
    fun closeConnections(): Boolean {
        val clients = listOfNotNull(commandClientConnections, commandClient)
        for (client in clients) {
            try {
                client.closeConnections()
                Log.i(TAG, "Connections closed via CommandClient")
                return true
            } catch (e: Exception) {
                Log.w(TAG, "closeConnections failed: ${e.message}")
            }
        }
        return false
    }

    /**
     * 关闭指定连接
     */
    fun closeConnection(connId: String): Boolean {
        val client = commandClientConnections ?: commandClient ?: return false
        return try {
            val method = client.javaClass.methods.find {
                it.name == "closeConnection" && it.parameterCount == 1
            }
            method?.invoke(client, connId)
            true
        } catch (e: Exception) {
            false
        }
    }

    /**
     * 触发 URL 测试并等待结�?     * 使用 CommandClient.urlTest(groupTag) API 触发测试
     * 结果通过 writeGroups 回调异步返回
     *
     * v1.12.20: urlTest 是异步的，需要轮询等待结�?     *
     * @param groupTag 要测试的 group 标签 (�?"PROXY")
     * @param timeoutMs 等待结果的超时时�?     * @return 节点延迟映射 (tag -> delay ms)，失败返回空 Map
     */
    suspend fun urlTestGroup(groupTag: String, timeoutMs: Long = 10000L): Map<String, Int> {
        // 优先使用 Group client，回退到主 client
        val client = commandClientGroup ?: commandClient ?: return emptyMap()

        return urlTestMutex.withLock {
            try {
                // 清空之前的结�?                urlTestResults.clear()
                pendingUrlTestGroupTag = groupTag

                // 触发 URL 测试
                Log.i(TAG, "Triggering URL test for group: $groupTag")
                client.urlTest(groupTag)

                // 等待测试完成 - 轮询检查结�?                val startTime = System.currentTimeMillis()
                val pollInterval = 500L
                var lastResultCount = 0

                while (System.currentTimeMillis() - startTime < timeoutMs) {
                    delay(pollInterval)

                    val currentCount = urlTestResults.size
                    if (currentCount > 0) {
                        // 如果结果数量稳定了（连续两次相同），认为测试完成
                        if (currentCount == lastResultCount) {
                            Log.i(TAG, "URL test completed with $currentCount results")
                            break
                        }
                        lastResultCount = currentCount
                    }
                }

                val results = urlTestResults.toMap()
                if (results.isEmpty()) {
                    Log.w(TAG, "URL test timeout or no results for group: $groupTag")
                }
                results
            } catch (e: Exception) {
                Log.e(TAG, "URL test failed for group $groupTag: ${e.message}")
                emptyMap()
            } finally {
                pendingUrlTestGroupTag = null
                urlTestCompletionCallback = null
            }
        }
    }

    /**
     * 获取缓存�?URL 测试结果
     * @param tag 节点标签
     * @return 延迟�?(ms)，未测试返回 null
     */
    fun getCachedUrlTestDelay(tag: String): Int? = urlTestResults[tag]

    private fun createClientHandler(): CommandClientHandler = object : CommandClientHandler {
        override fun connected() {}

        override fun disconnected(message: String?) {
            Log.w(TAG, "CommandClient disconnected: $message")
        }

        override fun clearLogs() {
            runCatching { LogRepository.getInstance().clearLogs() }
        }

        override fun writeLogs(messageList: StringIterator?) {
            if (messageList == null) return
            val repo = LogRepository.getInstance()
            runCatching {
                while (messageList.hasNext()) {
                    val msg = messageList.next()
                    if (!msg.isNullOrBlank()) {
                        repo.addLog(msg)
                    }
                }
            }
        }

        @Suppress("LongMethod")
        override fun writeStatus(message: StatusMessage?) {
            if (message == null) return
            try {
                val currentUp = message.uplinkTotal
                val currentDown = message.downlinkTotal
                val currentTime = System.currentTimeMillis()

                if (lastSpeedUpdateTime == 0L || currentTime < lastSpeedUpdateTime) {
                    lastSpeedUpdateTime = currentTime
                    lastUplinkTotal = currentUp
                    lastDownlinkTotal = currentDown
                    return
                }

                if (currentUp < lastUplinkTotal || currentDown < lastDownlinkTotal) {
                    lastUplinkTotal = currentUp
                    lastDownlinkTotal = currentDown
                    lastSpeedUpdateTime = currentTime
                    return
                }

                val diffUp = currentUp - lastUplinkTotal
                val diffDown = currentDown - lastDownlinkTotal

                if (diffUp > 0 || diffDown > 0) {
                    val trafficRepo = TrafficRepository.getInstance(context)
                    val configRepo = ConfigRepository.getInstance(context)

                    val perOutboundTraffic = try {
                        BoxWrapperManager.getTrafficByOutbound()
                            .filterKeys { tag ->
                                !tag.equals("direct", ignoreCase = true) &&
                                    !tag.equals("block", ignoreCase = true) &&
                                    !tag.equals("dns-out", ignoreCase = true)
                            }
                    } catch (e: Exception) {
                        Log.w(TAG, "getTrafficByOutbound failed, fallback to activeNode", e)
                        emptyMap()
                    }

                    if (perOutboundTraffic.isNotEmpty()) {
                        var totalOutboundUp = 0L
                        var totalOutboundDown = 0L
                        perOutboundTraffic.forEach { (_, traffic) ->
                            totalOutboundUp += traffic.first
                            totalOutboundDown += traffic.second
                        }

                        if (totalOutboundUp > 0 || totalOutboundDown > 0) {
                            perOutboundTraffic.forEach { (nodeTag, traffic) ->
                                val (outboundUp, outboundDown) = traffic
                                val allocUp = if (totalOutboundUp > 0) {
                                    (diffUp * outboundUp / totalOutboundUp)
                                } else 0L
                                val allocDown = if (totalOutboundDown > 0) {
                                    (diffDown * outboundDown / totalOutboundDown)
                                } else 0L

                                if (allocUp > 0 || allocDown > 0) {
                                    val node = configRepo.getNodeByName(nodeTag)
                                    if (node != null) {
                                        trafficRepo.addTraffic(node.id, allocUp, allocDown, node.name)
                                    } else {
                                        trafficRepo.addTraffic(nodeTag, allocUp, allocDown, nodeTag)
                                    }
                                }
                            }
                        }
                    } else {
                        val activeNodeId = configRepo.activeNodeId.value
                        if (activeNodeId != null) {
                            val nodeName = configRepo.getNodeById(activeNodeId)?.name
                            trafficRepo.addTraffic(activeNodeId, diffUp, diffDown, nodeName)
                        }
                    }
                }

                lastUplinkTotal = currentUp
                lastDownlinkTotal = currentDown
                lastSpeedUpdateTime = currentTime
            } catch (e: Exception) {
                Log.e(TAG, "writeStatus callback error", e)
            }
        }

        override fun writeGroups(groups: OutboundGroupIterator?) {
            if (groups == null) return
            try {
                processGroups(groups)
            } catch (e: Exception) {
                Log.e(TAG, "Error processing groups update", e)
            }
        }

        override fun initializeClashMode(modeList: StringIterator?, currentMode: String?) {}
        override fun updateClashMode(newMode: String?) {}

        override fun writeConnections(connections: Connections?) {
            connections ?: return
            try {
                processConnections(connections)
            } catch (e: Exception) {
                Log.e(TAG, "Error processing connections", e)
            }
        }
    }

    private fun processGroups(groups: OutboundGroupIterator) {
        val configRepo = ConfigRepository.getInstance(context)
        var changed = false
        val pendingGroup = pendingUrlTestGroupTag
        val testResults = mutableMapOf<String, Int>()

        Log.d(TAG, "writeGroups called, pendingGroup=$pendingGroup")

        while (groups.hasNext()) {
            val group = groups.next()
            val groupChanged = processGroup(group, pendingGroup, testResults, configRepo)
            if (groupChanged) changed = true
        }

        notifyUrlTestCompletion(pendingGroup, testResults)
        if (changed) {
            callbacks?.requestNotificationUpdate(false)
        }
    }

    private fun processGroup(
        group: OutboundGroup,
        pendingGroup: String?,
        testResults: MutableMap<String, Int>,
        configRepo: ConfigRepository
    ): Boolean {
        val tag = group.tag
        val selected = group.selected
        var changed = false

        Log.d(TAG, "Processing group: $tag, selected=$selected")

        if (!tag.isNullOrBlank() && !selected.isNullOrBlank()) {
            val prev = groupSelectedOutbounds.put(tag, selected)
            if (prev != selected) changed = true
        }

        collectGroupTestResults(group, tag, pendingGroup, testResults)
        changed = updateProxyGroupSelection(tag, selected, configRepo) || changed

        return changed
    }

    private fun collectGroupTestResults(
        group: OutboundGroup,
        tag: String?,
        pendingGroup: String?,
        testResults: MutableMap<String, Int>
    ) {
        val items = group.items ?: return
        var itemCount = 0
        var delayCount = 0

        while (items.hasNext()) {
            val item = items.next()
            val itemTag = item?.tag
            val delay = item?.urlTestDelay ?: 0
            itemCount++
            if (!itemTag.isNullOrBlank() && delay > 0) {
                delayCount++
                if (pendingGroup != null && tag.equals(pendingGroup, ignoreCase = true)) {
                    testResults[itemTag] = delay
                    urlTestResults[itemTag] = delay
                }
            }
        }
        Log.d(TAG, "Group $tag: $itemCount items, $delayCount with delay")
    }

    private fun updateProxyGroupSelection(
        tag: String?,
        selected: String?,
        configRepo: ConfigRepository
    ): Boolean {
        if (!tag.equals("PROXY", ignoreCase = true)) return false
        if (selected.isNullOrBlank() || selected == realTimeNodeName) return false

        realTimeNodeName = selected
        VpnStateStore.setActiveLabel(selected)
        Log.i(TAG, "Real-time node update: $selected")
        serviceScope.launch {
            configRepo.syncActiveNodeFromProxySelection(selected)
        }
        return true
    }

    private fun notifyUrlTestCompletion(pendingGroup: String?, testResults: Map<String, Int>) {
        if (pendingGroup == null) return
        Log.i(TAG, "URL test results for $pendingGroup: ${testResults.size} items")
        if (testResults.isNotEmpty()) {
            urlTestCompletionCallback?.invoke(testResults)
        }
    }

    @Suppress("LongMethod", "CyclomaticComplexMethod", "CognitiveComplexMethod", "NestedBlockDepth")
    private fun processConnections(connections: Connections) {
        // 处理连接
        val iterator = connections.iterator()
        var newestConnection: Connection? = null
        val ids = ArrayList<String>(64)
        val egressCounts = LinkedHashMap<String, Int>()
        val configRepo = ConfigRepository.getInstance(context)

        while (iterator.hasNext()) {
            val connection = iterator.next() ?: continue
            // 跳过关闭的连�?            if (connection.closedAt > 0) continue
            // 跳过 dns-out
            val outbound = connection.outbound
            if (outbound == "dns-out") continue

            if (newestConnection == null || connection.createdAt > newestConnection.createdAt) {
                newestConnection = connection
            }

            val id = connection.id
            if (!id.isNullOrBlank()) {
                ids.add(id)
            }

            // 解析 egress
            var candidateTag: String? = outbound
            if (candidateTag.isNullOrBlank() || candidateTag == "dns-out") {
                candidateTag = null
            }

            if (!candidateTag.isNullOrBlank()) {
                val resolved = callbacks?.resolveEgressNodeName(candidateTag)
                    ?: configRepo.resolveNodeNameFromOutboundTag(candidateTag)
                    ?: candidateTag
                if (!resolved.isNullOrBlank()) {
                    egressCounts[resolved] = (egressCounts[resolved] ?: 0) + 1
                }
            }
        }

        recentConnectionIds = ids

        // 生成标签
        val newLabel = when {
            egressCounts.isEmpty() -> null
            egressCounts.size == 1 -> egressCounts.keys.first()
            else -> {
                val sorted = egressCounts.entries.sortedByDescending { it.value }.map { it.key }
                val top = sorted.take(2)
                val more = sorted.size - top.size
                if (more > 0) "Mixed: ${top.joinToString(" + ")}(+$more)"
                else "Mixed: ${top.joinToString(" + ")}"
            }
        }

        val labelChanged = newLabel != activeConnectionLabel
        if (labelChanged) {
            activeConnectionLabel = newLabel
            if (newLabel != lastConnectionsLabelLogged) {
                lastConnectionsLabelLogged = newLabel
                Log.d(TAG, "Connections label updated: ${newLabel ?: "(null)"}")
            }
        }

        // 更新活跃连接节点
        var newNode: String? = null
        if (newestConnection != null) {
            // 使用 chain 获取出站�?            val chainIter = newestConnection.chain()
            val chainList = mutableListOf<String>()
            if (chainIter != null) {
                while (chainIter.hasNext()) {
                    val tag = chainIter.next()
                    if (!tag.isNullOrBlank() && tag != "dns-out") {
                        chainList.add(tag)
                    }
                }
            }
            newNode = chainList.lastOrNull()
        }

        if (newNode != activeConnectionNode || labelChanged) {
            activeConnectionNode = newNode
            callbacks?.requestNotificationUpdate(false)
        }
    }

    fun cleanup() {
        stop()
        groupSelectedOutbounds.clear()
        urlTestResults.clear()
        pendingUrlTestGroupTag = null
        urlTestCompletionCallback = null
        realTimeNodeName = null
        activeConnectionNode = null
        activeConnectionLabel = null
        recentConnectionIds = emptyList()
        callbacks = null
        isNonEssentialSuspended = false
    }

    fun suspendNonEssential() {
        if (isNonEssentialSuspended) return
        isNonEssentialSuspended = true

        commandClientLogs?.disconnect()
        commandClientLogs = null

        commandClientConnections?.disconnect()
        commandClientConnections = null

        Log.i(TAG, "Non-essential clients suspended (Logs, Connections)")
    }

    fun resumeNonEssential() {
        if (!isNonEssentialSuspended) return
        isNonEssentialSuspended = false

        if (commandServer == null) {
            Log.w(TAG, "Cannot resume: no CommandServer")
            return
        }

        // 2025-fix: 复用已存储的 handler，如果不存在则创建并存储
        val handler = clientHandler ?: createClientHandler().also { clientHandler = it }

        try {
            val optionsLog = CommandClientOptions()
            // v1.12.20: 使用 command 属性而不�?addCommand 方法
            optionsLog.command = Libbox.CommandLog
            optionsLog.statusInterval = 1500L * 1000L * 1000L
            commandClientLogs = Libbox.newCommandClient(handler, optionsLog)
            commandClientLogs?.connect()
            Log.i(TAG, "CommandClient (Logs) resumed")
        } catch (e: Exception) {
            Log.e(TAG, "Failed to resume Logs client", e)
        }

        try {
            val optionsConn = CommandClientOptions()
            // v1.12.20: 使用 command 属性而不�?addCommand 方法
            optionsConn.command = Libbox.CommandConnections
            optionsConn.statusInterval = 5000L * 1000L * 1000L
            commandClientConnections = Libbox.newCommandClient(handler, optionsConn)
            commandClientConnections?.connect()
            Log.i(TAG, "CommandClient (Connections) resumed")
        } catch (e: Exception) {
            Log.e(TAG, "Failed to resume Connections client", e)
        }
    }

    val isNonEssentialActive: Boolean
        get() = !isNonEssentialSuspended && (commandClientLogs != null || commandClientConnections != null)
}







