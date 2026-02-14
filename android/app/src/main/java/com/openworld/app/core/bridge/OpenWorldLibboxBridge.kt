package com.openworld.app.core.bridge

import com.google.gson.Gson
import com.google.gson.JsonArray
import com.google.gson.JsonElement
import com.google.gson.JsonObject
import com.openworld.core.OpenWorldCore
import okhttp3.OkHttpClient
import okhttp3.Request
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch

object Libbox {
    const val CommandStatus: Int = 1
    const val CommandGroup: Int = 2
    const val CommandLog: Int = 3
    const val CommandConnections: Int = 4

    private val gson = Gson()

    fun version(): String = runCatching { OpenWorldCore.version() }.getOrElse { "unknown" }

    fun isPaused(): Boolean = runCatching { OpenWorldCore.isPaused() }.getOrDefault(false)

    fun pauseService(): Boolean = runCatching { OpenWorldCore.pause() }.getOrDefault(false)

    fun resumeService(): Boolean = runCatching { OpenWorldCore.resume() }.getOrDefault(false)

    fun resetAllConnections(system: Boolean): Boolean {
        return runCatching { OpenWorldCore.resetAllConnections(system) }.getOrDefault(false)
    }

    fun hasSelector(): Boolean = runCatching { OpenWorldCore.hasSelector() }.getOrDefault(false)

    fun selectOutboundByTag(nodeTag: String): Boolean =
        runCatching { OpenWorldCore.selectOutbound(nodeTag) }.getOrDefault(false)

    fun getSelectedOutbound(): String = runCatching { OpenWorldCore.getSelectedOutbound().orEmpty() }.getOrDefault("")

    fun listOutboundsString(): String? = runCatching { OpenWorldCore.listOutbounds() }.getOrNull()

    fun getTrafficTotalUplink(): Long = runCatching { OpenWorldCore.getTrafficTotalUplink() }.getOrDefault(0L)

    fun getTrafficTotalDownlink(): Long = runCatching { OpenWorldCore.getTrafficTotalDownlink() }.getOrDefault(0L)

    fun resetTrafficStats(): Boolean = runCatching { OpenWorldCore.resetTrafficStats() }.getOrDefault(false)

    fun getConnectionCount(): Long = runCatching { OpenWorldCore.getConnectionCount() }.getOrDefault(0L)

    fun closeAllTrackedConnections(): Long =
        runCatching { OpenWorldCore.closeAllTrackedConnections().toLong() }.getOrDefault(0L)

    fun getOpenWorldVersion(): String = version()

    fun recoverNetworkAuto(): Boolean = runCatching { OpenWorldCore.recoverNetworkAuto() }.getOrDefault(false)

    fun checkNetworkRecoveryNeeded(): Boolean = false

    fun getTrafficByOutbound(): TrafficByOutboundIterator? = null

    fun newHTTPClient(): HTTPClient = HTTPClient()

    fun newService(configContent: String, platformInterface: PlatformInterface): BoxService {
        return BoxService(configContent, platformInterface)
    }

    fun newCommandServer(handler: CommandServerHandler, maxLines: Int): CommandServer {
        return CommandServer(handler = handler, maxLines = maxLines)
    }

    fun newCommandClient(handler: CommandClientHandler, options: CommandClientOptions): CommandClient {
        return CommandClient(handler = handler, options = options)
    }

    internal fun parseProxyGroups(json: String?): OutboundGroupIterator {
        if (json.isNullOrBlank()) return EmptyOutboundGroupIterator
        return runCatching {
            val arr = gson.fromJson(json, JsonElement::class.java)
            val groups = mutableListOf<OutboundGroup>()
            when {
                arr.isJsonArray -> {
                    arr.asJsonArray.forEach { element ->
                        parseGroupObject(element.asJsonObject)?.let(groups::add)
                    }
                }
                arr.isJsonObject -> {
                    val obj = arr.asJsonObject
                    val list = obj.getAsJsonArray("groups") ?: JsonArray()
                    list.forEach { element ->
                        parseGroupObject(element.asJsonObject)?.let(groups::add)
                    }
                }
            }
            ListOutboundGroupIterator(groups)
        }.getOrDefault(EmptyOutboundGroupIterator)
    }

    private fun parseGroupObject(obj: JsonObject): OutboundGroup? {
        val tag = obj.get("tag")?.asString ?: return null
        val selected = obj.get("selected")?.asString.orEmpty()
        val itemsArray = obj.getAsJsonArray("items") ?: JsonArray()
        val items = itemsArray.mapNotNull { item ->
            runCatching {
                val it = item.asJsonObject
                OutboundGroupItem(
                    tag = it.get("tag")?.asString,
                    urlTestDelay = when {
                        it.has("urlTestDelay") -> it.get("urlTestDelay").asInt
                        it.has("url_test_delay") -> it.get("url_test_delay").asInt
                        else -> 0
                    }
                )
            }.getOrNull()
        }
        return OutboundGroup(tag = tag, selected = selected, items = ListOutboundGroupItemIterator(items))
    }

    internal fun parseConnections(json: String?): Connections {
        if (json.isNullOrBlank()) return Connections(ListConnectionIterator(emptyList()))
        val list = runCatching {
            val root = gson.fromJson(json, JsonElement::class.java)
            val source = when {
                root.isJsonArray -> root.asJsonArray
                root.isJsonObject && root.asJsonObject.has("connections") -> root.asJsonObject.getAsJsonArray("connections")
                else -> JsonArray()
            }
            source.mapNotNull { item ->
                runCatching {
                    val obj = item.asJsonObject
                    val chain = obj.getAsJsonArray("chain")?.mapNotNull { c -> c.asString } ?: emptyList()
                    Connection(
                        id = obj.get("id")?.asString,
                        outbound = obj.get("outbound")?.asString,
                        createdAt = obj.get("created_at")?.asLong ?: obj.get("createdAt")?.asLong ?: 0L,
                        closedAt = obj.get("closed_at")?.asLong ?: obj.get("closedAt")?.asLong ?: 0L,
                        chainValues = chain
                    )
                }.getOrNull()
            }
        }.getOrDefault(emptyList())
        return Connections(ListConnectionIterator(list))
    }
}

class BoxService(
    private val configContent: String,
    private val platformInterface: PlatformInterface
) {
    fun start() {
        val tunFd = runCatching { platformInterface.openTun(TunOptions()) }.getOrDefault(-1)
        if (tunFd >= 0) {
            OpenWorldCore.setTunFd(tunFd)
        }
        OpenWorldCore.start(configContent)
    }

    fun close() {
        OpenWorldCore.stop()
    }
}

class CommandServer(
    private val handler: CommandServerHandler,
    private val maxLines: Int
) {
    private var service: BoxService? = null

    fun start() {}

    fun close() {
        service = null
    }

    fun setService(service: BoxService) {
        this.service = service
    }
}

interface CommandServerHandler {
    fun postServiceClose()
    fun serviceReload()
    fun getSystemProxyStatus(): SystemProxyStatus?
    fun setSystemProxyEnabled(isEnabled: Boolean)
}

class CommandClientOptions {
    var command: Int = Libbox.CommandStatus
    var statusInterval: Long = 3_000_000_000L
}

class CommandClient(
    private val handler: CommandClientHandler,
    private val options: CommandClientOptions
) {
    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    private var job: Job? = null

    fun connect() {
        if (job?.isActive == true) return
        handler.connected()
        job = scope.launch {
            val intervalMs = (options.statusInterval / 1_000_000L).coerceAtLeast(500L)
            while (isActive) {
                emitByCommand()
                delay(intervalMs)
            }
        }
    }

    private fun emitByCommand() {
        when (options.command) {
            Libbox.CommandStatus -> {
                val status = StatusMessage(
                    uplinkTotal = OpenWorldCore.getTrafficTotalUplink(),
                    downlinkTotal = OpenWorldCore.getTrafficTotalDownlink()
                )
                handler.writeStatus(status)
            }
            Libbox.CommandGroup -> {
                val groups = Libbox.parseProxyGroups(OpenWorldCore.getProxyGroups())
                handler.writeGroups(groups)
            }
            Libbox.CommandConnections -> {
                val connections = Libbox.parseConnections(OpenWorldCore.getActiveConnections())
                handler.writeConnections(connections)
            }
            Libbox.CommandLog -> Unit
        }
    }

    fun disconnect() {
        job?.cancel()
        job = null
        handler.disconnected(null)
    }

    fun selectOutbound(groupTag: String, outboundTag: String): Boolean {
        return if (groupTag.equals("PROXY", ignoreCase = true)) {
            OpenWorldCore.selectOutbound(outboundTag)
        } else {
            OpenWorldCore.setGroupSelected(groupTag, outboundTag)
        }
    }

    fun urlTest(groupTag: String): Boolean {
        return runCatching {
            OpenWorldCore.testGroupDelay(groupTag, "https://www.gstatic.com/generate_204", 5_000)
            true
        }.getOrDefault(false)
    }

    fun closeConnections(): Boolean {
        return OpenWorldCore.resetAllConnections(false)
    }

    fun closeConnection(id: String): Boolean {
        val parsed = id.toLongOrNull() ?: return false
        return OpenWorldCore.closeConnectionById(parsed)
    }
}

interface CommandClientHandler {
    fun connected()
    fun disconnected(message: String?)
    fun clearLogs()
    fun writeLogs(messageList: StringIterator?)
    fun writeStatus(message: StatusMessage?)
    fun writeGroups(groups: OutboundGroupIterator?)
    fun initializeClashMode(modeList: StringIterator?, currentMode: String?)
    fun updateClashMode(newMode: String?)
    fun writeConnections(connections: Connections?)
}

data class StatusMessage(
    val uplinkTotal: Long,
    val downlinkTotal: Long
)

interface StringIterator {
    fun hasNext(): Boolean
    fun next(): String
    fun len(): Int
}

class ListStringIterator(private val values: List<String>) : StringIterator {
    private var index: Int = 0
    override fun hasNext(): Boolean = index < values.size
    override fun next(): String = values.getOrElse(index++) { "" }
    override fun len(): Int = values.size
}

data class OutboundGroupItem(
    val tag: String?,
    val urlTestDelay: Int
)

interface OutboundGroupItemIterator {
    fun hasNext(): Boolean
    fun next(): OutboundGroupItem?
}

class ListOutboundGroupItemIterator(private val values: List<OutboundGroupItem>) : OutboundGroupItemIterator {
    private var index: Int = 0
    override fun hasNext(): Boolean = index < values.size
    override fun next(): OutboundGroupItem? = values.getOrNull(index++)
}

data class OutboundGroup(
    val tag: String?,
    val selected: String?,
    val items: OutboundGroupItemIterator?
)

interface OutboundGroupIterator {
    fun hasNext(): Boolean
    fun next(): OutboundGroup
}

class ListOutboundGroupIterator(private val values: List<OutboundGroup>) : OutboundGroupIterator {
    private var index: Int = 0
    override fun hasNext(): Boolean = index < values.size
    override fun next(): OutboundGroup = values.getOrElse(index++) { OutboundGroup(null, null, null) }
}

object EmptyOutboundGroupIterator : OutboundGroupIterator {
    override fun hasNext(): Boolean = false
    override fun next(): OutboundGroup = OutboundGroup(null, null, null)
}

data class Connection(
    val id: String?,
    val outbound: String?,
    val createdAt: Long,
    val closedAt: Long,
    private val chainValues: List<String>
) {
    fun chain(): StringIterator = ListStringIterator(chainValues)
}

interface ConnectionIterator {
    fun hasNext(): Boolean
    fun next(): Connection?
}

class ListConnectionIterator(private val values: List<Connection>) : ConnectionIterator {
    private var index: Int = 0
    override fun hasNext(): Boolean = index < values.size
    override fun next(): Connection? = values.getOrNull(index++)
}

data class Connections(private val values: ConnectionIterator) {
    fun iterator(): ConnectionIterator = values
}

data class SystemProxyStatus(val enabled: Boolean = false)
data class Notification(val title: String? = null, val content: String? = null)
data class WIFIState(val ssid: String? = null)

data class TunOptions(val mtu: Int = 1500)

interface NetworkInterfaceIterator {
    fun hasNext(): Boolean
    fun next(): NetworkInterface
}

class NetworkInterface {
    var name: String = ""
    var index: Int = 0
    var mtu: Int = 0
    var flags: Int = 0
    var addresses: StringIterator? = null
}

interface InterfaceUpdateListener {
    fun updateDefaultInterface(name: String, index: Int, isExpensive: Boolean, isConstrained: Boolean)
}

interface LocalDNSTransport {
    fun raw(): Boolean
    fun lookup(ctx: ExchangeContext, network: String, domain: String)
    fun exchange(ctx: ExchangeContext, message: ByteArray)
}

interface ExchangeContext {
    fun success(result: String)
    fun errorCode(code: Int)
}

interface TrafficByOutboundIterator {
    fun hasNext(): Boolean
    fun next(): TrafficByOutbound?
}

data class TrafficByOutbound(
    val tag: String,
    val upload: Long,
    val download: Long
)

class HTTPClient {
    private val okHttp = OkHttpClient()

    fun trySocks5(port: Int) {}
    fun modernTLS() {}
    fun keepAlive() {}
    fun newRequest(): HTTPRequest = HTTPRequest(okHttp)
    fun close() {}
}

class HTTPRequest(private val client: OkHttpClient) {
    private var url: String = ""
    private var method: String = "GET"
    private val headers = linkedMapOf<String, String>()

    fun setURL(url: String) {
        this.url = url
    }

    fun setMethod(method: String) {
        this.method = method
    }

    fun randomUserAgent() {
        if (!headers.containsKey("User-Agent")) {
            headers["User-Agent"] = "OpenWorld/Android"
        }
    }

    fun setHeader(key: String, value: String) {
        headers[key] = value
    }

    fun execute(): HTTPResponse {
        val requestBuilder = Request.Builder().url(url)
        headers.forEach { (k, v) -> requestBuilder.header(k, v) }
        val request = when (method.uppercase()) {
            "GET" -> requestBuilder.get().build()
            else -> requestBuilder.get().build()
        }
        val body = client.newCall(request).execute().use { it.body?.string().orEmpty() }
        return HTTPResponse(HTTPString(body))
    }
}

data class HTTPResponse(val content: HTTPString?)

data class HTTPString(val value: String)

interface PlatformInterface {
    fun localDNSTransport(): LocalDNSTransport
    fun autoDetectInterfaceControl(fd: Int)
    fun openTun(options: TunOptions?): Int
    fun usePlatformAutoDetectInterfaceControl(): Boolean
    fun useProcFS(): Boolean
    fun findConnectionOwner(
        ipProtocol: Int,
        sourceAddress: String?,
        sourcePort: Int,
        destinationAddress: String?,
        destinationPort: Int
    ): Int

    fun packageNameByUid(uid: Int): String
    fun uidByPackageName(packageName: String?): Int
    fun startDefaultInterfaceMonitor(listener: InterfaceUpdateListener?)
    fun closeDefaultInterfaceMonitor(listener: InterfaceUpdateListener?)
    fun getInterfaces(): NetworkInterfaceIterator?
    fun underNetworkExtension(): Boolean
    fun includeAllNetworks(): Boolean
    fun readWIFIState(): WIFIState?
    fun clearDNSCache()
    fun sendNotification(notification: Notification?)
    fun systemCertificates(): StringIterator?
    fun writeLog(message: String?)
}





