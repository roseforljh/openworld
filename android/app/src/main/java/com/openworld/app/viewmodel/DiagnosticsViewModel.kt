package com.openworld.app.viewmodel

import android.app.Application
import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.os.Build
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.openworld.app.model.AppSettings
import com.openworld.app.repository.CoreRepository
import com.openworld.app.repository.SettingsRepository
import com.openworld.core.OpenWorldCore
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

class DiagnosticsViewModel(application: Application) : AndroidViewModel(application) {

    private val settingsRepository = SettingsRepository.getInstance(application)

    private val _resultTitle = MutableStateFlow("")
    val resultTitle = _resultTitle.asStateFlow()

    private val _resultMessage = MutableStateFlow("")
    val resultMessage = _resultMessage.asStateFlow()

    private val _showResultDialog = MutableStateFlow(false)
    val showResultDialog = _showResultDialog.asStateFlow()

    private val _isConnectivityLoading = MutableStateFlow(false)
    val isConnectivityLoading = _isConnectivityLoading.asStateFlow()

    private val _isPingLoading = MutableStateFlow(false)
    val isPingLoading = _isPingLoading.asStateFlow()

    private val _isDnsLoading = MutableStateFlow(false)
    val isDnsLoading = _isDnsLoading.asStateFlow()

    private val _isRoutingLoading = MutableStateFlow(false)
    val isRoutingLoading = _isRoutingLoading.asStateFlow()

    private val _isRunConfigLoading = MutableStateFlow(false)
    val isRunConfigLoading = _isRunConfigLoading.asStateFlow()

    private val _isAppRoutingDiagLoading = MutableStateFlow(false)
    val isAppRoutingDiagLoading = _isAppRoutingDiagLoading.asStateFlow()

    private val _isConnOwnerStatsLoading = MutableStateFlow(false)
    val isConnOwnerStatsLoading = _isConnOwnerStatsLoading.asStateFlow()

    fun dismissDialog() {
        _showResultDialog.value = false
    }

    fun showRunningConfigSummary() {
        if (_isRunConfigLoading.value) return
        viewModelScope.launch {
            _isRunConfigLoading.value = true
            _resultTitle.value = "Running Config Summary"
            try {
                val settings = withContext(Dispatchers.IO) { settingsRepository.settings.first() }
                val networkType = resolveNetworkType()
                val effectiveMtu = resolveEffectiveMtu(settings, networkType)
                val effectiveTunStack = resolveTunStack(settings)
                val running = runCatching { OpenWorldCore.isRunning() }.getOrDefault(false)
                val status = runCatching { CoreRepository.getStatus() }.getOrDefault(CoreRepository.CoreStatus())
                val ruleCount = runCatching { CoreRepository.getRoutingRuleCount() }.getOrDefault(0)

                _resultMessage.value = buildString {
                    appendLine("=== Throughput / Runtime Hints ===")
                    appendLine("Network: $networkType")
                    appendLine("TUN stack (setting): ${settings.tunStack.name}")
                    appendLine("TUN stack (effective): $effectiveTunStack")
                    appendLine("MTU auto: ${settings.tunMtuAuto}")
                    appendLine("MTU manual: ${settings.tunMtu}")
                    appendLine("MTU effective: $effectiveMtu")
                    appendLine("QUIC blocked: ${settings.blockQuic}")
                    appendLine()
                    appendLine("=== Core Status ===")
                    appendLine("Running: $running")
                    appendLine("Mode: ${status.mode}")
                    appendLine("Connections: ${status.connections}")
                    appendLine("Upload: ${status.upload}")
                    appendLine("Download: ${status.download}")
                    appendLine()
                    appendLine("=== Routing Summary ===")
                    appendLine("Route rules count: $ruleCount")
                    appendLine("Routing mode: ${settings.routingMode.name}")
                    appendLine("Default rule: ${settings.defaultRule.name}")
                }
            } catch (e: Exception) {
                _resultMessage.value = "读取运行配置失败: ${e.message}"
            } finally {
                _isRunConfigLoading.value = false
                _showResultDialog.value = true
            }
        }
    }

    fun exportRunningConfigToExternalFiles() {
        if (_isRunConfigLoading.value) return
        viewModelScope.launch {
            _isRunConfigLoading.value = true
            _resultTitle.value = "导出运行配置"
            try {
                val settings = withContext(Dispatchers.IO) { settingsRepository.settings.first() }
                val outBase = getApplication<Application>().getExternalFilesDir(null)
                if (outBase == null) {
                    _resultMessage.value = "Export failed: externalFilesDir unavailable."
                } else {
                    val exportDir = File(outBase, "exports").also { it.mkdirs() }
                    val ts = SimpleDateFormat("yyyyMMdd_HHmmss", Locale.US).format(Date())
                    val dst = File(exportDir, "diagnostics_$ts.txt")
                    val content = buildString {
                        appendLine("OpenWorld Diagnostics Export")
                        appendLine("Time: ${SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.US).format(Date())}")
                        appendLine("Running: ${runCatching { OpenWorldCore.isRunning() }.getOrDefault(false)}")
                        appendLine("Mode: ${settings.routingMode.name}")
                        appendLine("TUN stack: ${settings.tunStack.name}")
                        appendLine("MTU: ${settings.tunMtu}")
                        appendLine("Proxy port: ${settings.proxyPort}")
                    }
                    withContext(Dispatchers.IO) { dst.writeText(content) }
                    _resultMessage.value = "Exported to:\n${dst.absolutePath}"
                }
            } catch (e: Exception) {
                _resultMessage.value = "Export failed: ${e.message}"
            } finally {
                _isRunConfigLoading.value = false
                _showResultDialog.value = true
            }
        }
    }

    fun runAppRoutingDiagnostics() {
        if (_isAppRoutingDiagLoading.value) return
        viewModelScope.launch {
            _isAppRoutingDiagLoading.value = true
            _resultTitle.value = "应用分流诊断"
            try {
                val procPaths = listOf("/proc/net/tcp", "/proc/net/tcp6", "/proc/net/udp", "/proc/net/udp6")
                val procReport = buildString {
                    appendLine("Android API: ${Build.VERSION.SDK_INT}")
                    appendLine()
                    appendLine("ProcFS Readability:")
                    procPaths.forEach { path ->
                        val file = File(path)
                        val status = try {
                            if (!file.exists()) "Not exist"
                            else if (!file.canRead()) "Exist but not readable"
                            else {
                                val firstLine = runCatching { file.bufferedReader().use { it.readLine() } }.getOrNull()
                                "Readable (First line: ${firstLine ?: "null"})"
                            }
                        } catch (e: Exception) { "Error: ${e.message}" }
                        appendLine("- $path: $status")
                    }
                    appendLine()
                    appendLine("Note:")
                    appendLine("- If /proc/net/* is not readable, package_name rules may not work.")
                }
                _resultMessage.value = procReport
            } catch (e: Exception) {
                _resultMessage.value = "Diagnostics failed: ${e.message}"
            } finally {
                _isAppRoutingDiagLoading.value = false
                _showResultDialog.value = true
            }
        }
    }

    fun showConnectionOwnerStats() {
        if (_isConnOwnerStatsLoading.value) return
        viewModelScope.launch {
            _isConnOwnerStatsLoading.value = true
            _resultTitle.value = "Connection Owner Stats"
            try {
                val connections = CoreRepository.getActiveConnections()
                _resultMessage.value = buildString {
                    appendLine("Active connections: ${connections.size}")
                    appendLine()
                    if (connections.isNotEmpty()) {
                        appendLine("Top connections:")
                        connections.take(10).forEach { conn ->
                            appendLine("- ${conn.destination} via ${conn.outbound} (${conn.network})")
                        }
                    }
                }
            } catch (e: Exception) {
                _resultMessage.value = "Failed to read stats: ${e.message}"
            } finally {
                _isConnOwnerStatsLoading.value = false
                _showResultDialog.value = true
            }
        }
    }

    fun resetConnectionOwnerStats() {
        CoreRepository.resetAllConnections(false)
        _resultTitle.value = "Connection Owner Stats"
        _resultMessage.value = "连接统计已重置。"
        _showResultDialog.value = true
    }

    fun runConnectivityCheck() {
        if (_isConnectivityLoading.value) return
        viewModelScope.launch {
            _isConnectivityLoading.value = true
            _resultTitle.value = "连通性检查"
            try {
                val report = withContext(Dispatchers.IO) {
                    val running = runCatching { OpenWorldCore.isRunning() }.getOrDefault(false)
                    val dnsCheck = runCatching { CoreRepository.dnsQuery("example.com", "A") }.getOrDefault("")
                    val dnsOk = dnsCheck.contains("answer", true) || dnsCheck.contains("93.184.216.34")

                    buildString {
                        appendLine("Target: www.google.com")
                        appendLine("Core active: $running")
                        appendLine()
                        appendLine("[DNS 可达性] ${if (dnsOk) "OK" else "FAILED"}")
                        appendLine()
                        appendLine("Note:")
                        appendLine("- DIRECT checks local network")
                        appendLine("- If Core active=false, proxy tests may fail")
                    }
                }
                _resultMessage.value = report
            } catch (e: Exception) {
                _resultMessage.value = "Error: ${e.message}"
            } finally {
                _isConnectivityLoading.value = false
                _showResultDialog.value = true
            }
        }
    }

    fun runPingTest() {
        if (_isPingLoading.value) return
        viewModelScope.launch {
            _isPingLoading.value = true
            _resultTitle.value = "TCP Ping Test"
            val host = "8.8.8.8"
            val port = 53
            try {
                val results = mutableListOf<Long>()
                val count = 4
                withContext(Dispatchers.IO) {
                    repeat(count) {
                        val rtt = tcpPing(host, port)
                        if (rtt >= 0) results.add(rtt)
                    }
                }
                val summary = if (results.isNotEmpty()) {
                    val min = results.minOrNull() ?: 0
                    val max = results.maxOrNull() ?: 0
                    val avg = results.average().toInt()
                    val loss = ((count - results.size).toDouble() / count * 100).toInt()
                    "Sent: $count, Received: ${results.size}, Loss: $loss%\nMin: ${min}ms, Avg: ${avg}ms, Max: ${max}ms"
                } else {
                    "Sent: $count, Received: 0, Loss: 100%"
                }
                _resultMessage.value = "Target: $host:$port (Google DNS)\nMethod: TCP Ping\n\n$summary"
            } catch (e: Exception) {
                _resultMessage.value = "TCP Ping failed: ${e.message}"
            } finally {
                _isPingLoading.value = false
                _showResultDialog.value = true
            }
        }
    }

    fun runDnsQuery() {
        if (_isDnsLoading.value) return
        viewModelScope.launch {
            _isDnsLoading.value = true
            _resultTitle.value = "DNS Query"
            val host = "www.google.com"
            try {
                val ips = withContext(Dispatchers.IO) { InetAddress.getAllByName(host) }
                val ipList = ips.joinToString("\n") { it.hostAddress ?: "(null)" }
                _resultMessage.value = "Domain: $host\n\nResult:\n$ipList\n\nNote: Result affected by current DNS/VPN settings."
            } catch (e: Exception) {
                _resultMessage.value = "Domain: $host\n\nFailed: ${e.message}"
            } finally {
                _isDnsLoading.value = false
                _showResultDialog.value = true
            }
        }
    }

    fun runRoutingTest() {
        if (_isRoutingLoading.value) return
        viewModelScope.launch {
            _isRoutingLoading.value = true
            _resultTitle.value = "Routing Test"
            try {
                val rules = CoreRepository.listRules()
                val testDomain = "baidu.com"
                var matchedRule = "Final (No match)"
                var matchedOutbound = "direct"

                for (rule in rules) {
                    if (rule.payload.isNotEmpty() && testDomain.contains(rule.payload)) {
                        matchedRule = "${rule.type}: ${rule.payload}"
                        matchedOutbound = rule.outbound
                        break
                    }
                }

                _resultMessage.value = "Test Domain: $testDomain\n\nResult:\nRule: $matchedRule\nOutbound: $matchedOutbound\n\nNote: Simulated routing, not actual traffic flow."
            } catch (e: Exception) {
                _resultMessage.value = "Routing test failed: ${e.message}"
            } finally {
                _isRoutingLoading.value = false
                _showResultDialog.value = true
            }
        }
    }

    private fun tcpPing(host: String, port: Int): Long {
        return try {
            val start = System.currentTimeMillis()
            Socket().use { socket ->
                socket.connect(InetSocketAddress(host, port), 5000)
            }
            System.currentTimeMillis() - start
        } catch (_: Exception) { -1L }
    }

    private fun resolveNetworkType(): String {
        val cm = getApplication<Application>()
            .getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager
        val caps = cm?.activeNetwork?.let { cm.getNetworkCapabilities(it) } ?: return "unknown"
        return when {
            caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) -> "wifi"
            caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) -> "ethernet"
            caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) -> "cellular"
            else -> "other"
        }
    }

    private fun resolveEffectiveMtu(settings: AppSettings, networkType: String): Int {
        if (!settings.tunMtuAuto) return settings.tunMtu
        val recommended = when (networkType) {
            "wifi", "ethernet" -> 1480
            "cellular" -> 1400
            else -> settings.tunMtu
        }
        return minOf(settings.tunMtu, recommended)
    }

    private fun resolveTunStack(settings: AppSettings): String {
        return if (Build.MODEL.contains("SM-G986U", ignoreCase = true)) {
            "GVISOR (forced for device ${Build.MODEL})"
        } else {
            settings.tunStack.name
        }
    }
}
