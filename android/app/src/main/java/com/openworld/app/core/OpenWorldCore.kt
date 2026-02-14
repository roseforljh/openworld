package com.openworld.app.core

import android.content.Context
import android.util.Log
import com.google.gson.Gson
import com.openworld.app.model.Outbound
import com.openworld.app.model.OpenWorldConfig
import com.openworld.app.ipc.VpnStateStore
import com.openworld.core.OpenWorldCore as NativeCore
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File

/**
 * OpenWorld 核心封装�? * 负责�?OpenWorldCore (libopenworld.so) 交互
 */
class OpenWorldCore private constructor(private val context: Context) {

    private val gson = Gson()
    private val workDir: File = File(context.filesDir, "openworld_work")
    private val tempDir: File = File(context.cacheDir, "openworld_temp")

    // OpenWorld 内核是否可用
    private var coreAvailable = false

    companion object {
        private const val TAG = "OpenWorldCore"

        @Volatile
        private var instance: OpenWorldCore? = null

        fun getInstance(context: Context): OpenWorldCore {
            return instance ?: synchronized(this) {
                instance ?: OpenWorldCore(context.applicationContext).also { instance = it }
            }
        }

        fun ensureCoreSetup(context: Context) {
            getInstance(context)
        }
    }

    init {
        workDir.mkdirs()
        tempDir.mkdirs()
        coreAvailable = checkCoreAvailable()
    }

    private fun checkCoreAvailable(): Boolean {
        return try {
            val version = NativeCore.version()
            version.isNotBlank()
        } catch (e: Exception) {
            Log.e(TAG, "OpenWorldCore not available: ${e.message}")
            false
        }
    }

    /**
     * 检查内核是否可�?     */
    fun isCoreAvailable(): Boolean = coreAvailable

    /**
     * 验证配置是否有效
     */
    suspend fun validateConfig(config: OpenWorldConfig): Result<Unit> = withContext(Dispatchers.IO) {
        if (!coreAvailable) {
            return@withContext try {
                gson.toJson(config)
                Result.success(Unit)
            } catch (e: Exception) {
                Result.failure(e)
            }
        }

        try {
            val configJson = gson.toJson(config)
            // OpenWorldCore 没有 checkConfig，回退�?JSON 验证
            gson.fromJson(configJson, OpenWorldConfig::class.java)
            Result.success(Unit)
        } catch (e: Exception) {
            Log.e(TAG, "Config validation failed", e)
            Result.failure(e)
        }
    }

    /**
     * 验证单个 Outbound 是否有效
     */
    fun validateOutbound(outbound: Outbound): Boolean {
        if (!coreAvailable) return true

        // 跳过特殊类型�?outbound
        if (outbound.type in listOf("direct", "block", "dns", "selector", "urltest", "url-test")) {
            return true
        }

        val minimalConfig = OpenWorldConfig(
            log = null,
            dns = null,
            inbounds = null,
            outbounds = listOf(
                outbound,
                Outbound(type = "direct", tag = "direct")
            ),
            route = null,
            experimental = null
        )

        return try {
            gson.toJson(minimalConfig)
            true
        } catch (e: Exception) {
            Log.w(TAG, "Outbound validation failed for '${outbound.tag}': ${e.message}")
            false
        }
    }

    fun formatConfig(config: OpenWorldConfig): String = gson.toJson(config)

    suspend fun testOutboundLatency(outbound: Outbound, allOutbounds: List<Outbound>): Long {
        val tag = outbound.tag
        if (tag.isBlank()) return -1L
        return withContext(Dispatchers.IO) {
            runCatching {
                NativeCore.urlTest(tag, "https://www.gstatic.com/generate_204", 4500).toLong()
            }.getOrDefault(-1L)
        }
    }

    suspend fun testOutboundsLatency(
        outbounds: List<Outbound>,
        onNodeComplete: (String, Long) -> Unit
    ) = withContext(Dispatchers.IO) {
        outbounds.forEach { outbound ->
            val tag = outbound.tag
            if (tag.isBlank()) return@forEach
            val latency = runCatching {
                NativeCore.urlTest(tag, "https://www.gstatic.com/generate_204", 4500).toLong()
            }.getOrDefault(-1L)
            onNodeComplete(tag, latency)
        }
    }

    /**
     * 独立延迟测试（不依赖核心启动�?     * 使用新的latencyTester API
     *
     * @param outbounds 要测试的节点列表
     * @param url 测试URL
     * @param timeoutMs 超时时间（毫秒）
     * @return Map<节点标签, 延迟毫秒�?
     */
    suspend fun testOutboundsLatencyStandalone(
        outbounds: List<Outbound>,
        url: String = "https://www.gstatic.com/generate_204",
        timeoutMs: Int = 5000
    ): Map<String, Long> = withContext(Dispatchers.IO) {
        if (outbounds.isEmpty()) {
            Log.d(TAG, "testOutboundsLatencyStandalone: outbounds is empty")
            return@withContext emptyMap()
        }

        Log.d(TAG, "testOutboundsLatencyStandalone: Testing ${outbounds.size} nodes, timeout=$timeoutMs ms")

        // 将outbounds转换为JSON
        val gson = Gson()
        val outboundsJson = gson.toJson(outbounds)
        Log.d(TAG, "testOutboundsLatencyStandalone: JSON size=${outboundsJson.length}")

        // 初始化测试器
        val initResult = NativeCore.latencyTesterInit(outboundsJson)
        if (initResult != 0) {
            Log.d(TAG, "testOutboundsLatencyStandalone: initResult=$initResult")
            Log.e(TAG, "Failed to init latency tester: $initResult")
            return@withContext outbounds.associate { it.tag to -1L }
        }

        // 执行测试
        Log.d(TAG, "testOutboundsLatencyStandalone: Starting latency test...")
        val startTime = System.currentTimeMillis()
        val resultsJson = NativeCore.latencyTestAll(url, timeoutMs)
        val elapsed = System.currentTimeMillis() - startTime
        Log.d(TAG, "testOutboundsLatencyStandalone: Test completed in ${elapsed}ms")
        
        NativeCore.latencyTesterFree()
        Log.d(TAG, "testOutboundsLatencyStandalone: Tester freed")

        if (resultsJson.isNullOrEmpty()) {
            Log.w(TAG, "testOutboundsLatencyStandalone: resultsJson is null or empty")
            return@withContext outbounds.associate { it.tag to -1L }
        }

        // 解析结果
        try {
            val results: List<Map<String, Any>> = gson.fromJson(
                resultsJson,
                object : com.google.gson.reflect.TypeToken<List<Map<String, Any>>>() {}.type
            )
            
            Log.d(TAG, "testOutboundsLatencyStandalone: resultsJson=$resultsJson")

            val latencyMap = results.associate {
                val tag = it["tag"] as? String ?: ""
                val latency = (it["latency_ms"] as? Number)?.toLong() ?: -1L
                val error = it["error"]
                Log.d(TAG, "testOutboundsLatencyStandalone: node=$tag, latency=${latency}ms, error=$error")
                tag to latency
            }
            Log.d(TAG, "testOutboundsLatencyStandalone: Total ${latencyMap.size} nodes tested")
            latencyMap
        } catch (e: Exception) {
            Log.e(TAG, "Failed to parse latency results", e)
            outbounds.associate { it.tag to -1L }
        }
    }

    /**
     * 检查是否有活跃的连�?     */
    fun hasActiveConnections(): Boolean {
        if (!coreAvailable) return false
        return try {
            BoxWrapperManager.isAvailable() && VpnStateStore.getActive()
        } catch (e: Exception) {
            false
        }
    }

    /**
     * 获取活跃连接列表
     */
    @Suppress("FunctionOnlyReturningConstant")
    fun getActiveConnections(): List<ActiveConnection> = emptyList()

    /**
     * 关闭指定应用的连�?     */
    fun closeConnectionsForApp(packageName: String): Int {
        if (!coreAvailable) return 0
        return BoxWrapperManager.closeConnectionsForApp(packageName)
    }

    fun closeConnections(packageName: String, uid: Int): Boolean {
        return closeConnectionsForApp(packageName) > 0
    }

    data class ActiveConnection(
        val packageName: String?,
        val uid: Int,
        val network: String,
        val remoteAddr: String,
        val remotePort: Int,
        val state: String,
        val connectionCount: Int = 0,
        val totalUpload: Long = 0,
        val totalDownload: Long = 0,
        val oldestConnMs: Long = 0,
        val newestConnMs: Long = 0,
        val hasRecentData: Boolean = true
    )

    fun cleanup() {
        // 清理资源
    }
}







