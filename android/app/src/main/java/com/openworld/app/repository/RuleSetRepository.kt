package com.openworld.app.repository

import android.content.Context
import android.util.Log
import com.openworld.app.model.AppSettings
import com.openworld.app.model.RuleSet
import com.openworld.app.model.RuleSetType
import com.openworld.app.util.NetworkClient
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.withContext
import okhttp3.OkHttpClient
import okhttp3.Request
import java.io.File

/**
 * RuleSetRepository - Manages rule set downloads and caching
 */
class RuleSetRepository private constructor(private val context: Context) {

    companion object {
        private const val TAG = "RuleSetRepository"

        @Volatile
        private var instance: RuleSetRepository? = null

        fun getInstance(context: Context): RuleSetRepository {
            return instance ?: synchronized(this) {
                instance ?: RuleSetRepository(context.applicationContext).also { instance = it }
            }
        }
    }

    private val ruleSetDir: File
        get() = File(context.filesDir, "rulesets").also { it.mkdirs() }

    private val settingsRepository = SettingsRepository.getInstance(context)

    private fun getDirectClient(): OkHttpClient {
        return NetworkClient.createClientWithTimeout(
            connectTimeoutSeconds = 30,
            readTimeoutSeconds = 60,
            writeTimeoutSeconds = 30
        )
    }

    private fun getProxyClient(settings: AppSettings): OkHttpClient? {
        // Mocking VPN state check: Assuming VPN is NOT active or handled elsewhere for now
        // if (!VpnStateStore.getActive() || settings.proxyPort <= 0) {
        if (settings.proxyPort <= 0) {
            return null
        }
        return NetworkClient.createClientWithProxy(
            proxyPort = settings.proxyPort,
            connectTimeoutSeconds = 30,
            readTimeoutSeconds = 60,
            writeTimeoutSeconds = 30
        )
    }

    fun isRuleSetLocal(tag: String): Boolean {
        return getRuleSetFile(tag).exists()
    }

    suspend fun ensureRuleSetsReady(
        forceUpdate: Boolean = false,
        allowNetwork: Boolean = false,
        onProgress: (String) -> Unit = {}
    ): Boolean = withContext(Dispatchers.IO) {
        val settings = settingsRepository.settings.first()
        var allReady = true

        settings.ruleSets.filter { it.enabled && it.type == RuleSetType.REMOTE }.forEach { ruleSet ->
            val file = getRuleSetFile(ruleSet.tag)

            if (allowNetwork && (!file.exists() || (forceUpdate))) {
                onProgress("Updating rule set: ${ruleSet.tag}...")
                val success = downloadCustomRuleSet(ruleSet, settings)
                if (!success && !file.exists()) {
                    allReady = false
                    Log.e(TAG, "Failed to download rule set ${ruleSet.tag}")
                }
            } else if (!file.exists()) {
                allReady = false
                Log.w(TAG, "Rule set ${ruleSet.tag} missing")
            }
        }

        allReady
    }

    suspend fun prefetchRuleSet(
        ruleSet: RuleSet,
        forceUpdate: Boolean = false,
        allowNetwork: Boolean = true
    ): Boolean = withContext(Dispatchers.IO) {
        if (!ruleSet.enabled) return@withContext true

        val settings = settingsRepository.settings.first()

        return@withContext when (ruleSet.type) {
            RuleSetType.LOCAL -> File(ruleSet.path).exists()
            RuleSetType.REMOTE -> {
                val file = getRuleSetFile(ruleSet.tag)
                if (!allowNetwork) {
                    file.exists()
                } else if (!file.exists() || forceUpdate) {
                    val success = downloadCustomRuleSet(ruleSet, settings)
                    success || file.exists()
                } else {
                    true
                }
            }
        }
    }

    fun getRuleSetPath(tag: String): String {
        return getRuleSetFile(tag).absolutePath
    }

    private fun getRuleSetFile(tag: String): File {
        return File(ruleSetDir, "$tag.srs")
    }

    private suspend fun downloadCustomRuleSet(
        ruleSet: RuleSet,
        settings: AppSettings
    ): Boolean {
        if (ruleSet.url.isBlank()) return false
        val mirrorUrl = settings.ghProxyMirror.url

        val mirrorUrlString = normalizeRuleSetUrl(ruleSet.url, mirrorUrl)
        val success = downloadFileWithFallback(mirrorUrlString, getRuleSetFile(ruleSet.tag), settings)

        if (success) return true

        if (mirrorUrlString != ruleSet.url) {
            Log.w(TAG, "Mirror download failed, trying original URL: ${ruleSet.url}")
            return downloadFileWithFallback(ruleSet.url, getRuleSetFile(ruleSet.tag), settings)
        }

        return false
    }

    private fun normalizeRuleSetUrl(url: String, mirrorUrl: String): String {
        val rawPrefix = "https://raw.githubusercontent.com/"
        val cdnPrefix = "https://cdn.jsdelivr.net/gh/"
        var rawUrl = url

        if (rawUrl.startsWith(cdnPrefix)) {
            val path = rawUrl.removePrefix(cdnPrefix)
            val parts = path.split("@", limit = 2)
            if (parts.size == 2) {
                val userRepo = parts[0]
                val branchPath = parts[1]
                rawUrl = "$rawPrefix$userRepo/$branchPath"
            }
        }

        if (rawUrl.contains("raw.githubusercontent.com")) {
            var path = rawUrl.substringAfter("raw.githubusercontent.com/")
            while (path.contains("raw.githubusercontent.com/")) {
                path = path.substringAfter("raw.githubusercontent.com/")
            }
            if (path.startsWith("https://") || path.startsWith("http://")) {
                path = path.replace("https://", "").replace("http://", "")
            }
            rawUrl = rawPrefix + path
        }

        var updatedUrl = rawUrl

        if (mirrorUrl.contains("cdn.jsdelivr.net")) {
            if (rawUrl.startsWith(rawPrefix)) {
                val path = rawUrl.removePrefix(rawPrefix)
                val parts = path.split("/", limit = 4)
                if (parts.size >= 4) {
                    val user = parts[0]
                    val repo = parts[1]
                    val branch = parts[2]
                    val filePath = parts[3]
                    updatedUrl = "$cdnPrefix$user/$repo@$branch/$filePath"
                }
            }
        } else if (mirrorUrl != rawPrefix) {
            if (rawUrl.startsWith(rawPrefix)) {
                updatedUrl = rawUrl.replace(rawPrefix, mirrorUrl)
            }
        }

        return updatedUrl
    }

    private suspend fun downloadFileWithFallback(
        url: String,
        targetFile: File,
        settings: AppSettings
    ): Boolean {
        val proxyClient = getProxyClient(settings)
        if (proxyClient != null) {
            try {
                val success = downloadFile(proxyClient, url, targetFile)
                if (success) {
                    return true
                }
            } catch (e: Exception) {
                Log.w(TAG, "Proxy download error: ${e.message}, falling back to direct")
            }
        }

        return downloadFile(getDirectClient(), url, targetFile)
    }

    private fun downloadFile(client: OkHttpClient, url: String, targetFile: File): Boolean {
        return try {
            val request = Request.Builder().url(url).build()
            client.newCall(request).execute().use { response ->
                if (!response.isSuccessful) return false

                val body = response.body ?: return false
                val tempFile = File(targetFile.parent, "${targetFile.name}.tmp")

                body.byteStream().use { input ->
                    tempFile.outputStream().use { output ->
                        input.copyTo(output)
                    }
                }

                if (tempFile.length() > 10) {
                     if (targetFile.exists()) {
                        targetFile.delete()
                    }
                    tempFile.renameTo(targetFile)
                    true
                } else {
                    tempFile.delete()
                    false
                }
            }
        } catch (e: Exception) {
            Log.e(TAG, "Download error: ${e.message}", e)
            false
        }
    }
}
