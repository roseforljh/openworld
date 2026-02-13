package com.openworld.app.ui.screens

import android.net.VpnService
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.material3.Button
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import com.openworld.app.config.ConfigManager
import com.openworld.app.ui.components.StandardCard
import com.openworld.core.OpenWorldCore
import kotlinx.coroutines.delay

private enum class CheckLevel { PASS, WARN, FAIL }

private data class StartupCheck(
    val title: String,
    val message: String,
    val level: CheckLevel
)

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SplashScreen(
    onFinished: () -> Unit = {}
) {
    val context = LocalContext.current
    var checks by remember { mutableStateOf<List<StartupCheck>>(emptyList()) }
    var checking by remember { mutableStateOf(true) }
    var nonce by remember { mutableStateOf(0) }

    suspend fun runChecks() {
        checking = true

        val vpnGranted = VpnService.prepare(context) == null
        val profileCount = runCatching { ConfigManager.listProfiles(context).size }.getOrDefault(0)
        val coreVersion = runCatching { OpenWorldCore.version() }.getOrDefault("")
        val coreReady = coreVersion.isNotBlank() && !coreVersion.equals("N/A", ignoreCase = true)

        val next = listOf(
            StartupCheck(
                title = "VPN 权限",
                message = if (vpnGranted) "已授权" else "未授权（首次连接时会请求）",
                level = if (vpnGranted) CheckLevel.PASS else CheckLevel.WARN
            ),
            StartupCheck(
                title = "配置完整性",
                message = if (profileCount > 0) "已检测到 $profileCount 份配置" else "未发现配置，将使用默认配置",
                level = if (profileCount > 0) CheckLevel.PASS else CheckLevel.WARN
            ),
            StartupCheck(
                title = "核心可用性",
                message = if (coreReady) "可用（$coreVersion）" else "不可用（JNI/内核初始化失败）",
                level = if (coreReady) CheckLevel.PASS else CheckLevel.FAIL
            )
        )

        checks = next
        checking = false

        if (next.none { it.level == CheckLevel.FAIL }) {
            delay(600)
            onFinished()
        }
    }

    LaunchedEffect(nonce) {
        runChecks()
    }

    Scaffold { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(20.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.Center
        ) {
            Text(
                text = "OpenWorld",
                style = MaterialTheme.typography.headlineMedium,
                fontWeight = FontWeight.Bold
            )
            Spacer(modifier = Modifier.height(16.dp))

            StandardCard {
                Column(modifier = Modifier.padding(horizontal = 16.dp, vertical = 12.dp)) {
                    if (checking) {
                        Row(verticalAlignment = Alignment.CenterVertically) {
                            CircularProgressIndicator(modifier = Modifier.size(18.dp), strokeWidth = 2.dp)
                            Spacer(modifier = Modifier.width(6.dp))
                            Text("正在执行启动检查…", style = MaterialTheme.typography.bodyMedium)
                        }
                    } else {
                        checks.forEach { item ->
                            val prefix = when (item.level) {
                                CheckLevel.PASS -> "通过"
                                CheckLevel.WARN -> "提示"
                                CheckLevel.FAIL -> "失败"
                            }
                            Text(
                                text = "$prefix · ${item.title}",
                                style = MaterialTheme.typography.titleSmall,
                                color = when (item.level) {
                                    CheckLevel.PASS -> MaterialTheme.colorScheme.primary
                                    CheckLevel.WARN -> MaterialTheme.colorScheme.tertiary
                                    CheckLevel.FAIL -> MaterialTheme.colorScheme.error
                                }
                            )
                            Text(
                                text = item.message,
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                                modifier = Modifier.padding(bottom = 8.dp)
                            )
                        }
                    }
                }
            }

            val hasFail = checks.any { it.level == CheckLevel.FAIL }
            if (!checking && hasFail) {
                Spacer(modifier = Modifier.height(14.dp))
                Row(modifier = Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    Button(onClick = { onFinished() }, modifier = Modifier.weight(1f)) {
                        Text("继续进入")
                    }
                    Button(onClick = { nonce += 1 }, modifier = Modifier.weight(1f)) {
                        Text("重试")
                    }
                }
            }
        }
    }
}
