package com.openworld.app.ui.screens

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.net.VpnService
import android.widget.Toast
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.ContentCopy
import androidx.compose.material3.Button
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import com.openworld.app.repository.CoreRepository
import com.openworld.core.OpenWorldCore

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun DiagnosticsScreen(onBack: () -> Unit) {
    val context = LocalContext.current
    var result by remember { mutableStateOf(buildResult(context)) }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("诊断") },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "返回")
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(containerColor = MaterialTheme.colorScheme.background)
            )
        }
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(16.dp)
                .verticalScroll(rememberScrollState()),
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            Text(result, style = MaterialTheme.typography.bodySmall)

            Button(onClick = { result = buildResult(context) }, modifier = Modifier.fillMaxWidth()) {
                Text("重新检测")
            }
            Button(onClick = {
                copyText(context, result)
                Toast.makeText(context, "诊断结果已复制", Toast.LENGTH_SHORT).show()
            }, modifier = Modifier.fillMaxWidth()) {
                Icon(Icons.Filled.ContentCopy, contentDescription = null)
                Text("  复制结果")
            }
        }
    }
}

private fun buildResult(context: Context): String {
    val dnsCheck = runCatching { CoreRepository.dnsQuery("example.com", "A") }.getOrDefault("")
    val dnsOk = dnsCheck.contains("answer", true) || dnsCheck.contains("93.184.216.34")
    val status = runCatching { CoreRepository.getStatus() }.getOrDefault(CoreRepository.CoreStatus())
    val vpnPrepared = VpnService.prepare(context) == null
    val running = runCatching { OpenWorldCore.isRunning() }.getOrDefault(false)

    return buildString {
        appendLine("[DNS 可达性] ${if (dnsOk) "OK" else "FAILED"}")
        appendLine("[Core 运行状态] ${if (running) "RUNNING" else "STOPPED"}")
        appendLine("[VPN 权限] ${if (vpnPrepared) "GRANTED" else "REQUIRED"}")
        appendLine("[连接数] ${status.connections}")
        appendLine("[模式] ${status.mode}")
        appendLine("[上传] ${status.upload}")
        appendLine("[下载] ${status.download}")
    }
}

private fun copyText(context: Context, text: String) {
    val cm = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
    cm.setPrimaryClip(ClipData.newPlainText("diagnostics", text))
}
