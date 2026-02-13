package com.openworld.app.ui.screens

import android.widget.Toast
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Check
import androidx.compose.material3.Button
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.lifecycle.viewmodel.compose.viewModel
import com.openworld.app.repository.CoreRepository
import com.openworld.app.ui.components.SingleSelectDialog
import com.openworld.app.viewmodel.SettingsViewModel

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun DnsScreen(
    onBack: () -> Unit = {},
    viewModel: SettingsViewModel = viewModel()
) {
    val state by viewModel.state.collectAsState()
    val context = LocalContext.current
    var localDns by remember(state.dnsLocal) { mutableStateOf(state.dnsLocal) }
    var remoteDns by remember(state.dnsRemote) { mutableStateOf(state.dnsRemote) }
    var dnsMode by remember(state.dnsMode) { mutableStateOf(state.dnsMode) }
    var dnsServersText by remember(state.dnsServers) { mutableStateOf(state.dnsServers.joinToString("\n")) }
    var showModeDialog by remember { mutableStateOf(false) }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("DNS 设置") },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "返回")
                    }
                },
                actions = {
                    IconButton(onClick = {
                        viewModel.setDnsLocal(localDns)
                        viewModel.setDnsRemote(remoteDns)
                        viewModel.setDnsMode(dnsMode)
                        viewModel.setDnsServers(
                            dnsServersText.split("\n").map { it.trim() }.filter { it.isNotBlank() }
                        )
                        Toast.makeText(context, "DNS 设置已保存", Toast.LENGTH_SHORT).show()
                        onBack()
                    }) {
                        Icon(
                            Icons.Filled.Check,
                            contentDescription = "保存",
                            tint = MaterialTheme.colorScheme.primary
                        )
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = MaterialTheme.colorScheme.background
                )
            )
        }
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(16.dp)
        ) {
            // 本地 DNS 卡片
            Card(
                shape = RoundedCornerShape(16.dp),
                colors = CardDefaults.cardColors(
                    containerColor = MaterialTheme.colorScheme.surface
                )
            ) {
                Column(modifier = Modifier.padding(16.dp)) {
                    Text("本地 DNS", style = MaterialTheme.typography.titleMedium)
                    Text(
                        text = "用于解析国内域名，建议使用运营商或公共 DNS",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                    Spacer(modifier = Modifier.height(12.dp))
                    OutlinedTextField(
                        value = localDns,
                        onValueChange = { localDns = it },
                        label = { Text("DNS 地址") },
                        placeholder = { Text("223.5.5.5") },
                        singleLine = true,
                        shape = RoundedCornerShape(12.dp),
                        modifier = Modifier.fillMaxWidth()
                    )
                }
            }

            // 远程 DNS 卡片
            Card(
                shape = RoundedCornerShape(16.dp),
                colors = CardDefaults.cardColors(
                    containerColor = MaterialTheme.colorScheme.surface
                )
            ) {
                Column(modifier = Modifier.padding(16.dp)) {
                    Text("远程 DNS", style = MaterialTheme.typography.titleMedium)
                    Text(
                        text = "用于解析海外域名，支持 DoT/DoH 协议",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                    Spacer(modifier = Modifier.height(12.dp))
                    OutlinedTextField(
                        value = remoteDns,
                        onValueChange = { remoteDns = it },
                        label = { Text("DNS 地址") },
                        placeholder = { Text("tls://8.8.8.8") },
                        singleLine = true,
                        shape = RoundedCornerShape(12.dp),
                        modifier = Modifier.fillMaxWidth()
                    )
                }
            }

            Card(
                shape = RoundedCornerShape(16.dp),
                colors = CardDefaults.cardColors(
                    containerColor = MaterialTheme.colorScheme.surface
                )
            ) {
                Column(
                    modifier = Modifier.padding(16.dp),
                    verticalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    Text("DNS 模式", style = MaterialTheme.typography.titleSmall)
                    Text(
                        text = dnsMode,
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.primary
                    )
                    Button(onClick = { showModeDialog = true }) {
                        Text("切换模式")
                    }
                }
            }

            Card(
                shape = RoundedCornerShape(16.dp),
                colors = CardDefaults.cardColors(
                    containerColor = MaterialTheme.colorScheme.surfaceVariant.copy(alpha = 0.5f)
                )
            ) {
                Column(
                    modifier = Modifier.padding(16.dp),
                    verticalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    Text(
                        text = "DNS 服务器列表（每行一个）",
                        style = MaterialTheme.typography.titleSmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                    OutlinedTextField(
                        value = dnsServersText,
                        onValueChange = { dnsServersText = it },
                        minLines = 3,
                        maxLines = 6,
                        modifier = Modifier.fillMaxWidth(),
                        shape = RoundedCornerShape(12.dp)
                    )
                    Button(onClick = {
                        val ok = CoreRepository.dnsFlush()
                        Toast.makeText(context, if (ok) "DNS 缓存已清除" else "DNS 缓存清除失败", Toast.LENGTH_SHORT).show()
                    }) {
                        Text("清除 DNS 缓存")
                    }
                }
            }
        }
    }

    if (showModeDialog) {
        SingleSelectDialog(
            title = "DNS 模式",
            options = listOf("auto", "manual", "split"),
            selectedOption = dnsMode,
            onSelect = {
                dnsMode = it
                showModeDialog = false
            },
            onDismiss = { showModeDialog = false }
        )
    }
}
