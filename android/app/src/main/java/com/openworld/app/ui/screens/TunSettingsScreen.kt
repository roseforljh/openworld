package com.openworld.app.ui.screens

import android.widget.Toast
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Check
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Switch
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
import com.openworld.app.ui.components.SingleSelectDialog
import com.openworld.app.viewmodel.SettingsViewModel

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun TunSettingsScreen(
    onBack: () -> Unit,
    viewModel: SettingsViewModel = viewModel()
) {
    val state by viewModel.state.collectAsState()
    val context = LocalContext.current
    var mtu by remember(state.tunMtu) { mutableStateOf(state.tunMtu.toString()) }
    var showDnsModeDialog by remember { mutableStateOf(false) }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("TUN 设置") },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "返回")
                    }
                },
                actions = {
                    IconButton(onClick = {
                        viewModel.setTunMtu(mtu.toIntOrNull() ?: 1500)
                        Toast.makeText(context, "设置已保存，需重连生效", Toast.LENGTH_SHORT).show()
                        onBack()
                    }) {
                        Icon(Icons.Filled.Check, contentDescription = "保存", tint = MaterialTheme.colorScheme.primary)
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
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            OutlinedTextField(
                value = mtu,
                onValueChange = { mtu = it.filter { c -> c.isDigit() } },
                label = { Text("MTU") },
                singleLine = true,
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(12.dp)
            )

            androidx.compose.foundation.layout.Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween
            ) {
                Text("启用 IPv6")
                Switch(
                    checked = state.tunIpv6Enabled,
                    onCheckedChange = { viewModel.setTunIpv6Enabled(it) }
                )
            }

            androidx.compose.foundation.layout.Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween
            ) {
                Text("DNS 策略")
                Text(
                    text = state.dnsMode,
                    color = MaterialTheme.colorScheme.primary,
                    modifier = Modifier
                        .padding(4.dp)
                        .then(Modifier)
                )
            }
            androidx.compose.material3.TextButton(onClick = { showDnsModeDialog = true }) {
                Text("切换 DNS 模式")
            }

            Text(
                text = "连接中修改此页配置需重连生效",
                style = MaterialTheme.typography.bodySmall,
                color = MaterialTheme.colorScheme.onSurfaceVariant
            )
        }
    }

    if (showDnsModeDialog) {
        SingleSelectDialog(
            title = "DNS 模式",
            options = listOf("auto", "manual", "split"),
            selectedOption = state.dnsMode,
            onSelect = {
                viewModel.setDnsMode(it)
                showDnsModeDialog = false
            },
            onDismiss = { showDnsModeDialog = false }
        )
    }
}
