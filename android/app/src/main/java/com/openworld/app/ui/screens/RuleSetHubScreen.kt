package com.openworld.app.ui.screens

import android.widget.Toast
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Download
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.lifecycle.viewmodel.compose.viewModel
import com.openworld.app.ui.components.StandardCard
import com.openworld.app.viewmodel.RuleRoutingViewModel

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun RuleSetHubScreen(
    onBack: () -> Unit = {},
    viewModel: RuleRoutingViewModel = viewModel()
) {
    val state by viewModel.state.collectAsState()
    val context = LocalContext.current

    val presets = listOf(
        Triple("geosite-cn", "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-cn.srs", "国内域名规则"),
        Triple("geosite-geolocation-!cn", "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-geolocation-!cn.srs", "海外域名规则"),
        Triple("geoip-cn", "https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/geoip-cn.srs", "国内 IP 规则"),
        Triple("geoip-private", "https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/geoip-private.srs", "私网 IP 规则")
    )

    LaunchedEffect(Unit) {
        viewModel.toast.collect {
            Toast.makeText(context, it, Toast.LENGTH_SHORT).show()
        }
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("规则库") },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "返回")
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = MaterialTheme.colorScheme.background
                )
            )
        }
    ) { padding ->
        LazyColumn(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(horizontal = 16.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            item {
                Spacer(modifier = Modifier.height(4.dp))
                Text(
                    text = "一键导入常用规则源，若名称重复会提示冲突。",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.padding(vertical = 6.dp)
                )
            }
            items(presets, key = { it.first }) { preset ->
                val exists = state.ruleSets.any { it.name.equals(preset.first, ignoreCase = true) }
                StandardCard {
                    Column(modifier = Modifier.padding(horizontal = 12.dp, vertical = 10.dp)) {
                        Text(preset.first, style = MaterialTheme.typography.titleSmall)
                        Text(
                            text = preset.third,
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                        Text(
                            text = preset.second,
                            style = MaterialTheme.typography.labelSmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis
                        )
                        Spacer(modifier = Modifier.height(8.dp))
                        androidx.compose.material3.Button(
                            onClick = {
                                if (exists) {
                                    Toast.makeText(context, "已存在同名规则集", Toast.LENGTH_SHORT).show()
                                } else {
                                    viewModel.addRuleSet(preset.first, preset.second, 24)
                                }
                            },
                            enabled = !exists && !state.saving,
                            modifier = Modifier.fillMaxWidth()
                        ) {
                            Icon(Icons.Filled.Download, contentDescription = null)
                            Text(if (exists) "  已导入" else "  导入")
                        }
                    }
                }
            }
            item { Spacer(modifier = Modifier.height(16.dp)) }
        }
    }
}
