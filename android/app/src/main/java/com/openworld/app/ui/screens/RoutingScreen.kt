package com.openworld.app.ui.screens

import android.widget.Toast
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
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
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.lifecycle.viewmodel.compose.viewModel
import com.openworld.app.repository.CoreRepository
import com.openworld.app.ui.components.SingleSelectDialog
import com.openworld.app.ui.components.StandardCard
import com.openworld.app.ui.components.SettingItem
import com.openworld.app.viewmodel.RuleRoutingViewModel
import com.openworld.app.viewmodel.SettingsViewModel

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun RoutingScreen(
    onBack: () -> Unit = {},
    onRuleSets: () -> Unit = {},
    onRuleSetHub: () -> Unit = {},
    onDomainRules: () -> Unit = {},
    onAppRules: () -> Unit = {},
    viewModel: SettingsViewModel = viewModel(),
    ruleRoutingViewModel: RuleRoutingViewModel = viewModel()
) {
    val state by viewModel.state.collectAsState()
    val routingState by ruleRoutingViewModel.state.collectAsState()
    val context = LocalContext.current
    var showModeDialog by remember { mutableStateOf(false) }
    var showDefaultOutboundDialog by remember { mutableStateOf(false) }

    LaunchedEffect(Unit) {
        ruleRoutingViewModel.toast.collect {
            Toast.makeText(context, it, Toast.LENGTH_SHORT).show()
        }
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("路由设置") },
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
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(16.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            StandardCard {
                SettingItem(
                    title = "当前路由模式",
                    value = state.routingMode.uppercase(),
                    subtitle = "点击切换 Rule / Global / Direct",
                    onClick = { showModeDialog = true }
                )
                SettingItem(
                    title = "默认策略",
                    value = routingState.selectedOutbound.ifBlank { "未设置" },
                    subtitle = if (routingState.hasSelector) "点击切换默认出站" else "当前内核未暴露选择器",
                    onClick = if (routingState.hasSelector) ({ showDefaultOutboundDialog = true }) else null
                )
                SettingItem(
                    title = "规则数量",
                    value = CoreRepository.getRoutingRuleCount().toString(),
                    subtitle = "当前已加载的路由规则条目"
                )
                SettingItem(
                    title = "规则集数量",
                    value = routingState.ruleSets.size.toString(),
                    subtitle = "当前已导入规则集"
                )
                SettingItem(
                    title = "域名规则",
                    value = routingState.domainRules.size.toString(),
                    subtitle = "自定义域名分流条目"
                )
                SettingItem(
                    title = "应用规则",
                    value = routingState.appRules.size.toString(),
                    subtitle = "按应用包名分流条目"
                )
            }

            if (routingState.needsReconnectHint) {
                StandardCard {
                    SettingItem(
                        title = "重启提示",
                        subtitle = "规则与应用分流配置变更后，需断开并重新连接 VPN 生效"
                    )
                }
            }

            routingState.warning?.let { warning ->
                StandardCard {
                    SettingItem(
                        title = "提示",
                        subtitle = warning
                    )
                }
            }

            routingState.error?.let { error ->
                StandardCard {
                    SettingItem(
                        title = "错误",
                        subtitle = error,
                        onClick = { ruleRoutingViewModel.clearError() }
                    )
                }
            }

            StandardCard {
                SettingItem(
                    title = "规则集",
                    subtitle = "查看、更新、删除规则集",
                    onClick = onRuleSets
                )
                SettingItem(
                    title = "规则库",
                    subtitle = "导入预设规则源并检查冲突",
                    onClick = onRuleSetHub
                )
                SettingItem(
                    title = "域名规则",
                    subtitle = "按域名后缀/关键词/全匹配分流",
                    onClick = onDomainRules
                )
                SettingItem(
                    title = "应用分流",
                    subtitle = "按应用包名设置分流策略",
                    onClick = onAppRules
                )
            }
        }
    }

    if (showModeDialog) {
        SingleSelectDialog(
            title = "选择路由模式",
            options = listOf("rule", "global", "direct"),
            selectedOption = state.routingMode,
            onSelect = {
                viewModel.setRoutingMode(it)
                showModeDialog = false
            },
            onDismiss = { showModeDialog = false }
        )
    }

    if (showDefaultOutboundDialog) {
        SingleSelectDialog(
            title = "默认策略（出站）",
            options = routingState.outbounds.ifEmpty { listOf("direct", "proxy", "reject") },
            selectedOption = routingState.selectedOutbound,
            onSelect = {
                ruleRoutingViewModel.setDefaultOutbound(it)
                showDefaultOutboundDialog = false
            },
            onDismiss = { showDefaultOutboundDialog = false }
        )
    }
}
