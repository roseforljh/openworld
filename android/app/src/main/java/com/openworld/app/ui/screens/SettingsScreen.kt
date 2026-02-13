package com.openworld.app.ui.screens

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Dns
import androidx.compose.material.icons.filled.BugReport
import androidx.compose.material.icons.filled.Info
import androidx.compose.material.icons.filled.Language
import androidx.compose.material.icons.filled.Route
import androidx.compose.material.icons.filled.Save
import androidx.compose.material.icons.filled.SwapVert
import androidx.compose.material.icons.filled.Timeline
import androidx.compose.material.icons.outlined.Article
import androidx.compose.material.icons.outlined.Palette
import androidx.compose.material.icons.outlined.PlayCircle
import androidx.compose.material.icons.outlined.Security
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.MaterialTheme
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
import androidx.navigation.NavController
import com.openworld.app.MainActivity
import com.openworld.app.model.AppThemeMode
import com.openworld.app.ui.components.ConfirmDialog
import com.openworld.app.ui.components.SettingItem
import com.openworld.app.ui.components.SettingSwitchItem
import com.openworld.app.ui.components.SingleSelectDialog
import com.openworld.app.ui.components.StandardCard
import com.openworld.app.ui.navigation.Screen
import com.openworld.app.viewmodel.SettingsViewModel

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun SettingsScreen(
    navController: NavController,
    viewModel: SettingsViewModel = viewModel()
) {
    val state by viewModel.state.collectAsState()
    val context = LocalContext.current
    var showThemeDialog by remember { mutableStateOf(false) }
    var showLanguageDialog by remember { mutableStateOf(false) }
    var showRestartDialog by remember { mutableStateOf(false) }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("设置") },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = MaterialTheme.colorScheme.background
                )
            )
        }
    ) { padding ->
        androidx.compose.foundation.layout.Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
                .padding(horizontal = 16.dp)
                .verticalScroll(rememberScrollState()),
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            Spacer(modifier = Modifier.height(4.dp))

            StandardCard {
                SettingItem(
                    title = "主题",
                    subtitle = "跟随系统 / 浅色 / 深色",
                    icon = Icons.Outlined.Palette,
                    onClick = { showThemeDialog = true }
                )
                SettingItem(
                    title = "语言",
                    subtitle = when (state.appLanguage) {
                        "zh-cn" -> "简体中文"
                        "en" -> "English"
                        else -> "跟随系统"
                    },
                    icon = Icons.Filled.Language,
                    onClick = { showLanguageDialog = true }
                )
                SettingItem(
                    title = "连接与启动",
                    subtitle = "查看连接模式与启动行为",
                    icon = Icons.Outlined.PlayCircle,
                    onClick = { navController.navigate(Screen.ConnectionSettings.route) }
                )
            }

            StandardCard {
                SettingItem(
                    title = "路由设置",
                    subtitle = state.routingMode.uppercase(),
                    icon = Icons.Filled.Route,
                    onClick = { navController.navigate(Screen.RoutingSettings.route) }
                )
                SettingItem(
                    title = "DNS 设置",
                    subtitle = "本地: ${state.dnsLocal}",
                    icon = Icons.Filled.Dns,
                    onClick = { navController.navigate(Screen.DnsSettings.route) }
                )
                SettingItem(
                    title = "TUN 设置",
                    subtitle = "MTU ${state.tunMtu} / IPv6 ${if (state.tunIpv6Enabled) "开" else "关"}",
                    icon = Icons.Outlined.Security,
                    onClick = { navController.navigate(Screen.TunSettings.route) }
                )
            }

            StandardCard {
                SettingItem(
                    title = "诊断",
                    subtitle = "DNS / VPN / Core 状态检测",
                    icon = Icons.Filled.BugReport,
                    onClick = { navController.navigate(Screen.Diagnostics.route) }
                )
                SettingItem(
                    title = "数据管理",
                    subtitle = "备份导出 / 恢复导入",
                    icon = Icons.Filled.Save,
                    onClick = { navController.navigate(Screen.DataManagement.route) }
                )
            }

            StandardCard {
                SettingSwitchItem(
                    title = "调试日志",
                    subtitle = "启用后将显示更多日志",
                    icon = Icons.Outlined.Article,
                    checked = state.debugLogging,
                    onCheckedChange = { viewModel.setDebugLoggingEnabled(it) }
                )
                SettingItem(
                    title = "运行日志",
                    subtitle = "查看内核运行日志",
                    icon = Icons.Outlined.Article,
                    onClick = { navController.navigate(Screen.Logs.route) }
                )
            }

            StandardCard {
                SettingItem(
                    title = "流量统计",
                    subtitle = "按出站分组查看流量",
                    icon = Icons.Filled.Timeline,
                    onClick = { navController.navigate(Screen.TrafficStats.route) }
                )
                SettingItem(
                    title = "活跃连接",
                    subtitle = "查看当前连接状态",
                    icon = Icons.Filled.SwapVert,
                    onClick = { navController.navigate(Screen.Connections.route) }
                )
            }

            StandardCard {
                SettingItem(
                    title = "关于 OpenWorld",
                    subtitle = "v${state.appVersion} / 内核 ${state.coreVersion}",
                    icon = Icons.Filled.Info,
                    onClick = { navController.navigate(Screen.About.route) }
                )
            }

            Spacer(modifier = Modifier.height(16.dp))
        }
    }

    if (showThemeDialog) {
        val activity = context as? MainActivity
        SingleSelectDialog(
            title = "选择主题",
            options = listOf("SYSTEM", "LIGHT", "DARK"),
            selectedOption = state.appTheme,
            onSelect = {
                viewModel.setAppTheme(it)
                activity?.updateTheme(AppThemeMode.valueOf(it))
                showThemeDialog = false
            },
            onDismiss = { showThemeDialog = false }
        )
    }

    if (showLanguageDialog) {
        SingleSelectDialog(
            title = "选择语言",
            options = listOf("system", "zh-cn", "en"),
            selectedOption = state.appLanguage,
            onSelect = {
                viewModel.setAppLanguage(it)
                showLanguageDialog = false
                showRestartDialog = true
            },
            onDismiss = { showLanguageDialog = false }
        )
    }

    if (showRestartDialog) {
        val activity = context as? MainActivity
        ConfirmDialog(
            title = "重启提示",
            message = "语言切换将在重启应用后完全生效，是否立即重启？",
            confirmText = "立即重启",
            onConfirm = {
                showRestartDialog = false
                activity?.recreate()
            },
            onDismiss = { showRestartDialog = false }
        )
    }
}

