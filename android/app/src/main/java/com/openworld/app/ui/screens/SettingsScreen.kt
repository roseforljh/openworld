package com.openworld.app.ui.screens

import android.widget.Toast
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.asPaddingValues
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.statusBars
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.Analytics
import androidx.compose.material.icons.rounded.BugReport
import androidx.compose.material.icons.rounded.Dns
import androidx.compose.material.icons.rounded.Download
import androidx.compose.material.icons.rounded.History
import androidx.compose.material.icons.rounded.Info
import androidx.compose.material.icons.rounded.Language
import androidx.compose.material.icons.rounded.PowerSettingsNew
import androidx.compose.material.icons.rounded.Route
import androidx.compose.material.icons.rounded.Sync
import androidx.compose.material.icons.rounded.SystemUpdate
import androidx.compose.material.icons.rounded.Upload
import androidx.compose.material.icons.rounded.VpnKey
import androidx.compose.material.icons.rounded.Brightness6
import androidx.compose.material.icons.rounded.Schedule
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.lifecycle.viewmodel.compose.viewModel
import androidx.navigation.NavController
import com.openworld.app.R
import com.openworld.app.model.AppThemeMode
import com.openworld.app.model.AppLanguage
import com.openworld.app.ui.components.SettingItem
import com.openworld.app.ui.components.SettingSwitchItem
import com.openworld.app.ui.components.StandardCard
import com.openworld.app.ui.navigation.Screen
import com.openworld.app.viewmodel.SettingsViewModel
import kotlinx.coroutines.launch

@Composable
fun SettingsScreen(
    navController: NavController,
    viewModel: SettingsViewModel = viewModel()
) {
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val scrollState = rememberScrollState()
    val settings by viewModel.settings.collectAsState()
    // val exportState by viewModel.exportState.collectAsState()
    // val importState by viewModel.importState.collectAsState()

    var showThemeDialog by remember { mutableStateOf(false) }
    var showLanguageDialog by remember { mutableStateOf(false) }
    var isUpdatingRuleSets by remember { mutableStateOf(false) }

    // Placeholder for About/Theme/Language Dialogs which reuse SingleSelectDialog or others
    
    val statusBarPadding = WindowInsets.statusBars.asPaddingValues()

    Column(
        modifier = Modifier
            .fillMaxSize()
            .background(MaterialTheme.colorScheme.background)
            .padding(top = statusBarPadding.calculateTopPadding())
            .verticalScroll(scrollState)
            .padding(16.dp)
    ) {
        Text(
            text = stringResource(R.string.settings_title),
            style = MaterialTheme.typography.headlineMedium,
            fontWeight = FontWeight.Bold,
            color = MaterialTheme.colorScheme.onBackground,
            modifier = Modifier.padding(bottom = 16.dp)
        )

        // 1. Connection & Startup
        SettingsGroupTitle(stringResource(R.string.settings_general))
        StandardCard {
            SettingItem(
                title = stringResource(R.string.settings_app_theme),
                value = stringResource(settings.appTheme.displayNameRes),
                icon = Icons.Rounded.Brightness6,
                onClick = { showThemeDialog = true }
            )
            SettingItem(
                title = stringResource(R.string.settings_app_language),
                value = stringResource(settings.appLanguage.displayNameRes),
                icon = Icons.Rounded.Language,
                onClick = { showLanguageDialog = true }
            )
            SettingSwitchItem(
                title = "自动检查更新",
                subtitle = "启动应用时自动检查新版本",
                icon = Icons.Rounded.SystemUpdate,
                checked = settings.autoCheckUpdate,
                onCheckedChange = { viewModel.setAutoCheckUpdate(it) }
            )
            SettingItem(
                title = stringResource(R.string.settings_connection_startup),
                subtitle = stringResource(R.string.settings_connection_startup_subtitle),
                icon = Icons.Rounded.PowerSettingsNew,
                onClick = { navController.navigate(Screen.ConnectionSettings.route) }
            )
        }

        Spacer(modifier = Modifier.height(16.dp))

        // 2. Network
        SettingsGroupTitle(stringResource(R.string.settings_network))
        StandardCard {
            SettingItem(
                title = stringResource(R.string.settings_routing),
                subtitle = stringResource(R.string.settings_routing_subtitle),
                icon = Icons.Rounded.Route,
                onClick = { navController.navigate(Screen.RoutingSettings.route) }
            )
            SettingItem(
                title = stringResource(R.string.settings_dns),
                value = stringResource(R.string.settings_dns_auto),
                icon = Icons.Rounded.Dns,
                onClick = { navController.navigate(Screen.DnsSettings.route) }
            )
            SettingItem(
                title = stringResource(R.string.settings_tun_vpn),
                subtitle = stringResource(R.string.settings_tun_vpn_subtitle),
                icon = Icons.Rounded.VpnKey,
                onClick = { navController.navigate(Screen.TunSettings.route) }
            )
        }

        Spacer(modifier = Modifier.height(16.dp))

        // 3. Tools
        SettingsGroupTitle(stringResource(R.string.settings_tools))
        StandardCard {
            SettingSwitchItem(
                title = stringResource(R.string.settings_ruleset_auto_update),
                subtitle = if (settings.ruleSetAutoUpdateEnabled)
                    stringResource(R.string.settings_ruleset_auto_update_enabled, settings.ruleSetAutoUpdateInterval)
                else
                    stringResource(R.string.settings_ruleset_auto_update_disabled),
                icon = Icons.Rounded.Schedule,
                checked = settings.ruleSetAutoUpdateEnabled,
                onCheckedChange = { viewModel.setRuleSetAutoUpdateEnabled(it) }
            )
             SettingSwitchItem(
                title = stringResource(R.string.settings_debug_mode),
                subtitle = stringResource(R.string.settings_debug_mode_subtitle),
                icon = Icons.Rounded.BugReport,
                checked = settings.debugLoggingEnabled,
                onCheckedChange = { viewModel.setDebugLoggingEnabled(it) }
            )
            SettingItem(
                title = stringResource(R.string.settings_logs),
                icon = Icons.Rounded.History,
                onClick = { navController.navigate(Screen.Logs.route) }
            )
            SettingItem(
                title = stringResource(R.string.settings_network_diagnostics),
                icon = Icons.Rounded.BugReport,
                onClick = { navController.navigate(Screen.Diagnostics.route) }
            )
        }

        Spacer(modifier = Modifier.height(16.dp))

        // 4. Data
        SettingsGroupTitle(stringResource(R.string.settings_data_management))
        StandardCard {
            SettingItem(
                title = "流量统计",
                subtitle = "查看各节点流量使用情况",
                icon = Icons.Rounded.Analytics,
                onClick = { navController.navigate(Screen.TrafficStats.route) }
            )
            SettingItem(
                title = stringResource(R.string.settings_export_data),
                subtitle = stringResource(R.string.settings_export_data_subtitle),
                icon = Icons.Rounded.Upload,
                onClick = {
                    Toast.makeText(context, "Coming soon", Toast.LENGTH_SHORT).show()
                }
            )
            SettingItem(
                title = stringResource(R.string.settings_import_data),
                subtitle = stringResource(R.string.settings_import_data_subtitle),
                icon = Icons.Rounded.Download,
                onClick = {
                     Toast.makeText(context, "Coming soon", Toast.LENGTH_SHORT).show()
                }
            )
        }

        Spacer(modifier = Modifier.height(16.dp))

        // 5. About
        SettingsGroupTitle(stringResource(R.string.settings_about))
        StandardCard {
            SettingItem(
                title = stringResource(R.string.settings_about_app),
                icon = Icons.Rounded.Info,
                onClick = { 
                     // showAboutDialog = true 
                     Toast.makeText(context, "OpenWorld v0.1.0", Toast.LENGTH_SHORT).show()
                }
            )
        }

        Spacer(modifier = Modifier.height(32.dp))
    }
    
    // Dialogs placeholders
    if (showThemeDialog) {
        // Implement Theme Dialog or use SingleSelectDialog if replicated
    }
}

@Composable
fun SettingsGroupTitle(title: String) {
    Text(
        text = title,
        style = MaterialTheme.typography.titleMedium,
        color = MaterialTheme.colorScheme.onBackground,
        fontWeight = FontWeight.Bold,
        modifier = Modifier.padding(bottom = 8.dp, start = 4.dp)
    )
}
