package com.openworld.app.ui.screens

import android.widget.Toast
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Edit
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FloatingActionButton
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
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.lifecycle.viewmodel.compose.viewModel
import com.openworld.app.ui.components.ConfirmDialog
import com.openworld.app.ui.components.InputDialog
import com.openworld.app.ui.components.SingleSelectDialog
import com.openworld.app.ui.components.StandardCard
import com.openworld.app.viewmodel.RuleRoutingViewModel

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun AppRulesScreen(
    onBack: () -> Unit = {},
    viewModel: RuleRoutingViewModel = viewModel()
) {
    val state by viewModel.state.collectAsState()
    val context = LocalContext.current
    var showAddDialog by remember { mutableStateOf(false) }
    var editTarget by remember { mutableStateOf<RuleRoutingViewModel.AppRuleUi?>(null) }
    var deleteId by remember { mutableStateOf<String?>(null) }
    var showModeDialog by remember { mutableStateOf(false) }

    LaunchedEffect(Unit) {
        viewModel.toast.collect {
            Toast.makeText(context, it, Toast.LENGTH_SHORT).show()
        }
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("应用分流") },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "返回")
                    }
                },
                actions = {
                    IconButton(onClick = { showModeDialog = true }) {
                        Text(if (state.appRoutingMode == "whitelist") "白名单" else "黑名单")
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(containerColor = MaterialTheme.colorScheme.background)
            )
        },
        floatingActionButton = {
            FloatingActionButton(onClick = { showAddDialog = true }) {
                Icon(Icons.Filled.Add, contentDescription = "新增应用规则")
            }
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
                    text = "当前模式：${if (state.appRoutingMode == "whitelist") "白名单（仅列表走代理）" else "黑名单（仅列表直连）"}",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                    modifier = Modifier.padding(vertical = 6.dp)
                )
            }
            items(state.appRules, key = { it.id }) { rule ->
                StandardCard {
                    Row(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(horizontal = 12.dp, vertical = 10.dp),
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Column(modifier = Modifier.weight(1f)) {
                            Text(rule.packageName, style = MaterialTheme.typography.titleSmall)
                            Text(
                                text = "出站：${rule.outbound}",
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant,
                                maxLines = 1,
                                overflow = TextOverflow.Ellipsis
                            )
                        }
                        IconButton(onClick = { editTarget = rule }) {
                            Icon(Icons.Filled.Edit, contentDescription = "编辑")
                        }
                        IconButton(onClick = { deleteId = rule.id }) {
                            Icon(Icons.Filled.Delete, contentDescription = "删除", tint = MaterialTheme.colorScheme.error)
                        }
                    }
                }
            }
            item { Spacer(modifier = Modifier.height(80.dp)) }
        }
    }

    if (showModeDialog) {
        SingleSelectDialog(
            title = "应用分流模式",
            options = listOf("whitelist", "blacklist"),
            selectedOption = state.appRoutingMode,
            onSelect = {
                viewModel.setAppRoutingMode(it)
                showModeDialog = false
            },
            onDismiss = { showModeDialog = false }
        )
    }

    if (showAddDialog) {
        AppRuleEditorDialog(
            title = "新增应用规则",
            outbounds = state.outbounds,
            onDismiss = { showAddDialog = false },
            onConfirm = { pkg, outbound ->
                viewModel.addAppRule(pkg, outbound)
                showAddDialog = false
            }
        )
    }

    if (editTarget != null) {
        AppRuleEditorDialog(
            title = "编辑应用规则",
            initialPackageName = editTarget!!.packageName,
            initialOutbound = editTarget!!.outbound,
            outbounds = state.outbounds,
            onDismiss = { editTarget = null },
            onConfirm = { pkg, outbound ->
                viewModel.updateAppRule(editTarget!!.id, pkg, outbound)
                editTarget = null
            }
        )
    }

    if (deleteId != null) {
        ConfirmDialog(
            title = "删除应用规则",
            message = "确认删除该应用规则？",
            confirmText = "删除",
            onConfirm = {
                viewModel.removeAppRule(deleteId!!)
                deleteId = null
            },
            onDismiss = { deleteId = null }
        )
    }
}

@Composable
private fun AppRuleEditorDialog(
    title: String,
    initialPackageName: String = "",
    initialOutbound: String = "direct",
    outbounds: List<String>,
    onDismiss: () -> Unit,
    onConfirm: (packageName: String, outbound: String) -> Unit
) {
    var step by remember { mutableStateOf(0) }
    var packageName by remember { mutableStateOf(initialPackageName) }
    var outbound by remember { mutableStateOf(initialOutbound) }
    var showOutboundDialog by remember { mutableStateOf(false) }

    if (step == 0) {
        InputDialog(
            title = "$title - 包名",
            initialValue = packageName,
            placeholder = "例如 com.android.chrome",
            confirmText = "下一步",
            onConfirm = {
                packageName = it
                step = 1
            },
            onDismiss = onDismiss
        )
    } else {
        InputDialog(
            title = "$title - 出站",
            initialValue = outbound,
            placeholder = "direct / proxy / reject",
            confirmText = "选择",
            onConfirm = { showOutboundDialog = true },
            onDismiss = onDismiss
        )
        if (showOutboundDialog) {
            SingleSelectDialog(
                title = "目标出站",
                options = outbounds.ifEmpty { listOf("direct", "proxy", "reject") },
                selectedOption = outbound,
                onSelect = {
                    outbound = it
                    showOutboundDialog = false
                    onConfirm(packageName, outbound)
                },
                onDismiss = { showOutboundDialog = false }
            )
        }
    }
}
