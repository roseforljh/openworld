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
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material3.CircularProgressIndicator
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
import com.openworld.app.ui.components.StandardCard
import com.openworld.app.viewmodel.RuleRoutingViewModel
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun RuleSetsScreen(
    onBack: () -> Unit = {},
    viewModel: RuleRoutingViewModel = viewModel()
) {
    val state by viewModel.state.collectAsState()
    val context = LocalContext.current
    var showAddDialog by remember { mutableStateOf(false) }
    var deleteTarget by remember { mutableStateOf<String?>(null) }

    LaunchedEffect(Unit) {
        viewModel.toast.collect {
            Toast.makeText(context, it, Toast.LENGTH_SHORT).show()
        }
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("规则集") },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "返回")
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = MaterialTheme.colorScheme.background
                )
            )
        },
        floatingActionButton = {
            FloatingActionButton(onClick = { showAddDialog = true }) {
                Icon(Icons.Filled.Add, contentDescription = "导入规则集")
            }
        }
    ) { padding ->
        if (state.loading) {
            Column(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(padding),
                verticalArrangement = Arrangement.Center,
                horizontalAlignment = Alignment.CenterHorizontally
            ) {
                CircularProgressIndicator()
            }
        } else {
            LazyColumn(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(padding)
                    .padding(horizontal = 16.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp)
            ) {
                item { Spacer(modifier = Modifier.height(4.dp)) }
                items(state.ruleSets, key = { it.name }) { item ->
                    StandardCard {
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(horizontal = 12.dp, vertical = 10.dp),
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Column(modifier = Modifier.weight(1f)) {
                                Text(item.name, style = MaterialTheme.typography.titleSmall)
                                Text(
                                    text = item.url,
                                    style = MaterialTheme.typography.bodySmall,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                                    maxLines = 1,
                                    overflow = TextOverflow.Ellipsis
                                )
                                Text(
                                    text = "节点 ${item.nodeCount} · 更新 ${formatTime(item.lastUpdated)}",
                                    style = MaterialTheme.typography.labelSmall,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant
                                )
                            }
                            IconButton(onClick = { viewModel.updateRuleSet(item.name) }, enabled = !state.saving) {
                                Icon(Icons.Filled.Refresh, contentDescription = "更新")
                            }
                            IconButton(onClick = { deleteTarget = item.name }, enabled = !state.saving) {
                                Icon(Icons.Filled.Delete, contentDescription = "删除", tint = MaterialTheme.colorScheme.error)
                            }
                        }
                    }
                }
                item { Spacer(modifier = Modifier.height(80.dp)) }
            }
        }
    }

    if (showAddDialog) {
        AddRuleSetDialog(
            saving = state.saving,
            onConfirm = { name, url, hours ->
                viewModel.addRuleSet(name, url, hours)
                showAddDialog = false
            },
            onDismiss = { showAddDialog = false }
        )
    }

    if (deleteTarget != null) {
        ConfirmDialog(
            title = "删除规则集",
            message = "确认删除规则集 ${deleteTarget} ?",
            confirmText = "删除",
            onConfirm = {
                viewModel.removeRuleSet(deleteTarget!!)
                deleteTarget = null
            },
            onDismiss = { deleteTarget = null }
        )
    }
}

@Composable
private fun AddRuleSetDialog(
    saving: Boolean,
    onConfirm: (name: String, url: String, intervalHours: Int) -> Unit,
    onDismiss: () -> Unit
) {
    var step by remember { mutableStateOf(0) }
    var name by remember { mutableStateOf("") }
    var url by remember { mutableStateOf("") }

    if (step == 0) {
        InputDialog(
            title = "规则集名称",
            initialValue = name,
            placeholder = "例如 geosite-cn",
            confirmText = "下一步",
            onConfirm = {
                name = it
                step = 1
            },
            onDismiss = onDismiss
        )
    } else {
        InputDialog(
            title = "规则集 URL",
            initialValue = url,
            placeholder = "https://...",
            confirmText = if (saving) "导入中" else "导入",
            onConfirm = {
                url = it
                onConfirm(name, url, 24)
            },
            onDismiss = onDismiss
        )
    }
}

private fun formatTime(ts: Long): String {
    if (ts <= 0) return "未更新"
    return try {
        SimpleDateFormat("MM-dd HH:mm", Locale.getDefault()).format(Date(ts))
    } catch (_: Exception) {
        "未知"
    }
}
