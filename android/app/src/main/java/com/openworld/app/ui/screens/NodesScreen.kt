package com.openworld.app.ui.screens

import android.widget.Toast
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.animateContentSize
import androidx.compose.foundation.clickable
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
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.KeyboardArrowDown
import androidx.compose.material.icons.filled.KeyboardArrowUp
import androidx.compose.material.icons.filled.NetworkCheck
import androidx.compose.material.icons.filled.Search
import androidx.compose.material.icons.filled.SortByAlpha
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FloatingActionButton
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateMapOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.navigation.NavController
import com.openworld.app.ui.navigation.Screen
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.lifecycle.viewmodel.compose.viewModel
import com.openworld.app.ui.components.InputDialog
import com.openworld.app.ui.components.NodeCard
import com.openworld.app.viewmodel.NodesViewModel

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun NodesScreen(
    navController: NavController,
    viewModel: NodesViewModel = viewModel()
) {
    val state by viewModel.state.collectAsState()
    val expandedGroups = remember { mutableStateMapOf<String, Boolean>() }
    var showSearch by remember { mutableStateOf(false) }
    var showFabMenu by remember { mutableStateOf(false) }
    var showImportDialog by remember { mutableStateOf(false) }
    val context = LocalContext.current

    // Toast 事件
    LaunchedEffect(Unit) {
        viewModel.toastEvent.collect { msg ->
            Toast.makeText(context, msg, Toast.LENGTH_SHORT).show()
        }
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("节点") },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = MaterialTheme.colorScheme.background
                ),
                actions = {
                    IconButton(onClick = { showSearch = !showSearch }) {
                        Icon(
                            Icons.Filled.Search,
                            contentDescription = "搜索",
                            tint = MaterialTheme.colorScheme.onSurface
                        )
                    }
                    IconButton(onClick = { viewModel.cycleSortMode() }) {
                        Icon(
                            Icons.Filled.SortByAlpha,
                            contentDescription = "排序",
                            tint = if (state.sortMode != NodesViewModel.SortMode.DEFAULT)
                                MaterialTheme.colorScheme.primary
                            else MaterialTheme.colorScheme.onSurface
                        )
                    }
                    IconButton(
                        onClick = { viewModel.testAllGroupsDelay() },
                        enabled = !state.testing
                    ) {
                        Icon(
                            Icons.Filled.NetworkCheck,
                            contentDescription = "全部测速",
                            tint = MaterialTheme.colorScheme.onSurface
                        )
                    }
                }
            )
        },
        floatingActionButton = {
            FloatingActionButton(onClick = { showFabMenu = !showFabMenu }) {
                Icon(Icons.Filled.Add, contentDescription = "操作")
            }
        }
    ) { padding ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
        ) {
            // 搜索栏
            AnimatedVisibility(visible = showSearch) {
                OutlinedTextField(
                    value = state.searchQuery,
                    onValueChange = { viewModel.setSearchQuery(it) },
                    placeholder = { Text("搜索节点...") },
                    singleLine = true,
                    shape = RoundedCornerShape(12.dp),
                    colors = OutlinedTextFieldDefaults.colors(
                        focusedBorderColor = MaterialTheme.colorScheme.primary,
                        unfocusedBorderColor = MaterialTheme.colorScheme.surfaceVariant
                    ),
                    leadingIcon = {
                        Icon(
                            Icons.Filled.Search,
                            contentDescription = null,
                            tint = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    },
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(horizontal = 16.dp, vertical = 8.dp)
                )
            }

            // 排序提示
            if (state.sortMode != NodesViewModel.SortMode.DEFAULT) {
                val sortLabel = when (state.sortMode) {
                    NodesViewModel.SortMode.NAME -> "按名称排序"
                    NodesViewModel.SortMode.DELAY -> "按延迟排序"
                    else -> ""
                }
                Text(
                    text = sortLabel,
                    style = MaterialTheme.typography.labelSmall,
                    color = MaterialTheme.colorScheme.primary,
                    modifier = Modifier.padding(horizontal = 16.dp, vertical = 4.dp)
                )
            }

            // 测速进度条
            if (state.testing) {
                Column(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(horizontal = 16.dp, vertical = 4.dp)
                ) {
                    LinearProgressIndicator(
                        progress = { state.testProgress },
                        modifier = Modifier.fillMaxWidth(),
                        color = MaterialTheme.colorScheme.primary,
                        trackColor = MaterialTheme.colorScheme.surfaceVariant
                    )
                    if (state.testCurrent.isNotEmpty()) {
                        Text(
                            text = "正在测速: ${state.testCurrent}",
                            style = MaterialTheme.typography.labelSmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant,
                            modifier = Modifier.padding(top = 2.dp)
                        )
                    }
                }
            }

            AnimatedVisibility(visible = showFabMenu) {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(horizontal = 16.dp, vertical = 4.dp),
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    TextButton(
                        onClick = {
                            viewModel.testAllLatency()
                            showFabMenu = false
                        },
                        enabled = !state.testing
                    ) { Text("测速全部") }
                    TextButton(
                        onClick = {
                            showImportDialog = true
                            showFabMenu = false
                        }
                    ) { Text("添加节点") }
                    TextButton(
                        onClick = {
                            viewModel.clearLatency()
                            showFabMenu = false
                        }
                    ) { Text("清除延迟") }
                }
            }

            LazyColumn(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(horizontal = 16.dp),
                verticalArrangement = Arrangement.spacedBy(4.dp)
            ) {
                state.groups.forEach { group ->
                    val expanded = expandedGroups.getOrDefault(group.name, true)

                    // 分组头
                    item(key = "header_${group.name}") {
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .clickable { expandedGroups[group.name] = !expanded }
                                .padding(vertical = 12.dp)
                                .animateContentSize(),
                            horizontalArrangement = Arrangement.SpaceBetween,
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Column(modifier = Modifier.weight(1f)) {
                                Text(
                                    text = group.name,
                                    style = MaterialTheme.typography.titleMedium,
                                    maxLines = 1,
                                    overflow = TextOverflow.Ellipsis
                                )
                                Text(
                                    text = "${group.type} - ${group.members.size} 个节点",
                                    style = MaterialTheme.typography.bodySmall,
                                    color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.5f)
                                )
                            }
                            Row(verticalAlignment = Alignment.CenterVertically) {
                                TextButton(
                                    onClick = { viewModel.testGroupDelay(group.name) },
                                    enabled = !state.testing
                                ) {
                                    Text(
                                        if (state.testing && state.testCurrent == group.name)
                                            "测速中..."
                                        else "测速"
                                    )
                                }
                                Icon(
                                    imageVector = if (expanded) Icons.Default.KeyboardArrowUp
                                    else Icons.Default.KeyboardArrowDown,
                                    contentDescription = null,
                                    modifier = Modifier.size(24.dp)
                                )
                            }
                        }
                    }

                    // 节点列表
                    if (expanded) {
                        items(
                            items = group.members,
                            key = { "${group.name}_${it.name}" }
                        ) { node ->
                            NodeCard(
                                name = node.alias.ifBlank { node.name },
                                delay = node.delay,
                                isSelected = node.selected,
                                isTesting = state.testing && state.testCurrent == group.name,
                                onClick = { viewModel.selectNode(group.name, node.name) },
                                onDetail = {
                                    navController.navigate(Screen.NodeDetail.nodeDetailRoute(group.name, node.name))
                                },
                                onTest = { viewModel.testNodeDelay(group.name) },
                                onDelete = { viewModel.deleteNodeLocal(group.name, node.name) }
                            )
                        }

                        item(key = "spacer_${group.name}") {
                            Spacer(modifier = Modifier.height(8.dp))
                        }
                    }
                }

                // 空状态
                if (state.groups.isEmpty()) {
                    item {
                        Column(
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(vertical = 48.dp),
                            horizontalAlignment = Alignment.CenterHorizontally
                        ) {
                            Text(
                                text = if (state.searchQuery.isNotEmpty()) "未找到匹配节点" else "暂无节点",
                                style = MaterialTheme.typography.bodyLarge,
                                color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.5f)
                            )
                        }
                    }
                }
            }
        }
    }

    if (showImportDialog) {
        InputDialog(
            title = "导入节点链接",
            label = "请输入订阅链接",
            placeholder = "https://example.com/sub",
            confirmText = "导入",
            onConfirm = {
                viewModel.importNodeByLink(it)
                showImportDialog = false
            },
            onDismiss = { showImportDialog = false }
        )
    }
}
