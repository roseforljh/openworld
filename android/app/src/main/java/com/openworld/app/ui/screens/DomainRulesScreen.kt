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
import androidx.compose.material.icons.filled.KeyboardArrowDown
import androidx.compose.material.icons.filled.KeyboardArrowUp
import androidx.compose.material.icons.filled.Search
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FloatingActionButton
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.OutlinedTextField
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
fun DomainRulesScreen(
    onBack: () -> Unit = {},
    viewModel: RuleRoutingViewModel = viewModel()
) {
    val state by viewModel.state.collectAsState()
    val context = LocalContext.current
    var showAddDialog by remember { mutableStateOf(false) }
    var editTarget by remember { mutableStateOf<RuleRoutingViewModel.DomainRuleUi?>(null) }
    var deleteId by remember { mutableStateOf<String?>(null) }
    var previewInput by remember { mutableStateOf("") }

    LaunchedEffect(Unit) {
        viewModel.toast.collect {
            Toast.makeText(context, it, Toast.LENGTH_SHORT).show()
        }
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("域名规则") },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "返回")
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(containerColor = MaterialTheme.colorScheme.background)
            )
        },
        floatingActionButton = {
            FloatingActionButton(onClick = { showAddDialog = true }) {
                Icon(Icons.Filled.Add, contentDescription = "新增规则")
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
                item {
                    Spacer(modifier = Modifier.height(4.dp))
                    Text(
                        text = "支持 suffix / keyword / full，按列表顺序进行匹配。",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurfaceVariant,
                        modifier = Modifier.padding(vertical = 6.dp)
                    )
                    StandardCard {
                        Column(modifier = Modifier.padding(horizontal = 12.dp, vertical = 10.dp)) {
                            Text("匹配预览", style = MaterialTheme.typography.titleSmall)
                            OutlinedTextField(
                                value = previewInput,
                                onValueChange = { previewInput = it },
                                singleLine = true,
                                label = { Text("输入域名") },
                                leadingIcon = { Icon(Icons.Filled.Search, contentDescription = null) },
                                modifier = Modifier.fillMaxWidth()
                            )
                            Spacer(modifier = Modifier.height(6.dp))
                            Text(
                                text = viewModel.previewDomainMatch(previewInput),
                                style = MaterialTheme.typography.bodySmall,
                                color = MaterialTheme.colorScheme.onSurfaceVariant
                            )
                        }
                    }
                }
                items(state.domainRules, key = { it.id }) { rule ->
                    StandardCard {
                        Row(
                            modifier = Modifier
                                .fillMaxWidth()
                                .padding(horizontal = 12.dp, vertical = 10.dp),
                            verticalAlignment = Alignment.CenterVertically
                        ) {
                            Column(modifier = Modifier.weight(1f)) {
                                Text(
                                    text = "${rule.type.uppercase()} -> ${rule.outbound}",
                                    style = MaterialTheme.typography.titleSmall
                                )
                                Text(
                                    text = rule.domain,
                                    style = MaterialTheme.typography.bodySmall,
                                    color = MaterialTheme.colorScheme.onSurfaceVariant,
                                    maxLines = 1,
                                    overflow = TextOverflow.Ellipsis
                                )
                            }
                            IconButton(onClick = { viewModel.moveDomainRuleUp(rule.id) }, enabled = !state.saving) {
                                Icon(Icons.Filled.KeyboardArrowUp, contentDescription = "上移")
                            }
                            IconButton(onClick = { viewModel.moveDomainRuleDown(rule.id) }, enabled = !state.saving) {
                                Icon(Icons.Filled.KeyboardArrowDown, contentDescription = "下移")
                            }
                            IconButton(onClick = { editTarget = rule }, enabled = !state.saving) {
                                Icon(Icons.Filled.Edit, contentDescription = "编辑")
                            }
                            IconButton(onClick = { deleteId = rule.id }, enabled = !state.saving) {
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
        DomainRuleEditorDialog(
            title = "新增域名规则",
            outbounds = state.outbounds,
            onDismiss = { showAddDialog = false },
            onConfirm = { type, domain, outbound ->
                viewModel.addDomainRule(type, domain, outbound)
                showAddDialog = false
            }
        )
    }

    if (editTarget != null) {
        DomainRuleEditorDialog(
            title = "编辑域名规则",
            initialType = editTarget!!.type,
            initialDomain = editTarget!!.domain,
            initialOutbound = editTarget!!.outbound,
            outbounds = state.outbounds,
            onDismiss = { editTarget = null },
            onConfirm = { type, domain, outbound ->
                viewModel.updateDomainRule(editTarget!!.id, type, domain, outbound)
                editTarget = null
            }
        )
    }

    if (deleteId != null) {
        ConfirmDialog(
            title = "删除规则",
            message = "确认删除该域名规则？",
            confirmText = "删除",
            onConfirm = {
                viewModel.removeDomainRule(deleteId!!)
                deleteId = null
            },
            onDismiss = { deleteId = null }
        )
    }
}

@Composable
private fun DomainRuleEditorDialog(
    title: String,
    initialType: String = "suffix",
    initialDomain: String = "",
    initialOutbound: String = "direct",
    outbounds: List<String>,
    onDismiss: () -> Unit,
    onConfirm: (type: String, domain: String, outbound: String) -> Unit
) {
    var step by remember { mutableStateOf(0) }
    var type by remember { mutableStateOf(initialType) }
    var domain by remember { mutableStateOf(initialDomain) }
    var outbound by remember { mutableStateOf(initialOutbound) }
    var showTypeDialog by remember { mutableStateOf(false) }
    var showOutboundDialog by remember { mutableStateOf(false) }

    when (step) {
        0 -> InputDialog(
            title = "$title - 域名",
            initialValue = domain,
            placeholder = "例如 google.com",
            confirmText = "下一步",
            onConfirm = {
                domain = it
                step = 1
            },
            onDismiss = onDismiss
        )
        1 -> {
            InputDialog(
                title = "$title - 匹配类型",
                initialValue = type,
                placeholder = "suffix / keyword / full",
                confirmText = "选择",
                onConfirm = {
                    showTypeDialog = true
                },
                onDismiss = onDismiss
            )
            if (showTypeDialog) {
                val options = listOf("suffix", "keyword", "full")
                SingleSelectDialog(
                    title = "匹配类型",
                    options = options,
                    selectedIndex = options.indexOf(type).coerceAtLeast(0),
                    onSelect = { index ->
                        type = options[index]
                        showTypeDialog = false
                        step = 2
                    },
                    onDismiss = { showTypeDialog = false }
                )
            }
        }
        else -> {
            InputDialog(
                title = "$title - 出站",
                initialValue = outbound,
                placeholder = "direct / proxy / reject",
                confirmText = "保存",
                onConfirm = {
                    showOutboundDialog = true
                },
                onDismiss = onDismiss
            )
            if (showOutboundDialog) {
                val options = outbounds.ifEmpty { listOf("direct", "proxy", "reject") }
                SingleSelectDialog(
                    title = "目标出站",
                    options = options,
                    selectedIndex = options.indexOf(outbound).coerceAtLeast(0),
                    onSelect = { index ->
                        outbound = options[index]
                        showOutboundDialog = false
                        onConfirm(type, domain, outbound)
                    },
                    onDismiss = { showOutboundDialog = false }
                )
            }
        }
    }
}
