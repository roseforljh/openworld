package com.openworld.app.ui.screens

import android.net.Uri
import android.widget.Toast
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
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
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Add
import androidx.compose.material.icons.filled.ContentPaste
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Description
import androidx.compose.material.icons.filled.Link
import androidx.compose.material.icons.filled.Refresh
import androidx.compose.material.icons.filled.QrCodeScanner
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FloatingActionButton
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SmallFloatingActionButton
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.lifecycle.viewmodel.compose.viewModel
import androidx.navigation.NavController
import com.journeyapps.barcodescanner.ScanContract
import com.journeyapps.barcodescanner.ScanOptions
import com.openworld.app.ui.components.ConfirmDialog
import com.openworld.app.ui.components.StandardCard
import com.openworld.app.ui.navigation.Screen
import com.openworld.app.ui.theme.Green500
import com.openworld.app.viewmodel.ProfilesViewModel
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ProfilesScreen(
    navController: NavController,
    viewModel: ProfilesViewModel = viewModel()
) {
    val state by viewModel.state.collectAsState()
    var showImportDialog by remember { mutableStateOf(false) }
    var deleteTarget by remember { mutableStateOf<String?>(null) }
    val context = LocalContext.current
    val scope = rememberCoroutineScope()
    val contentResolver = context.contentResolver
    var pendingFileName by remember { mutableStateOf<String?>(null) }
    var pendingQrName by remember { mutableStateOf<String?>(null) }

    val filePicker = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.OpenDocument(),
        onResult = { uri: Uri? ->
            val name = pendingFileName
            if (uri != null && !name.isNullOrBlank()) {
                scope.launch {
                    val content = withContext(Dispatchers.IO) {
                        runCatching {
                            contentResolver.openInputStream(uri)?.bufferedReader()?.use { it.readText() }.orEmpty()
                        }.getOrDefault("")
                    }
                    if (content.isNotBlank()) {
                        viewModel.importFromClipboard(content, name)
                    } else {
                        Toast.makeText(context, "文件读取失败", Toast.LENGTH_SHORT).show()
                    }
                }
            }
            pendingFileName = null
        }
    )

    val qrScanner = rememberLauncherForActivityResult(
        contract = ScanContract(),
        onResult = { result ->
            val name = pendingQrName
            if (!name.isNullOrBlank()) {
                val text = result.contents.orEmpty()
                if (text.isNotBlank()) {
                    viewModel.importFromQr(text, name)
                } else {
                    Toast.makeText(context, "未识别到二维码内容", Toast.LENGTH_SHORT).show()
                }
            }
            pendingQrName = null
        }
    )

    // Toast 事件
    LaunchedEffect(Unit) {
        viewModel.toastEvent.collect { msg ->
            Toast.makeText(context, msg, Toast.LENGTH_SHORT).show()
        }
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("配置") },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = MaterialTheme.colorScheme.background
                ),
                actions = {
                    // 全部更新订阅
                    IconButton(
                        onClick = { viewModel.updateAllSubscriptions() },
                        enabled = !state.updating
                    ) {
                        if (state.updating) {
                            CircularProgressIndicator(
                                modifier = Modifier.size(20.dp),
                                strokeWidth = 2.dp
                            )
                        } else {
                            Icon(
                                Icons.Filled.Refresh,
                                contentDescription = "更新全部订阅",
                                tint = MaterialTheme.colorScheme.onSurface
                            )
                        }
                    }
                }
            )
        },
        floatingActionButton = {
            FloatingActionButton(
                onClick = { showImportDialog = true },
                containerColor = MaterialTheme.colorScheme.primary
            ) {
                Icon(Icons.Default.Add, contentDescription = "添加配置")
            }
        }
    ) { padding ->
        if (state.profiles.isEmpty()) {
            Box(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(padding)
            ) {
                Column(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(horizontal = 16.dp)
                        .align(Alignment.TopCenter),
                    verticalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    Spacer(modifier = Modifier.height(8.dp))
                    ImportStageCard(state = state)
                }

                Column(
                    modifier = Modifier.align(Alignment.Center),
                    horizontalAlignment = Alignment.CenterHorizontally
                ) {
                    Text(
                        text = "暂无配置",
                        style = MaterialTheme.typography.bodyLarge,
                        color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.5f)
                    )
                    Spacer(modifier = Modifier.height(8.dp))
                    Text(
                        text = "点击右下角按钮添加",
                        style = MaterialTheme.typography.bodySmall,
                        color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.3f)
                    )
                }
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
                    ImportStageCard(state = state)
                }

                items(state.profiles, key = { it.name }) { profile ->
                    ProfileCard(
                        profile = profile,
                        isUpdating = state.updating && state.updatingProfile == profile.name,
                        onSelect = { viewModel.selectProfile(profile.name) },
                        onUpdate = { viewModel.updateSubscription(profile.name) },
                        onEdit = { navController.navigate(Screen.ProfileEditor.profileEditorRoute(profile.name)) },
                        onDelete = { deleteTarget = profile.name }
                    )
                }

                item { Spacer(modifier = Modifier.height(80.dp)) }
            }
        }
    }

    // 导入对话框
    if (showImportDialog) {
        ImportProfileDialog(
            importing = state.importing,
            onDismiss = { showImportDialog = false },
            onImportUrl = { name, url ->
                viewModel.importFromUrl(url, name)
                showImportDialog = false
            },
            onImportClipboard = { name, content ->
                viewModel.importFromClipboard(content, name)
                showImportDialog = false
            },
            onImportFile = { name ->
                pendingFileName = name
                filePicker.launch(arrayOf("*/*"))
                showImportDialog = false
            },
            onImportQr = { name ->
                pendingQrName = name
                val options = ScanOptions().apply {
                    setPrompt("请扫描配置二维码")
                    setBeepEnabled(false)
                    setOrientationLocked(false)
                }
                qrScanner.launch(options)
                showImportDialog = false
            }
        )
    }

    // 删除确认
    if (deleteTarget != null) {
        ConfirmDialog(
            title = "删除配置",
            message = "确定要删除配置 \"${deleteTarget}\" 吗？此操作不可撤销。",
            confirmText = "删除",
            onConfirm = {
                viewModel.deleteProfile(deleteTarget!!)
                deleteTarget = null
            },
            onDismiss = { deleteTarget = null }
        )
    }
}

@Composable
private fun ImportStageCard(state: ProfilesViewModel.UiState) {
    val stageText = when (state.importStage) {
        ProfilesViewModel.ImportStage.IDLE -> ""
        ProfilesViewModel.ImportStage.VALIDATING -> "导入阶段：预校验"
        ProfilesViewModel.ImportStage.DOWNLOADING -> "导入阶段：下载配置"
        ProfilesViewModel.ImportStage.PARSING -> "导入阶段：解析内容"
        ProfilesViewModel.ImportStage.SAVING -> "导入阶段：保存配置"
        ProfilesViewModel.ImportStage.FINISHED -> "导入阶段：完成"
        ProfilesViewModel.ImportStage.FAILED -> "导入阶段：失败"
    }

    if (stageText.isBlank() && state.importError.isNullOrBlank()) return

    StandardCard {
        Column(modifier = Modifier.padding(horizontal = 12.dp, vertical = 10.dp)) {
            if (stageText.isNotBlank()) {
                Text(
                    text = stageText,
                    style = MaterialTheme.typography.bodySmall,
                    color = when (state.importStage) {
                        ProfilesViewModel.ImportStage.FAILED -> MaterialTheme.colorScheme.error
                        ProfilesViewModel.ImportStage.FINISHED -> MaterialTheme.colorScheme.primary
                        else -> MaterialTheme.colorScheme.onSurfaceVariant
                    }
                )
            }
            if (!state.importError.isNullOrBlank()) {
                Spacer(modifier = Modifier.height(4.dp))
                Text(
                    text = "失败原因：${state.importError}",
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.error
                )
            }
        }
    }
}

@Composable
private fun ProfileCard(
    profile: ProfilesViewModel.ProfileInfo,
    isUpdating: Boolean,
    onSelect: () -> Unit,
    onUpdate: () -> Unit,
    onEdit: () -> Unit,
    onDelete: () -> Unit
) {
    Card(
        shape = RoundedCornerShape(12.dp),
        colors = CardDefaults.cardColors(
            containerColor = if (profile.isActive)
                Green500.copy(alpha = 0.08f)
            else MaterialTheme.colorScheme.surface
        ),
        onClick = onSelect,
        modifier = Modifier.fillMaxWidth()
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(16.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            // 选中指示器
            if (profile.isActive) {
                Box(
                    modifier = Modifier
                        .size(8.dp)
                        .clip(CircleShape)
                        .background(Green500)
                )
                Spacer(modifier = Modifier.width(12.dp))
            }

            // 信息区
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = profile.name,
                    style = MaterialTheme.typography.bodyLarge,
                    color = MaterialTheme.colorScheme.onSurface,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis
                )
                Spacer(modifier = Modifier.height(2.dp))
                Row(
                    horizontalArrangement = Arrangement.spacedBy(12.dp)
                ) {
                    if (profile.fileSizeText.isNotEmpty()) {
                        Text(
                            text = profile.fileSizeText,
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.5f)
                        )
                    }
                    if (profile.lastModifiedText.isNotEmpty()) {
                        Text(
                            text = profile.lastModifiedText,
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.5f)
                        )
                    }
                }
                if (!profile.subscriptionUrl.isNullOrBlank()) {
                    Text(
                        text = profile.subscriptionUrl,
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.primary.copy(alpha = 0.6f),
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis,
                        modifier = Modifier.padding(top = 2.dp)
                    )
                }
            }

            // 操作按钮
            if (!profile.subscriptionUrl.isNullOrBlank()) {
                IconButton(
                    onClick = onUpdate,
                    enabled = !isUpdating,
                    modifier = Modifier.size(36.dp)
                ) {
                    if (isUpdating) {
                        CircularProgressIndicator(
                            modifier = Modifier.size(18.dp),
                            strokeWidth = 2.dp
                        )
                    } else {
                        Icon(
                            Icons.Filled.Refresh,
                            contentDescription = "更新订阅",
                            tint = MaterialTheme.colorScheme.primary,
                            modifier = Modifier.size(20.dp)
                        )
                    }
                }
            }

            IconButton(
                onClick = onEdit,
                modifier = Modifier.size(36.dp)
            ) {
                Icon(
                    Icons.Filled.Description,
                    contentDescription = "编辑",
                    tint = MaterialTheme.colorScheme.primary,
                    modifier = Modifier.size(20.dp)
                )
            }

            IconButton(
                onClick = onDelete,
                modifier = Modifier.size(36.dp)
            ) {
                Icon(
                    Icons.Filled.Delete,
                    contentDescription = "删除",
                    tint = MaterialTheme.colorScheme.error,
                    modifier = Modifier.size(20.dp)
                )
            }
        }
    }
}

@Composable
private fun ImportProfileDialog(
    importing: Boolean,
    onDismiss: () -> Unit,
    onImportUrl: (name: String, url: String) -> Unit,
    onImportClipboard: (name: String, content: String) -> Unit,
    onImportFile: (name: String) -> Unit,
    onImportQr: (name: String) -> Unit
) {
    var name by remember { mutableStateOf("") }
    var url by remember { mutableStateOf("") }
    var clipboardContent by remember { mutableStateOf("") }
    var mode by remember { mutableStateOf("url") }

    AlertDialog(
        onDismissRequest = { if (!importing) onDismiss() },
        shape = RoundedCornerShape(16.dp),
        containerColor = MaterialTheme.colorScheme.surface,
        title = { Text("添加配置") },
        text = {
            Column(verticalArrangement = Arrangement.spacedBy(12.dp)) {
                Row(horizontalArrangement = Arrangement.spacedBy(8.dp)) {
                    TextButton(onClick = { mode = "url" }) {
                        Icon(
                            Icons.Filled.Link,
                            contentDescription = null,
                            modifier = Modifier.size(16.dp),
                            tint = if (mode == "url") MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurfaceVariant
                        )
                        Spacer(modifier = Modifier.width(4.dp))
                        Text("订阅链接", color = if (mode == "url") MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurfaceVariant)
                    }
                    TextButton(onClick = { mode = "clipboard" }) {
                        Icon(
                            Icons.Filled.ContentPaste,
                            contentDescription = null,
                            modifier = Modifier.size(16.dp),
                            tint = if (mode == "clipboard") MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurfaceVariant
                        )
                        Spacer(modifier = Modifier.width(4.dp))
                        Text("粘贴内容", color = if (mode == "clipboard") MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurfaceVariant)
                    }
                    TextButton(onClick = { mode = "file" }) {
                        Icon(
                            Icons.Filled.Description,
                            contentDescription = null,
                            modifier = Modifier.size(16.dp),
                            tint = if (mode == "file") MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurfaceVariant
                        )
                        Spacer(modifier = Modifier.width(4.dp))
                        Text("本地文件", color = if (mode == "file") MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurfaceVariant)
                    }
                    TextButton(onClick = { mode = "qr" }) {
                        Icon(
                            Icons.Filled.QrCodeScanner,
                            contentDescription = null,
                            modifier = Modifier.size(16.dp),
                            tint = if (mode == "qr") MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurfaceVariant
                        )
                        Spacer(modifier = Modifier.width(4.dp))
                        Text("二维码", color = if (mode == "qr") MaterialTheme.colorScheme.primary else MaterialTheme.colorScheme.onSurfaceVariant)
                    }
                }

                OutlinedTextField(
                    value = name,
                    onValueChange = { name = it },
                    label = { Text("配置名称") },
                    singleLine = true,
                    modifier = Modifier.fillMaxWidth()
                )

                when (mode) {
                    "url" -> {
                        OutlinedTextField(
                            value = url,
                            onValueChange = { url = it },
                            label = { Text("订阅 URL") },
                            singleLine = true,
                            modifier = Modifier.fillMaxWidth()
                        )
                    }
                    "clipboard" -> {
                        OutlinedTextField(
                            value = clipboardContent,
                            onValueChange = { clipboardContent = it },
                            label = { Text("配置内容") },
                            minLines = 3,
                            maxLines = 6,
                            modifier = Modifier.fillMaxWidth()
                        )
                    }
                    "file" -> {
                        Text(
                            text = "点击导入将打开系统文件选择器",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                    else -> {
                        Text(
                            text = "点击导入将打开扫码页面",
                            style = MaterialTheme.typography.bodySmall,
                            color = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                }
            }
        },
        confirmButton = {
            TextButton(
                onClick = {
                    when (mode) {
                        "url" -> onImportUrl(name, url)
                        "clipboard" -> onImportClipboard(name, clipboardContent)
                        "file" -> onImportFile(name)
                        else -> onImportQr(name)
                    }
                },
                enabled = !importing && name.isNotBlank() &&
                        when (mode) {
                            "url" -> url.isNotBlank()
                            "clipboard" -> clipboardContent.isNotBlank()
                            else -> true
                        }
            ) {
                if (importing) {
                    CircularProgressIndicator(
                        modifier = Modifier.size(16.dp),
                        strokeWidth = 2.dp
                    )
                } else {
                    Text("导入")
                }
            }
        },
        dismissButton = {
            TextButton(
                onClick = onDismiss,
                enabled = !importing
            ) {
                Text("取消")
            }
        }
    )
}
