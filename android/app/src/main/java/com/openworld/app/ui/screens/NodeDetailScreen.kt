package com.openworld.app.ui.screens

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
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
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.Share
import androidx.compose.material.icons.filled.Speed
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.lifecycle.viewmodel.compose.viewModel
import com.openworld.app.viewmodel.NodesViewModel

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun NodeDetailScreen(
    groupName: String,
    nodeName: String,
    onBack: () -> Unit,
    viewModel: NodesViewModel = viewModel()
) {
    val context = LocalContext.current
    val detail = remember(groupName, nodeName) { viewModel.getNodeDetail(groupName, nodeName) }
    var alias by remember(detail.alias) { mutableStateOf(detail.alias) }

    LaunchedEffect(Unit) {
        viewModel.toastEvent.collect {
            Toast.makeText(context, it, Toast.LENGTH_SHORT).show()
        }
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("节点详情") },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "返回")
                    }
                },
                actions = {
                    IconButton(onClick = {
                        viewModel.saveNodeDetail(groupName, nodeName, alias)
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
                value = alias,
                onValueChange = { alias = it },
                label = { Text("节点名称") },
                placeholder = { Text(nodeName) },
                singleLine = true,
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(12.dp)
            )

            Text("协议: ${detail.protocol.ifBlank { "unknown" }}", style = MaterialTheme.typography.bodyMedium)
            Text("原始标识: $nodeName", style = MaterialTheme.typography.bodySmall, color = MaterialTheme.colorScheme.onSurfaceVariant)
            Text("延迟: ${if (detail.delay >= 0) "${detail.delay}ms" else "未测速"}", style = MaterialTheme.typography.bodySmall)

            Button(
                onClick = { viewModel.testNodeDelay(groupName) },
                modifier = Modifier.fillMaxWidth()
            ) {
                Icon(Icons.Filled.Speed, contentDescription = null)
                Text("  测速")
            }

            Button(
                onClick = {
                    val link = viewModel.exportNodeLink(groupName, nodeName)
                    copyText(context, link)
                    Toast.makeText(context, "链接已复制", Toast.LENGTH_SHORT).show()
                },
                modifier = Modifier.fillMaxWidth()
            ) {
                Icon(Icons.Filled.Share, contentDescription = null)
                Text("  导出链接")
            }

            Button(
                onClick = {
                    viewModel.deleteNodeLocal(groupName, nodeName)
                    onBack()
                },
                modifier = Modifier.fillMaxWidth(),
                colors = ButtonDefaults.buttonColors(containerColor = MaterialTheme.colorScheme.error)
            ) {
                Icon(Icons.Filled.Delete, contentDescription = null)
                Text("  删除节点")
            }
        }
    }
}

private fun copyText(context: Context, text: String) {
    val cm = context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
    cm.setPrimaryClip(ClipData.newPlainText("node_link", text))
}
