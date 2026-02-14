package com.openworld.app.ui.screens

import android.widget.Toast
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.verticalScroll
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
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
import androidx.navigation.NavController
import com.openworld.app.model.SingBoxOutbound
import com.openworld.app.model.TlsConfig
import com.openworld.app.ui.components.EditableTextItem
import com.openworld.app.viewmodel.NodesViewModel

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun NodeDetailScreen(
    navController: NavController,
    nodeId: String,
    createProtocol: String = "",
    viewModel: NodesViewModel = viewModel()
) {
    val context = LocalContext.current
    var editingOutbound by remember { mutableStateOf<SingBoxOutbound?>(null) }
    var originalTag by remember { mutableStateOf("") }

    LaunchedEffect(nodeId) {
        if (nodeId == "new") {
            if (createProtocol.isNotEmpty()) {
                val newOutbound = createEmptySingBoxOutbound(createProtocol)
                editingOutbound = newOutbound
                originalTag = ""
            }
        } else {
            val existing = viewModel.getNodeDetail(nodeId, nodeId) // Assuming group name is same as node ID or handled by viewModel logic
            if (existing != null) {
                editingOutbound = existing
                originalTag = existing.tag
            } else {
                Toast.makeText(context, "Node not found", Toast.LENGTH_SHORT).show()
                navController.popBackStack()
            }
        }
    }

    Scaffold(
        containerColor = MaterialTheme.colorScheme.background,
        contentWindowInsets = WindowInsets(0, 0, 0, 0),
        topBar = {
            TopAppBar(
                title = { Text(if (nodeId == "new") "New Node" else "Edit Node") }
            )
        }
    ) { paddingValues ->
        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(paddingValues)
                .verticalScroll(androidx.compose.foundation.rememberScrollState())
                .padding(16.dp)
                .navigationBarsPadding()
        ) {
            editingOutbound?.let { outbound ->
                EditableTextItem(
                    title = "Name",
                    value = outbound.tag,
                    onValueChange = { editingOutbound = outbound.copy(tag = it) }
                )
                EditableTextItem(
                    title = "Address",
                    value = outbound.server ?: "",
                    onValueChange = { editingOutbound = outbound.copy(server = it) }
                )
                EditableTextItem(
                    title = "Port",
                    value = outbound.serverPort?.toString() ?: "",
                    onValueChange = { editingOutbound = outbound.copy(serverPort = it.toIntOrNull()) }
                )
                
                // Add save button logic here or in TopAppBar actions
            } ?: Text("Loading...")
        }
    }
}

private fun createEmptySingBoxOutbound(protocol: String): SingBoxOutbound {
    return SingBoxOutbound(
        type = protocol,
        tag = "New-${protocol.uppercase()}",
        server = "",
        serverPort = 443
    )
}
