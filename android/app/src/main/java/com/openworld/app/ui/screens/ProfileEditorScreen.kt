package com.openworld.app.ui.screens

import android.widget.Toast
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.verticalScroll
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Check
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Switch
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
import com.openworld.app.viewmodel.ProfilesViewModel

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun ProfileEditorScreen(
    profileName: String,
    onBack: () -> Unit,
    viewModel: ProfilesViewModel = viewModel()
) {
    val context = LocalContext.current
    val profile = remember(profileName) { viewModel.getProfileInfo(profileName) }

    var name by remember(profileName) { mutableStateOf(profileName) }
    var url by remember(profile?.subscriptionUrl) { mutableStateOf(profile?.subscriptionUrl.orEmpty()) }
    var autoUpdate by remember(profile?.autoUpdate) { mutableStateOf(profile?.autoUpdate == true) }
    var intervalHours by remember(profile?.updateIntervalHours) { mutableStateOf((profile?.updateIntervalHours ?: 24).toString()) }

    LaunchedEffect(Unit) {
        viewModel.toastEvents.collect { Toast.makeText(context, it, Toast.LENGTH_SHORT).show() }
    }

    Scaffold(
        containerColor = MaterialTheme.colorScheme.background,
        contentWindowInsets = WindowInsets(0, 0, 0, 0),
        topBar = {
            TopAppBar(
                title = { Text("配置编辑") },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "返回")
                    }
                },
                actions = {
                    IconButton(onClick = {
                        viewModel.saveProfileSettings(
                            originalName = profileName,
                            newName = name,
                            subscriptionUrl = url,
                            autoUpdate = autoUpdate,
                            updateIntervalHours = intervalHours.toIntOrNull() ?: 24
                        )
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
                .verticalScroll(androidx.compose.foundation.rememberScrollState())
                .padding(16.dp)
                .navigationBarsPadding(),
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            OutlinedTextField(
                value = name,
                onValueChange = { name = it },
                label = { Text("配置名称") },
                singleLine = true,
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(12.dp)
            )

            OutlinedTextField(
                value = url,
                onValueChange = { url = it },
                label = { Text("订阅 URL") },
                singleLine = true,
                modifier = Modifier.fillMaxWidth(),
                shape = RoundedCornerShape(12.dp)
            )

            androidx.compose.foundation.layout.Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.SpaceBetween
            ) {
                Text("自动更新")
                Switch(checked = autoUpdate, onCheckedChange = { autoUpdate = it })
            }

            OutlinedTextField(
                value = intervalHours,
                onValueChange = { intervalHours = it.filter { c -> c.isDigit() } },
                label = { Text("更新间隔(小时)") },
                singleLine = true,
                modifier = Modifier.fillMaxWidth(),
                enabled = autoUpdate,
                shape = RoundedCornerShape(12.dp)
            )
        }
    }
}
