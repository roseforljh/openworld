package com.openworld.app.ui.screens

import android.Manifest
import android.content.pm.PackageManager
import android.net.Uri
import android.widget.Toast
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.tween
import androidx.compose.animation.expandVertically
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.shrinkVertically
import androidx.compose.foundation.background
import androidx.compose.foundation.gestures.awaitEachGesture
import androidx.compose.foundation.gestures.awaitFirstDown
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.asPaddingValues
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.statusBars
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.itemsIndexed
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.Add
import androidx.compose.material.icons.rounded.ContentPaste
import androidx.compose.material.icons.rounded.Description
import androidx.compose.material.icons.rounded.Link
import androidx.compose.material.icons.rounded.QrCodeScanner
import androidx.compose.material.icons.rounded.Search
import androidx.compose.material3.FloatingActionButton
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
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
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.input.nestedscroll.NestedScrollConnection
import androidx.compose.ui.input.nestedscroll.NestedScrollSource
import androidx.compose.ui.input.nestedscroll.nestedScroll
import androidx.compose.ui.input.pointer.PointerEventPass
import androidx.compose.ui.input.pointer.pointerInput
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.core.content.ContextCompat
import androidx.lifecycle.viewmodel.compose.viewModel
import androidx.navigation.NavController
import com.journeyapps.barcodescanner.ScanContract
import com.journeyapps.barcodescanner.ScanOptions
import com.openworld.app.R
import com.openworld.app.model.ProfileType
import com.openworld.app.model.ProfileUi
import com.openworld.app.model.UpdateStatus
import com.openworld.app.ui.components.InputDialog
import com.openworld.app.ui.components.ProfileCard
import com.openworld.app.ui.components.StandardCard
import com.openworld.app.ui.navigation.Screen
import com.openworld.app.viewmodel.ProfilesViewModel
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.collectLatest
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.BufferedReader
import java.io.InputStreamReader

@Composable
fun ProfilesScreen(
    navController: NavController,
    viewModel: ProfilesViewModel = viewModel()
) {
    val profiles by viewModel.profiles.collectAsState()
    val activeProfileId by viewModel.activeProfileId.collectAsState()
    val importState by viewModel.importState.collectAsState()
    val updateStatus by viewModel.updateStatus.collectAsState()

    var showSearchDialog by remember { mutableStateOf(false) }
    var showImportSelection by remember { mutableStateOf(false) }
    var showSubscriptionInput by remember { mutableStateOf(false) }
    var showClipboardInput by remember { mutableStateOf(false) }
    var editingProfile by remember { mutableStateOf<ProfileUi?>(null) }

    val context = LocalContext.current
    val clipboardManager = LocalClipboardManager.current

    LaunchedEffect(Unit) {
        viewModel.toastEvents.collectLatest { message ->
            Toast.makeText(context, message, Toast.LENGTH_SHORT).show()
        }
    }
    
    // DeepLinkHandler skipped for now

    LaunchedEffect(updateStatus) {
        updateStatus?.let {
            Toast.makeText(context, it, Toast.LENGTH_SHORT).show()
        }
    }

    LaunchedEffect(importState) {
        when (val state = importState) {
            is ProfilesViewModel.ImportState.Success -> {
                Toast.makeText(context, context.getString(R.string.profiles_import_success, state.profile.name), Toast.LENGTH_SHORT).show()
                viewModel.resetImportState()
            }
            is ProfilesViewModel.ImportState.Error -> {
                Toast.makeText(context, context.getString(R.string.profiles_import_failed, state.message), Toast.LENGTH_LONG).show()
                viewModel.resetImportState()
            }
            else -> {}
        }
    }

    if (importState is ProfilesViewModel.ImportState.Loading) {
        ImportLoadingDialog(
            message = (importState as ProfilesViewModel.ImportState.Loading).message,
            onCancel = { viewModel.cancelImport() }
        )
    }

    val scope = rememberCoroutineScope()
    val listState = rememberLazyListState()
    var isFabVisible by remember { mutableStateOf(true) }

    val nestedScrollConnection = remember {
        object : NestedScrollConnection {
            override fun onPreScroll(available: Offset, source: NestedScrollSource): Offset {
                if (available.y < -10f) {
                    isFabVisible = false
                } else if (available.y > 10f) {
                    isFabVisible = true
                }
                return Offset.Zero
            }
        }
    }

    var lastY by remember { mutableStateOf(0f) }

    val filePickerLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.OpenDocument()
    ) { uri: Uri? ->
        if (uri != null) {
            scope.launch {
                try {
                    val content = withContext(Dispatchers.IO) {
                        context.contentResolver.openInputStream(uri)?.use { inputStream ->
                            BufferedReader(InputStreamReader(inputStream)).use { reader ->
                                reader.readText()
                            }
                        } ?: ""
                    }

                    if (content.isNotBlank()) {
                        val fileName = uri.lastPathSegment?.let { segment ->
                            segment.substringAfterLast("/")
                                .substringAfterLast(":")
                                .substringBeforeLast(".")
                                .takeIf { it.isNotBlank() }
                        } ?: context.getString(R.string.profiles_file_import)

                        viewModel.importFromContent(fileName, content)
                    } else {
                        Toast.makeText(context, context.getString(R.string.profiles_file_empty), Toast.LENGTH_SHORT).show()
                    }
                } catch (e: Exception) {
                    Toast.makeText(context, context.getString(R.string.profiles_read_file_failed, e.message), Toast.LENGTH_LONG).show()
                }
            }
        }
    }

    val qrCodeLauncher = rememberLauncherForActivityResult(
        contract = ScanContract()
    ) { result ->
        if (result.contents != null) {
            viewModel.importSubscription(context.getString(R.string.profiles_qrcode_subscription), result.contents, 0)
        }
    }

    fun createScanOptions(): ScanOptions {
        return ScanOptions().apply {
            setDesiredBarcodeFormats(ScanOptions.QR_CODE)
            setPrompt("")
            setCameraId(0)
            setBeepEnabled(true)
            setBarcodeImageEnabled(false)
            setOrientationLocked(false)
            // setCaptureActivity(QrScannerActivity::class.java) // Commented out
        }
    }

    val cameraPermissionLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.RequestPermission()
    ) { isGranted ->
        if (isGranted) {
            qrCodeLauncher.launch(createScanOptions())
        } else {
            Toast.makeText(context, context.getString(R.string.profiles_camera_permission_required), Toast.LENGTH_SHORT).show()
        }
    }

    if (showImportSelection) {
        ImportSelectionDialog(
            onDismiss = { showImportSelection = false },
            onTypeSelected = { type ->
                showImportSelection = false
                when (type) {
                    ProfileImportType.Subscription -> showSubscriptionInput = true
                    ProfileImportType.Clipboard -> showClipboardInput = true
                    ProfileImportType.File -> {
                        filePickerLauncher.launch(arrayOf(
                            "application/json",
                            "text/plain",
                            "application/x-yaml",
                            "text/yaml",
                            "*/*"
                        ))
                    }
                    ProfileImportType.QRCode -> {
                        when {
                            ContextCompat.checkSelfPermission(
                                context,
                                Manifest.permission.CAMERA
                            ) == PackageManager.PERMISSION_GRANTED -> {
                                qrCodeLauncher.launch(createScanOptions())
                            }
                            else -> {
                                cameraPermissionLauncher.launch(Manifest.permission.CAMERA)
                            }
                        }
                    }
                }
            }
        )
    }

    if (showSubscriptionInput) {
        SubscriptionInputDialog(
            onDismiss = { showSubscriptionInput = false },
            onConfirm = { name, url, autoUpdateInterval, dnsPreResolve, dnsServer ->
                viewModel.importSubscription(name, url, autoUpdateInterval, dnsPreResolve, dnsServer)
                showSubscriptionInput = false
            }
        )
    }

    if (showClipboardInput) {
        val clipboardEmptyMsg = stringResource(R.string.profiles_clipboard_empty)
        val nameInvalidMsg = stringResource(R.string.profiles_name_invalid)
        val defaultClipboardName = stringResource(R.string.profiles_clipboard_import)

        InputDialog(
            title = stringResource(R.string.profiles_import_clipboard),
            placeholder = stringResource(R.string.profiles_import_clipboard_hint),
            initialValue = "",
            confirmText = stringResource(R.string.common_import),
            onConfirm = { name ->
                if (name.contains("://")) {
                    Toast.makeText(context, nameInvalidMsg, Toast.LENGTH_SHORT).show()
                    return@InputDialog
                }

                val content = clipboardManager.getText()?.text ?: ""
                if (content.isNotBlank()) {
                    viewModel.importFromContent(if (name.isBlank()) defaultClipboardName else name, content)
                    showClipboardInput = false
                } else {
                    Toast.makeText(context, clipboardEmptyMsg, Toast.LENGTH_SHORT).show()
                }
            },
            onDismiss = { showClipboardInput = false }
        )
    }

    if (showSearchDialog) {
        InputDialog(
            title = stringResource(R.string.profiles_search),
            placeholder = stringResource(R.string.profiles_search_hint),
            confirmText = stringResource(R.string.common_search),
            onConfirm = { showSearchDialog = false },
            onDismiss = { showSearchDialog = false }
        )
    }

    if (editingProfile != null) {
        val profile = editingProfile!!
        SubscriptionInputDialog(
            initialName = profile.name,
            initialUrl = profile.url ?: "",
            // initialAutoUpdateInterval = profile.autoUpdateInterval,
            // initialDnsPreResolve = profile.dnsPreResolve,
            // initialDnsServer = profile.dnsServer,
            title = stringResource(R.string.profiles_edit_profile),
            onDismiss = { editingProfile = null },
            onConfirm = { name, url, autoUpdateInterval, dnsPreResolve, dnsServer ->
                viewModel.updateProfileMetadata(profile.id, name, url, autoUpdateInterval, dnsPreResolve, dnsServer)
                editingProfile = null
            }
        )
    }

     Scaffold(
        containerColor = MaterialTheme.colorScheme.background,
        contentWindowInsets = WindowInsets(0, 0, 0, 0),
        floatingActionButton = {
            AnimatedVisibility(
                visible = isFabVisible,
                enter = fadeIn(animationSpec = tween(300)),
                exit = fadeOut(animationSpec = tween(300))
            ) {
                FloatingActionButton(
                    onClick = { showImportSelection = true },
                    containerColor = MaterialTheme.colorScheme.primary,
                    contentColor = MaterialTheme.colorScheme.onPrimary
                ) {
                    Icon(Icons.Rounded.Add, contentDescription = "Add Profile")
                }
            }
        }
    ) { padding ->
        val statusBarPadding = WindowInsets.statusBars.asPaddingValues()
        Column(
            modifier = Modifier
                .fillMaxSize()
                .pointerInput(Unit) {
                    awaitEachGesture {
                        val down = awaitFirstDown(pass = PointerEventPass.Initial)
                        lastY = down.position.y
                        do {
                            val event = awaitPointerEvent(PointerEventPass.Initial)
                            val currentY = event.changes.firstOrNull()?.position?.y ?: lastY
                            val deltaY = currentY - lastY
                            if (deltaY < -30f) {
                                isFabVisible = false
                            } else if (deltaY > 30f) {
                                isFabVisible = true
                            }
                            lastY = currentY
                        } while (event.changes.any { it.pressed })
                    }
                }
                .nestedScroll(nestedScrollConnection)
                .padding(top = statusBarPadding.calculateTopPadding())
                .padding(bottom = padding.calculateBottomPadding())
        ) {
            // Header
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(16.dp),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.SpaceBetween
            ) {
                Text(
                    text = stringResource(R.string.profiles_title),
                    style = MaterialTheme.typography.headlineMedium,
                    fontWeight = FontWeight.Bold,
                    color = MaterialTheme.colorScheme.onBackground
                )
                IconButton(onClick = { showSearchDialog = true }) {
                    Icon(Icons.Rounded.Search, contentDescription = "Search", tint = MaterialTheme.colorScheme.onBackground)
                }
            }

            // List
            LazyColumn(
                state = listState,
                contentPadding = PaddingValues(16.dp),
                verticalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                itemsIndexed(profiles, key = { _, profile -> profile.id }) { index, profile ->
                    var visible by remember { mutableStateOf(false) }
                    LaunchedEffect(Unit) {
                        if (index < 15) {
                            delay(index * 30L)
                        }
                        visible = true
                    }

                    val alpha by animateFloatAsState(
                        targetValue = if (visible) 1f else 0f,
                        animationSpec = tween(durationMillis = 300),
                        label = "alpha"
                    )
                    val translateY by animateFloatAsState(
                        targetValue = if (visible) 0f else 40f,
                        animationSpec = tween(durationMillis = 300),
                        label = "translateY"
                    )

                    ProfileCard(
                        name = profile.name,
                        type = profile.type.name,
                        isSelected = profile.id == activeProfileId,
                        isEnabled = profile.enabled,
                        isUpdating = profile.updateStatus == UpdateStatus.Updating,
                        updateStatus = profile.updateStatus,
                        expireDate = profile.expireDate,
                        totalTraffic = profile.totalTraffic,
                        usedTraffic = profile.usedTraffic,
                        lastUpdated = profile.lastUpdated,
                        dnsPreResolve = profile.dnsPreResolve,
                        onClick = { viewModel.setActiveProfile(profile.id) },
                        onUpdate = {
                            viewModel.updateProfile(profile.id)
                        },
                        onToggle = {
                            viewModel.toggleProfileEnabled(profile.id)
                        },
                        onEdit = {
                            if (profile.type == ProfileType.Subscription ||
                                profile.type == ProfileType.Imported) {
                                editingProfile = profile
                            } else {
                                navController.navigate(Screen.ProfileEditor.profileEditorRoute(profile.name))
                            }
                        },
                        onDelete = {
                            viewModel.deleteProfile(profile.id)
                        },
                        modifier = Modifier.graphicsLayer(
                            alpha = alpha,
                            translationY = translateY
                        )
                    )
                }
            }
        }
    }
}

private enum class ProfileImportType { Subscription, File, Clipboard, QRCode }

@Composable
private fun ImportSelectionDialog(
    onDismiss: () -> Unit,
    onTypeSelected: (ProfileImportType) -> Unit
) {
    androidx.compose.ui.window.Dialog(onDismissRequest = onDismiss) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .background(MaterialTheme.colorScheme.surface, RoundedCornerShape(16.dp))
                .padding(24.dp),
            verticalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            ImportOptionCard(
                icon = Icons.Rounded.Link,
                title = stringResource(R.string.profiles_subscription_link),
                subtitle = stringResource(R.string.common_import),
                onClick = { onTypeSelected(ProfileImportType.Subscription) }
            )
            ImportOptionCard(
                icon = Icons.Rounded.Description,
                title = stringResource(R.string.profiles_local_file),
                subtitle = stringResource(R.string.profiles_local_file_subtitle),
                onClick = { onTypeSelected(ProfileImportType.File) }
            )
            ImportOptionCard(
                icon = Icons.Rounded.ContentPaste,
                title = stringResource(R.string.profiles_clipboard),
                subtitle = stringResource(R.string.profiles_clipboard_subtitle),
                onClick = { onTypeSelected(ProfileImportType.Clipboard) }
            )
            ImportOptionCard(
                icon = Icons.Rounded.QrCodeScanner,
                title = stringResource(R.string.profiles_scan_qrcode),
                subtitle = stringResource(R.string.profiles_scan_qrcode_subtitle),
                onClick = { onTypeSelected(ProfileImportType.QRCode) }
            )
        }
    }
}

@Composable
private fun ImportLoadingDialog(message: String, onCancel: () -> Unit = {}) {
     androidx.compose.ui.window.Dialog(onDismissRequest = {}) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .background(MaterialTheme.colorScheme.surface, RoundedCornerShape(24.dp))
                .padding(24.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.spacedBy(16.dp)
        ) {
             androidx.compose.material3.CircularProgressIndicator(
                    color = MaterialTheme.colorScheme.primary
             )
            Text(
                text = message,
                style = MaterialTheme.typography.bodyLarge,
                fontWeight = FontWeight.Medium,
                color = MaterialTheme.colorScheme.onSurface
            )
            TextButton(
                onClick = onCancel,
                modifier = Modifier.align(Alignment.End)
            ) {
                Text(
                    text = stringResource(R.string.common_cancel),
                    color = MaterialTheme.colorScheme.error
                )
            }
        }
    }
}

@Composable
private fun ImportOptionCard(
    icon: ImageVector,
    title: String,
    subtitle: String,
    onClick: () -> Unit
) {
    StandardCard(onClick = onClick) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(16.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            Icon(
                imageVector = icon,
                contentDescription = null,
                tint = MaterialTheme.colorScheme.onSurface,
                modifier = Modifier.size(32.dp)
            )
            Spacer(modifier = Modifier.width(16.dp))
            Column {
                Text(
                    text = title,
                    style = MaterialTheme.typography.titleMedium,
                    fontWeight = FontWeight.Bold,
                    color = MaterialTheme.colorScheme.onSurface
                )
                Text(
                    text = subtitle,
                    style = MaterialTheme.typography.bodyMedium,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
        }
    }
}

@Composable
private fun SubscriptionInputDialog(
    initialName: String = "",
    initialUrl: String = "",
    // initialAutoUpdateInterval: Int = 0,
    // initialDnsPreResolve: Boolean = false,
    // initialDnsServer: String? = null,
    title: String = stringResource(R.string.profiles_add_subscription),
    onDismiss: () -> Unit,
    onConfirm: (name: String, url: String, autoUpdateInterval: Int, dnsPreResolve: Boolean, dnsServer: String?) -> Unit
) {
    var name by remember { mutableStateOf(initialName) }
    var url by remember { mutableStateOf(initialUrl) }

    androidx.compose.ui.window.Dialog(onDismissRequest = onDismiss) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .background(MaterialTheme.colorScheme.surface, RoundedCornerShape(28.dp))
                .padding(24.dp)
        ) {
            Text(
                text = title,
                style = MaterialTheme.typography.titleLarge,
                fontWeight = FontWeight.Bold,
                color = MaterialTheme.colorScheme.onSurface
            )
            Spacer(modifier = Modifier.height(16.dp))

            androidx.compose.material3.OutlinedTextField(
                value = name,
                onValueChange = { name = it },
                label = { Text(stringResource(R.string.profiles_name_label)) },
                modifier = Modifier.fillMaxWidth(),
                singleLine = true,
                shape = RoundedCornerShape(16.dp)
            )

            Spacer(modifier = Modifier.height(12.dp))

            androidx.compose.material3.OutlinedTextField(
                value = url,
                onValueChange = { url = it },
                label = { Text(stringResource(R.string.profiles_url_label)) },
                modifier = Modifier.fillMaxWidth(),
                singleLine = true,
                shape = RoundedCornerShape(16.dp)
            )

            Spacer(modifier = Modifier.height(24.dp))

            Row(horizontalArrangement = Arrangement.End, modifier = Modifier.fillMaxWidth()) {
                TextButton(onClick = onDismiss) {
                    Text(stringResource(R.string.common_cancel))
                }
                Spacer(modifier = Modifier.width(8.dp))
                TextButton(onClick = { onConfirm(name, url, 0, false, null) }) {
                    Text(stringResource(R.string.common_confirm))
                }
            }
        }
    }
}
