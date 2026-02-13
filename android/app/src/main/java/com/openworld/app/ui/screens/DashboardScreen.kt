package com.openworld.app.ui.screens

import android.app.Activity
import android.net.VpnService
import android.widget.Toast

import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.animation.core.FastOutSlowInEasing
import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.tween
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
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
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.Bolt
import androidx.compose.material.icons.rounded.BugReport
import androidx.compose.material.icons.rounded.Refresh
import androidx.compose.material.icons.rounded.SwapVert
import androidx.compose.material.icons.rounded.Terminal
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

import androidx.lifecycle.viewmodel.compose.viewModel
import androidx.navigation.NavController

import androidx.compose.ui.graphics.Color
import com.openworld.app.ui.components.BigToggle
import com.openworld.app.ui.components.ConnectionStatusChip
import com.openworld.app.ui.components.InfoCard
import com.openworld.app.ui.components.ModeChip
import com.openworld.app.ui.components.SingleSelectDialog
import com.openworld.app.ui.components.StatusChip
import com.openworld.app.ui.navigation.Screen
import com.openworld.app.ui.theme.Green500
import com.openworld.app.ui.theme.Neutral500
import com.openworld.app.util.FormatUtil
import com.openworld.app.viewmodel.DashboardViewModel
import kotlin.math.cos
import kotlin.math.sin

@Composable
fun DashboardScreen(
    navController: NavController,
    viewModel: DashboardViewModel = viewModel()
) {
    val state by viewModel.state.collectAsState()
    val vpnPermissionNeeded by viewModel.vpnPermissionNeeded.collectAsState()
    val context = LocalContext.current

    // Toast 事件
    LaunchedEffect(Unit) {
        viewModel.toastEvent.collect { msg ->
            Toast.makeText(context, msg, Toast.LENGTH_SHORT).show()
        }
    }

    // VPN 权限
    val vpnLauncher = rememberLauncherForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == Activity.RESULT_OK) {
            viewModel.onVpnPermissionGranted()
        } else {
            viewModel.onVpnPermissionDenied()
        }
    }

    if (vpnPermissionNeeded) {
        val intent = VpnService.prepare(context)
        if (intent != null) {
            vpnLauncher.launch(intent)
        } else {
            viewModel.onVpnPermissionGranted()
        }
    }

    // 对话框状态
    var showModeDialog by remember { mutableStateOf(false) }
    var showProfileDialog by remember { mutableStateOf(false) }
    var showNodeDialog by remember { mutableStateOf(false) }

    val statusBarPadding = WindowInsets.statusBars.asPaddingValues()

    // Background Animation
    val isRunning = state.connected || state.connecting
    val infiniteTransition = rememberInfiniteTransition(label = "BackgroundAnimation")

    val pulseScale by infiniteTransition.animateFloat(
        initialValue = 1f,
        targetValue = if (isRunning) 1.05f else 1f,
        animationSpec = infiniteRepeatable(
            animation = tween(1500, easing = FastOutSlowInEasing),
            repeatMode = RepeatMode.Reverse
        ),
        label = "PulseScale"
    )

    val pulseAlpha by infiniteTransition.animateFloat(
        initialValue = 0.3f,
        targetValue = if (isRunning) 0.6f else 0.3f,
        animationSpec = infiniteRepeatable(
            animation = tween(1500, easing = FastOutSlowInEasing),
            repeatMode = RepeatMode.Reverse
        ),
        label = "PulseAlpha"
    )

    val defaultBaseColor = MaterialTheme.colorScheme.onSurface

    Box(modifier = Modifier.fillMaxSize()) {
        // Background Decoration - 3D Box Cage (Back Face & Connections)
        Canvas(modifier = Modifier.fillMaxSize()) {
            val center = center
            val baseSize = size.minDimension * 0.55f * pulseScale

            val baseAlpha = if (isRunning) pulseAlpha * 0.5f else 0.15f
            val color = defaultBaseColor.copy(alpha = baseAlpha)
            val strokeWidth = if (isRunning) 2.dp.toPx() else 1.dp.toPx()

            val rotationX = Math.toRadians(15.0).toFloat()
            val rotationY = Math.toRadians(35.0).toFloat()

            fun project(x: Float, y: Float, z: Float): Offset {
                val y1 = y * cos(rotationX) - z * sin(rotationX)
                val z1 = y * sin(rotationX) + z * cos(rotationX)
                val x2 = x * cos(rotationY) + z1 * sin(rotationY)
                return Offset(center.x + x2, center.y + y1)
            }

            val s = baseSize / 1.5f

            val p1 = project(-s, -s, -s)
            val p2 = project(s, -s, -s)
            val p3 = project(s, s, -s)
            val p4 = project(-s, s, -s)
            val p5 = project(-s, -s, s)
            val p6 = project(s, -s, s)
            val p7 = project(s, s, s)
            val p8 = project(-s, s, s)

            val path = Path()
            // Back Face (p5-p8)
            path.moveTo(p5.x, p5.y)
            path.lineTo(p6.x, p6.y)
            path.lineTo(p7.x, p7.y)
            path.lineTo(p8.x, p8.y)
            path.close()

            // Connections
            path.moveTo(p1.x, p1.y); path.lineTo(p5.x, p5.y)
            path.moveTo(p2.x, p2.y); path.lineTo(p6.x, p6.y)
            path.moveTo(p3.x, p3.y); path.lineTo(p7.x, p7.y)
            path.moveTo(p4.x, p4.y); path.lineTo(p8.x, p8.y)

            drawPath(
                path = path,
                color = color,
                style = Stroke(width = strokeWidth)
            )
        }

        Column(
            modifier = Modifier
                .fillMaxSize()
                .padding(top = statusBarPadding.calculateTopPadding())
                .padding(24.dp),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.SpaceBetween
        ) {
            // 1. Status Bar (Chips)
            Column(
                modifier = Modifier.fillMaxWidth(),
                verticalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                // App Logo & Title
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    modifier = Modifier.padding(bottom = 12.dp)
                ) {
                    androidx.compose.ui.viewinterop.AndroidView(
                        factory = { ctx ->
                            android.widget.ImageView(ctx).apply {
                                setImageResource(com.openworld.app.R.mipmap.ic_launcher_round)
                            }
                        },
                        modifier = Modifier
                            .size(40.dp)
                            .padding(end = 12.dp)
                    )
                    Text(
                        text = "KunBox",
                        style = MaterialTheme.typography.headlineMedium.copy(
                            fontWeight = FontWeight.Bold,
                            letterSpacing = 1.sp
                        ),
                        color = MaterialTheme.colorScheme.onBackground
                    )
                }

                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceBetween,
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    StatusChip(
                        label = if (state.connected) "已连接" else if (state.connecting) "连接中" else "未连接",
                        isActive = state.connected
                    )

                    val indicatorColor = when {
                        state.connected -> Color(0xFF4CAF50)
                        state.connecting -> Neutral500
                        else -> Neutral500
                    }

                    ModeChip(
                        mode = state.mode.uppercase(),
                        indicatorColor = indicatorColor,
                        onClick = { showModeDialog = true }
                    )
                }

                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.Start
                ) {
                    StatusChip(
                        label = state.activeProfile.ifEmpty { "未选择配置" },
                        onClick = { showProfileDialog = true }
                    )
                    Spacer(modifier = Modifier.width(8.dp))
                    StatusChip(
                        label = state.activeNodeTag.ifEmpty { "未选择节点" },
                        onClick = { showNodeDialog = true }
                    )
                }
            }

            // 2. Main Toggle - 居中显示
            Box(
                contentAlignment = Alignment.Center,
                modifier = Modifier.weight(1f)
            ) {
                BigToggle(
                    isRunning = state.connected || state.connecting,
                    onClick = { viewModel.toggleConnection() }
                )
            }

            // 3. Stats & Quick Actions
            Column(
                modifier = Modifier.fillMaxWidth(),
                horizontalAlignment = Alignment.CenterHorizontally
            ) {
                InfoCard(
                    uploadSpeed = FormatUtil.formatSpeed(state.uploadRate),
                    downloadSpeed = FormatUtil.formatSpeed(state.downloadRate),
                    ping = if (state.ping > 0) "${state.ping} ms" else "0 ms",
                    isPingLoading = state.testingLatency,
                    onPingClick = { viewModel.testAllNodesLatency() }
                )

                Spacer(modifier = Modifier.height(24.dp))

                // Quick Actions
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.SpaceEvenly
                ) {
                    QuickActionButton(androidx.compose.material.icons.Icons.Rounded.Refresh, "更新订阅") { viewModel.updateAllSubscriptions() }
                    QuickActionButton(androidx.compose.material.icons.Icons.Rounded.Bolt, "延迟测试") { viewModel.testAllNodesLatency() }
                    QuickActionButton(androidx.compose.material.icons.Icons.Rounded.Terminal, "日志") { navController.navigate(Screen.Logs.route) }
                    QuickActionButton(androidx.compose.material.icons.Icons.Rounded.BugReport, "诊断") { navController.navigate(Screen.Diagnostics.route) }
                }
            }
        }

        // Foreground Decoration - 3D Box Cage (Front Face)
        Canvas(modifier = Modifier.fillMaxSize()) {
            val center = center
            val baseSize = size.minDimension * 0.55f * pulseScale

            val baseAlpha = if (isRunning) pulseAlpha * 0.5f else 0.15f
            val color = defaultBaseColor.copy(alpha = baseAlpha)
            val strokeWidth = if (isRunning) 2.dp.toPx() else 1.dp.toPx()

            val rotationX = Math.toRadians(15.0).toFloat()
            val rotationY = Math.toRadians(35.0).toFloat()

            fun project(x: Float, y: Float, z: Float): Offset {
                val y1 = y * cos(rotationX) - z * sin(rotationX)
                val z1 = y * sin(rotationX) + z * cos(rotationX)
                val x2 = x * cos(rotationY) + z1 * sin(rotationY)
                return Offset(center.x + x2, center.y + y1)
            }

            val s = baseSize / 1.5f

            val p1 = project(-s, -s, -s)
            val p2 = project(s, -s, -s)
            val p3 = project(s, s, -s)
            val p4 = project(-s, s, -s)

            val path = Path()
            // Front Face
            path.moveTo(p1.x, p1.y)
            path.lineTo(p2.x, p2.y)
            path.lineTo(p3.x, p3.y)
            path.lineTo(p4.x, p4.y)
            path.close()

            drawPath(
                path = path,
                color = color,
                style = Stroke(width = strokeWidth)
            )
        }
    }

    // ── 对话框 ──

    if (showModeDialog) {
        val options = listOf("rule", "global", "direct")
        SingleSelectDialog(
            title = "路由模式",
            options = options,
            selectedIndex = options.indexOf(state.mode).coerceAtLeast(0),
            onSelect = { index ->
                viewModel.setMode(options[index])
                showModeDialog = false
            },
            onDismiss = { showModeDialog = false }
        )
    }

    if (showProfileDialog) {
        val profiles = state.profiles.ifEmpty { listOf("default") }
        SingleSelectDialog(
            title = "选择配置",
            options = profiles,
            selectedIndex = profiles.indexOf(state.activeProfile).coerceAtLeast(0),
            onSelect = { index ->
                viewModel.setActiveProfile(profiles[index])
                showProfileDialog = false
            },
            onDismiss = { showProfileDialog = false }
        )
    }

    if (showNodeDialog) {
        val allNodes = state.groups.flatMap { g ->
            g.members.map { "${g.name}/$it" }
        }
        val selectedNode = state.groups.flatMap { g ->
            g.members.filter { it == state.activeNodeTag }.map { "${g.name}/$it" }
        }.firstOrNull() ?: ""

        if (allNodes.isNotEmpty()) {
            SingleSelectDialog(
                title = "选择节点",
                options = allNodes,
                selectedIndex = allNodes.indexOf(selectedNode).coerceAtLeast(0),
                onSelect = { index ->
                    val fullName = allNodes[index]
                    val parts = fullName.split("/", limit = 2)
                    if (parts.size == 2) {
                        viewModel.setActiveNode(parts[0], parts[1])
                    }
                    showNodeDialog = false
                },
                onDismiss = { showNodeDialog = false }
            )
        } else {
            showNodeDialog = false
        }
    }
}

@Composable
private fun QuickActionButton(
    icon: androidx.compose.ui.graphics.vector.ImageVector,
    label: String,
    loading: Boolean = false,
    onClick: () -> Unit
) {
    Column(horizontalAlignment = Alignment.CenterHorizontally) {
        IconButton(onClick = onClick, enabled = !loading) {
            if (loading) {
                androidx.compose.material3.CircularProgressIndicator(
                    modifier = Modifier.size(20.dp),
                    strokeWidth = 2.dp,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            } else {
                Icon(
                    imageVector = icon,
                    contentDescription = label,
                    tint = MaterialTheme.colorScheme.onBackground
                )
            }
        }
        Text(
            text = label,
            style = MaterialTheme.typography.labelSmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
    }
}
