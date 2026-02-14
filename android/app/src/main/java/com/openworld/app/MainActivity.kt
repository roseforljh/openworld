package com.openworld.app

import android.content.Intent
import android.Manifest
import android.app.ActivityManager
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.SystemBarStyle
import androidx.activity.enableEdgeToEdge
import androidx.activity.compose.setContent
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.core.FastOutSlowInEasing
import androidx.compose.animation.core.tween
import androidx.compose.animation.expandVertically
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.shrinkVertically
import androidx.compose.animation.slideInVertically
import androidx.compose.animation.slideOutVertically
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.heightIn
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarDuration
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.ui.res.stringResource
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.shadow
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.ui.platform.LocalContext
import androidx.core.content.ContextCompat
import androidx.lifecycle.viewmodel.compose.viewModel
import androidx.navigation.compose.currentBackStackEntryAsState
import androidx.navigation.compose.rememberNavController
import com.openworld.app.repository.SettingsRepository
import com.openworld.app.viewmodel.DashboardViewModel
import com.openworld.app.model.ConnectionState
import com.openworld.app.model.AppLanguage
import com.openworld.app.utils.LocaleHelper
import com.openworld.app.utils.DeepLinkHandler
import com.openworld.app.ipc.OpenWorldRemote
import com.openworld.app.service.VpnTileService
import com.openworld.app.ui.components.AppNavBar
import com.openworld.app.ui.navigation.AppNavigation
import com.openworld.app.ui.theme.PureWhite
import com.openworld.app.ui.theme.OpenWorldTheme
import android.content.ComponentName
import android.service.quicksettings.TileService
import androidx.work.WorkManager
import com.openworld.app.worker.RuleSetUpdateWorker
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.collectLatest
import android.app.Activity
import com.openworld.app.ui.scanner.QrScannerActivity
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.compose.LifecycleEventEffect

class MainActivity : ComponentActivity() {

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
    }

    override fun attachBaseContext(newBase: Context) {
        // �?SharedPreferences 读取语言设置
        val prefs = newBase.getSharedPreferences("settings", Context.MODE_PRIVATE)
        val languageName = prefs.getString("app_language_cache", null)
        val language = if (languageName != null) {
            try {
                AppLanguage.valueOf(languageName)
            } catch (e: Exception) {
                AppLanguage.SYSTEM
            }
        } else {
            AppLanguage.SYSTEM
        }

        val context = LocaleHelper.wrap(newBase, language)
        super.attachBaseContext(context)
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        // �?super.onCreate 之前启用边到边显�?        enableEdgeToEdge(
            statusBarStyle = SystemBarStyle.dark(android.graphics.Color.TRANSPARENT),
            navigationBarStyle = SystemBarStyle.dark(android.graphics.Color.TRANSPARENT)
        )
        super.onCreate(savedInstanceState)
        setContent {
            OpenWorldApp()
        }

        cancelRuleSetUpdateWork()
    }

    private fun cancelRuleSetUpdateWork() {
        WorkManager.getInstance(this).cancelUniqueWork(RuleSetUpdateWorker.WORK_NAME)
    }
}

@Composable
fun OpenWorldApp() {
    val context = LocalContext.current

    val notificationPermissionLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.RequestPermission(),
        onResult = { isGranted ->
        }
    )

    LaunchedEffect(Unit) {
        OpenWorldRemote.ensureBound(context)
        // Best-effort: ask system to refresh QS tile state after app process restarts/force-stops.
        runCatching {
            TileService.requestListeningState(context, ComponentName(context, VpnTileService::class.java))
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            val permission = ContextCompat.checkSelfPermission(context, Manifest.permission.POST_NOTIFICATIONS)

            if (permission != PackageManager.PERMISSION_GRANTED) {
                notificationPermissionLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
            }
        }
    }

    val settingsRepository = remember { SettingsRepository.getInstance(context) }
    val settings by settingsRepository.settings.collectAsState(initial = null)
    val dashboardViewModel: DashboardViewModel = viewModel()

    // 前台恢复时统一�?refreshState（内部已包含 ensureBound + MMKV 即时恢复�?    // 不再�?ON_START 单独调用 ensureBound，避免与 ON_RESUME �?refreshState 竞争
    // 导致 rebind 打断正在进行的连接，触发 STOPPED 闪烁
    LifecycleEventEffect(Lifecycle.Event.ON_RESUME) {
        dashboardViewModel.refreshState()
    }

    // 当语言设置变化�?缓存�?SharedPreferences �?attachBaseContext 使用
    LaunchedEffect(settings?.appLanguage) {
        settings?.appLanguage?.let { language ->
            val prefs = context.getSharedPreferences("settings", Context.MODE_PRIVATE)
            prefs.edit().putString("app_language_cache", language.name).apply()
        }
    }

    // 自动检查更�?- �?VPN 连接后检查，�?App 启动 10 秒后检查（直连尝试�?    val isVpnRunningForUpdate by OpenWorldRemote.isRunning.collectAsState()
    var updateChecked by remember { mutableStateOf(false) }

    LaunchedEffect(settings?.autoCheckUpdate, isVpnRunningForUpdate) {
        if (settings?.autoCheckUpdate != true || updateChecked) return@LaunchedEffect

        if (isVpnRunningForUpdate) {
            // VPN 已连接，延迟 1 秒后通过代理检�?            kotlinx.coroutines.delay(1000L)
            updateChecked = true
            com.openworld.app.utils.AppUpdateChecker.checkAndNotify(context)
        }
    }

    // 兜底：如�?10 秒后 VPN 仍未连接，尝试直连检�?    LaunchedEffect(settings?.autoCheckUpdate) {
        if (settings?.autoCheckUpdate != true) return@LaunchedEffect
        kotlinx.coroutines.delay(10000L)
        if (!updateChecked) {
            updateChecked = true
            com.openworld.app.utils.AppUpdateChecker.checkAndNotify(context)
        }
    }

    // Handle App Shortcuts - need navController reference
    var pendingNavigation by remember { mutableStateOf<String?>(null) }

    LaunchedEffect(Unit) {
        val activity = context as? Activity
        activity?.intent?.let { intent ->
            when (intent.action) {
                "com.openworld.app.action.SCAN" -> {
                    val scanIntent = android.content.Intent(context, QrScannerActivity::class.java)
                    context.startActivity(scanIntent)
                    intent.action = null
                }
                "com.openworld.app.action.SWITCH_NODE" -> {
                    // 设置待导航目标，等待 navController 初始化后执行
                    pendingNavigation = "nodes"
                    intent.action = null
                }
                android.content.Intent.ACTION_VIEW -> {
                    // 处理 URL Scheme (singbox:// �?kunbox://)
                    intent.data?.let { uri ->
                        val scheme = uri.scheme
                        val host = uri.host

                        if ((scheme == "singbox" || scheme == "kunbox") && host == "install-config") {
                            val url = uri.getQueryParameter("url")
                            val name = uri.getQueryParameter("name") ?: "导入的订�?
                            val intervalStr = uri.getQueryParameter("interval")
                            val interval = intervalStr?.toIntOrNull() ?: 0

                            if (!url.isNullOrBlank()) {
                                // 使用 DeepLinkHandler 存储数据
                                DeepLinkHandler.setPendingSubscriptionImport(name, url, interval)
                                // 导航�?profiles 页面
                                pendingNavigation = "profiles"
                            }
                        }
                    }
                    // 清除 data 防止重复处理
                    intent.data = null
                }
            }
        }
    }
    val connectionState by dashboardViewModel.connectionState.collectAsState()
    val isRunning by OpenWorldRemote.isRunning.collectAsState()
    val isStarting by OpenWorldRemote.isStarting.collectAsState()
    val manuallyStopped by OpenWorldRemote.manuallyStopped.collectAsState()

    // 监听 VPN 状态变化，清理网络连接池，避免复用失效�?Socket
    LaunchedEffect(isRunning, isStarting) {
        // �?VPN 状态发生重大变化（启动、停止、重启）时，底层的网络接口可能已变更
        // 此时必须清理连接池，防止 OkHttp 复用绑定在旧网络接口上的连接导致 "use of closed network connection"
        // 必须�?IO 线程执行，因�?connectionPool.evictAll() 会关�?SSL socket，涉及网�?I/O
        kotlinx.coroutines.withContext(kotlinx.coroutines.Dispatchers.IO) {
            com.openworld.app.utils.NetworkClient.clearConnectionPool()
        }
    }

    // 自动连接逻辑
    LaunchedEffect(settings?.autoConnect, connectionState) {
        if (settings?.autoConnect == true &&
            connectionState == ConnectionState.Idle &&
            !isRunning &&
            !isStarting &&
            !manuallyStopped
        ) {
            // Delay a bit to ensure everything is initialized
            delay(1000)
            if (connectionState == ConnectionState.Idle && !isRunning) {
                dashboardViewModel.toggleConnection()
            }
        }
    }

    // 在最近任务中隐藏逻辑
    LaunchedEffect(settings?.excludeFromRecent) {
        val am = context.getSystemService(Context.ACTIVITY_SERVICE) as? ActivityManager
        am?.appTasks?.forEach {
            it.setExcludeFromRecents(settings?.excludeFromRecent == true)
        }
    }

    val snackbarHostState = remember { SnackbarHostState() }

    LaunchedEffect(Unit) {
        SettingsRepository.restartRequiredEvents.collectLatest {
            // 如果 VPN 没有在运行，也没有正在启动，就不弹窗（因为下次启动自然生效）
            if (!OpenWorldRemote.isRunning.value && !OpenWorldRemote.isStarting.value) return@collectLatest

            // 新提示出现时，立即关闭旧的，只保留最新的那一�?            snackbarHostState.currentSnackbarData?.dismiss()

            snackbarHostState.showSnackbar(
                message = context.getString(R.string.settings_restart_needed),
                duration = SnackbarDuration.Short
            )
        }
    }

    val appTheme = settings?.appTheme ?: com.openworld.app.model.AppThemeMode.SYSTEM

    OpenWorldTheme(appTheme = appTheme) {
        val navController = rememberNavController()

        // Handle pending navigation from App Shortcuts
        LaunchedEffect(pendingNavigation) {
            pendingNavigation?.let { route ->
                delay(100) // 确保 navController 已初始化
                navController.navigate(route) {
                    popUpTo(navController.graph.startDestinationId) {
                        saveState = true
                    }
                    launchSingleTop = true
                    restoreState = true
                }
                pendingNavigation = null
            }
        }

        // Get current destination
        val navBackStackEntry = navController.currentBackStackEntryAsState()
        val currentRoute = navBackStackEntry.value?.destination?.route
        val showBottomBar = currentRoute in listOf(
            "dashboard", "nodes", "profiles", "settings"
        )

        Box(modifier = Modifier.fillMaxSize()) {
            Scaffold(
                snackbarHost = {
                    SnackbarHost(
                        hostState = snackbarHostState,
                        snackbar = { data ->
                            Surface(
                                modifier = Modifier
                                    .padding(horizontal = 12.dp)
                                    .heightIn(min = 52.dp)
                                    .shadow(6.dp, RoundedCornerShape(12.dp)),
                                color = PureWhite,
                                contentColor = Color.Black,
                                shape = RoundedCornerShape(12.dp)
                            ) {
                                Row(
                                    modifier = Modifier
                                        .fillMaxWidth()
                                        .padding(horizontal = 12.dp, vertical = 10.dp),
                                    verticalAlignment = Alignment.CenterVertically
                                ) {
                                    Text(
                                        text = data.visuals.message,
                                        modifier = Modifier.weight(1f),
                                        style = MaterialTheme.typography.bodySmall,
                                        fontWeight = FontWeight.Normal,
                                        color = Color.Black,
                                        maxLines = 1,
                                        overflow = TextOverflow.Ellipsis
                                    )

                                    Spacer(modifier = Modifier.width(12.dp))

                                    Text(
                                        text = stringResource(R.string.main_restart),
                                        modifier = Modifier
                                            .heightIn(min = 24.dp)
                                            .clickable {
                                                data.dismiss()
                                                if (isRunning || isStarting) {
                                                    dashboardViewModel.restartVpn()
                                                }
                                            }
                                            .padding(horizontal = 8.dp, vertical = 4.dp),
                                        style = MaterialTheme.typography.labelMedium,
                                        fontWeight = FontWeight.SemiBold,
                                        color = Color(0xFF00C853)
                                    )
                                }
                            }
                        }
                    )
                },
                bottomBar = {
                    AnimatedVisibility(
                        visible = showBottomBar,
                        enter = slideInVertically(
                            initialOffsetY = { it },
                            animationSpec = tween(durationMillis = 400, easing = FastOutSlowInEasing)
                        ) + expandVertically(
                            expandFrom = Alignment.Bottom,
                            animationSpec = tween(durationMillis = 400, easing = FastOutSlowInEasing)
                        ) + fadeIn(animationSpec = tween(durationMillis = 400)),
                        exit = slideOutVertically(
                            targetOffsetY = { it },
                            animationSpec = tween(durationMillis = 400, easing = FastOutSlowInEasing)
                        ) + shrinkVertically(
                            shrinkTowards = Alignment.Bottom,
                            animationSpec = tween(durationMillis = 400, easing = FastOutSlowInEasing)
                        ) + fadeOut(animationSpec = tween(durationMillis = 400))
                    ) {
                        AppNavBar(navController = navController)
                    }
                },
                contentWindowInsets = WindowInsets(0, 0, 0, 0) // 不自动添加系统栏 insets
            ) { innerPadding ->
                Surface(
                    modifier = Modifier
                        .fillMaxSize()
                        .padding(bottom = innerPadding.calculateBottomPadding()) // 只应用底�?padding
                ) {
                    AppNavigation(navController)
                }
            }
        }
    }
}







