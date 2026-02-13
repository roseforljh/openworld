package com.openworld.app

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.navigation.compose.rememberNavController
import com.openworld.app.model.AppThemeMode
import com.openworld.app.repository.SettingsStore
import com.openworld.app.ui.components.AppNavBar
import com.openworld.app.ui.navigation.AppNavigation
import com.openworld.app.ui.navigation.getTabForRoute
import com.openworld.app.ui.theme.OpenWorldTheme
import com.openworld.app.util.LocaleManager
import com.openworld.core.OpenWorldCore
import androidx.compose.runtime.derivedStateOf
import androidx.compose.runtime.remember
import androidx.compose.ui.Modifier
import androidx.navigation.compose.currentBackStackEntryAsState

class MainActivity : ComponentActivity() {

    private var themeMode by mutableStateOf(AppThemeMode.SYSTEM)

    override fun attachBaseContext(newBase: android.content.Context) {
        super.attachBaseContext(LocaleManager.wrapContext(newBase))
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        enableEdgeToEdge()
        super.onCreate(savedInstanceState)
        themeMode = SettingsStore.getThemeMode(this)

        setContent {
            OpenWorldTheme(themeMode = themeMode) {
                val navController = rememberNavController()
                val navBackStackEntry by navController.currentBackStackEntryAsState()
                val currentRoute = navBackStackEntry?.destination?.route

                // 主 Tab 路由列表
                val tabRoutes = setOf("dashboard", "nodes", "profiles", "settings")
                val showBottomBar by remember(currentRoute) {
                    derivedStateOf { getTabForRoute(currentRoute) == currentRoute && currentRoute in tabRoutes }
                }

                Scaffold(
                    contentWindowInsets = WindowInsets(0, 0, 0, 0),
                    bottomBar = {
                        if (showBottomBar) {
                            AppNavBar(navController = navController)
                        }
                    }
                ) { innerPadding ->
                    // 仅应用底部 padding（底栏高度），顶部由各页面自行处理
                    Surface(
                        modifier = Modifier
                            .fillMaxSize()
                            .padding(bottom = innerPadding.calculateBottomPadding())
                    ) {
                        AppNavigation(
                            navController = navController
                        )
                    }
                }
            }
        }
    }

    override fun onTrimMemory(level: Int) {
        super.onTrimMemory(level)
        if (level >= android.content.ComponentCallbacks2.TRIM_MEMORY_MODERATE) {
            try {
                OpenWorldCore.notifyMemoryLow()
            } catch (_: Exception) {}
        }
    }

    fun updateTheme(mode: AppThemeMode) {
        SettingsStore.setThemeMode(this, mode)
        themeMode = mode
    }
}
