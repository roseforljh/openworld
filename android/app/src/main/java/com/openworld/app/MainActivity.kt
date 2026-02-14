package com.openworld.app

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.SystemBarStyle
import androidx.activity.enableEdgeToEdge
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.Scaffold
import androidx.compose.foundation.layout.Box
import androidx.compose.animation.AnimatedVisibility
import androidx.compose.animation.core.FastOutSlowInEasing
import androidx.compose.animation.core.tween
import androidx.compose.animation.expandVertically
import androidx.compose.animation.fadeIn
import androidx.compose.animation.fadeOut
import androidx.compose.animation.shrinkVertically
import androidx.compose.animation.slideInVertically
import androidx.compose.animation.slideOutVertically
import androidx.compose.ui.Alignment
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.navigation.compose.rememberNavController
import com.openworld.app.model.AppThemeMode
import com.openworld.app.repository.SettingsStore
import com.openworld.app.ui.components.AppNavBar
import com.openworld.app.ui.navigation.AppNavigation
import com.openworld.app.ui.theme.OpenWorldTheme
import com.openworld.app.util.LocaleManager
import com.openworld.core.OpenWorldCore
import androidx.compose.ui.Modifier
import androidx.navigation.compose.currentBackStackEntryAsState

class MainActivity : ComponentActivity() {

    private var themeMode by mutableStateOf(AppThemeMode.SYSTEM)

    override fun attachBaseContext(newBase: android.content.Context) {
        super.attachBaseContext(LocaleManager.wrapContext(newBase))
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        enableEdgeToEdge(
            statusBarStyle = SystemBarStyle.dark(android.graphics.Color.TRANSPARENT),
            navigationBarStyle = SystemBarStyle.dark(android.graphics.Color.TRANSPARENT)
        )
        super.onCreate(savedInstanceState)
        themeMode = SettingsStore.getThemeMode(this)

        setContent {
            OpenWorldTheme(themeMode = themeMode) {
                val navController = rememberNavController()
                val navBackStackEntry by navController.currentBackStackEntryAsState()
                val currentRoute = navBackStackEntry?.destination?.route
                val showBottomBar = currentRoute in listOf(
                    "dashboard", "nodes", "profiles", "settings"
                )

                Scaffold(
                    contentWindowInsets = WindowInsets(0, 0, 0, 0),
                    bottomBar = {
                        AnimatedVisibility(
                            visible = showBottomBar,
                            enter = slideInVertically(
                                initialOffsetY = { it },
                                animationSpec = tween(durationMillis = 400, easing = FastOutSlowInEasing)
                            ) + expandVertically(
                                expandFrom = Alignment.Bottom,
                                animationSpec = tween(durationMillis = 400, easing = FastOutSlowInEasing)
                            ) + fadeIn(
                                animationSpec = tween(durationMillis = 400)
                            ),
                            exit = slideOutVertically(
                                targetOffsetY = { it },
                                animationSpec = tween(durationMillis = 400, easing = FastOutSlowInEasing)
                            ) + shrinkVertically(
                                shrinkTowards = Alignment.Bottom,
                                animationSpec = tween(durationMillis = 400, easing = FastOutSlowInEasing)
                            ) + fadeOut(
                                animationSpec = tween(durationMillis = 400)
                            )
                        ) {
                            AppNavBar(navController = navController)
                        }
                    }
                ) { innerPadding ->
                    Box(
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
