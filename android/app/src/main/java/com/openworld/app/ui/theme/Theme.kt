package com.openworld.app.ui.theme

import android.app.Activity
import androidx.compose.foundation.isSystemInDarkTheme
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.darkColorScheme
import androidx.compose.material3.lightColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.SideEffect
import androidx.compose.ui.platform.LocalView
import androidx.core.view.WindowCompat
import com.openworld.app.model.AppThemeMode

private val DarkColorScheme = darkColorScheme(
    primary = PureWhite,
    secondary = Neutral400,
    tertiary = Blue400,
    background = OLEDBlack,
    surface = Neutral900,
    surfaceVariant = Neutral850,
    surfaceContainer = Neutral900,
    surfaceContainerHigh = Neutral800,
    onBackground = Neutral200,
    onSurface = PureWhite,
    onSurfaceVariant = Neutral400,
    outline = Neutral700,
    outlineVariant = Neutral800,
    error = Red400,
)

private val LightColorScheme = lightColorScheme(
    primary = Neutral850,
    secondary = Neutral600,
    tertiary = Blue500,
    background = LightBackground,
    surface = LightSurface,
    surfaceVariant = LightSurfaceVariant,
    surfaceContainer = LightSurface,
    surfaceContainerHigh = Neutral100,
    onBackground = LightOnBackground,
    onSurface = LightOnSurface,
    onSurfaceVariant = LightOnSurfaceVariant,
    outline = Neutral300,
    outlineVariant = Neutral200,
    error = Red500,
)

@Composable
fun OpenWorldTheme(
    themeMode: AppThemeMode = AppThemeMode.SYSTEM,
    content: @Composable () -> Unit
) {
    val darkTheme = when (themeMode) {
        AppThemeMode.DARK -> true
        AppThemeMode.LIGHT -> false
        AppThemeMode.SYSTEM -> isSystemInDarkTheme()
    }

    val colorScheme = if (darkTheme) DarkColorScheme else LightColorScheme

    val view = LocalView.current
    if (!view.isInEditMode) {
        SideEffect {
            val window = (view.context as Activity).window
            window.statusBarColor = android.graphics.Color.TRANSPARENT
            window.navigationBarColor = android.graphics.Color.TRANSPARENT
            WindowCompat.setDecorFitsSystemWindows(window, false)
            WindowCompat.getInsetsController(window, view).apply {
                isAppearanceLightStatusBars = !darkTheme
                isAppearanceLightNavigationBars = !darkTheme
            }
        }
    }

    MaterialTheme(
        colorScheme = colorScheme,
        typography = AppTypography,
        content = content
    )
}
