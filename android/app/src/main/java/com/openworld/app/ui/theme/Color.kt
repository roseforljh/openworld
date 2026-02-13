package com.openworld.app.ui.theme

import androidx.compose.ui.graphics.Color

// Monochromatic OLED Palette
val OLEDBlack = Color(0xFF000000)
val Neutral950 = Color(0xFF0A0A0A)
val Neutral900 = Color(0xFF121212)
val Neutral850 = Color(0xFF1A1A1A) // Keep this as OpenWorld uses it
val Neutral800 = Color(0xFF262626)
val Neutral700 = Color(0xFF404040)
val Neutral600 = Color(0xFF525252)
val Neutral500 = Color(0xFF737373)
val Neutral400 = Color(0xFFA3A3A3)
val Neutral300 = Color(0xFFBDBDBD)
val Neutral200 = Color(0xFFE5E5E5)
val Neutral100 = Color(0xFFF5F5F5)
val Neutral50 = Color(0xFFFAFAFA)
val PureWhite = Color(0xFFFFFFFF)

// Light Palette
val LightBackground = Color(0xFFF5F5F7)
val LightSurface = Color(0xFFFFFFFF)
val LightSurfaceVariant = Color(0xFFF0F0F2)
val LightDivider = Color(0xFFE5E5E5)
val LightOnBackground = Color(0xFF1D1D1F)
val LightOnSurface = Color(0xFF1D1D1F)
val LightOnSurfaceVariant = Color(0xFF86868B)

// Semantic Colors from KunBox
val Red500 = Color(0xFFEF4444) // Destructive
val Primary = Color(0xFF3B82F6) // Blue 500

val AppBackground = OLEDBlack
val SurfaceCard = Neutral900
val SurfaceCardAlt = Neutral950
val Divider = Neutral800
val TextPrimary = PureWhite
val TextSecondary = Neutral500
val TextTertiary = Neutral700
val AccentWhite = PureWhite
val Destructive = Red500

// === Backward compat aliases (used by existing code in OpenWorld) ===
val Green500 = Color(0xFF22C55E)
val Green400 = Color(0xFF4ADE80)
val Red400 = Color(0xFFF87171)
val Orange500 = Color(0xFFF97316)
val Orange400 = Color(0xFFFB923C)
val Blue500 = Color(0xFF3B82F6)
val Blue400 = Color(0xFF60A5FA)
val Yellow500 = Color(0xFFEAB308)

val AccentGreen = Green500
val AccentRed = Red500
val AccentBlue = Blue500
val AccentOrange = Orange500
val AccentYellow = Yellow500
