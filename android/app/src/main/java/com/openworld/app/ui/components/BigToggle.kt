package com.openworld.app.ui.components

import androidx.compose.animation.core.LinearEasing
import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.Spring
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.spring
import androidx.compose.animation.core.tween
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.interaction.collectIsPressedAsState
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.PowerSettingsNew
import androidx.compose.material3.Icon
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.scale
import androidx.compose.ui.draw.shadow
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.graphicsLayer
import androidx.compose.ui.unit.dp
import com.openworld.app.ui.theme.Green500
import com.openworld.app.ui.theme.Red500

@Composable
fun BigToggle(
    connected: Boolean,
    connecting: Boolean,
    onClick: () -> Unit,
    modifier: Modifier = Modifier
) {
    val interactionSource = remember { MutableInteractionSource() }
    val isPressed by interactionSource.collectIsPressedAsState()

    // 按下弹簧缩放
    val pressScale by animateFloatAsState(
        targetValue = if (isPressed) 0.88f else 1f,
        animationSpec = spring(
            dampingRatio = Spring.DampingRatioMediumBouncy,
            stiffness = Spring.StiffnessLow
        ),
        label = "press_scale"
    )

    // 断开时浮动动画
    val infiniteTransition = rememberInfiniteTransition(label = "float")
    val floatOffset by infiniteTransition.animateFloat(
        initialValue = 0f,
        targetValue = if (!connected && !connecting) 6f else 0f,
        animationSpec = infiniteRepeatable(
            animation = tween(2000, easing = LinearEasing),
            repeatMode = RepeatMode.Reverse
        ),
        label = "float_offset"
    )

    val primaryColor = when {
        connecting -> Color(0xFFF97316)
        connected -> Green500
        else -> Red500
    }

    val gradient = Brush.radialGradient(
        colors = listOf(primaryColor, primaryColor.copy(alpha = 0.6f))
    )

    Box(
        contentAlignment = Alignment.Center,
        modifier = modifier
            .size(140.dp)
            .graphicsLayer {
                scaleX = pressScale
                scaleY = pressScale
                translationY = floatOffset
            }
            .shadow(
                elevation = if (connected) 16.dp else 8.dp,
                shape = CircleShape,
                ambientColor = primaryColor.copy(alpha = 0.3f),
                spotColor = primaryColor.copy(alpha = 0.3f)
            )
            .clip(CircleShape)
            .background(gradient)
            .clickable(
                interactionSource = interactionSource,
                indication = null,
                onClick = onClick
            )
    ) {
        Icon(
            imageVector = Icons.Filled.PowerSettingsNew,
            contentDescription = if (connected) "断开" else "连接",
            tint = Color.White,
            modifier = Modifier.size(48.dp)
        )
    }
}
