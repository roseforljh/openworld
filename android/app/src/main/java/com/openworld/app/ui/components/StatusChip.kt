package com.openworld.app.ui.components

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.unit.dp
import com.openworld.app.ui.theme.Green500

@Composable
fun StatusChip(
    label: String,
    isActive: Boolean = false,
    activeColor: Color = Green500,
    inactiveColor: Color = MaterialTheme.colorScheme.surfaceVariant,
    icon: ImageVector? = null,
    onClick: (() -> Unit)? = null,
    modifier: Modifier = Modifier
) {
    val bgColor = if (isActive) activeColor.copy(alpha = 0.15f) else inactiveColor
    val textColor = if (isActive) activeColor else MaterialTheme.colorScheme.onSurface.copy(alpha = 0.7f)

    Row(
        modifier = modifier
            .clip(RoundedCornerShape(50))
            .background(bgColor)
            .then(if (onClick != null) Modifier.clickable { onClick() } else Modifier)
            .padding(horizontal = 12.dp, vertical = 6.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        if (icon != null) {
            Icon(
                imageVector = icon,
                contentDescription = null,
                tint = textColor,
                modifier = Modifier.size(14.dp)
            )
            Spacer(modifier = Modifier.width(4.dp))
        }
        Text(
            text = label,
            style = MaterialTheme.typography.labelLarge,
            color = textColor
        )
    }
}

@Composable
fun ModeChip(
    mode: String,
    onClick: (() -> Unit)? = null,
    modifier: Modifier = Modifier
) {
    val dotColor = when (mode.lowercase()) {
        "rule" -> Green500
        "global" -> Color(0xFF3B82F6)
        "direct" -> Color(0xFFF97316)
        else -> MaterialTheme.colorScheme.onSurfaceVariant
    }

    Row(
        modifier = modifier
            .clip(RoundedCornerShape(50))
            .background(MaterialTheme.colorScheme.surfaceVariant)
            .then(if (onClick != null) Modifier.clickable { onClick() } else Modifier)
            .padding(horizontal = 12.dp, vertical = 6.dp),
        verticalAlignment = Alignment.CenterVertically
    ) {
        Box(
            modifier = Modifier
                .size(8.dp)
                .clip(CircleShape)
                .background(dotColor)
        )
        Spacer(modifier = Modifier.width(6.dp))
        Text(
            text = mode.uppercase(),
            style = MaterialTheme.typography.labelLarge,
            color = MaterialTheme.colorScheme.onSurface.copy(alpha = 0.8f)
        )
    }
}

@Composable
fun ConnectionStatusChip(
    connected: Boolean,
    connecting: Boolean,
    onClick: (() -> Unit)? = null,
    modifier: Modifier = Modifier
) {
    val label = when {
        connecting -> "连接中..."
        connected -> "已连接"
        else -> "未连接"
    }
    val color = when {
        connecting -> Color(0xFFF97316)
        connected -> Green500
        else -> Color(0xFFEF4444)
    }
    StatusChip(
        label = label,
        isActive = connected || connecting,
        activeColor = color,
        onClick = onClick,
        modifier = modifier
    )
}
