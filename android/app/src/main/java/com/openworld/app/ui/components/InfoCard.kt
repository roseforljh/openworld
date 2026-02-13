package com.openworld.app.ui.components

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.ArrowDownward
import androidx.compose.material.icons.filled.ArrowUpward
import androidx.compose.material.icons.filled.NetworkPing
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.unit.dp
import com.openworld.app.ui.theme.Blue500
import com.openworld.app.ui.theme.Green500
import com.openworld.app.ui.theme.Orange500
import com.openworld.app.util.FormatUtil

@Composable
fun InfoCard(
    uploadRate: Long,
    downloadRate: Long,
    ping: Int = -1,
    modifier: Modifier = Modifier
) {
    Card(
        shape = RoundedCornerShape(16.dp),
        colors = CardDefaults.cardColors(
            containerColor = MaterialTheme.colorScheme.surface
        ),
        modifier = modifier.fillMaxWidth()
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(horizontal = 16.dp, vertical = 20.dp),
            horizontalArrangement = Arrangement.SpaceEvenly
        ) {
            InfoItem(
                icon = Icons.Filled.ArrowUpward,
                label = "上传",
                value = FormatUtil.formatSpeed(uploadRate),
                tint = Green500
            )
            InfoItem(
                icon = Icons.Filled.ArrowDownward,
                label = "下载",
                value = FormatUtil.formatSpeed(downloadRate),
                tint = Blue500
            )
            InfoItem(
                icon = Icons.Filled.NetworkPing,
                label = "延迟",
                value = if (ping > 0) "${ping}ms" else "--",
                tint = Orange500
            )
        }
    }
}

@Composable
private fun InfoItem(
    icon: ImageVector,
    label: String,
    value: String,
    tint: androidx.compose.ui.graphics.Color
) {
    Column(horizontalAlignment = Alignment.CenterHorizontally) {
        Icon(
            imageVector = icon,
            contentDescription = label,
            tint = tint,
            modifier = Modifier.size(20.dp)
        )
        Text(
            text = value,
            style = MaterialTheme.typography.titleMedium,
            color = MaterialTheme.colorScheme.onSurface,
            modifier = Modifier.padding(top = 4.dp)
        )
        Text(
            text = label,
            style = MaterialTheme.typography.labelSmall,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
    }
}
