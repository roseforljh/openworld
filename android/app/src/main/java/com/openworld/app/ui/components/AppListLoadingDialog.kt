package com.openworld.app.ui.components

import com.openworld.app.R
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.LinearProgressIndicator
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.ui.res.stringResource
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import com.openworld.app.repository.InstalledAppsRepository
import com.openworld.app.ui.theme.Divider
import com.openworld.app.ui.theme.PureWhite
import com.openworld.app.ui.theme.SurfaceCard
import com.openworld.app.ui.theme.TextPrimary
import com.openworld.app.ui.theme.TextSecondary

/**
 * 应用列表加载对话�? * 显示加载进度和状�? */
@Composable
fun AppListLoadingDialog(
    loadingState: InstalledAppsRepository.LoadingState
) {
    // 只在加载中状态显示对话框
    if (loadingState !is InstalledAppsRepository.LoadingState.Loading) return

    Dialog(
        onDismissRequest = { /* 不可取消 */ },
        properties = DialogProperties(
            dismissOnBackPress = false,
            dismissOnClickOutside = false
        )
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .background(SurfaceCard, RoundedCornerShape(28.dp))
                .padding(32.dp),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            // 圆形进度指示器（带进度）
            CircularProgressIndicator(
                progress = { loadingState.progress },
                modifier = Modifier.size(72.dp),
                color = PureWhite,
                strokeWidth = 6.dp,
                trackColor = Divider
            )

            Spacer(modifier = Modifier.height(24.dp))

            Text(
                text = stringResource(R.string.app_list_loading),
                style = MaterialTheme.typography.titleMedium,
                color = TextPrimary
            )

            Spacer(modifier = Modifier.height(8.dp))

            Text(
                text = stringResource(R.string.app_list_loaded, loadingState.current, loadingState.total),
                style = MaterialTheme.typography.bodyMedium,
                color = TextSecondary
            )

            Spacer(modifier = Modifier.height(20.dp))

            // 线性进度条
            LinearProgressIndicator(
                progress = { loadingState.progress },
                modifier = Modifier
                    .fillMaxWidth()
                    .height(6.dp),
                color = PureWhite,
                trackColor = Divider
            )
        }
    }
}

/**
 * 简化版加载对话框（无具体进度，只显示加载中�? */
@Composable
fun SimpleLoadingDialog(
    show: Boolean,
    message: String = stringResource(R.string.common_loading)
) {
    if (!show) return

    Dialog(
        onDismissRequest = { /* 不可取消 */ },
        properties = DialogProperties(
            dismissOnBackPress = false,
            dismissOnClickOutside = false
        )
    ) {
        Column(
            modifier = Modifier
                .fillMaxWidth()
                .background(SurfaceCard, RoundedCornerShape(28.dp))
                .padding(32.dp),
            horizontalAlignment = Alignment.CenterHorizontally
        ) {
            CircularProgressIndicator(
                modifier = Modifier.size(56.dp),
                color = PureWhite,
                strokeWidth = 5.dp
            )

            Spacer(modifier = Modifier.height(20.dp))

            Text(
                text = message,
                style = MaterialTheme.typography.titleMedium,
                color = TextPrimary
            )
        }
    }
}







