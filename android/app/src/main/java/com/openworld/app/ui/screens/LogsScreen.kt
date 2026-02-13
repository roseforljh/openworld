package com.openworld.app.ui.screens

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.filled.ArrowBack
import androidx.compose.material.icons.filled.Delete
import androidx.compose.material.icons.filled.VerticalAlignBottom
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilterChip
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import androidx.lifecycle.viewmodel.compose.viewModel
import com.openworld.app.repository.LogRepository
import com.openworld.app.ui.theme.AccentGreen
import com.openworld.app.ui.theme.AccentOrange
import com.openworld.app.ui.theme.AccentRed
import com.openworld.app.viewmodel.LogsViewModel
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun LogsScreen(
    onBack: () -> Unit = {},
    viewModel: LogsViewModel = viewModel()
) {
    val state by viewModel.state.collectAsState()
    var filterLevel by remember { mutableIntStateOf(-1) }
    val listState = rememberLazyListState()
    val timeFormat = remember { SimpleDateFormat("HH:mm:ss", Locale.getDefault()) }

    val filteredLogs = if (filterLevel < 0) state.logs
    else state.logs.filter { it.level >= filterLevel }

    // 自动滚动到底部
    LaunchedEffect(filteredLogs.size, state.autoScroll) {
        if (state.autoScroll && filteredLogs.isNotEmpty()) {
            listState.animateScrollToItem(filteredLogs.size - 1)
        }
    }

    Scaffold(
        topBar = {
            TopAppBar(
                title = { Text("日志 (${filteredLogs.size})") },
                navigationIcon = {
                    IconButton(onClick = onBack) {
                        Icon(Icons.AutoMirrored.Filled.ArrowBack, contentDescription = "返回")
                    }
                },
                actions = {
                    // 自动滚动切换
                    IconButton(onClick = { viewModel.toggleAutoScroll() }) {
                        Icon(
                            Icons.Default.VerticalAlignBottom,
                            contentDescription = "自动滚动",
                            tint = if (state.autoScroll) MaterialTheme.colorScheme.primary
                            else MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                    // 清除日志
                    IconButton(onClick = { viewModel.clearLogs() }) {
                        Icon(
                            Icons.Default.Delete,
                            contentDescription = "清除",
                            tint = MaterialTheme.colorScheme.onSurfaceVariant
                        )
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(
                    containerColor = MaterialTheme.colorScheme.background
                )
            )
        }
    ) { padding ->
        LazyColumn(
            state = listState,
            modifier = Modifier
                .fillMaxSize()
                .padding(padding)
        ) {
            // 过滤器
            item {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(horizontal = 16.dp, vertical = 8.dp),
                    horizontalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    val levels = listOf(-1 to "全部", 1 to "DEBUG", 2 to "INFO", 3 to "WARN", 4 to "ERROR")
                    levels.forEach { (level, name) ->
                        FilterChip(
                            selected = filterLevel == level,
                            onClick = { filterLevel = level },
                            label = { Text(name, style = MaterialTheme.typography.labelSmall) }
                        )
                    }
                }
            }

            items(filteredLogs) { entry ->
                val color = when (entry.level) {
                    4 -> AccentRed
                    3 -> AccentOrange
                    2 -> AccentGreen
                    else -> MaterialTheme.colorScheme.onSurface.copy(alpha = 0.6f)
                }
                val time = timeFormat.format(Date(entry.timestamp))
                Text(
                    text = "$time [${LogRepository.levelName(entry.level)}] ${entry.message}",
                    style = MaterialTheme.typography.bodySmall,
                    fontFamily = FontFamily.Monospace,
                    color = color,
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(horizontal = 16.dp, vertical = 2.dp)
                )
            }
        }
    }
}
