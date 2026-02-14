package com.openworld.app.viewmodel

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.openworld.app.model.AppSettings
import com.openworld.app.repository.LogRepository
import com.openworld.app.repository.SettingsRepository
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch

class LogsViewModel(app: Application) : AndroidViewModel(app) {

    private val settingsRepository = SettingsRepository.getInstance(app)

    data class UiState(
        val logs: List<LogRepository.LogEntry> = emptyList(),
        val autoScroll: Boolean = true
    )

    private val _state = MutableStateFlow(UiState())
    val state: StateFlow<UiState> = _state.asStateFlow()

    val settings: StateFlow<AppSettings> = settingsRepository.settings

    init {
        startPolling()
    }

    fun clearLogs() {
        LogRepository.clear()
        _state.value = _state.value.copy(logs = emptyList())
    }

    fun toggleAutoScroll() {
        _state.value = _state.value.copy(autoScroll = !_state.value.autoScroll)
    }

    fun getLogsForExport(): String {
        return LogRepository.getAll().joinToString("\n") { entry ->
            "[${LogRepository.levelName(entry.level)}] ${entry.message}"
        }
    }

    private fun startPolling() {
        viewModelScope.launch(Dispatchers.IO) {
            while (isActive) {
                LogRepository.pullFromCore()
                _state.value = _state.value.copy(logs = LogRepository.getAll())
                delay(1000)
            }
        }
    }
}
