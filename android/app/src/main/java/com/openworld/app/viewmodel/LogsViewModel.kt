package com.openworld.app.viewmodel

import android.app.Application
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.openworld.app.repository.LogRepository
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch

class LogsViewModel(app: Application) : AndroidViewModel(app) {

    data class UiState(
        val logs: List<LogRepository.LogEntry> = emptyList(),
        val autoScroll: Boolean = true
    )

    private val _state = MutableStateFlow(UiState())
    val state: StateFlow<UiState> = _state.asStateFlow()

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
