package com.openworld.app.viewmodel

import android.app.Application
import android.net.Uri
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.openworld.app.repository.DataBackupManager
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch

data class DataManagementUiState(
    val exporting: Boolean = false,
    val importing: Boolean = false,
    val lastMessage: String = ""
)

class DataManagementViewModel(app: Application) : AndroidViewModel(app) {

    private val _state = MutableStateFlow(DataManagementUiState())
    val state: StateFlow<DataManagementUiState> = _state.asStateFlow()

    private val _toast = MutableSharedFlow<String>(extraBufferCapacity = 1)
    val toast: SharedFlow<String> = _toast.asSharedFlow()

    fun exportBackup(uri: Uri) {
        viewModelScope.launch(Dispatchers.IO) {
            _state.value = _state.value.copy(exporting = true)
            try {
                DataBackupManager.exportToUri(getApplication(), uri)
                _state.value = _state.value.copy(lastMessage = "备份导出成功")
                _toast.tryEmit("备份导出成功")
            } catch (e: Exception) {
                val msg = e.message ?: "未知错误"
                _state.value = _state.value.copy(lastMessage = "备份导出失败: $msg")
                _toast.tryEmit("备份导出失败: $msg")
            } finally {
                _state.value = _state.value.copy(exporting = false)
            }
        }
    }

    fun importBackup(uri: Uri) {
        viewModelScope.launch(Dispatchers.IO) {
            _state.value = _state.value.copy(importing = true)
            try {
                DataBackupManager.importFromUri(getApplication(), uri)
                _state.value = _state.value.copy(lastMessage = "恢复导入成功，建议重连 VPN")
                _toast.tryEmit("恢复导入成功，建议重连 VPN")
            } catch (e: Exception) {
                val msg = e.message ?: "未知错误"
                _state.value = _state.value.copy(lastMessage = "恢复导入失败: $msg")
                _toast.tryEmit("恢复导入失败: $msg")
            } finally {
                _state.value = _state.value.copy(importing = false)
            }
        }
    }
}
