package com.openworld.app.viewmodel

import android.app.Application
import android.content.Context
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.google.gson.JsonParser
import com.openworld.app.config.ConfigManager
import com.openworld.app.repository.CoreRepository
import com.openworld.core.OpenWorldCore
import org.yaml.snakeyaml.Yaml
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch

class NodesViewModel(app: Application) : AndroidViewModel(app) {

    enum class SortMode { DEFAULT, NAME, DELAY }

    data class NodeInfo(
        val name: String,
        val delay: Int = -1,
        val selected: Boolean = false,
        val isTesting: Boolean = false,
        val alias: String = ""
    )

    data class GroupInfo(
        val name: String,
        val type: String,
        val selected: String?,
        val members: List<NodeInfo>
    )

    data class NodeDetail(
        val groupName: String,
        val nodeName: String,
        val alias: String,
        val protocol: String,
        val delay: Int,
        val selected: Boolean
    )

    data class UiState(
        val groups: List<GroupInfo> = emptyList(),
        val searchQuery: String = "",
        val sortMode: SortMode = SortMode.DEFAULT,
        val testing: Boolean = false,
        val testProgress: Float = 0f,
        val testCurrent: String = ""
    )

    private val _state = MutableStateFlow(UiState())
    val state: StateFlow<UiState> = _state.asStateFlow()

    private val _toastEvent = MutableSharedFlow<String>(extraBufferCapacity = 1)
    val toastEvent: SharedFlow<String> = _toastEvent.asSharedFlow()

    private var rawGroups: List<GroupInfo> = emptyList()

    private fun nodePrefs() =
        getApplication<Application>().getSharedPreferences("node_meta", Context.MODE_PRIVATE)

    private fun keyAlias(group: String, node: String) = "alias_${group}_$node"

    private fun keyHidden(group: String, node: String) = "hidden_${group}_$node"

    private fun nodeAlias(group: String, node: String): String =
        nodePrefs().getString(keyAlias(group, node), "") ?: ""

    private fun isHidden(group: String, node: String): Boolean =
        nodePrefs().getBoolean(keyHidden(group, node), false)

    init {
        refresh()
    }

    fun refresh() {
        viewModelScope.launch(Dispatchers.IO) {
            val coreGroups = CoreRepository.getProxyGroups().map { g ->
                GroupInfo(
                    name = g.name,
                    type = g.type,
                    selected = g.selected,
                    members = g.members
                        .filterNot { isHidden(g.name, it) }
                        .map { name ->
                            val delay = try {
                                OpenWorldCore.getLastDelay(name)
                            } catch (_: Exception) {
                                -1
                            }
                            NodeInfo(
                                name = name,
                                delay = delay,
                                selected = name == g.selected,
                                alias = nodeAlias(g.name, name)
                            )
                        }
                )
            }

            val groups = if (coreGroups.isNotEmpty()) coreGroups else fallbackGroupsFromActiveProfile()
            rawGroups = groups
            applyFilterAndSort()
        }
    }

    fun getNodeDetail(groupName: String, nodeName: String): NodeDetail {
        val group = rawGroups.firstOrNull { it.name == groupName }
        val node = group?.members?.firstOrNull { it.name == nodeName }
        return NodeDetail(
            groupName = groupName,
            nodeName = nodeName,
            alias = node?.alias ?: nodeAlias(groupName, nodeName),
            protocol = group?.type ?: "",
            delay = node?.delay ?: -1,
            selected = node?.selected == true
        )
    }

    fun saveNodeDetail(groupName: String, nodeName: String, alias: String) {
        val cleanAlias = alias.trim()
        val prefs = nodePrefs().edit()
        if (cleanAlias.isBlank()) {
            prefs.remove(keyAlias(groupName, nodeName))
        } else {
            prefs.putString(keyAlias(groupName, nodeName), cleanAlias)
        }
        prefs.apply()
        refresh()
        _toastEvent.tryEmit("节点信息已保存")
    }

    fun deleteNodeLocal(groupName: String, nodeName: String) {
        nodePrefs().edit().putBoolean(keyHidden(groupName, nodeName), true).apply()
        refresh()
        _toastEvent.tryEmit("已从列表移除节点")
    }

    fun restoreHiddenNodes() {
        val all = nodePrefs().all.keys.filter { it.startsWith("hidden_") }
        val editor = nodePrefs().edit()
        all.forEach { editor.remove(it) }
        editor.apply()
        refresh()
        _toastEvent.tryEmit("已恢复隐藏节点")
    }

    fun exportNodeLink(groupName: String, nodeName: String): String {
        val alias = nodeAlias(groupName, nodeName)
        val display = alias.ifBlank { nodeName }
        return "openworld://node?group=${groupName}&name=${display}"
    }

    fun setSearchQuery(query: String) {
        _state.value = _state.value.copy(searchQuery = query)
        applyFilterAndSort()
    }

    fun setSortMode(mode: SortMode) {
        _state.value = _state.value.copy(sortMode = mode)
        applyFilterAndSort()
    }

    fun cycleSortMode() {
        val next = when (_state.value.sortMode) {
            SortMode.DEFAULT -> SortMode.NAME
            SortMode.NAME -> SortMode.DELAY
            SortMode.DELAY -> SortMode.DEFAULT
        }
        setSortMode(next)
    }

    private fun applyFilterAndSort() {
        val query = _state.value.searchQuery.trim().lowercase()
        val sortMode = _state.value.sortMode

        val filtered = rawGroups.map { group ->
            val members = group.members
                .filter {
                    if (query.isEmpty()) true
                    else it.name.lowercase().contains(query) || it.alias.lowercase().contains(query)
                }
                .let { list ->
                    when (sortMode) {
                        SortMode.DEFAULT -> list
                        SortMode.NAME -> list.sortedBy { (it.alias.ifBlank { it.name }).lowercase() }
                        SortMode.DELAY -> list.sortedWith(
                            compareBy<NodeInfo> { if (it.delay < 0) Int.MAX_VALUE else it.delay }
                                .thenBy { (it.alias.ifBlank { it.name }).lowercase() }
                        )
                    }
                }
            group.copy(members = members)
        }.filter { it.members.isNotEmpty() || query.isEmpty() }

        _state.value = _state.value.copy(groups = filtered)
    }

    fun setActiveNode(groupName: String, nodeName: String) {
        viewModelScope.launch(Dispatchers.IO) {
            try {
                OpenWorldCore.setGroupSelected(groupName, nodeName)
                refresh()
                _toastEvent.tryEmit("已切换: $nodeName")
            } catch (e: Exception) {
                _toastEvent.tryEmit("切换失败: ${e.message}")
            }
        }
    }

    fun selectNode(groupName: String, nodeName: String) = setActiveNode(groupName, nodeName)

    fun testNodeDelay(groupName: String) = testGroupDelay(groupName)

    fun testGroupDelay(groupName: String) {
        viewModelScope.launch(Dispatchers.IO) {
            _state.value = _state.value.copy(testing = true, testCurrent = groupName)
            try {
                CoreRepository.testGroupDelay(groupName, "https://www.gstatic.com/generate_204", 5000)
                _toastEvent.tryEmit("$groupName 测速完成")
            } catch (e: Exception) {
                _toastEvent.tryEmit("测速失败: ${e.message}")
            } finally {
                _state.value = _state.value.copy(testing = false, testCurrent = "")
                refresh()
            }
        }
    }

    fun testAllGroupsDelay() {
        viewModelScope.launch(Dispatchers.IO) {
            _state.value = _state.value.copy(testing = true, testProgress = 0f)
            val groups = rawGroups
            val total = groups.size.coerceAtLeast(1)

            for ((index, group) in groups.withIndex()) {
                _state.value = _state.value.copy(
                    testCurrent = group.name,
                    testProgress = index.toFloat() / total
                )
                try {
                    CoreRepository.testGroupDelay(group.name, "https://www.gstatic.com/generate_204", 5000)
                } catch (_: Exception) {
                }
            }

            _state.value = _state.value.copy(testing = false, testProgress = 1f, testCurrent = "")
            refresh()
            _toastEvent.tryEmit("全部测速完成")
        }
    }

    fun testAllLatency() = testAllGroupsDelay()

    fun clearLatency() {
        viewModelScope.launch(Dispatchers.IO) {
            val ok = CoreRepository.clearDelayHistory()
            if (ok) _toastEvent.tryEmit("延迟缓存已清除")
            else _toastEvent.tryEmit("延迟缓存清除失败")
            refresh()
        }
    }

    fun importNodeByLink(link: String) {
        viewModelScope.launch(Dispatchers.IO) {
            if (link.isBlank()) {
                _toastEvent.tryEmit("链接不能为空")
                return@launch
            }
            val result = try { OpenWorldCore.importSubscription(link).orEmpty() } catch (_: Exception) { "" }
            if (result.contains("error", ignoreCase = true) || result.isBlank()) {
                _toastEvent.tryEmit("导入节点失败")
            } else {
                _toastEvent.tryEmit("节点导入完成")
                refresh()
            }
        }
    }

    private fun fallbackGroupsFromActiveProfile(): List<GroupInfo> {
        val ctx = getApplication<Application>()
        val active = ConfigManager.getActiveProfile(ctx)
        val content = ConfigManager.loadProfile(ctx, active).orEmpty().trim()
        if (content.isBlank()) return emptyList()

        return runCatching {
            if (content.startsWith("{")) {
                fallbackFromJson(content)
            } else {
                fallbackFromYaml(content)
            }
        }.getOrDefault(emptyList())
    }

    private fun fallbackFromJson(content: String): List<GroupInfo> {
        val root = JsonParser.parseString(content)
        if (!root.isJsonObject) return emptyList()
        val obj = root.asJsonObject

        val outbounds = obj.getAsJsonArray("outbounds") ?: return emptyList()
        val names = outbounds.mapNotNull { e ->
            val o = e.asJsonObject
            val type = o.get("type")?.asString.orEmpty().lowercase()
            val tag = o.get("tag")?.asString.orEmpty()
            if (tag.isBlank()) null else {
                when (type) {
                    "selector", "urltest", "direct", "block", "dns" -> null
                    else -> tag
                }
            }
        }

        if (names.isEmpty()) return emptyList()
        return listOf(
            GroupInfo(
                name = "Fallback",
                type = "select",
                selected = names.firstOrNull(),
                members = names.filterNot { isHidden("Fallback", it) }.map {
                    NodeInfo(name = it, delay = -1, selected = it == names.firstOrNull(), alias = nodeAlias("Fallback", it))
                }
            )
        )
    }

    @Suppress("UNCHECKED_CAST")
    private fun fallbackFromYaml(content: String): List<GroupInfo> {
        val yaml = Yaml().load<Any>(content) as? Map<String, Any?> ?: return emptyList()
        val proxies = yaml["proxies"] as? List<Map<String, Any?>> ?: emptyList()
        val groups = yaml["proxy-groups"] as? List<Map<String, Any?>> ?: emptyList()

        if (groups.isNotEmpty()) {
            return groups.mapNotNull { g ->
                val name = g["name"]?.toString().orEmpty()
                if (name.isBlank()) return@mapNotNull null
                val type = g["type"]?.toString().orEmpty().ifBlank { "select" }
                val members = (g["proxies"] as? List<*>)?.mapNotNull { it?.toString() }.orEmpty()
                GroupInfo(
                    name = name,
                    type = type,
                    selected = members.firstOrNull(),
                    members = members.filterNot { isHidden(name, it) }.map {
                        NodeInfo(name = it, delay = -1, selected = it == members.firstOrNull(), alias = nodeAlias(name, it))
                    }
                )
            }
        }

        if (proxies.isEmpty()) return emptyList()
        val members = proxies.mapNotNull { it["name"]?.toString() }
        return listOf(
            GroupInfo(
                name = "Fallback",
                type = "select",
                selected = members.firstOrNull(),
                members = members.filterNot { isHidden("Fallback", it) }.map {
                    NodeInfo(name = it, delay = -1, selected = it == members.firstOrNull(), alias = nodeAlias("Fallback", it))
                }
            )
        )
    }
}
