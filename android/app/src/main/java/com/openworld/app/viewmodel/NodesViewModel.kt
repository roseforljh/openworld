package com.openworld.app.viewmodel

import android.app.Application
import android.content.Context
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.google.gson.JsonParser
import com.openworld.app.config.ConfigManager
import com.openworld.app.model.AppGroup
import com.openworld.app.model.NodeFilter
import com.openworld.app.model.NodeSortType
import com.openworld.app.model.NodeUi
import com.openworld.app.model.ProfileType
import com.openworld.app.model.ProfileUi
import com.openworld.app.repository.CoreRepository
import com.openworld.core.OpenWorldCore
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharedFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import org.yaml.snakeyaml.Yaml

class NodesViewModel(app: Application) : AndroidViewModel(app) {

    private val _nodes = MutableStateFlow<List<NodeUi>>(emptyList())
    val nodes: StateFlow<List<NodeUi>> = _nodes.asStateFlow()

    private val _activeNodeId = MutableStateFlow<String?>(null)
    val activeNodeId: StateFlow<String?> = _activeNodeId.asStateFlow()

    private val _testingNodeIds = MutableStateFlow<List<String>>(emptyList())
    val testingNodeIds: StateFlow<List<String>> = _testingNodeIds.asStateFlow()

    private val _nodeFilter = MutableStateFlow(NodeFilter())
    val nodeFilter: StateFlow<NodeFilter> = _nodeFilter.asStateFlow()

    private val _sortType = MutableStateFlow(NodeSortType.DEFAULT)
    val sortType: StateFlow<NodeSortType> = _sortType.asStateFlow()

    private val _testProgress = MutableStateFlow<Pair<Int, Int>?>(null)
    val testProgress: StateFlow<Pair<Int, Int>?> = _testProgress.asStateFlow() // (completed, total)

    private val _isTesting = MutableStateFlow(false)
    val isTesting: StateFlow<Boolean> = _isTesting.asStateFlow()

    private val _profiles = MutableStateFlow<List<ProfileUi>>(emptyList())
    val profiles: StateFlow<List<ProfileUi>> = _profiles.asStateFlow()

    private val _toastEvents = MutableSharedFlow<String>(extraBufferCapacity = 1)
    val toastEvents: SharedFlow<String> = _toastEvents.asSharedFlow()

    // Cache the full list to support filtering/sorting against
    private var allNodes: List<NodeUi> = emptyList()

    init {
        refresh()
        loadProfiles()
    }

    private fun nodePrefs() =
        getApplication<Application>().getSharedPreferences("node_meta", Context.MODE_PRIVATE)

    private fun keyAlias(group: String, node: String) = "alias_${group}_$node"
    private fun keyHidden(group: String, node: String) = "hidden_${group}_$node"
    private fun nodeAlias(group: String, node: String): String =
        nodePrefs().getString(keyAlias(group, node), "") ?: ""
    private fun isHidden(group: String, node: String): Boolean =
        nodePrefs().getBoolean(keyHidden(group, node), false)

    fun refresh() {
        viewModelScope.launch(Dispatchers.IO) {
            try {
                // Fetch groups from Core
                val coreGroups = CoreRepository.getProxyGroups()
                val newNodes = mutableListOf<NodeUi>()

                // Also consider fallback if coreGroups is empty? 
                // Existing logic had a fallback mechanism. Let's keep it simple first or port it if needed.
                // Assuming CoreRepository returns something valid or we use fallback.
                
                val groupsToProcess = if (coreGroups.isNotEmpty()) {
                     coreGroups.map { g ->
                         GroupInfo(g.name, g.type, g.selected, g.members) 
                     }
                } else {
                    fallbackGroupsFromActiveProfile()
                }

                groupsToProcess.forEach { group ->
                    val groupName = group.name
                    // We only want leaf nodes usually, or we show groups as nodes? 
                    // In KunBox, it likely flattens or shows groups.
                    // Based on NodeUi having 'group' field, it likely flattens.
                    
                    group.members.forEach { nodeName ->
                        if (!isHidden(groupName, nodeName)) {
                            val id = "$groupName/$nodeName"
                            val delay = try {
                                OpenWorldCore.getLastDelay(nodeName)
                            } catch (_: Exception) {
                                null
                            }?.toLong()?.takeIf { it >= 0 }

                            val alias = nodeAlias(groupName, nodeName)
                            val display = alias.ifBlank { nodeName }
                            
                            // Determine protocol/type. 
                            // OpenWorldCore doesn't easily give type per node unless we parse config.
                            // We can use group type or try to infer.
                            // For now, use "Unknown" or group type as fallback?
                            // Actually, let's use group.type for now, or just "Proxy".
                            val protocol = group.type // This is group type (e.g. Selector), not node protocol.
                            // To get real node protocol, we need to parse config. 
                            // For 1:1 replication visual, we can just put "Proxy" or try to find it.
                            
                            val isSelected = (group.selected == nodeName)
                            // If this group is the "Selector" group (usually 'Proxy' or 'GLOBAL'), 
                            // and this node is selected, mark it.
                            // We need to identify which group is the "main" one.
                            // Usually 'Proxy' or first selector.
                            
                            if (isSelected && (groupName == "Proxy" || groupName == "GLOBAL" || groupName == "ðŸ”° é€‰æ‹©èŠ¹ç‚¹")) { // Common names
                                _activeNodeId.value = id
                            }

                            newNodes.add(
                                NodeUi(
                                    id = id,
                                    name = display, // Use alias or name for display
                                    // real name needed for operations
                                    protocol = "Proxy", // Placeholder, hard to get without parsing
                                    group = groupName,
                                    regionFlag = null, // Parsing flags is complex
                                    latencyMs = delay,
                                    sourceProfileId = "", // Need to link to profile
                                    isFavorite = false // Implement favorite later
                                )
                            )
                        }
                    }
                }
                
                allNodes = newNodes
                applyFilterAndSort()
                
            } catch (e: Exception) {
                e.printStackTrace()
            }
        }
    }

    private fun applyFilterAndSort() {
        var result = allNodes

        // Filter
        val filter = _nodeFilter.value
        val query = filter.includeKeywords // Using includeKeywords for generic search/filter logic if wanted
        // Actually NodeFilter has specific logic.
        /*
        enum class FilterMode { NONE, INCLUDE, EXCLUDE }
        */
        if (filter.filterMode == com.openworld.app.model.FilterMode.INCLUDE) {
             result = result.filter { node -> 
                 filter.includeKeywords.any { k -> node.name.contains(k, true) }
             }
        } else if (filter.filterMode == com.openworld.app.model.FilterMode.EXCLUDE) {
             result = result.filter { node -> 
                 filter.excludeKeywords.none { k -> node.name.contains(k, true) }
             }
        }

        // Sort
        result = when (_sortType.value) {
            NodeSortType.DEFAULT -> result
            NodeSortType.NAME -> result.sortedBy { it.name }
            NodeSortType.LATENCY -> result.sortedBy { it.latencyMs ?: Long.MAX_VALUE }
            NodeSortType.REGION -> result // Region not implemented
            else -> result
        }

        _nodes.value = result
    }

    fun setSortType(type: NodeSortType) {
        _sortType.value = type
        applyFilterAndSort()
    }

    fun setNodeFilter(filter: NodeFilter) {
        _nodeFilter.value = filter
        applyFilterAndSort()
    }
    
    fun setActiveNode(id: String) {
        // ID format: "group/name"
        val parts = id.split("/", limit = 2)
        if (parts.size != 2) return
        val group = parts[0]
        val name = parts[1]
        
        viewModelScope.launch(Dispatchers.IO) {
            try {
                // We need to find the real name if we displayed alias
                // Check allNodes for this ID to get real props?
                // The ID was constructed from real group and real name (iterated from CoreRepository)
                // So 'name' here IS the real name (nodeName in loop).
                // Wait, in refresh() I constructed ID as "$groupName/$nodeName".
                // So 'name' variable here is the real underlying node name.
                
                OpenWorldCore.setGroupSelected(group, name)
                _activeNodeId.value = id
                refresh()
                _toastEvents.tryEmit("Switched to $name")
            } catch (e: Exception) {
                _toastEvents.tryEmit("Failed to switch: ${e.message}")
            }
        }
    }

    fun testLatency(id: String) {
        val parts = id.split("/", limit = 2)
        if (parts.size != 2) return
        val group = parts[0]
        val name = parts[1] // This is real node name

        viewModelScope.launch(Dispatchers.IO) {
            val currentTesting = _testingNodeIds.value.toMutableList()
            currentTesting.add(id)
            _testingNodeIds.value = currentTesting
            
            try {
                // CoreRepository.testGroupDelay tests a whole group or logic?
                // It takes groupName.
                // If we want to test a specific node, we might need a different API or 
                // just test the group it belongs to?
                // CoreRepository.testGroupDelay(groupName) tests the group.
                // OpenWorldCore has urlTest? 
                // There isn't a direct "test single node" API exposed in CoreRepository provided in context.
                // But typically we test the group.
                // If we want to update just this node's latency in UI:
                // We can run testGroupDelay(group) which updates all in group.
                CoreRepository.testGroupDelay(group, "https://www.gstatic.com/generate_204", 5000)
                refresh()
            } catch (e: Exception) {
                 _toastEvents.tryEmit("Test failed: ${e.message}")
            } finally {
                val newTesting = _testingNodeIds.value.toMutableList()
                newTesting.remove(id)
                _testingNodeIds.value = newTesting
            }
        }
    }

    fun testAllLatency() {
        if (_isTesting.value) return
        viewModelScope.launch(Dispatchers.IO) {
            _isTesting.value = true
            val groups = allNodes.map { it.group }.distinct()
            val total = groups.size
            var completed = 0
            _testProgress.value = 0 to total
            
            groups.forEach { group ->
                try {
                    CoreRepository.testGroupDelay(group, "https://www.gstatic.com/generate_204", 5000)
                } catch(_: Exception) {}
                completed++
                _testProgress.value = completed to total
            }
            _isTesting.value = false
            _testProgress.value = null
            refresh()
            _toastEvents.tryEmit("All Latency Test Completed")
        }
    }
    
    fun clearLatency() {
        viewModelScope.launch(Dispatchers.IO) {
            CoreRepository.clearDelayHistory()
            refresh()
            _toastEvents.tryEmit("Latency history cleared")
        }
    }

    fun deleteNode(id: String) {
         val parts = id.split("/", limit = 2)
        if (parts.size != 2) return
        val group = parts[0]
        val name = parts[1]
        
        // Local delete (hide)
        nodePrefs().edit().putBoolean(keyHidden(group, name), true).apply()
        refresh()
        _toastEvents.tryEmit("Node hidden")
    }

    fun exportNode(id: String): String? {
        val parts = id.split("/", limit = 2)
        if (parts.size != 2) return null
        val group = parts[0]
        val name = parts[1]
        val alias = nodeAlias(group, name)
        val display = alias.ifBlank { name }
        return "openworld://node?group=${group}&name=${display}"
    }
    
    fun addNode(content: String, targetProfileId: String? = null, newProfileName: String? = null) {
        viewModelScope.launch(Dispatchers.IO) {
             // Logic to import node. 
             // OpenWorldCore.importSubscription(content)??
             // Need to handle profile association. 
             // For now, simple import.
             try {
                OpenWorldCore.importSubscription(content)
                refresh()
                _toastEvents.tryEmit("Node imported")
             } catch (e: Exception) {
                 _toastEvents.tryEmit("Import failed: ${e.message}")
             }
        }
    }

    private fun loadProfiles() {
        viewModelScope.launch(Dispatchers.IO) {
             val p = ConfigManager.getProfiles(getApplication())
             val uiProfiles = p.map { 
                 ProfileUi(
                     id = it.id, 
                     name = it.name,
                     type = it.type, // It's already ProfileType
                     url = it.url, // It's url not source
                     lastUpdated = it.lastUpdated,
                     enabled = it.enabled,
                     // ... other defaults
                 ) 
             }
             _profiles.value = uiProfiles
        }
    }

    // Helpers from original logical
    data class GroupInfo(
        val name: String,
        val type: String,
        val selected: String?,
        val members: List<String>
    )

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
                members = names
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
                    members = members
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
                members = members
            )
        )
    }
    fun getNodeDetail(group: String, node: String): com.openworld.app.model.SingBoxOutbound? {
        // Try to finding the node in the active profile or other profiles
        // For simplicity, we assume we are editing nodes in the active profile or a specific profile
        // If 'group' is the profile name, we load that profile.
        // But usually 'group' is a selector tag in the running config.
        
        // Strategy:
        // 1. Load active profile config.
        // 2. Look for outbound with tag == node.
        val context = getApplication<Application>()
        val activeProfile = ConfigManager.getActiveProfile(context)
        val content = ConfigManager.loadProfile(context, activeProfile) ?: return null
        val config = ConfigManager.parseConfig(content) ?: return null
        
        return config.outbounds?.find { it.tag == node }
    }

    fun saveNodeDetail(oldTag: String, newOutbound: com.openworld.app.model.SingBoxOutbound) {
        val context = getApplication<Application>()
        val activeProfile = ConfigManager.getActiveProfile(context)
        
        ConfigManager.updateProfileConfig(context, activeProfile) { config ->
            val outbounds = config.outbounds ?: emptyList()
            val newOutbounds = outbounds.map { 
                if (it.tag == oldTag) newOutbound else it 
            }.toMutableList()
            
            // If it was a new node (oldTag not found), add it
            if (outbounds.none { it.tag == oldTag }) {
                newOutbounds.add(newOutbound)
            }
            
            config.copy(outbounds = newOutbounds)
        }
        
        refresh()
        _toastEvents.tryEmit("Saved")
    }

    fun createNode(outbound: com.openworld.app.model.SingBoxOutbound, targetProfileId: String? = null) {
        val context = getApplication<Application>()
        val profileId = targetProfileId ?: ConfigManager.getActiveProfile(context)

        // If target is empty/null, do nothing or default to active
        if (profileId.isEmpty()) return

        ConfigManager.updateProfileConfig(context, profileId) { config ->
            val newOutbounds = (config.outbounds ?: emptyList()).toMutableList()
            // Check if tag exists to avoid duplicates? Or just append?
            // KunBox likely appends or renames. For now, simple append.
            newOutbounds.add(outbound)
            config.copy(outbounds = newOutbounds)
        }
        refresh()
        _toastEvents.tryEmit("Node Created")
    }

    fun createNodeInNewProfile(outbound: com.openworld.app.model.SingBoxOutbound, newProfileName: String) {
        val context = getApplication<Application>()
        viewModelScope.launch(Dispatchers.IO) {
            val profileId = ConfigManager.createProfile(context, newProfileName, com.openworld.app.model.ProfileType.LocalFile)
            if (profileId != null) {
                createNode(outbound, profileId)
            } else {
                _toastEvents.tryEmit("Failed to create profile")
            }
        }
    }

    fun deleteNodeLocal(group: String, node: String) {
        val context = getApplication<Application>()
        val activeProfile = ConfigManager.getActiveProfile(context)
        
        ConfigManager.updateProfileConfig(context, activeProfile) { config ->
            val newOutbounds = (config.outbounds ?: emptyList()).filter { it.tag != node }
            config.copy(outbounds = newOutbounds)
        }
        refresh()
        _toastEvents.tryEmit("Node Deleted")
    }

    fun exportNodeLink(group: String, node: String): String {
        // Generate link based on Outbound content
        // This requires a serializer from Outbound to Link (vmess://, etc.)
        // This is complex, for now return placeholder or implement simple one
        return "Not implemented yet" 
    }
    
    fun testNodeDelay(group: String) {
         viewModelScope.launch(Dispatchers.IO) {
            try {
                CoreRepository.testGroupDelay(group, "https://www.gstatic.com/generate_204", 5000)
                refresh()
                _toastEvents.tryEmit("Test finished")
            } catch (e: Exception) {
                _toastEvents.tryEmit("Test failed: ${e.message}")
            }
        }
    }
}
