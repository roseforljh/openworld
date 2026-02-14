package com.openworld.app.ui.screens

import androidx.compose.foundation.ExperimentalFoundationApi
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.layout.asPaddingValues
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.pager.HorizontalPager
import androidx.compose.foundation.pager.rememberPagerState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.automirrored.rounded.ArrowBack
import androidx.compose.material.icons.rounded.Add
import androidx.compose.material.icons.rounded.Search
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewmodel.compose.viewModel
import androidx.navigation.NavController
import com.openworld.app.R
import com.openworld.app.model.*
import com.openworld.app.viewmodel.SettingsViewModel
import kotlinx.coroutines.launch

@OptIn(ExperimentalMaterial3Api::class, ExperimentalFoundationApi::class)
@Composable
fun AppRulesScreen(
    navController: NavController,
    viewModel: SettingsViewModel = viewModel()
) {
    val appGroups by viewModel.appGroups.collectAsStateWithLifecycle()
    val appRules by viewModel.appRules.collectAsStateWithLifecycle()
    val installedApps by viewModel.installedApps.collectAsStateWithLifecycle()

    // TEMPORARY FIX: OpenWorld SettingsViewModel does not expose nodes/profiles yet.
    val nodes = emptyList<NodeUi>()
    val profiles = emptyList<ProfileUi>()

    val pagerState = rememberPagerState(pageCount = { 2 })
    val scope = rememberCoroutineScope()
    val titles = listOf(stringResource(R.string.app_rules_tab_rules), stringResource(R.string.app_rules_tab_groups))

    var showRuleEditor by remember { mutableStateOf(false) }
    var showGroupEditor by remember { mutableStateOf(false) }
    var editingRule by remember { mutableStateOf<AppRule?>(null) }
    var editingGroup by remember { mutableStateOf<AppGroup?>(null) }

    var searchQuery by remember { mutableStateOf("") }

    Scaffold(
        containerColor = MaterialTheme.colorScheme.background,
        contentWindowInsets = WindowInsets(0, 0, 0, 0),
        topBar = {
            TopAppBar(
                title = { Text(stringResource(R.string.app_routing_title)) },
                navigationIcon = {
                    IconButton(onClick = { navController.popBackStack() }) {
                        Icon(Icons.AutoMirrored.Rounded.ArrowBack, contentDescription = null)
                    }
                },
                colors = TopAppBarDefaults.topAppBarColors(containerColor = Color.Transparent)
            )
        },
        floatingActionButton = {
            ExtendedFloatingActionButton(
                onClick = {
                    if (pagerState.currentPage == 0) {
                        editingRule = null
                        showRuleEditor = true
                    } else {
                        editingGroup = null
                        showGroupEditor = true
                    }
                },
                icon = { Icon(Icons.Rounded.Add, contentDescription = null) },
                text = { Text(text = if (pagerState.currentPage == 0) stringResource(R.string.app_rules_add) else stringResource(R.string.app_groups_create)) }
            )
        }
    ) { paddingValues ->
        Column(
            modifier = Modifier
                .padding(paddingValues)
                .fillMaxSize()
        ) {
            Box(modifier = Modifier.padding(16.dp)) {
                OutlinedTextField(
                    value = searchQuery,
                    onValueChange = { searchQuery = it },
                    modifier = Modifier.fillMaxWidth(),
                    placeholder = { Text(stringResource(R.string.common_search)) },
                    leadingIcon = { Icon(Icons.Rounded.Search, contentDescription = null) },
                    singleLine = true,
                    shape = RoundedCornerShape(12.dp)
                )
            }

            TabRow(
                selectedTabIndex = pagerState.currentPage,
                containerColor = Color.Transparent,
                divider = {}
            ) {
                titles.forEachIndexed { index, title ->
                    Tab(
                        selected = pagerState.currentPage == index,
                        onClick = { scope.launch { pagerState.animateScrollToPage(index) } },
                        text = { Text(title, fontWeight = if (pagerState.currentPage == index) FontWeight.Bold else FontWeight.Normal) }
                    )
                }
            }

            HorizontalPager(
                state = pagerState,
                modifier = Modifier.fillMaxSize()
            ) { page ->
                if (page == 0) {
                    val filteredRules = appRules.filter {
                        it.appName.contains(searchQuery, ignoreCase = true) || it.packageName.contains(searchQuery, ignoreCase = true)
                    }
                    LazyColumn(
                        modifier = Modifier.fillMaxSize(),
                        contentPadding = PaddingValues(bottom = 80.dp + WindowInsets.navigationBars.asPaddingValues().calculateBottomPadding()),
                        verticalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        items(filteredRules, key = { it.id }) { rule ->
                            val outboundText = when (rule.outboundMode) {
                                RuleSetOutboundMode.DIRECT -> stringResource(R.string.outbound_direct)
                                RuleSetOutboundMode.BLOCK -> stringResource(R.string.outbound_block)
                                RuleSetOutboundMode.PROXY -> stringResource(R.string.outbound_proxy)
                                RuleSetOutboundMode.NODE -> rule.outboundValue ?: stringResource(R.string.unknown)
                                RuleSetOutboundMode.PROFILE -> rule.outboundValue ?: stringResource(R.string.unknown)
                                else -> stringResource(R.string.outbound_direct)
                            }

                            AppRuleItem(
                                rule = rule,
                                outboundText = outboundText,
                                onClick = {
                                    editingRule = rule
                                    showRuleEditor = true
                                },
                                onDelete = { viewModel.deleteAppRule(rule.id) }
                            )
                        }
                    }
                } else {
                    val filteredGroups = appGroups.filter {
                        it.name.contains(searchQuery, ignoreCase = true)
                    }
                    LazyColumn(
                        modifier = Modifier.fillMaxSize(),
                        contentPadding = PaddingValues(bottom = 80.dp),
                        verticalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        items(filteredGroups, key = { it.id }) { group ->
                             val outboundText = when (group.outboundMode) {
                                RuleSetOutboundMode.DIRECT -> stringResource(R.string.outbound_direct)
                                RuleSetOutboundMode.BLOCK -> stringResource(R.string.outbound_block)
                                RuleSetOutboundMode.PROXY -> stringResource(R.string.outbound_proxy)
                                RuleSetOutboundMode.NODE -> group.outboundValue ?: stringResource(R.string.unknown)
                                RuleSetOutboundMode.PROFILE -> group.outboundValue ?: stringResource(R.string.unknown)
                                else -> stringResource(R.string.outbound_direct)
                            }

                            AppGroupItem(
                                group = group,
                                outboundText = outboundText,
                                onClick = {
                                    editingGroup = group
                                    showGroupEditor = true
                                },
                                onToggle = { viewModel.toggleAppGroupEnabled(group.id) },
                                onDelete = { viewModel.deleteAppGroup(group.id) }
                            )
                        }
                    }
                }
            }
        }
    }

    if (showRuleEditor) {
        AppRuleEditorDialog(
            initialRule = editingRule,
            installedApps = installedApps,
            nodes = nodes,
            profiles = profiles,
            onDismiss = { showRuleEditor = false },
            onConfirm = { rule ->
                if (editingRule == null) {
                    viewModel.addAppRule(rule)
                } else {
                    viewModel.updateAppRule(rule)
                }
                showRuleEditor = false
            }
        )
    }

    if (showGroupEditor) {
        AppGroupEditorDialog(
            initialGroup = editingGroup,
            installedApps = installedApps,
            nodes = nodes,
            profiles = profiles,
            onDismiss = { showGroupEditor = false },
            onConfirm = { group ->
                if (editingGroup == null) {
                    viewModel.addAppGroup(group)
                } else {
                    viewModel.updateAppGroup(group)
                }
                showGroupEditor = false
            }
        )
    }
}
