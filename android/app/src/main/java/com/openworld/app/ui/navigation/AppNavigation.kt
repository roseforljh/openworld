package com.openworld.app.ui.navigation

import androidx.compose.animation.AnimatedContentTransitionScope
import androidx.compose.animation.EnterTransition
import androidx.compose.animation.ExitTransition
import androidx.compose.animation.core.FastOutSlowInEasing
import androidx.compose.animation.core.tween
import androidx.compose.animation.slideInHorizontally
import androidx.compose.animation.slideOutHorizontally
import androidx.compose.runtime.Composable
import androidx.compose.ui.unit.IntOffset
import androidx.navigation.NavBackStackEntry
import androidx.navigation.NavHostController
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import com.openworld.app.ui.screens.DashboardScreen
import com.openworld.app.ui.screens.NodesScreen
import com.openworld.app.ui.screens.ProfilesScreen
import com.openworld.app.ui.screens.SettingsScreen
// New Screens
import com.openworld.app.ui.screens.ProfileEditorScreen
import com.openworld.app.ui.screens.NodeDetailScreen
import com.openworld.app.ui.screens.RoutingSettingsScreen
import com.openworld.app.ui.screens.DnsSettingsScreen
import com.openworld.app.ui.screens.TunSettingsScreen
import com.openworld.app.ui.screens.DiagnosticsScreen
import com.openworld.app.ui.screens.ConnectionSettingsScreen
import com.openworld.app.ui.screens.LogsScreen
import com.openworld.app.ui.screens.RuleSetsScreen
import com.openworld.app.ui.screens.CustomRulesScreen
import com.openworld.app.ui.screens.AppRoutingScreen
import com.openworld.app.ui.screens.RuleSetHubScreen
import com.openworld.app.ui.screens.DomainRulesScreen
import com.openworld.app.ui.screens.TrafficStatsScreen

sealed class Screen(val route: String) {
    object Dashboard : Screen("dashboard")
    object Nodes : Screen("nodes")
    object Profiles : Screen("profiles")
    object Settings : Screen("settings")

    // Details & Wizards
    object ProfileEditor : Screen("profile_editor")
    object NodeDetail : Screen("node_detail/{nodeId}") {
        fun createRoute(nodeId: String) = "node_detail/$nodeId"
    }
    object NodeCreate : Screen("node_create/{protocol}") {
        fun createRoute(protocol: String) = "node_create/$protocol"
    }
    object RoutingSettings : Screen("routing_settings")
    object DnsSettings : Screen("dns_settings")
    object TunSettings : Screen("tun_settings")
    object Diagnostics : Screen("diagnostics")
    object Logs : Screen("logs")
    object ConnectionSettings : Screen("connection_settings")
    object RuleSets : Screen("rule_sets")
    object CustomRules : Screen("custom_rules")
    object DomainRules : Screen("domain_rules")
    object AppRules : Screen("app_rules")
    object RuleSetHub : Screen("rule_set_hub")
    object TrafficStats : Screen("traffic_stats")
}

const val NAV_ANIMATION_DURATION = 450

private fun tabIndex(route: String?): Int {
    // 先获取该路由所属的 Tab，再返回 Tab 的索�?    val tab = getTabForRoute(route)
    return when (tab) {
        Screen.Dashboard.route -> 0
        Screen.Nodes.route -> 1
        Screen.Profiles.route -> 2
        Screen.Settings.route -> 3
        else -> 0
    }
}

// Map sub-routes to their parent tab
fun getTabForRoute(route: String?): String {
    if (route == null) return Screen.Dashboard.route
    return when {
        route == Screen.Dashboard.route -> Screen.Dashboard.route

        route == Screen.Nodes.route -> Screen.Nodes.route
        route.startsWith("node_detail") -> Screen.Nodes.route
        route.startsWith("node_create") -> Screen.Nodes.route

        route == Screen.Profiles.route -> Screen.Profiles.route
        route == Screen.ProfileEditor.route -> Screen.Profiles.route

        route == Screen.Settings.route -> Screen.Settings.route
        route == Screen.RoutingSettings.route -> Screen.Settings.route
        route == Screen.DnsSettings.route -> Screen.Settings.route
        route == Screen.TunSettings.route -> Screen.Settings.route
        route == Screen.ConnectionSettings.route -> Screen.Settings.route
        route == Screen.RuleSets.route -> Screen.Settings.route
        route == Screen.CustomRules.route -> Screen.Settings.route
        route == Screen.DomainRules.route -> Screen.Settings.route
        route == Screen.AppRules.route -> Screen.Settings.route
        route == Screen.RuleSetHub.route -> Screen.Settings.route
        route == Screen.Diagnostics.route -> Screen.Settings.route
        route == Screen.Logs.route -> Screen.Settings.route
        route == Screen.TrafficStats.route -> Screen.Settings.route

        else -> Screen.Dashboard.route
    }
}

@Composable
fun AppNavigation(navController: NavHostController) {
    val slideSpec = tween<IntOffset>(
        durationMillis = NAV_ANIMATION_DURATION,
        easing = FastOutSlowInEasing
    )
    val fadeSpec = tween<Float>(
        durationMillis = NAV_ANIMATION_DURATION,
        easing = FastOutSlowInEasing
    )

    val enterTransition: AnimatedContentTransitionScope<NavBackStackEntry>.() -> EnterTransition = {
        slideInHorizontally(initialOffsetX = { it }, animationSpec = slideSpec)
    }
    val exitTransition: AnimatedContentTransitionScope<NavBackStackEntry>.() -> ExitTransition = {
        ExitTransition.None
    }
    val popEnterTransition: AnimatedContentTransitionScope<NavBackStackEntry>.() -> EnterTransition = {
        EnterTransition.None
    }
    val popExitTransition: AnimatedContentTransitionScope<NavBackStackEntry>.() -> ExitTransition = {
        slideOutHorizontally(targetOffsetX = { it }, animationSpec = slideSpec)
    }

    val tabEnterTransition: AnimatedContentTransitionScope<NavBackStackEntry>.() -> EnterTransition = {
        val fromRoute = initialState.destination.route
        val toRoute = targetState.destination.route
        val fromIndex = tabIndex(fromRoute)
        val toIndex = tabIndex(toRoute)
        if (toIndex > fromIndex) {
            slideInHorizontally(initialOffsetX = { it }, animationSpec = slideSpec)
        } else {
            slideInHorizontally(initialOffsetX = { -it }, animationSpec = slideSpec)
        }
    }

    val tabExitTransition: AnimatedContentTransitionScope<NavBackStackEntry>.() -> ExitTransition = {
        val fromRoute = initialState.destination.route
        val toRoute = targetState.destination.route
        val fromTab = getTabForRoute(fromRoute)
        val toTab = getTabForRoute(toRoute)
        // 如果是同一�?Tab 内的导航（进入子页面），底层页面不动
        if (fromTab == toTab) {
            ExitTransition.None
        } else {
            val fromIndex = tabIndex(fromRoute)
            val toIndex = tabIndex(toRoute)
            if (toIndex > fromIndex) {
                slideOutHorizontally(targetOffsetX = { -it }, animationSpec = slideSpec)
            } else {
                slideOutHorizontally(targetOffsetX = { it }, animationSpec = slideSpec)
            }
        }
    }

    // 从子页面返回时，父级页面不需要动�?    val tabPopEnterTransition: AnimatedContentTransitionScope<NavBackStackEntry>.() -> EnterTransition = {
        val fromRoute = initialState.destination.route
        val toRoute = targetState.destination.route
        val fromTab = getTabForRoute(fromRoute)
        val toTab = getTabForRoute(toRoute)
        // 如果是同一�?Tab 内返回（从子页面返回），父级页面不动
        if (fromTab == toTab) {
            EnterTransition.None
        } else {
            val fromIndex = tabIndex(fromRoute)
            val toIndex = tabIndex(toRoute)
            if (toIndex > fromIndex) {
                slideInHorizontally(initialOffsetX = { it }, animationSpec = slideSpec)
            } else {
                slideInHorizontally(initialOffsetX = { -it }, animationSpec = slideSpec)
            }
        }
    }

    NavHost(
        navController = navController,
        startDestination = Screen.Dashboard.route
    ) {
        // Main Tabs
        composable(
            route = Screen.Dashboard.route,
            enterTransition = tabEnterTransition,
            exitTransition = tabExitTransition,
            popEnterTransition = tabPopEnterTransition,
            popExitTransition = tabExitTransition
        ) { DashboardScreen(navController) }
        composable(
            route = Screen.Nodes.route,
            enterTransition = tabEnterTransition,
            exitTransition = tabExitTransition,
            popEnterTransition = tabPopEnterTransition,
            popExitTransition = tabExitTransition
        ) { NodesScreen(navController) }
        composable(
            route = Screen.Profiles.route,
            enterTransition = tabEnterTransition,
            exitTransition = tabExitTransition,
            popEnterTransition = tabPopEnterTransition,
            popExitTransition = tabExitTransition
        ) { ProfilesScreen(navController) }
        composable(
            route = Screen.Settings.route,
            enterTransition = tabEnterTransition,
            exitTransition = tabExitTransition,
            popEnterTransition = tabPopEnterTransition,
            popExitTransition = tabExitTransition
        ) { SettingsScreen(navController) }

        // Sub Screens
        composable(
            route = Screen.ProfileEditor.route,
            enterTransition = enterTransition,
            exitTransition = exitTransition,
            popEnterTransition = popEnterTransition,
            popExitTransition = popExitTransition
        ) { ProfileEditorScreen(navController) }

        composable(
            route = Screen.NodeDetail.route,
            arguments = listOf(
                androidx.navigation.navArgument("nodeId") { type = androidx.navigation.NavType.StringType }
            ),
            enterTransition = enterTransition,
            exitTransition = exitTransition,
            popEnterTransition = popEnterTransition,
            popExitTransition = popExitTransition
        ) { backStackEntry ->
            val nodeId = backStackEntry.arguments?.getString("nodeId") ?: ""
            NodeDetailScreen(navController = navController, nodeId = nodeId)
        }
        composable(
            route = Screen.NodeCreate.route,
            arguments = listOf(
                androidx.navigation.navArgument("protocol") { type = androidx.navigation.NavType.StringType }
            ),
            enterTransition = enterTransition,
            exitTransition = exitTransition,
            popEnterTransition = popEnterTransition,
            popExitTransition = popExitTransition
        ) { backStackEntry ->
            val protocol = backStackEntry.arguments?.getString("protocol") ?: "vmess"
            NodeDetailScreen(navController = navController, nodeId = "", createProtocol = protocol)
        }
        composable(
            route = Screen.RoutingSettings.route,
            enterTransition = enterTransition,
            exitTransition = exitTransition,
            popEnterTransition = popEnterTransition,
            popExitTransition = popExitTransition
        ) { RoutingSettingsScreen(navController) }
        composable(
            route = Screen.DnsSettings.route,
            enterTransition = enterTransition,
            exitTransition = exitTransition,
            popEnterTransition = popEnterTransition,
            popExitTransition = popExitTransition
        ) { DnsSettingsScreen(navController) }
        composable(
            route = Screen.TunSettings.route,
            enterTransition = enterTransition,
            exitTransition = exitTransition,
            popEnterTransition = popEnterTransition,
            popExitTransition = popExitTransition
        ) { TunSettingsScreen(navController) }
        composable(
            route = Screen.Diagnostics.route,
            enterTransition = enterTransition,
            exitTransition = exitTransition,
            popEnterTransition = popEnterTransition,
            popExitTransition = popExitTransition
        ) { DiagnosticsScreen(navController) }
        composable(
            route = Screen.Logs.route,
            enterTransition = enterTransition,
            exitTransition = exitTransition,
            popEnterTransition = popEnterTransition,
            popExitTransition = popExitTransition
        ) { LogsScreen(navController) }
        composable(
            route = Screen.ConnectionSettings.route,
            enterTransition = enterTransition,
            exitTransition = exitTransition,
            popEnterTransition = popEnterTransition,
            popExitTransition = popExitTransition
        ) { ConnectionSettingsScreen(navController) }
        composable(
            route = Screen.RuleSets.route,
            enterTransition = enterTransition,
            exitTransition = exitTransition,
            popEnterTransition = popEnterTransition,
            popExitTransition = popExitTransition
        ) { RuleSetsScreen(navController) }
        composable(
            route = Screen.CustomRules.route,
            enterTransition = enterTransition,
            exitTransition = exitTransition,
            popEnterTransition = popEnterTransition,
            popExitTransition = popExitTransition
        ) { CustomRulesScreen(navController) }
        composable(
            route = Screen.DomainRules.route,
            enterTransition = enterTransition,
            exitTransition = exitTransition,
            popEnterTransition = popEnterTransition,
            popExitTransition = popExitTransition
        ) { DomainRulesScreen(navController) }
        composable(
            route = Screen.AppRules.route,
            enterTransition = enterTransition,
            exitTransition = exitTransition,
            popEnterTransition = popEnterTransition,
            popExitTransition = popExitTransition
        ) { AppRoutingScreen(navController) }
        composable(
            route = Screen.RuleSetHub.route,
            enterTransition = enterTransition,
            exitTransition = exitTransition,
            popEnterTransition = popEnterTransition,
            popExitTransition = popExitTransition
        ) { RuleSetHubScreen(navController) }
        composable(
            route = Screen.TrafficStats.route,
            enterTransition = enterTransition,
            exitTransition = exitTransition,
            popEnterTransition = popEnterTransition,
            popExitTransition = popExitTransition
        ) { TrafficStatsScreen(navController) }
    }
}







