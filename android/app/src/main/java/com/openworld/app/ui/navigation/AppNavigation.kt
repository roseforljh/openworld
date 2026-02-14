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
import android.net.Uri
import androidx.navigation.NavBackStackEntry
import androidx.navigation.NavHostController
import androidx.navigation.NavType
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.navArgument
import com.openworld.app.ui.screens.AboutScreen
import com.openworld.app.ui.screens.AppRulesScreen
import com.openworld.app.ui.screens.ConnectionSettingsScreen
import com.openworld.app.ui.screens.ConnectionsScreen
import com.openworld.app.ui.screens.DashboardScreen
import com.openworld.app.ui.screens.DataManagementScreen
import com.openworld.app.ui.screens.DiagnosticsScreen
import com.openworld.app.ui.screens.DnsScreen
import com.openworld.app.ui.screens.DomainRulesScreen
import com.openworld.app.ui.screens.LogsScreen
import com.openworld.app.ui.screens.NodeDetailScreen
import com.openworld.app.ui.screens.NodesScreen
import com.openworld.app.ui.screens.ProfileEditorScreen
import com.openworld.app.ui.screens.ProfilesScreen
import com.openworld.app.ui.screens.RuleSetHubScreen
import com.openworld.app.ui.screens.RuleSetsScreen
import com.openworld.app.ui.screens.RoutingScreen
import com.openworld.app.ui.screens.SettingsScreen
import com.openworld.app.ui.screens.TrafficStatsScreen
import com.openworld.app.ui.screens.TunSettingsScreen

// ── Screen 路由定义 ──

sealed class Screen(val route: String) {
    object Dashboard : Screen("dashboard")
    object Nodes : Screen("nodes")
    object Profiles : Screen("profiles")
    object Settings : Screen("settings")

    object RoutingSettings : Screen("routing_settings")
    object DnsSettings : Screen("dns_settings")
    object TunSettings : Screen("tun_settings")
    object ConnectionSettings : Screen("connection_settings")
    object Diagnostics : Screen("diagnostics")
    object DataManagement : Screen("data_management")
    object RuleSets : Screen("rule_sets")
    object RuleSetHub : Screen("rule_set_hub")
    object DomainRules : Screen("domain_rules")
    object AppRules : Screen("app_rules")
    object Logs : Screen("logs")
    object Connections : Screen("connections")
    object TrafficStats : Screen("traffic_stats")
    object About : Screen("about")

    object NodeDetail : Screen("node_detail/{groupName}/{nodeName}") {
        fun nodeDetailRoute(groupName: String, nodeName: String): String =
            "node_detail/${Uri.encode(groupName)}/${Uri.encode(nodeName)}"
    }

    object ProfileEditor : Screen("profile_editor/{profileName}") {
        fun profileEditorRoute(profileName: String): String = "profile_editor/${Uri.encode(profileName)}"
    }

    object NodeCreate : Screen("node_create/{protocol}") {
        fun createRoute(protocol: String): String = "node_create/${Uri.encode(protocol)}"
    }
}

// ── Tab 索引 ──

const val NAV_ANIMATION_DURATION = 450

private fun tabIndex(route: String?): Int {
    val tab = getTabForRoute(route)
    return when (tab) {
        Screen.Dashboard.route -> 0
        Screen.Nodes.route -> 1
        Screen.Profiles.route -> 2
        Screen.Settings.route -> 3
        else -> 0
    }
}

/** 根据当前路由获取所属 Tab 路由 */
fun getTabForRoute(route: String?): String {
    if (route == null) return Screen.Dashboard.route
    return when {
        route == Screen.Dashboard.route -> Screen.Dashboard.route

        route == Screen.Nodes.route -> Screen.Nodes.route
        route.startsWith("node_detail") -> Screen.Nodes.route

        route == Screen.Profiles.route -> Screen.Profiles.route
        route.startsWith("profile_editor") -> Screen.Profiles.route

        route == Screen.Settings.route -> Screen.Settings.route
        route == Screen.RoutingSettings.route -> Screen.Settings.route
        route == Screen.DnsSettings.route -> Screen.Settings.route
        route == Screen.TunSettings.route -> Screen.Settings.route
        route == Screen.ConnectionSettings.route -> Screen.Settings.route
        route == Screen.RuleSets.route -> Screen.Settings.route
        route == Screen.DomainRules.route -> Screen.Settings.route
        route == Screen.AppRules.route -> Screen.Settings.route
        route == Screen.RuleSetHub.route -> Screen.Settings.route
        route == Screen.Diagnostics.route -> Screen.Settings.route
        route == Screen.Logs.route -> Screen.Settings.route
        route == Screen.TrafficStats.route -> Screen.Settings.route
        route == Screen.DataManagement.route -> Screen.Settings.route
        route == Screen.About.route -> Screen.Settings.route
        route == Screen.Connections.route -> Screen.Settings.route

        else -> Screen.Dashboard.route
    }
}

@Composable
fun AppNavigation(navController: NavHostController) {
    val slideSpec = tween<IntOffset>(
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

    val tabPopEnterTransition: AnimatedContentTransitionScope<NavBackStackEntry>.() -> EnterTransition = {
        val fromRoute = initialState.destination.route
        val toRoute = targetState.destination.route
        val fromTab = getTabForRoute(fromRoute)
        val toTab = getTabForRoute(toRoute)
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
        // ── Tab 页面 ──
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
        ) { NodesScreen(navController = navController) }
        composable(
            route = Screen.Profiles.route,
            enterTransition = tabEnterTransition,
            exitTransition = tabExitTransition,
            popEnterTransition = tabPopEnterTransition,
            popExitTransition = tabExitTransition
        ) { ProfilesScreen(navController = navController) }
        composable(
            route = Screen.Settings.route,
            enterTransition = tabEnterTransition,
            exitTransition = tabExitTransition,
            popEnterTransition = tabPopEnterTransition,
            popExitTransition = tabExitTransition
        ) { SettingsScreen(navController = navController) }

        // ── 子页面 ──
        composable(
            route = Screen.RoutingSettings.route,
            enterTransition = enterTransition,
            exitTransition = exitTransition,
            popEnterTransition = popEnterTransition,
            popExitTransition = popExitTransition
        ) { RoutingScreen(navController = navController) }
        composable(
            route = Screen.DnsSettings.route,
            enterTransition = enterTransition,
            exitTransition = exitTransition,
            popEnterTransition = popEnterTransition,
            popExitTransition = popExitTransition
        ) { DnsScreen(onBack = { navController.popBackStack() }) }
        composable(
            route = Screen.TunSettings.route,
            enterTransition = enterTransition,
            exitTransition = exitTransition,
            popEnterTransition = popEnterTransition,
            popExitTransition = popExitTransition
        ) { TunSettingsScreen(onBack = { navController.popBackStack() }) }
        composable(
            route = Screen.ConnectionSettings.route,
            enterTransition = enterTransition,
            exitTransition = exitTransition,
            popEnterTransition = popEnterTransition,
            popExitTransition = popExitTransition
        ) { ConnectionSettingsScreen(onBack = { navController.popBackStack() }) }
        composable(
            route = Screen.Diagnostics.route,
            enterTransition = enterTransition,
            exitTransition = exitTransition,
            popEnterTransition = popEnterTransition,
            popExitTransition = popExitTransition
        ) { DiagnosticsScreen(onBack = { navController.popBackStack() }) }
        composable(
            route = Screen.DataManagement.route,
            enterTransition = enterTransition,
            exitTransition = exitTransition,
            popEnterTransition = popEnterTransition,
            popExitTransition = popExitTransition
        ) { DataManagementScreen(onBack = { navController.popBackStack() }) }
        composable(
            route = Screen.RuleSets.route,
            enterTransition = enterTransition,
            exitTransition = exitTransition,
            popEnterTransition = popEnterTransition,
            popExitTransition = popExitTransition
        ) { RuleSetsScreen(navController = navController) }
        composable(
            route = Screen.RuleSetHub.route,
            enterTransition = enterTransition,
            exitTransition = exitTransition,
            popEnterTransition = popEnterTransition,
            popExitTransition = popExitTransition
        ) { RuleSetHubScreen(navController = navController) }
        composable(
            route = Screen.DomainRules.route,
            enterTransition = enterTransition,
            exitTransition = exitTransition,
            popEnterTransition = popEnterTransition,
            popExitTransition = popExitTransition
        ) { DomainRulesScreen(navController = navController) }
        composable(
            route = Screen.AppRules.route,
            enterTransition = enterTransition,
            exitTransition = exitTransition,
            popEnterTransition = popEnterTransition,
            popExitTransition = popExitTransition
        ) { AppRulesScreen(navController = navController) }
        composable(
            route = Screen.Connections.route,
            enterTransition = enterTransition,
            exitTransition = exitTransition,
            popEnterTransition = popEnterTransition,
            popExitTransition = popExitTransition
        ) { ConnectionsScreen(onBack = { navController.popBackStack() }) }
        composable(
            route = Screen.TrafficStats.route,
            enterTransition = enterTransition,
            exitTransition = exitTransition,
            popEnterTransition = popEnterTransition,
            popExitTransition = popExitTransition
        ) { TrafficStatsScreen(onBack = { navController.popBackStack() }) }
        composable(
            route = Screen.Logs.route,
            enterTransition = enterTransition,
            exitTransition = exitTransition,
            popEnterTransition = popEnterTransition,
            popExitTransition = popExitTransition
        ) { LogsScreen(onBack = { navController.popBackStack() }) }
        composable(
            route = Screen.About.route,
            enterTransition = enterTransition,
            exitTransition = exitTransition,
            popEnterTransition = popEnterTransition,
            popExitTransition = popExitTransition
        ) { AboutScreen(onBack = { navController.popBackStack() }) }
        composable(
            route = Screen.NodeDetail.route,
            arguments = listOf(
                navArgument("groupName") { type = NavType.StringType },
                navArgument("nodeName") { type = NavType.StringType }
            ),
            enterTransition = enterTransition,
            exitTransition = exitTransition,
            popEnterTransition = popEnterTransition,
            popExitTransition = popExitTransition
        ) { backStack ->
            val groupName = Uri.decode(backStack.arguments?.getString("groupName").orEmpty())
            val nodeName = Uri.decode(backStack.arguments?.getString("nodeName").orEmpty())
            // Pass combined ID to the new NodeDetailScreen
            NodeDetailScreen(
                navController = navController,
                nodeId = "$groupName/$nodeName"
            )
        }

        composable(
            route = Screen.NodeCreate.route,
            arguments = listOf(navArgument("protocol") { type = NavType.StringType }),
            enterTransition = enterTransition,
            exitTransition = exitTransition,
            popEnterTransition = popEnterTransition,
            popExitTransition = popExitTransition
        ) { backStack ->
            val protocol = Uri.decode(backStack.arguments?.getString("protocol").orEmpty())
            // Pass special ID for creation
            NodeDetailScreen(
                navController = navController,
                nodeId = "new:$protocol"
            )
        }
        composable(
            route = Screen.ProfileEditor.route,
            arguments = listOf(navArgument("profileName") { type = NavType.StringType }),
            enterTransition = enterTransition,
            exitTransition = exitTransition,
            popEnterTransition = popEnterTransition,
            popExitTransition = popExitTransition
        ) { backStack ->
            val profileName = Uri.decode(backStack.arguments?.getString("profileName").orEmpty())
            ProfileEditorScreen(
                profileName = profileName,
                onBack = { navController.popBackStack() }
            )
        }
    }
}
