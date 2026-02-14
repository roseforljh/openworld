package com.openworld.app.repository.store

import com.openworld.app.model.*

/**
 * SettingsStore 扩展方法 - 提供类型安全的设置更�? *
 * 使用示例�? * ```
 * settingsStore.setAutoConnect(true)
 * settingsStore.setTunStack(TunStack.MIXED)
 * settingsStore.setRuleSets(newRuleSets)
 * ```
 */

// ==================== 通用设置 ====================

fun SettingsStore.setAutoConnect(value: Boolean) {
    updateSettings { it.copy(autoConnect = value) }
}

fun SettingsStore.setExcludeFromRecent(value: Boolean) {
    updateSettings { it.copy(excludeFromRecent = value) }
}

fun SettingsStore.setAppTheme(value: AppThemeMode) {
    updateSettings { it.copy(appTheme = value) }
}

fun SettingsStore.setAppLanguage(value: AppLanguage) {
    updateSettings { it.copy(appLanguage = value) }
}

fun SettingsStore.setShowNotificationSpeed(value: Boolean) {
    updateSettings { it.copy(showNotificationSpeed = value) }
}

// ==================== TUN/VPN 设置 ====================

fun SettingsStore.setTunEnabled(value: Boolean) {
    updateSettings { it.copy(tunEnabled = value) }
}

fun SettingsStore.setTunStack(value: TunStack) {
    updateSettings { it.copy(tunStack = value) }
}

fun SettingsStore.setTunMtu(value: Int) {
    updateSettings { it.copy(tunMtu = value) }
}

fun SettingsStore.setTunMtuAuto(value: Boolean) {
    updateSettings { it.copy(tunMtuAuto = value) }
}

fun SettingsStore.setTunInterfaceName(value: String) {
    updateSettings { it.copy(tunInterfaceName = value) }
}

fun SettingsStore.setAutoRoute(value: Boolean) {
    updateSettings { it.copy(autoRoute = value) }
}

fun SettingsStore.setStrictRoute(value: Boolean) {
    updateSettings { it.copy(strictRoute = value) }
}

fun SettingsStore.setEndpointIndependentNat(value: Boolean) {
    updateSettings { it.copy(endpointIndependentNat = value) }
}

fun SettingsStore.setVpnRouteMode(value: VpnRouteMode) {
    updateSettings { it.copy(vpnRouteMode = value) }
}

fun SettingsStore.setVpnRouteIncludeCidrs(value: String) {
    updateSettings { it.copy(vpnRouteIncludeCidrs = value) }
}

fun SettingsStore.setVpnAppMode(value: VpnAppMode) {
    updateSettings { it.copy(vpnAppMode = value) }
}

fun SettingsStore.setVpnAllowlist(value: String) {
    updateSettings { it.copy(vpnAllowlist = value) }
}

fun SettingsStore.setVpnBlocklist(value: String) {
    updateSettings { it.copy(vpnBlocklist = value) }
}

// ==================== 代理端口设置 ====================

fun SettingsStore.setProxyPort(value: Int) {
    updateSettings { it.copy(proxyPort = value) }
}

fun SettingsStore.setAllowLan(value: Boolean) {
    updateSettings { it.copy(allowLan = value) }
}

fun SettingsStore.setAppendHttpProxy(value: Boolean) {
    updateSettings { it.copy(appendHttpProxy = value) }
}

// ==================== DNS 设置 ====================

fun SettingsStore.setLocalDns(value: String) {
    updateSettings { it.copy(localDns = value) }
}

fun SettingsStore.setRemoteDns(value: String) {
    updateSettings { it.copy(remoteDns = value) }
}

fun SettingsStore.setFakeDnsEnabled(value: Boolean) {
    updateSettings { it.copy(fakeDnsEnabled = value) }
}

fun SettingsStore.setFakeIpRange(value: String) {
    updateSettings { it.copy(fakeIpRange = value) }
}

fun SettingsStore.setDnsStrategy(value: DnsStrategy) {
    updateSettings { it.copy(dnsStrategy = value) }
}

fun SettingsStore.setRemoteDnsStrategy(value: DnsStrategy) {
    updateSettings { it.copy(remoteDnsStrategy = value) }
}

fun SettingsStore.setDirectDnsStrategy(value: DnsStrategy) {
    updateSettings { it.copy(directDnsStrategy = value) }
}

fun SettingsStore.setServerAddressStrategy(value: DnsStrategy) {
    updateSettings { it.copy(serverAddressStrategy = value) }
}

fun SettingsStore.setDnsCacheEnabled(value: Boolean) {
    updateSettings { it.copy(dnsCacheEnabled = value) }
}

// ==================== 路由设置 ====================

fun SettingsStore.setRoutingMode(value: RoutingMode) {
    updateSettings { it.copy(routingMode = value) }
}

fun SettingsStore.setDefaultRule(value: DefaultRule) {
    updateSettings { it.copy(defaultRule = value) }
}

fun SettingsStore.setBypassLan(value: Boolean) {
    updateSettings { it.copy(bypassLan = value) }
}

fun SettingsStore.setBlockQuic(value: Boolean) {
    updateSettings { it.copy(blockQuic = value) }
}

fun SettingsStore.setDebugLoggingEnabled(value: Boolean) {
    updateSettings { it.copy(debugLoggingEnabled = value) }
}

// ==================== 连接重置设置 ====================

fun SettingsStore.setWakeResetConnections(value: Boolean) {
    updateSettings { it.copy(wakeResetConnections = value) }
}

// ==================== 延迟测试设置 ====================

fun SettingsStore.setLatencyTestMethod(value: LatencyTestMethod) {
    updateSettings { it.copy(latencyTestMethod = value) }
}

fun SettingsStore.setLatencyTestUrl(value: String) {
    updateSettings { it.copy(latencyTestUrl = value) }
}

fun SettingsStore.setLatencyTestTimeout(value: Int) {
    updateSettings { it.copy(latencyTestTimeout = value) }
}

fun SettingsStore.setLatencyTestConcurrency(value: Int) {
    updateSettings { it.copy(latencyTestConcurrency = value) }
}

// ==================== 镜像设置 ====================

fun SettingsStore.setGhProxyMirror(value: GhProxyMirror) {
    updateSettings { it.copy(ghProxyMirror = value) }
}

// ==================== 高级路由 ====================

fun SettingsStore.setCustomRules(value: List<CustomRule>) {
    updateSettings { it.copy(customRules = value) }
}

fun SettingsStore.setRuleSets(value: List<RuleSet>) {
    updateSettings { it.copy(ruleSets = value) }
}

fun SettingsStore.setAppRules(value: List<AppRule>) {
    updateSettings { it.copy(appRules = value) }
}

fun SettingsStore.setAppGroups(value: List<AppGroup>) {
    updateSettings { it.copy(appGroups = value) }
}

// ==================== 规则集自动更�?====================

fun SettingsStore.setRuleSetAutoUpdateEnabled(value: Boolean) {
    updateSettings { it.copy(ruleSetAutoUpdateEnabled = value) }
}

fun SettingsStore.setRuleSetAutoUpdateInterval(value: Int) {
    updateSettings { it.copy(ruleSetAutoUpdateInterval = value) }
}

// ==================== 订阅更新超时 ====================

fun SettingsStore.setSubscriptionUpdateTimeout(value: Int) {
    updateSettings { it.copy(subscriptionUpdateTimeout = value) }
}

// ==================== 节点列表设置 ====================

fun SettingsStore.setNodeFilter(value: NodeFilter) {
    updateSettings { it.copy(nodeFilter = value) }
}

fun SettingsStore.setNodeSortType(value: NodeSortType) {
    updateSettings { it.copy(nodeSortType = value) }
}

fun SettingsStore.setCustomNodeOrder(value: List<String>) {
    updateSettings { it.copy(customNodeOrder = value) }
}

// ==================== 版本更新设置 ====================

fun SettingsStore.setAutoCheckUpdate(value: Boolean) {
    updateSettings { it.copy(autoCheckUpdate = value) }
}







