package com.openworld.core;

/**
 * OpenWorld 代理内核 Java SDK
 *
 * 通过 JNI 调用 Rust 编译的 libopenworld.so，提供完整的代理管理能力。
 *
 * 使用方法:
 * 1. 将 libopenworld.so 放入 app/src/main/jniLibs/{abi}/ 下
 * 2. 调用 OpenWorldCore.start(configJson) 启动
 * 3. 调用 OpenWorldCore.stop() 停止
 */
public class OpenWorldCore {

    static {
        System.loadLibrary("openworld");
    }

    // ═══════════════════════════════════════════════════════════════════
    // 生命周期
    // ═══════════════════════════════════════════════════════════════════

    /**
     * 启动代理内核
     * 
     * @param configJson JSON 或 YAML 配置字符串
     * @return 0=成功, -1=未运行, -2=已运行, -3=参数错误, -4=内部错误
     */
    public static native int start(String configJson);

    /** 停止代理内核 */
    public static native int stop();

    /** 检查是否运行中 */
    public static native boolean isRunning();

    /** 获取版本号 */
    public static native String version();

    // ═══════════════════════════════════════════════════════════════════
    // 暂停/恢复
    // ═══════════════════════════════════════════════════════════════════

    /** 暂停内核（省电模式） */
    public static native boolean pause();

    /** 恢复内核 */
    public static native boolean resume();

    /** 查询暂停状态 */
    public static native boolean isPaused();

    // ═══════════════════════════════════════════════════════════════════
    // 出站管理
    // ═══════════════════════════════════════════════════════════════════

    /** 切换出站节点 */
    public static native boolean selectOutbound(String tag);

    /** 获取当前选中出站节点 */
    public static native String getSelectedOutbound();

    /** 获取出站列表（\n 分隔） */
    public static native String listOutbounds();

    /** 是否有 selector 出站 */
    public static native boolean hasSelector();

    // ═══════════════════════════════════════════════════════════════════
    // 代理组管理
    // ═══════════════════════════════════════════════════════════════════

    /**
     * 获取所有代理组详情（JSON 数组）
     * 格式:
     * [{"name":"group1","type":"selector","selected":"proxy1","members":["p1","p2"]}]
     */
    public static native String getProxyGroups();

    /**
     * 在指定代理组中切换选中的代理
     * 
     * @param group 代理组名称
     * @param proxy 要选中的代理名称
     */
    public static native boolean setGroupSelected(String group, String proxy);

    /**
     * 对代理组进行批量延迟测速
     * 
     * @return JSON: [{"name":"proxy1","delay":120},{"name":"proxy2","delay":-1}]
     */
    public static native String testGroupDelay(String group, String url, int timeoutMs);

    /**
     * URL 延迟测试
     * 
     * @return 延迟毫秒数，-1=失败, -3=参数错误
     */
    public static native int urlTest(String outboundTag, String url, int timeoutMs);

    // ═══════════════════════════════════════════════════════════════════
    // 流量统计
    // ═══════════════════════════════════════════════════════════════════

    /** 累计上传字节 */
    public static native long getTrafficTotalUplink();

    /** 累计下载字节 */
    public static native long getTrafficTotalDownlink();

    /** 重置流量统计 */
    public static native boolean resetTrafficStats();

    /**
     * 获取实时流量快照（JSON）
     * 格式:
     * {"upload_total":1234,"download_total":5678,"connections":5,"per_outbound":{...}}
     */
    public static native String getTrafficSnapshot();

    /**
     * 获取实时流量速率（JSON）
     * 格式: {"upload_rate":1024,"download_rate":2048}
     */
    public static native String pollTrafficRate();

    // ═══════════════════════════════════════════════════════════════════
    // 连接管理
    // ═══════════════════════════════════════════════════════════════════

    /** 活跃连接数 */
    public static native long getConnectionCount();

    /** 重置所有连接 */
    public static native boolean resetAllConnections(boolean systemTriggered);

    /** 关闭空闲连接 */
    public static native long closeIdleConnections(long seconds);

    /**
     * 获取活跃连接详情（JSON 数组）
     * 格式:
     * [{"id":1,"destination":"example.com:443","outbound":"proxy","upload":1024,"download":2048}]
     */
    public static native String getActiveConnections();

    /** 关闭指定 ID 的连接 */
    public static native boolean closeConnectionById(long id);

    // ═══════════════════════════════════════════════════════════════════
    // 配置
    // ═══════════════════════════════════════════════════════════════════

    /**
     * 热重载配置（不停止内核）
     * 
     * @param configJson 新的配置内容
     * @return 0=成功
     */
    public static native int reloadConfig(String configJson);

    // ═══════════════════════════════════════════════════════════════════
    // 网络
    // ═══════════════════════════════════════════════════════════════════

    /** 自动网络恢复 */
    public static native boolean recoverNetworkAuto();

    /** 设置 TUN 文件描述符 */
    public static native int setTunFd(int fd);

    /** 设置系统 DNS */
    public static native boolean setSystemDns(String dnsAddress);

    // ═══════════════════════════════════════════════════════════════════
    // 订阅
    // ═══════════════════════════════════════════════════════════════════

    /**
     * 导入订阅 URL
     * 
     * @return JSON: {"count":10,"nodes":["node1","node2",...]} 或
     *         {"error":"message"}
     */
    public static native String importSubscription(String url);

    // ═══════════════════════════════════════════════════════════════════
    // Clash 模式
    // ═══════════════════════════════════════════════════════════════════

    /** 获取当前 Clash 模式 (rule/global/direct) */
    public static native String getClashMode();

    /** 设置 Clash 模式 */
    public static native boolean setClashMode(String mode);

    // ═══════════════════════════════════════════════════════════════════
    // DNS 查询
    // ═══════════════════════════════════════════════════════════════════

    /**
     * DNS 查询
     * 
     * @param name  域名
     * @param qtype 查询类型 (A/AAAA/CNAME/MX 等)
     * @return JSON 查询结果
     */
    public static native String dnsQuery(String name, String qtype);

    /** 刷新 DNS 缓存 */
    public static native boolean dnsFlush();

    // ═══════════════════════════════════════════════════════════════════
    // 内存 / 状态
    // ═══════════════════════════════════════════════════════════════════

    /**
     * 获取内存使用量（JSON）
     * 格式: {"rss":12345,"heap":6789}
     */
    public static native String getMemoryUsage();

    /**
     * 获取内核状态信息（JSON）
     * 格式: {"running":true,"uptime":3600,"connections":5,...}
     */
    public static native String getStatus();

    /** 触发 Rust 内存清理（释放缓存缓冲区等） */
    public static native int gc();

    // ═══════════════════════════════════════════════════════════════════
    // Profile 管理
    // ═══════════════════════════════════════════════════════════════════

    /** 列出所有 Profile（JSON 数组） */
    public static native String listProfiles();

    /** 切换当前 Profile */
    public static native boolean switchProfile(String name);

    /** 获取当前活跃 Profile 名称 */
    public static native String getCurrentProfile();

    /**
     * 导入 Profile
     * 
     * @param name Profile 名称
     * @param yaml YAML 内容
     */
    public static native boolean importProfile(String name, String yaml);

    /** 导出 Profile 为 YAML 字符串 */
    public static native String exportProfile(String name);

    /** 删除 Profile */
    public static native boolean deleteProfile(String name);

    // ═══════════════════════════════════════════════════════════════════
    // Provider 管理
    // ═══════════════════════════════════════════════════════════════════

    /** 列出所有 Provider（JSON 数组） */
    public static native String listProviders();

    /** 获取 Provider 下的节点列表（JSON 数组） */
    public static native String getProviderNodes(String name);

    /**
     * 添加 HTTP Provider
     * 
     * @param name     Provider 名称
     * @param url      订阅 URL
     * @param interval 更新间隔（秒）
     */
    public static native boolean addHttpProvider(String name, String url, long interval);

    /** 更新 Provider 节点 */
    public static native int updateProvider(String name);

    /** 移除 Provider */
    public static native boolean removeProvider(String name);

    // ═══════════════════════════════════════════════════════════════════
    // 延迟历史
    // ═══════════════════════════════════════════════════════════════════

    /**
     * 获取延迟历史记录（JSON 数组）
     * 
     * @param tagFilter 按 tag 过滤，null = 全部
     */
    public static native String getDelayHistory(String tagFilter);

    /** 清空延迟历史 */
    public static native boolean clearDelayHistory();

    /** 获取指定节点最近一次延迟值，-1=无记录 */
    public static native int getLastDelay(String tag);

    // ═══════════════════════════════════════════════════════════════════
    // 自动测速
    // ═══════════════════════════════════════════════════════════════════

    /**
     * 启动自动测速
     * 
     * @param groupTag     代理组名称
     * @param testUrl      测试 URL
     * @param intervalSecs 测试间隔（秒）
     * @param timeoutMs    单次超时（毫秒）
     */
    public static native boolean startAutoTest(String groupTag, String testUrl,
            int intervalSecs, int timeoutMs);

    /** 停止自动测速 */
    public static native boolean stopAutoTest();

    // ═══════════════════════════════════════════════════════════════════
    // 平台接口
    // ═══════════════════════════════════════════════════════════════════

    /**
     * 通知内核网络环境变更（Android ConnectivityManager 回调）
     * 
     * @param networkType 0=NONE, 1=WIFI, 2=CELLULAR, 3=ETHERNET
     * @param ssid        当前 SSID（WiFi），无则传 null
     * @param isMetered   是否为计费网络
     */
    public static native void notifyNetworkChanged(int networkType, String ssid, boolean isMetered);

    /** 获取平台状态（JSON） */
    public static native String getPlatformState();

    /** 通知内核系统内存不足 */
    public static native void notifyMemoryLow();

    /** 查询当前网络是否为计费 */
    public static native boolean isNetworkMetered();

    // ═══════════════════════════════════════════════════════════════════
    // GeoIP/GeoSite 更新
    // ═══════════════════════════════════════════════════════════════════

    /**
     * 更新 GeoIP/GeoSite 数据库
     * 
     * @param geoipPath   本地 GeoIP 文件路径
     * @param geoipUrl    GeoIP 下载 URL
     * @param geositePath 本地 GeoSite 文件路径
     * @param geositeUrl  GeoSite 下载 URL
     */
    public static native boolean updateGeoDatabases(String geoipPath, String geoipUrl,
            String geositePath, String geositeUrl);

    // ═══════════════════════════════════════════════════════════════════
    // 规则 CRUD
    // ═══════════════════════════════════════════════════════════════════

    /** 列出所有路由规则（JSON 数组） */
    public static native String rulesList();

    /**
     * 添加路由规则
     * 
     * @param ruleJson 规则 JSON
     * @return 新规则的索引，负数表示错误
     */
    public static native int rulesAdd(String ruleJson);

    /** 移除指定索引的规则 */
    public static native boolean rulesRemove(int index);

    // ═══════════════════════════════════════════════════════════════════
    // WakeLock / 通知
    // ═══════════════════════════════════════════════════════════════════

    /** 设置 WakeLock 状态（true=获取, false=释放） */
    public static native boolean wakelockSet(boolean acquire);

    /** 查询 WakeLock 是否持有 */
    public static native boolean wakelockHeld();

    /** 获取通知栏内容文本（含速率/连接数等） */
    public static native String notificationContent();

    // ═══════════════════════════════════════════════════════════════════
    // 便捷方法（非 native）
    // ═══════════════════════════════════════════════════════════════════

    /** 获取出站列表（数组形式） */
    public static String[] getOutboundList() {
        String raw = listOutbounds();
        if (raw == null || raw.isEmpty())
            return new String[0];
        return raw.split("\n");
    }

    /** 获取格式化的流量文本 */
    public static String formatTraffic(long bytes) {
        if (bytes < 1024)
            return bytes + " B";
        if (bytes < 1024 * 1024)
            return String.format("%.1f KB", bytes / 1024.0);
        if (bytes < 1024 * 1024 * 1024)
            return String.format("%.1f MB", bytes / (1024.0 * 1024));
        return String.format("%.2f GB", bytes / (1024.0 * 1024 * 1024));
    }

    /** 获取运行时长描述 */
    public static String getStatusText() {
        if (!isRunning())
            return "Stopped";
        if (isPaused())
            return "Paused";
        return "Running " + version();
    }
}
