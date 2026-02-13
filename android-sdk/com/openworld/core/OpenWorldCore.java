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
    // 代理组管理（新增）
    // ═══════════════════════════════════════════════════════════════════

    /**
     * 获取所有代理组详情（JSON 数组）
     * 格式: [{"name":"group1","type":"selector","selected":"proxy1","members":["p1","p2"]}]
     */
    public static native String getProxyGroups();

    /**
     * 在指定代理组中切换选中的代理
     * @param group 代理组名称
     * @param proxy 要选中的代理名称
     */
    public static native boolean setGroupSelected(String group, String proxy);

    /**
     * 对代理组进行批量延迟测速
     * @return JSON: [{"name":"proxy1","delay":120},{"name":"proxy2","delay":-1}]
     */
    public static native String testGroupDelay(String group, String url, int timeoutMs);

    /**
     * URL 延迟测试
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
     * 格式: {"upload_total":1234,"download_total":5678,"connections":5,"per_outbound":{...}}
     */
    public static native String getTrafficSnapshot();

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
     * 格式: [{"id":1,"destination":"example.com:443","outbound":"proxy","upload":1024,"download":2048}]
     */
    public static native String getActiveConnections();

    /** 关闭指定 ID 的连接 */
    public static native boolean closeConnectionById(long id);

    // ═══════════════════════════════════════════════════════════════════
    // 配置
    // ═══════════════════════════════════════════════════════════════════

    /**
     * 热重载配置（不停止内核）
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
     * @return JSON: {"count":10,"nodes":["node1","node2",...]} 或 {"error":"message"}
     */
    public static native String importSubscription(String url);

    // ═══════════════════════════════════════════════════════════════════
    // 便捷方法（非 native）
    // ═══════════════════════════════════════════════════════════════════

    /** 获取出站列表（数组形式） */
    public static String[] getOutboundList() {
        String raw = listOutbounds();
        if (raw == null || raw.isEmpty()) return new String[0];
        return raw.split("\n");
    }

    /** 获取格式化的流量文本 */
    public static String formatTraffic(long bytes) {
        if (bytes < 1024) return bytes + " B";
        if (bytes < 1024 * 1024) return String.format("%.1f KB", bytes / 1024.0);
        if (bytes < 1024 * 1024 * 1024) return String.format("%.1f MB", bytes / (1024.0 * 1024));
        return String.format("%.2f GB", bytes / (1024.0 * 1024 * 1024));
    }

    /** 获取运行时长描述 */
    public static String getStatusText() {
        if (!isRunning()) return "Stopped";
        if (isPaused()) return "Paused";
        return "Running " + version();
    }
}
