use std::net::{IpAddr, Ipv4Addr};

#[cfg(target_os = "linux")]
use std::ffi::c_void;
#[cfg(target_os = "linux")]
use std::process::Command;
#[cfg(any(target_os = "linux", target_os = "windows"))]
use std::sync::Mutex;
#[cfg(any(target_os = "linux", target_os = "windows"))]
use std::sync::atomic::{AtomicU16, Ordering};

use anyhow::{Context, Result};
use async_trait::async_trait;
#[cfg(any(target_os = "linux", target_os = "windows"))]
use tokio::time::{Duration, sleep};

/// TUN 设备平台抽象 trait
///
/// 每个平台实现此 trait，提供统一的 TUN 设备操作接口。
#[async_trait]
pub trait TunDevice: Send + Sync {
    /// 设备名称（如 utun0, wintun0, tun0）
    fn name(&self) -> &str;

    /// 读取一个 IP 包
    async fn read_packet(&self, buf: &mut [u8]) -> Result<usize>;

    /// 写入一个 IP 包
    async fn write_packet(&self, buf: &[u8]) -> Result<usize>;

    /// 设置设备 MTU
    fn set_mtu(&self, mtu: u16) -> Result<()>;

    /// 获取当前 MTU
    fn mtu(&self) -> u16;

    /// 关闭设备
    async fn close(&self) -> Result<()>;
}

/// TUN 设备配置
#[derive(Debug, Clone)]
pub struct TunConfig {
    pub name: String,
    pub address: Ipv4Addr,
    pub netmask: Ipv4Addr,
    pub mtu: u16,
    pub dns_hijack: bool,
    pub auto_route: bool,
    pub strict_route: bool,
    pub stack: TunStack,
}

impl Default for TunConfig {
    fn default() -> Self {
        Self {
            name: "utun-openworld".to_string(),
            address: Ipv4Addr::new(198, 18, 0, 1),
            netmask: Ipv4Addr::new(255, 254, 0, 0),
            mtu: 1500,
            dns_hijack: true,
            auto_route: true,
            strict_route: false,
            stack: TunStack::GVisor,
        }
    }
}

/// 用户态网络栈类型
#[derive(Debug, Clone, PartialEq)]
pub enum TunStack {
    /// gVisor 风格用户态栈（完整 TCP/IP）
    GVisor,
    /// 轻量栈（smoltcp）
    Lightweight,
    /// 系统栈（直接使用内核栈）
    System,
}

/// IP 包解析结果
#[derive(Debug, Clone)]
pub struct ParsedPacket {
    pub version: u8,
    pub protocol: IpProtocol,
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub payload_offset: usize,
    pub total_len: usize,
}

/// IP 协议类型
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum IpProtocol {
    Tcp,
    Udp,
    Icmp,
    Other(u8),
}

impl IpProtocol {
    pub fn from_number(n: u8) -> Self {
        match n {
            1 | 58 => Self::Icmp, // ICMPv4 = 1, ICMPv6 = 58
            6 => Self::Tcp,
            17 => Self::Udp,
            other => Self::Other(other),
        }
    }
}

/// 解析 IP 包头部
pub fn parse_ip_packet(data: &[u8]) -> Result<ParsedPacket> {
    if data.is_empty() {
        anyhow::bail!("empty packet");
    }

    let version = data[0] >> 4;
    match version {
        4 => parse_ipv4_packet(data),
        6 => parse_ipv6_packet(data),
        _ => anyhow::bail!("unsupported IP version: {}", version),
    }
}

fn parse_ipv4_packet(data: &[u8]) -> Result<ParsedPacket> {
    if data.len() < 20 {
        anyhow::bail!("IPv4 packet too short: {} bytes", data.len());
    }

    let ihl = ((data[0] & 0x0F) as usize) * 4;
    if ihl < 20 || data.len() < ihl {
        anyhow::bail!("invalid IPv4 IHL: {}", ihl);
    }

    let total_len = u16::from_be_bytes([data[2], data[3]]) as usize;
    let protocol_num = data[9];
    let protocol = IpProtocol::from_number(protocol_num);

    let src_ip = IpAddr::V4(Ipv4Addr::new(data[12], data[13], data[14], data[15]));
    let dst_ip = IpAddr::V4(Ipv4Addr::new(data[16], data[17], data[18], data[19]));

    let (src_port, dst_port) = if data.len() >= ihl + 4 && matches!(protocol, IpProtocol::Tcp | IpProtocol::Udp) {
        (
            u16::from_be_bytes([data[ihl], data[ihl + 1]]),
            u16::from_be_bytes([data[ihl + 2], data[ihl + 3]]),
        )
    } else {
        (0, 0)
    };

    Ok(ParsedPacket {
        version: 4,
        protocol,
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        payload_offset: ihl,
        total_len,
    })
}

fn parse_ipv6_packet(data: &[u8]) -> Result<ParsedPacket> {
    if data.len() < 40 {
        anyhow::bail!("IPv6 packet too short: {} bytes", data.len());
    }

    let payload_len = u16::from_be_bytes([data[4], data[5]]) as usize;
    let next_header = data[6];
    let protocol = IpProtocol::from_number(next_header);

    let mut src_bytes = [0u8; 16];
    src_bytes.copy_from_slice(&data[8..24]);
    let src_ip = IpAddr::V6(src_bytes.into());

    let mut dst_bytes = [0u8; 16];
    dst_bytes.copy_from_slice(&data[24..40]);
    let dst_ip = IpAddr::V6(dst_bytes.into());

    let l4_offset = 40;
    let (src_port, dst_port) = if data.len() >= l4_offset + 4 && matches!(protocol, IpProtocol::Tcp | IpProtocol::Udp) {
        (
            u16::from_be_bytes([data[l4_offset], data[l4_offset + 1]]),
            u16::from_be_bytes([data[l4_offset + 2], data[l4_offset + 3]]),
        )
    } else {
        (0, 0)
    };

    Ok(ParsedPacket {
        version: 6,
        protocol,
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        payload_offset: l4_offset,
        total_len: 40 + payload_len,
    })
}

/// TCP 流重组器（简化版）
///
/// 追踪 TCP 连接状态，从 IP 包序列中提取应用层数据流。
pub struct TcpReassembler {
    connections: std::collections::HashMap<TcpFlowKey, TcpFlowState>,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct TcpFlowKey {
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
}

impl TcpFlowKey {
    pub fn reverse(&self) -> Self {
        Self {
            src_ip: self.dst_ip,
            dst_ip: self.src_ip,
            src_port: self.dst_port,
            dst_port: self.src_port,
        }
    }
}

#[derive(Debug, Clone)]
pub struct TcpFlowState {
    pub state: TcpState,
    pub seq: u32,
    pub ack: u32,
    pub data_buf: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum TcpState {
    SynSent,
    SynReceived,
    Established,
    FinWait1,
    FinWait2,
    CloseWait,
    Closing,
    LastAck,
    TimeWait,
    Closed,
}

impl TcpReassembler {
    pub fn new() -> Self {
        Self {
            connections: std::collections::HashMap::new(),
        }
    }

    pub fn track_syn(&mut self, key: TcpFlowKey, seq: u32) {
        self.connections.insert(key, TcpFlowState {
            state: TcpState::SynSent,
            seq,
            ack: 0,
            data_buf: Vec::new(),
        });
    }

    pub fn track_synack(&mut self, key: TcpFlowKey, seq: u32, ack: u32) {
        self.connections.insert(key, TcpFlowState {
            state: TcpState::Established,
            seq,
            ack,
            data_buf: Vec::new(),
        });
    }

    pub fn push_data(&mut self, key: &TcpFlowKey, data: &[u8]) -> bool {
        if let Some(flow) = self.connections.get_mut(key) {
            flow.data_buf.extend_from_slice(data);
            true
        } else {
            false
        }
    }

    pub fn take_data(&mut self, key: &TcpFlowKey) -> Option<Vec<u8>> {
        if let Some(flow) = self.connections.get_mut(key) {
            if flow.data_buf.is_empty() {
                return None;
            }
            Some(std::mem::take(&mut flow.data_buf))
        } else {
            None
        }
    }

    pub fn close(&mut self, key: &TcpFlowKey) -> bool {
        self.connections.remove(key).is_some()
    }

    pub fn connection_count(&self) -> usize {
        self.connections.len()
    }

    pub fn get_state(&self, key: &TcpFlowKey) -> Option<TcpState> {
        self.connections.get(key).map(|f| f.state)
    }
}

/// UDP 会话提取器
///
/// 从 TUN 设备捕获的 IP 包中提取 UDP 会话，
/// 管理 NAT 映射关系用于双向数据转发。
pub struct UdpSessionManager {
    sessions: std::collections::HashMap<UdpSessionKey, UdpSessionState>,
    max_sessions: usize,
    idle_timeout_secs: u64,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct UdpSessionKey {
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
}

impl UdpSessionKey {
    pub fn reverse(&self) -> Self {
        Self {
            src_ip: self.dst_ip,
            dst_ip: self.src_ip,
            src_port: self.dst_port,
            dst_port: self.src_port,
        }
    }
}

#[derive(Debug, Clone)]
pub struct UdpSessionState {
    pub created_at: std::time::Instant,
    pub last_active: std::time::Instant,
    pub packets_sent: u64,
    pub packets_recv: u64,
    pub bytes_sent: u64,
    pub bytes_recv: u64,
}

impl UdpSessionManager {
    pub fn new(max_sessions: usize, idle_timeout_secs: u64) -> Self {
        Self {
            sessions: std::collections::HashMap::new(),
            max_sessions,
            idle_timeout_secs,
        }
    }

    /// Track a new or existing UDP session from a parsed packet.
    /// Returns true if this is a new session.
    pub fn track_packet(&mut self, parsed: &ParsedPacket, payload_len: usize) -> bool {
        if parsed.protocol != IpProtocol::Udp {
            return false;
        }

        let key = UdpSessionKey {
            src_ip: parsed.src_ip,
            dst_ip: parsed.dst_ip,
            src_port: parsed.src_port,
            dst_port: parsed.dst_port,
        };

        let now = std::time::Instant::now();
        if let Some(state) = self.sessions.get_mut(&key) {
            state.last_active = now;
            state.packets_sent += 1;
            state.bytes_sent += payload_len as u64;
            false
        } else {
            if self.sessions.len() >= self.max_sessions {
                self.evict_idle();
            }
            self.sessions.insert(key, UdpSessionState {
                created_at: now,
                last_active: now,
                packets_sent: 1,
                packets_recv: 0,
                bytes_sent: payload_len as u64,
                bytes_recv: 0,
            });
            true
        }
    }

    /// Track a reply packet (reverse direction)
    pub fn track_reply(&mut self, key: &UdpSessionKey, payload_len: usize) -> bool {
        if let Some(state) = self.sessions.get_mut(key) {
            state.last_active = std::time::Instant::now();
            state.packets_recv += 1;
            state.bytes_recv += payload_len as u64;
            true
        } else {
            false
        }
    }

    pub fn has_session(&self, key: &UdpSessionKey) -> bool {
        self.sessions.contains_key(key)
    }

    pub fn remove_session(&mut self, key: &UdpSessionKey) -> bool {
        self.sessions.remove(key).is_some()
    }

    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }

    pub fn get_stats(&self, key: &UdpSessionKey) -> Option<&UdpSessionState> {
        self.sessions.get(key)
    }

    /// Evict sessions that have been idle longer than the timeout
    pub fn evict_idle(&mut self) -> usize {
        let timeout = std::time::Duration::from_secs(self.idle_timeout_secs);
        let now = std::time::Instant::now();
        let before = self.sessions.len();
        self.sessions.retain(|_, state| now.duration_since(state.last_active) < timeout);
        before - self.sessions.len()
    }

    pub fn max_sessions(&self) -> usize {
        self.max_sessions
    }
}

/// IP 分片重组器
///
/// 处理被分片的 IP 包，将多个分片重组为完整的原始 IP 包。
/// 基于 (src_ip, dst_ip, identification) 三元组进行分组。
pub struct IpFragmentReassembler {
    fragments: std::collections::HashMap<FragmentKey, FragmentGroup>,
    max_groups: usize,
    timeout_secs: u64,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub struct FragmentKey {
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub identification: u16,
}

#[derive(Debug, Clone)]
pub struct FragmentEntry {
    pub offset: u16,
    pub data: Vec<u8>,
    pub more_fragments: bool,
}

#[derive(Debug)]
pub struct FragmentGroup {
    pub fragments: Vec<FragmentEntry>,
    pub created_at: std::time::Instant,
    pub total_len: Option<usize>,
    pub protocol: u8,
}

impl IpFragmentReassembler {
    pub fn new(max_groups: usize, timeout_secs: u64) -> Self {
        Self {
            fragments: std::collections::HashMap::new(),
            max_groups,
            timeout_secs,
        }
    }

    /// Add a fragment. Returns the reassembled payload if all fragments are present.
    pub fn add_fragment(
        &mut self,
        key: FragmentKey,
        offset: u16,
        data: Vec<u8>,
        more_fragments: bool,
        protocol: u8,
    ) -> Option<Vec<u8>> {
        if self.fragments.len() >= self.max_groups && !self.fragments.contains_key(&key) {
            self.evict_expired();
        }

        let group = self.fragments.entry(key).or_insert_with(|| FragmentGroup {
            fragments: Vec::new(),
            created_at: std::time::Instant::now(),
            total_len: None,
            protocol,
        });

        group.fragments.push(FragmentEntry {
            offset,
            data: data.clone(),
            more_fragments,
        });

        // If this fragment has MF=0, we know the total length
        if !more_fragments {
            let end = offset as usize * 8 + data.len();
            group.total_len = Some(end);
        }

        Self::try_reassemble_static(group)
    }

    fn try_reassemble_static(group: &FragmentGroup) -> Option<Vec<u8>> {
        let total_len = group.total_len?;

        // Sort fragments by offset
        let mut sorted: Vec<_> = group.fragments.iter().collect();
        sorted.sort_by_key(|f| f.offset);

        // Check for complete coverage
        let mut covered = 0usize;
        for frag in &sorted {
            let start = frag.offset as usize * 8;
            if start > covered {
                return None; // Gap
            }
            let end = start + frag.data.len();
            if end > covered {
                covered = end;
            }
        }

        if covered < total_len {
            return None; // Incomplete
        }

        // Reassemble
        let mut result = vec![0u8; total_len];
        for frag in &sorted {
            let start = frag.offset as usize * 8;
            let end = (start + frag.data.len()).min(total_len);
            result[start..end].copy_from_slice(&frag.data[..end - start]);
        }

        Some(result)
    }

    /// Remove a completed or expired group
    pub fn remove_group(&mut self, key: &FragmentKey) -> bool {
        self.fragments.remove(key).is_some()
    }

    /// Evict expired fragment groups
    pub fn evict_expired(&mut self) -> usize {
        let timeout = std::time::Duration::from_secs(self.timeout_secs);
        let now = std::time::Instant::now();
        let before = self.fragments.len();
        self.fragments.retain(|_, group| now.duration_since(group.created_at) < timeout);
        before - self.fragments.len()
    }

    pub fn group_count(&self) -> usize {
        self.fragments.len()
    }

    /// Parse IPv4 fragment fields from a raw packet
    pub fn parse_ipv4_fragment_info(data: &[u8]) -> Option<(FragmentKey, u16, bool, u8)> {
        if data.len() < 20 {
            return None;
        }
        if data[0] >> 4 != 4 {
            return None;
        }

        let identification = u16::from_be_bytes([data[4], data[5]]);
        let flags_offset = u16::from_be_bytes([data[6], data[7]]);
        let more_fragments = (flags_offset & 0x2000) != 0;
        let fragment_offset = flags_offset & 0x1FFF;
        let protocol = data[9];

        let src_ip = IpAddr::V4(Ipv4Addr::new(data[12], data[13], data[14], data[15]));
        let dst_ip = IpAddr::V4(Ipv4Addr::new(data[16], data[17], data[18], data[19]));

        // Only return if this is actually a fragment (MF=1 or offset!=0)
        if !more_fragments && fragment_offset == 0 {
            return None; // Not a fragment
        }

        let key = FragmentKey {
            src_ip,
            dst_ip,
            identification,
        };

        Some((key, fragment_offset, more_fragments, protocol))
    }
}

/// 系统代理自动配置
///
/// 根据平台自动设置/清除系统级代理。
pub struct SystemProxy {
    proxy_host: String,
    proxy_port: u16,
    socks_port: Option<u16>,
    bypass_list: Vec<String>,
}

impl SystemProxy {
    pub fn new(proxy_host: String, proxy_port: u16) -> Self {
        Self {
            proxy_host,
            proxy_port,
            socks_port: None,
            bypass_list: vec![
                "localhost".to_string(),
                "127.0.0.1".to_string(),
                "::1".to_string(),
                "10.*".to_string(),
                "172.16.*".to_string(),
                "192.168.*".to_string(),
            ],
        }
    }

    pub fn with_socks_port(mut self, port: u16) -> Self {
        self.socks_port = Some(port);
        self
    }

    pub fn with_bypass(mut self, bypass: Vec<String>) -> Self {
        self.bypass_list = bypass;
        self
    }

    pub fn proxy_host(&self) -> &str {
        &self.proxy_host
    }

    pub fn proxy_port(&self) -> u16 {
        self.proxy_port
    }

    pub fn socks_port(&self) -> Option<u16> {
        self.socks_port
    }

    pub fn bypass_list(&self) -> &[String] {
        &self.bypass_list
    }

    /// Generate platform-specific commands to enable system proxy
    #[allow(unused_variables)]
    pub fn enable_commands(&self) -> Vec<String> {
        #[allow(unused_mut)]
        let mut cmds = Vec::new();
        let bypass = self.bypass_list.join(";");

        #[cfg(target_os = "windows")]
        {
            cmds.push(format!(
                r#"reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v ProxyEnable /t REG_DWORD /d 1 /f"#
            ));
            cmds.push(format!(
                r#"reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v ProxyServer /t REG_SZ /d "{}:{}" /f"#,
                self.proxy_host, self.proxy_port
            ));
            cmds.push(format!(
                r#"reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v ProxyOverride /t REG_SZ /d "{}" /f"#,
                bypass
            ));
        }

        #[cfg(target_os = "macos")]
        {
            for service in &["Wi-Fi", "Ethernet"] {
                cmds.push(format!(
                    "networksetup -setwebproxy {} {} {}",
                    service, self.proxy_host, self.proxy_port
                ));
                cmds.push(format!(
                    "networksetup -setsecurewebproxy {} {} {}",
                    service, self.proxy_host, self.proxy_port
                ));
                if let Some(socks_port) = self.socks_port {
                    cmds.push(format!(
                        "networksetup -setsocksfirewallproxy {} {} {}",
                        service, self.proxy_host, socks_port
                    ));
                }
                cmds.push(format!(
                    "networksetup -setproxybypassdomains {} {}",
                    service,
                    self.bypass_list.join(" ")
                ));
            }
        }

        #[cfg(target_os = "linux")]
        {
            cmds.push(format!(
                "export http_proxy=http://{}:{}",
                self.proxy_host, self.proxy_port
            ));
            cmds.push(format!(
                "export https_proxy=http://{}:{}",
                self.proxy_host, self.proxy_port
            ));
            cmds.push(format!("export no_proxy={}", bypass));
        }

        cmds
    }

    /// Generate platform-specific commands to disable system proxy
    pub fn disable_commands(&self) -> Vec<String> {
        #[allow(unused_mut)]
        let mut cmds = Vec::new();

        #[cfg(target_os = "windows")]
        {
            cmds.push(format!(
                r#"reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings" /v ProxyEnable /t REG_DWORD /d 0 /f"#
            ));
        }

        #[cfg(target_os = "macos")]
        {
            for service in &["Wi-Fi", "Ethernet"] {
                cmds.push(format!("networksetup -setwebproxystate {} off", service));
                cmds.push(format!("networksetup -setsecurewebproxystate {} off", service));
                cmds.push(format!("networksetup -setsocksfirewallproxystate {} off", service));
            }
        }

        #[cfg(target_os = "linux")]
        {
            cmds.push("unset http_proxy".to_string());
            cmds.push("unset https_proxy".to_string());
            cmds.push("unset no_proxy".to_string());
        }

        cmds
    }
}

/// DNS 劫持配置
///
/// 拦截目标端口 53 的 DNS 查询，将其重定向到内置 DNS 解析器。
pub struct DnsHijack {
    enabled: bool,
    listen_port: u16,
    upstream_servers: Vec<String>,
    hijack_domains: Vec<String>,
}

impl DnsHijack {
    pub fn new(enabled: bool) -> Self {
        Self {
            enabled,
            listen_port: 53,
            upstream_servers: vec!["8.8.8.8".to_string(), "1.1.1.1".to_string()],
            hijack_domains: Vec::new(),
        }
    }

    pub fn with_upstream(mut self, servers: Vec<String>) -> Self {
        self.upstream_servers = servers;
        self
    }

    pub fn with_domains(mut self, domains: Vec<String>) -> Self {
        self.hijack_domains = domains;
        self
    }

    pub fn enabled(&self) -> bool {
        self.enabled
    }

    pub fn listen_port(&self) -> u16 {
        self.listen_port
    }

    pub fn upstream_servers(&self) -> &[String] {
        &self.upstream_servers
    }

    /// Check if a packet to port 53 should be hijacked
    pub fn should_hijack(&self, parsed: &ParsedPacket) -> bool {
        if !self.enabled {
            return false;
        }
        parsed.protocol == IpProtocol::Udp && parsed.dst_port == self.listen_port
    }

    /// Generate iptables/nftables rules to redirect DNS (Linux)
    pub fn generate_redirect_rules(&self, tun_name: &str) -> Vec<String> {
        #[allow(unused_mut)]
        let mut rules = Vec::new();
        #[cfg(target_os = "linux")]
        {
            rules.push(format!(
                "iptables -t nat -A PREROUTING -i {} -p udp --dport 53 -j REDIRECT --to-port {}",
                tun_name, self.listen_port
            ));
            rules.push(format!(
                "iptables -t nat -A OUTPUT -p udp --dport 53 -j REDIRECT --to-port {}",
                self.listen_port
            ));
        }
        #[cfg(target_os = "windows")]
        {
            let _ = tun_name;
        }
        #[cfg(target_os = "macos")]
        {
            rules.push(format!(
                "echo 'rdr pass on {} proto udp from any to any port 53 -> 127.0.0.1 port {}' | pfctl -a openworld -f -",
                tun_name, self.listen_port
            ));
        }
        rules
    }
}

/// ICMP 处理策略
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum IcmpPolicy {
    /// 透传 ICMP 包到出站
    Passthrough,
    /// 静默丢弃 ICMP 包
    Drop,
}

impl IcmpPolicy {
    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "passthrough" | "pass" => Self::Passthrough,
            "drop" | "reject" => Self::Drop,
            _ => Self::Drop,
        }
    }

    /// 根据策略判断 ICMP 包是否应被处理
    pub fn should_process(&self, parsed: &ParsedPacket) -> bool {
        if parsed.protocol != IpProtocol::Icmp {
            return true; // 非 ICMP 包总是处理
        }
        matches!(self, Self::Passthrough)
    }
}

/// ICMP 包类型识别
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum IcmpType {
    EchoRequest,
    EchoReply,
    DestinationUnreachable,
    TimeExceeded,
    Other(u8),
}

impl IcmpType {
    /// 从 ICMP type 字节解析
    pub fn from_v4(type_byte: u8) -> Self {
        match type_byte {
            0 => Self::EchoReply,
            3 => Self::DestinationUnreachable,
            8 => Self::EchoRequest,
            11 => Self::TimeExceeded,
            other => Self::Other(other),
        }
    }

    /// 从 ICMPv6 type 字节解析
    pub fn from_v6(type_byte: u8) -> Self {
        match type_byte {
            1 => Self::DestinationUnreachable,
            3 => Self::TimeExceeded,
            128 => Self::EchoRequest,
            129 => Self::EchoReply,
            other => Self::Other(other),
        }
    }
}

/// 解析 ICMP 包类型
pub fn parse_icmp_type(parsed: &ParsedPacket, data: &[u8]) -> Option<IcmpType> {
    if parsed.protocol != IpProtocol::Icmp {
        return None;
    }
    if data.len() <= parsed.payload_offset {
        return None;
    }
    let type_byte = data[parsed.payload_offset];
    Some(match parsed.version {
        4 => IcmpType::from_v4(type_byte),
        6 => IcmpType::from_v6(type_byte),
        _ => IcmpType::Other(type_byte),
    })
}

/// Windows wintun 驱动适配器配置
///
/// 代表通过 wintun.dll 创建的 TUN 适配器。
/// 使用 ring buffer 进行高性能 IP 包读写。
#[cfg(target_os = "windows")]
pub struct WintunDevice {
    name: String,
    mtu: AtomicU16,
    ring_capacity: u32,
    guid: Option<String>,
    runtime: Mutex<Option<WintunRuntime>>,
}

#[cfg(target_os = "windows")]
impl WintunDevice {
    pub fn new(config: &TunConfig) -> Result<Self> {
        Ok(Self {
            name: config.name.clone(),
            mtu: AtomicU16::new(config.mtu),
            ring_capacity: 0x400000, // 4MB default ring buffer
            guid: None,
            runtime: Mutex::new(None),
        })
    }

    pub fn with_guid(mut self, guid: String) -> Self {
        self.guid = Some(guid);
        self
    }

    pub fn with_ring_capacity(mut self, capacity: u32) -> Self {
        self.ring_capacity = capacity;
        self
    }

    pub fn ring_capacity(&self) -> u32 {
        self.ring_capacity
    }

    pub fn guid(&self) -> Option<&str> {
        self.guid.as_deref()
    }

    /// 生成创建 wintun 适配器所需的参数
    pub fn adapter_params(&self) -> WintunAdapterParams {
        WintunAdapterParams {
            name: self.name.clone(),
            tunnel_type: "OpenWorld".to_string(),
            guid: self.guid.clone(),
            ring_capacity: self.ring_capacity,
            mtu: self.mtu(),
        }
    }

    fn load_library() -> Result<WintunApi> {
        let library_name = to_utf16_null("wintun.dll");
        let module = unsafe { LoadLibraryW(library_name.as_ptr()) };
        if module.is_null() {
            let err = std::io::Error::last_os_error();
            anyhow::bail!("failed to load wintun.dll: {}", err);
        }

        let create_adapter = unsafe {
            load_proc::<WintunCreateAdapterFn>(module, b"WintunCreateAdapter\0")
                .context("failed to resolve WintunCreateAdapter")?
        };
        let close_adapter = unsafe {
            load_proc::<WintunCloseAdapterFn>(module, b"WintunCloseAdapter\0")
                .context("failed to resolve WintunCloseAdapter")?
        };
        let start_session = unsafe {
            load_proc::<WintunStartSessionFn>(module, b"WintunStartSession\0")
                .context("failed to resolve WintunStartSession")?
        };
        let end_session = unsafe {
            load_proc::<WintunEndSessionFn>(module, b"WintunEndSession\0")
                .context("failed to resolve WintunEndSession")?
        };
        let allocate_send_packet = unsafe {
            load_proc::<WintunAllocateSendPacketFn>(module, b"WintunAllocateSendPacket\0")
                .context("failed to resolve WintunAllocateSendPacket")?
        };
        let send_packet = unsafe {
            load_proc::<WintunSendPacketFn>(module, b"WintunSendPacket\0")
                .context("failed to resolve WintunSendPacket")?
        };
        let receive_packet = unsafe {
            load_proc::<WintunReceivePacketFn>(module, b"WintunReceivePacket\0")
                .context("failed to resolve WintunReceivePacket")?
        };
        let release_receive_packet = unsafe {
            load_proc::<WintunReleaseReceivePacketFn>(
                module,
                b"WintunReleaseReceivePacket\0",
            )
            .context("failed to resolve WintunReleaseReceivePacket")?
        };

        Ok(WintunApi {
            module,
            create_adapter,
            close_adapter,
            start_session,
            end_session,
            allocate_send_packet,
            send_packet,
            receive_packet,
            release_receive_packet,
        })
    }

    fn create_adapter(
        api: &WintunApi,
        name: &str,
        tunnel_type: &str,
        guid: Option<&str>,
    ) -> Result<WintunAdapterHandle> {
        let name_w = to_utf16_null(name);
        let tunnel_type_w = to_utf16_null(tunnel_type);
        let parsed_guid = if let Some(raw_guid) = guid {
            Some(parse_guid(raw_guid).context("invalid GUID format")?)
        } else {
            None
        };

        let guid_ptr = parsed_guid
            .as_ref()
            .map_or(std::ptr::null(), |value| value as *const Guid);

        let adapter = unsafe {
            (api.create_adapter)(
                name_w.as_ptr(),
                tunnel_type_w.as_ptr(),
                if parsed_guid.is_some() {
                    guid_ptr
                } else {
                    std::ptr::null()
                },
            )
        };

        if adapter.is_null() {
            let err = std::io::Error::last_os_error();
            anyhow::bail!("WintunCreateAdapter failed: {}", err);
        }

        Ok(adapter)
    }

    fn start_session(
        api: &WintunApi,
        adapter: WintunAdapterHandle,
        capacity: u32,
    ) -> Result<WintunSessionHandle> {
        let session = unsafe { (api.start_session)(adapter, capacity) };
        if session.is_null() {
            let err = std::io::Error::last_os_error();
            anyhow::bail!("WintunStartSession failed: {}", err);
        }
        Ok(session)
    }

    fn ensure_runtime_locked(
        &self,
        guard: &mut std::sync::MutexGuard<'_, Option<WintunRuntime>>,
    ) -> Result<()> {
        if guard.is_some() {
            return Ok(());
        }

        let api = Self::load_library()?;
        let adapter = Self::create_adapter(&api, &self.name, "OpenWorld", self.guid.as_deref())
            .with_context(|| format!("failed to create wintun adapter '{}'", self.name))?;
        let session = Self::start_session(&api, adapter, self.ring_capacity)?;

        **guard = Some(WintunRuntime {
            api,
            adapter,
            session,
        });
        Ok(())
    }

    fn close_locked(runtime_guard: &mut std::sync::MutexGuard<'_, Option<WintunRuntime>>) {
        if let Some(runtime) = runtime_guard.take() {
            unsafe {
                (runtime.api.end_session)(runtime.session);
                (runtime.api.close_adapter)(runtime.adapter);
                FreeLibrary(runtime.api.module);
            }
        }
    }
}

#[cfg(target_os = "windows")]
#[async_trait]
impl TunDevice for WintunDevice {
    fn name(&self) -> &str {
        &self.name
    }

    async fn read_packet(&self, buf: &mut [u8]) -> Result<usize> {
        if buf.is_empty() {
            anyhow::bail!("tun read buffer is empty");
        }

        loop {
            let result = {
                let mut runtime_guard = self
                    .runtime
                    .lock()
                    .map_err(|_| anyhow::anyhow!("wintun runtime mutex poisoned"))?;
                self.ensure_runtime_locked(&mut runtime_guard)?;

                let runtime = runtime_guard
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("wintun runtime is not initialized"))?;

                let mut packet_len = 0u32;
                let packet_ptr = unsafe { (runtime.api.receive_packet)(runtime.session, &mut packet_len) };
                if packet_ptr.is_null() {
                    let err = std::io::Error::last_os_error();
                    if err.raw_os_error() == Some(ERROR_NO_MORE_ITEMS) {
                        Ok(None)
                    } else {
                        Err(anyhow::anyhow!("WintunReceivePacket failed: {}", err))
                    }
                } else {
                    let packet_len = packet_len as usize;
                    if packet_len > buf.len() {
                        unsafe {
                            (runtime.api.release_receive_packet)(runtime.session, packet_ptr);
                        }
                        Err(anyhow::anyhow!(
                            "received packet too large: {} > {}",
                            packet_len,
                            buf.len()
                        ))
                    } else {
                        unsafe {
                            std::ptr::copy_nonoverlapping(packet_ptr, buf.as_mut_ptr(), packet_len);
                            (runtime.api.release_receive_packet)(runtime.session, packet_ptr);
                        }
                        Ok(Some(packet_len))
                    }
                }
            };

            match result {
                Ok(Some(len)) => return Ok(len),
                Ok(None) => {
                    sleep(Duration::from_millis(5)).await;
                    continue;
                }
                Err(e) => return Err(e),
            }
        }
    }

    async fn write_packet(&self, buf: &[u8]) -> Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }

        loop {
            let result = {
                let mut runtime_guard = self
                    .runtime
                    .lock()
                    .map_err(|_| anyhow::anyhow!("wintun runtime mutex poisoned"))?;
                self.ensure_runtime_locked(&mut runtime_guard)?;

                let runtime = runtime_guard
                    .as_ref()
                    .ok_or_else(|| anyhow::anyhow!("wintun runtime is not initialized"))?;
                let packet_ptr =
                    unsafe { (runtime.api.allocate_send_packet)(runtime.session, buf.len() as u32) };

                if packet_ptr.is_null() {
                    let err = std::io::Error::last_os_error();
                    if err.raw_os_error() == Some(ERROR_BUFFER_OVERFLOW) {
                        Ok(None)
                    } else {
                        Err(anyhow::anyhow!("WintunAllocateSendPacket failed: {}", err))
                    }
                } else {
                    unsafe {
                        std::ptr::copy_nonoverlapping(buf.as_ptr(), packet_ptr, buf.len());
                        (runtime.api.send_packet)(runtime.session, packet_ptr);
                    }
                    Ok(Some(buf.len()))
                }
            };

            match result {
                Ok(Some(len)) => return Ok(len),
                Ok(None) => {
                    sleep(Duration::from_millis(2)).await;
                    continue;
                }
                Err(e) => return Err(e),
            }
        }
    }

    fn set_mtu(&self, mtu: u16) -> Result<()> {
        self.mtu.store(mtu, Ordering::Relaxed);
        Ok(())
    }

    fn mtu(&self) -> u16 {
        self.mtu.load(Ordering::Relaxed)
    }

    async fn close(&self) -> Result<()> {
        let mut runtime_guard = self
            .runtime
            .lock()
            .map_err(|_| anyhow::anyhow!("wintun runtime mutex poisoned"))?;
        Self::close_locked(&mut runtime_guard);
        Ok(())
    }
}

/// Wintun 适配器创建参数
#[cfg(target_os = "windows")]
#[derive(Debug, Clone)]
pub struct WintunAdapterParams {
    pub name: String,
    pub tunnel_type: String,
    pub guid: Option<String>,
    pub ring_capacity: u32,
    pub mtu: u16,
}

#[cfg(target_os = "windows")]
type HModule = *mut std::ffi::c_void;

#[cfg(target_os = "windows")]
type WintunAdapterHandle = *mut std::ffi::c_void;

#[cfg(target_os = "windows")]
type WintunSessionHandle = *mut std::ffi::c_void;

#[cfg(target_os = "windows")]
const ERROR_NO_MORE_ITEMS: i32 = 259;

#[cfg(target_os = "windows")]
const ERROR_BUFFER_OVERFLOW: i32 = 111;

#[cfg(target_os = "windows")]
#[repr(C)]
#[derive(Clone, Copy)]
struct Guid {
    data1: u32,
    data2: u16,
    data3: u16,
    data4: [u8; 8],
}

#[cfg(target_os = "windows")]
type WintunCreateAdapterFn =
    unsafe extern "system" fn(*const u16, *const u16, *const Guid) -> WintunAdapterHandle;

#[cfg(target_os = "windows")]
type WintunCloseAdapterFn = unsafe extern "system" fn(WintunAdapterHandle);

#[cfg(target_os = "windows")]
type WintunStartSessionFn =
    unsafe extern "system" fn(WintunAdapterHandle, u32) -> WintunSessionHandle;

#[cfg(target_os = "windows")]
type WintunEndSessionFn = unsafe extern "system" fn(WintunSessionHandle);

#[cfg(target_os = "windows")]
type WintunAllocateSendPacketFn =
    unsafe extern "system" fn(WintunSessionHandle, u32) -> *mut u8;

#[cfg(target_os = "windows")]
type WintunSendPacketFn = unsafe extern "system" fn(WintunSessionHandle, *const u8);

#[cfg(target_os = "windows")]
type WintunReceivePacketFn =
    unsafe extern "system" fn(WintunSessionHandle, *mut u32) -> *mut u8;

#[cfg(target_os = "windows")]
type WintunReleaseReceivePacketFn = unsafe extern "system" fn(WintunSessionHandle, *const u8);

#[cfg(target_os = "windows")]
#[derive(Clone, Copy)]
struct WintunApi {
    module: HModule,
    create_adapter: WintunCreateAdapterFn,
    close_adapter: WintunCloseAdapterFn,
    start_session: WintunStartSessionFn,
    end_session: WintunEndSessionFn,
    allocate_send_packet: WintunAllocateSendPacketFn,
    send_packet: WintunSendPacketFn,
    receive_packet: WintunReceivePacketFn,
    release_receive_packet: WintunReleaseReceivePacketFn,
}

#[cfg(target_os = "windows")]
struct WintunRuntime {
    api: WintunApi,
    adapter: WintunAdapterHandle,
    session: WintunSessionHandle,
}

// SAFETY: WintunRuntime contains raw pointers from wintun.dll FFI handles.
// These handles are thread-safe as per wintun API documentation —
// the session handle can be used from multiple threads concurrently.
#[cfg(target_os = "windows")]
unsafe impl Send for WintunRuntime {}
#[cfg(target_os = "windows")]
unsafe impl Sync for WintunRuntime {}
#[cfg(target_os = "windows")]
unsafe impl Send for WintunDevice {}
#[cfg(target_os = "windows")]
unsafe impl Sync for WintunDevice {}

#[cfg(target_os = "windows")]
fn to_utf16_null(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

#[cfg(target_os = "windows")]
fn parse_guid(value: &str) -> Result<Guid> {
    let normalized = value.trim().trim_start_matches('{').trim_end_matches('}');
    let sections: Vec<&str> = normalized.split('-').collect();
    if sections.len() != 5 {
        anyhow::bail!("GUID must have 5 sections");
    }
    if sections[0].len() != 8
        || sections[1].len() != 4
        || sections[2].len() != 4
        || sections[3].len() != 4
        || sections[4].len() != 12
    {
        anyhow::bail!("GUID section length is invalid");
    }

    let data1 = u32::from_str_radix(sections[0], 16).context("invalid GUID data1")?;
    let data2 = u16::from_str_radix(sections[1], 16).context("invalid GUID data2")?;
    let data3 = u16::from_str_radix(sections[2], 16).context("invalid GUID data3")?;

    let mut data4 = [0u8; 8];
    data4[0] = u8::from_str_radix(&sections[3][0..2], 16).context("invalid GUID data4[0]")?;
    data4[1] = u8::from_str_radix(&sections[3][2..4], 16).context("invalid GUID data4[1]")?;
    for idx in 0..6 {
        let start = idx * 2;
        let end = start + 2;
        data4[idx + 2] = u8::from_str_radix(&sections[4][start..end], 16)
            .with_context(|| format!("invalid GUID data4[{}]", idx + 2))?;
    }

    Ok(Guid {
        data1,
        data2,
        data3,
        data4,
    })
}

#[cfg(target_os = "windows")]
unsafe fn load_proc<T: Copy>(module: HModule, name: &[u8]) -> Result<T> {
    let proc = GetProcAddress(module, name.as_ptr());
    if proc.is_null() {
        let err = std::io::Error::last_os_error();
        anyhow::bail!(
            "GetProcAddress({}) failed: {}",
            String::from_utf8_lossy(&name[..name.len().saturating_sub(1)]),
            err
        );
    }
    Ok(std::mem::transmute_copy(&proc))
}

#[cfg(target_os = "windows")]
extern "system" {
    fn LoadLibraryW(lp_lib_file_name: *const u16) -> HModule;
    fn GetProcAddress(h_module: HModule, lp_proc_name: *const u8) -> *mut std::ffi::c_void;
    fn FreeLibrary(h_lib_module: HModule) -> i32;
}

/// Linux TUN 设备配置
///
/// 通过 ioctl(TUNSETIFF) 创建 tun 设备，
/// 设置 IFF_TUN | IFF_NO_PI 标志。
#[cfg(target_os = "linux")]
pub struct LinuxTunDevice {
    name: String,
    mtu: AtomicU16,
    flags: LinuxTunFlags,
    address: Ipv4Addr,
    netmask: Ipv4Addr,
    fd: Mutex<Option<i32>>,
}

/// Linux TUN 设备标志
#[cfg(target_os = "linux")]
#[derive(Debug, Clone, Copy)]
pub struct LinuxTunFlags {
    pub tun: bool,
    pub no_pi: bool,
    pub multi_queue: bool,
}

#[cfg(target_os = "linux")]
impl Default for LinuxTunFlags {
    fn default() -> Self {
        Self {
            tun: true,
            no_pi: true,
            multi_queue: false,
        }
    }
}

#[cfg(target_os = "linux")]
impl LinuxTunFlags {
    /// IFF_TUN 常量
    pub const IFF_TUN: u16 = 0x0001;
    /// IFF_NO_PI 常量
    pub const IFF_NO_PI: u16 = 0x1000;
    /// IFF_MULTI_QUEUE 常量
    pub const IFF_MULTI_QUEUE: u16 = 0x0100;
    /// TUNSETIFF ioctl 编号
    pub const TUNSETIFF: u64 = 0x400454CA;

    /// 计算 ioctl flags 值
    pub fn to_bits(&self) -> u16 {
        let mut bits = 0u16;
        if self.tun {
            bits |= Self::IFF_TUN;
        }
        if self.no_pi {
            bits |= Self::IFF_NO_PI;
        }
        if self.multi_queue {
            bits |= Self::IFF_MULTI_QUEUE;
        }
        bits
    }
}

#[cfg(target_os = "linux")]
impl LinuxTunDevice {
    pub fn new(config: &TunConfig) -> Result<Self> {
        Ok(Self {
            name: config.name.clone(),
            mtu: AtomicU16::new(config.mtu),
            flags: LinuxTunFlags::default(),
            address: config.address,
            netmask: config.netmask,
            fd: Mutex::new(None),
        })
    }

    pub fn with_flags(mut self, flags: LinuxTunFlags) -> Self {
        self.flags = flags;
        self
    }

    pub fn flags(&self) -> &LinuxTunFlags {
        &self.flags
    }

    /// 生成创建 tun 设备的 ioctl 参数
    pub fn ioctl_params(&self) -> LinuxTunIoctlParams {
        LinuxTunIoctlParams {
            name: self.name.clone(),
            flags: self.flags.to_bits(),
            mtu: self.mtu(),
        }
    }

    /// 生成配置 tun 设备地址的 ip 命令
    pub fn ip_config_commands(&self, address: &str, netmask_prefix: u8) -> Vec<String> {
        vec![
            format!("ip link set {} up", self.name),
            format!("ip addr add {}/{} dev {}", address, netmask_prefix, self.name),
            format!("ip link set {} mtu {}", self.name, self.mtu()),
        ]
    }

    fn ensure_fd(&self) -> Result<i32> {
        let mut fd_guard = self
            .fd
            .lock()
            .map_err(|_| anyhow::anyhow!("linux tun fd mutex poisoned"))?;

        if let Some(fd) = *fd_guard {
            return Ok(fd);
        }

        let fd = Self::open_tun_device(&self.name, self.flags.to_bits())?;
        if let Err(e) = self.configure_interface() {
            unsafe {
                close(fd);
            }
            return Err(e);
        }

        *fd_guard = Some(fd);
        Ok(fd)
    }

    fn open_tun_device(name: &str, flags: u16) -> Result<i32> {
        let fd = unsafe { open(TUN_DEVICE_PATH.as_ptr().cast(), O_RDWR | O_NONBLOCK, 0) };
        if fd < 0 {
            let err = std::io::Error::last_os_error();
            anyhow::bail!("open(/dev/net/tun) failed: {}", err);
        }

        if name.as_bytes().len() >= IFNAMSIZ {
            unsafe {
                close(fd);
            }
            anyhow::bail!("tun interface name too long: {}", name);
        }

        let mut ifr = IfReq {
            ifr_name: [0u8; IFNAMSIZ],
            ifr_flags: flags as i16,
            ifr_ifru: [0u8; 24 - std::mem::size_of::<i16>()],
        };
        ifr.ifr_name[..name.len()].copy_from_slice(name.as_bytes());

        let ret = unsafe { ioctl(fd, LinuxTunFlags::TUNSETIFF as usize, &mut ifr) };
        if ret < 0 {
            let err = std::io::Error::last_os_error();
            unsafe {
                close(fd);
            }
            anyhow::bail!("ioctl(TUNSETIFF) failed: {}", err);
        }

        Ok(fd)
    }

    fn configure_interface(&self) -> Result<()> {
        let prefix = Self::netmask_prefix(self.netmask);
        let address = format!("{}/{}", self.address, prefix);
        let mtu_text = self.mtu().to_string();

        Self::run_ip_command(&["addr", "replace", &address, "dev", &self.name])?;
        Self::run_ip_command(&["link", "set", "dev", &self.name, "up"])?;
        Self::run_ip_command(&["link", "set", "dev", &self.name, "mtu", &mtu_text])?;

        Ok(())
    }

    fn run_ip_command(args: &[&str]) -> Result<()> {
        let status = Command::new("ip")
            .args(args)
            .status()
            .with_context(|| format!("failed to execute ip command: ip {}", args.join(" ")))?;

        if !status.success() {
            anyhow::bail!(
                "ip command failed (status={}): ip {}",
                status,
                args.join(" ")
            );
        }
        Ok(())
    }

    fn netmask_prefix(netmask: Ipv4Addr) -> u8 {
        netmask
            .octets()
            .iter()
            .map(|octet| octet.count_ones() as u8)
            .sum()
    }
}

#[cfg(target_os = "linux")]
#[async_trait]
impl TunDevice for LinuxTunDevice {
    fn name(&self) -> &str {
        &self.name
    }

    async fn read_packet(&self, buf: &mut [u8]) -> Result<usize> {
        if buf.is_empty() {
            anyhow::bail!("tun read buffer is empty");
        }

        loop {
            let fd = self.ensure_fd()?;
            let n = unsafe { read(fd, buf.as_mut_ptr().cast::<c_void>(), buf.len()) };
            if n > 0 {
                return Ok(n as usize);
            }
            if n == 0 {
                sleep(Duration::from_millis(2)).await;
                continue;
            }

            let err = std::io::Error::last_os_error();
            match err.raw_os_error() {
                Some(EAGAIN) | Some(EWOULDBLOCK) => {
                    sleep(Duration::from_millis(2)).await;
                }
                _ => anyhow::bail!("read(tun) failed: {}", err),
            }
        }
    }

    async fn write_packet(&self, buf: &[u8]) -> Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }

        let mut written = 0usize;
        while written < buf.len() {
            let fd = self.ensure_fd()?;
            let n = unsafe {
                write(
                    fd,
                    buf[written..].as_ptr().cast::<c_void>(),
                    buf.len() - written,
                )
            };

            if n > 0 {
                written += n as usize;
                continue;
            }
            if n == 0 {
                sleep(Duration::from_millis(2)).await;
                continue;
            }

            let err = std::io::Error::last_os_error();
            match err.raw_os_error() {
                Some(EAGAIN) | Some(EWOULDBLOCK) => {
                    sleep(Duration::from_millis(2)).await;
                }
                _ => anyhow::bail!("write(tun) failed: {}", err),
            }
        }

        Ok(written)
    }

    fn set_mtu(&self, mtu: u16) -> Result<()> {
        self.mtu.store(mtu, Ordering::Relaxed);

        let fd_opened = self
            .fd
            .lock()
            .map_err(|_| anyhow::anyhow!("linux tun fd mutex poisoned"))?
            .is_some();
        if fd_opened {
            let mtu_text = mtu.to_string();
            Self::run_ip_command(&["link", "set", "dev", &self.name, "mtu", &mtu_text])?;
        }
        Ok(())
    }

    fn mtu(&self) -> u16 {
        self.mtu.load(Ordering::Relaxed)
    }

    async fn close(&self) -> Result<()> {
        let mut fd_guard = self
            .fd
            .lock()
            .map_err(|_| anyhow::anyhow!("linux tun fd mutex poisoned"))?;
        if let Some(fd) = fd_guard.take() {
            let ret = unsafe { close(fd) };
            if ret < 0 {
                let err = std::io::Error::last_os_error();
                anyhow::bail!("close(tun) failed: {}", err);
            }
        }
        Ok(())
    }
}

/// Linux TUN ioctl 参数
#[cfg(target_os = "linux")]
#[derive(Debug, Clone)]
pub struct LinuxTunIoctlParams {
    pub name: String,
    pub flags: u16,
    pub mtu: u16,
}

#[cfg(target_os = "linux")]
const TUN_DEVICE_PATH: &[u8] = b"/dev/net/tun\0";

#[cfg(target_os = "linux")]
const IFNAMSIZ: usize = 16;

#[cfg(target_os = "linux")]
const O_RDWR: i32 = 0x0002;

#[cfg(target_os = "linux")]
const O_NONBLOCK: i32 = 0x0800;

#[cfg(target_os = "linux")]
const EAGAIN: i32 = 11;

#[cfg(target_os = "linux")]
const EWOULDBLOCK: i32 = 11;

#[cfg(target_os = "linux")]
#[repr(C)]
struct IfReq {
    ifr_name: [u8; IFNAMSIZ],
    ifr_flags: i16,
    ifr_ifru: [u8; 24 - std::mem::size_of::<i16>()],
}

#[cfg(target_os = "linux")]
extern "C" {
    fn open(pathname: *const i8, flags: i32, mode: u32) -> i32;
    fn ioctl(fd: i32, request: usize, ...) -> i32;
    fn read(fd: i32, buf: *mut c_void, count: usize) -> isize;
    fn write(fd: i32, buf: *const c_void, count: usize) -> isize;
    fn close(fd: i32) -> i32;
}

pub fn create_platform_tun_device(config: &TunConfig) -> Result<Box<dyn TunDevice>> {
    #[cfg(target_os = "windows")]
    {
        return Ok(Box::new(WintunDevice::new(config)?));
    }

    #[cfg(target_os = "linux")]
    {
        return Ok(Box::new(LinuxTunDevice::new(config)?));
    }

    #[allow(unreachable_code)]
    {
        let _ = config;
        anyhow::bail!("tun inbound is unsupported on this platform");
    }
}

/// 路由表操作抽象
pub struct RouteManager {
    original_routes: Vec<RouteEntry>,
}

#[derive(Debug, Clone)]
pub struct RouteEntry {
    pub destination: String,
    pub gateway: String,
    pub interface: String,
}

impl RouteManager {
    pub fn new() -> Self {
        Self {
            original_routes: Vec::new(),
        }
    }

    /// 添加排除路由（代理服务器 IP 直连）
    pub fn add_exclude_route(&mut self, dest: &str, gateway: &str, iface: &str) {
        self.original_routes.push(RouteEntry {
            destination: dest.to_string(),
            gateway: gateway.to_string(),
            interface: iface.to_string(),
        });
    }

    pub fn exclude_count(&self) -> usize {
        self.original_routes.len()
    }

    /// 生成平台特定的路由命令（仅生成命令字符串，不执行）
    pub fn generate_add_commands(&self, tun_name: &str) -> Vec<String> {
        let mut cmds = Vec::new();
        #[cfg(target_os = "windows")]
        {
            cmds.push(format!("route add 0.0.0.0 mask 0.0.0.0 198.18.0.1 metric 1 if {}", tun_name));
        }
        #[cfg(target_os = "linux")]
        {
            cmds.push(format!("ip route add default dev {} table 100", tun_name));
            cmds.push(format!("ip rule add fwmark 1 table 100"));
        }
        #[cfg(target_os = "macos")]
        {
            cmds.push(format!("route add -net 0.0.0.0/1 -interface {}", tun_name));
            cmds.push(format!("route add -net 128.0.0.0/1 -interface {}", tun_name));
        }
        // 添加排除路由
        for route in &self.original_routes {
            #[cfg(target_os = "windows")]
            cmds.push(format!("route add {} mask 255.255.255.255 {}", route.destination, route.gateway));
            #[cfg(target_os = "linux")]
            cmds.push(format!("ip route add {} via {} dev {}", route.destination, route.gateway, route.interface));
            #[cfg(target_os = "macos")]
            cmds.push(format!("route add -host {} {}", route.destination, route.gateway));
        }
        cmds
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn build_ipv4_tcp(src: [u8; 4], dst: [u8; 4], src_port: u16, dst_port: u16) -> Vec<u8> {
        let mut pkt = vec![0u8; 40];
        pkt[0] = 0x45; // version=4, IHL=5
        pkt[2] = 0; pkt[3] = 40; // total length = 40
        pkt[9] = 6; // TCP
        pkt[12..16].copy_from_slice(&src);
        pkt[16..20].copy_from_slice(&dst);
        pkt[20..22].copy_from_slice(&src_port.to_be_bytes());
        pkt[22..24].copy_from_slice(&dst_port.to_be_bytes());
        pkt
    }

    fn build_ipv6_udp(src: [u8; 16], dst: [u8; 16], src_port: u16, dst_port: u16) -> Vec<u8> {
        let mut pkt = vec![0u8; 48];
        pkt[0] = 0x60; // version=6
        pkt[4] = 0; pkt[5] = 8; // payload length = 8
        pkt[6] = 17; // UDP
        pkt[8..24].copy_from_slice(&src);
        pkt[24..40].copy_from_slice(&dst);
        pkt[40..42].copy_from_slice(&src_port.to_be_bytes());
        pkt[42..44].copy_from_slice(&dst_port.to_be_bytes());
        pkt
    }

    #[test]
    fn parse_ipv4_tcp_packet() {
        let pkt = build_ipv4_tcp([10, 0, 0, 1], [1, 1, 1, 1], 50000, 443);
        let parsed = parse_ip_packet(&pkt).unwrap();
        assert_eq!(parsed.version, 4);
        assert_eq!(parsed.protocol, IpProtocol::Tcp);
        assert_eq!(parsed.src_ip, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
        assert_eq!(parsed.dst_ip, IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)));
        assert_eq!(parsed.src_port, 50000);
        assert_eq!(parsed.dst_port, 443);
    }

    #[test]
    fn parse_ipv6_udp_packet() {
        let src = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let dst = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
        let pkt = build_ipv6_udp(src, dst, 53000, 53);
        let parsed = parse_ip_packet(&pkt).unwrap();
        assert_eq!(parsed.version, 6);
        assert_eq!(parsed.protocol, IpProtocol::Udp);
        assert_eq!(parsed.src_port, 53000);
        assert_eq!(parsed.dst_port, 53);
    }

    #[test]
    fn parse_empty_packet_fails() {
        assert!(parse_ip_packet(&[]).is_err());
    }

    #[test]
    fn parse_too_short_ipv4_fails() {
        assert!(parse_ip_packet(&[0x45, 0, 0]).is_err());
    }

    #[test]
    fn parse_unsupported_version() {
        let mut data = [0u8; 20];
        data[0] = 0x30; // version = 3
        assert!(parse_ip_packet(&data).is_err());
    }

    #[test]
    fn parse_icmp_protocol() {
        let mut pkt = build_ipv4_tcp([10, 0, 0, 1], [10, 0, 0, 2], 0, 0);
        pkt[9] = 1; // ICMP
        let parsed = parse_ip_packet(&pkt).unwrap();
        assert_eq!(parsed.protocol, IpProtocol::Icmp);
        assert_eq!(parsed.src_port, 0);
        assert_eq!(parsed.dst_port, 0);
    }

    #[test]
    fn ip_protocol_from_number() {
        assert_eq!(IpProtocol::from_number(6), IpProtocol::Tcp);
        assert_eq!(IpProtocol::from_number(17), IpProtocol::Udp);
        assert_eq!(IpProtocol::from_number(1), IpProtocol::Icmp);
        assert_eq!(IpProtocol::from_number(58), IpProtocol::Icmp);
        assert_eq!(IpProtocol::from_number(47), IpProtocol::Other(47));
    }

    #[test]
    fn tun_config_defaults() {
        let cfg = TunConfig::default();
        assert_eq!(cfg.mtu, 1500);
        assert_eq!(cfg.address, Ipv4Addr::new(198, 18, 0, 1));
        assert!(cfg.dns_hijack);
        assert!(cfg.auto_route);
        assert_eq!(cfg.stack, TunStack::GVisor);
    }

    #[test]
    fn tcp_reassembler_basic() {
        let mut reassembler = TcpReassembler::new();
        let key = TcpFlowKey {
            src_ip: "10.0.0.1".parse().unwrap(),
            dst_ip: "1.1.1.1".parse().unwrap(),
            src_port: 50000,
            dst_port: 443,
        };

        reassembler.track_syn(key.clone(), 1000);
        assert_eq!(reassembler.connection_count(), 1);
        assert_eq!(reassembler.get_state(&key), Some(TcpState::SynSent));

        reassembler.track_synack(key.clone(), 2000, 1001);
        assert_eq!(reassembler.get_state(&key), Some(TcpState::Established));

        assert!(reassembler.push_data(&key, b"hello"));
        assert!(reassembler.push_data(&key, b" world"));

        let data = reassembler.take_data(&key).unwrap();
        assert_eq!(&data, b"hello world");

        // 取走后为空
        assert!(reassembler.take_data(&key).is_none());

        assert!(reassembler.close(&key));
        assert_eq!(reassembler.connection_count(), 0);
    }

    #[test]
    fn tcp_flow_key_reverse() {
        let key = TcpFlowKey {
            src_ip: "10.0.0.1".parse().unwrap(),
            dst_ip: "1.1.1.1".parse().unwrap(),
            src_port: 50000,
            dst_port: 443,
        };
        let rev = key.reverse();
        assert_eq!(rev.src_ip, key.dst_ip);
        assert_eq!(rev.dst_ip, key.src_ip);
        assert_eq!(rev.src_port, key.dst_port);
        assert_eq!(rev.dst_port, key.src_port);
    }

    #[test]
    fn tcp_reassembler_push_unknown_key() {
        let mut reassembler = TcpReassembler::new();
        let key = TcpFlowKey {
            src_ip: "10.0.0.1".parse().unwrap(),
            dst_ip: "1.1.1.1".parse().unwrap(),
            src_port: 50000,
            dst_port: 443,
        };
        assert!(!reassembler.push_data(&key, b"data"));
    }

    #[test]
    fn route_manager_basic() {
        let mut rm = RouteManager::new();
        assert_eq!(rm.exclude_count(), 0);

        rm.add_exclude_route("203.0.113.1", "192.168.1.1", "eth0");
        assert_eq!(rm.exclude_count(), 1);

        let cmds = rm.generate_add_commands("utun0");
        // 平台相关，至少有排除路由
        assert!(!cmds.is_empty());
    }

    // --- UDP Session Manager tests ---

    #[test]
    fn udp_session_manager_track_new() {
        let mut mgr = UdpSessionManager::new(100, 300);
        let parsed = ParsedPacket {
            version: 4,
            protocol: IpProtocol::Udp,
            src_ip: "10.0.0.1".parse().unwrap(),
            dst_ip: "8.8.8.8".parse().unwrap(),
            src_port: 53000,
            dst_port: 53,
            payload_offset: 28,
            total_len: 60,
        };
        let is_new = mgr.track_packet(&parsed, 32);
        assert!(is_new);
        assert_eq!(mgr.session_count(), 1);
    }

    #[test]
    fn udp_session_manager_track_existing() {
        let mut mgr = UdpSessionManager::new(100, 300);
        let parsed = ParsedPacket {
            version: 4,
            protocol: IpProtocol::Udp,
            src_ip: "10.0.0.1".parse().unwrap(),
            dst_ip: "8.8.8.8".parse().unwrap(),
            src_port: 53000,
            dst_port: 53,
            payload_offset: 28,
            total_len: 60,
        };
        mgr.track_packet(&parsed, 32);
        let is_new = mgr.track_packet(&parsed, 64);
        assert!(!is_new);
        assert_eq!(mgr.session_count(), 1);
        let key = UdpSessionKey {
            src_ip: "10.0.0.1".parse().unwrap(),
            dst_ip: "8.8.8.8".parse().unwrap(),
            src_port: 53000,
            dst_port: 53,
        };
        let stats = mgr.get_stats(&key).unwrap();
        assert_eq!(stats.packets_sent, 2);
        assert_eq!(stats.bytes_sent, 96);
    }

    #[test]
    fn udp_session_manager_tcp_ignored() {
        let mut mgr = UdpSessionManager::new(100, 300);
        let parsed = ParsedPacket {
            version: 4,
            protocol: IpProtocol::Tcp,
            src_ip: "10.0.0.1".parse().unwrap(),
            dst_ip: "8.8.8.8".parse().unwrap(),
            src_port: 50000,
            dst_port: 443,
            payload_offset: 20,
            total_len: 60,
        };
        let is_new = mgr.track_packet(&parsed, 40);
        assert!(!is_new);
        assert_eq!(mgr.session_count(), 0);
    }

    #[test]
    fn udp_session_manager_reply() {
        let mut mgr = UdpSessionManager::new(100, 300);
        let key = UdpSessionKey {
            src_ip: "10.0.0.1".parse().unwrap(),
            dst_ip: "8.8.8.8".parse().unwrap(),
            src_port: 53000,
            dst_port: 53,
        };
        let parsed = ParsedPacket {
            version: 4,
            protocol: IpProtocol::Udp,
            src_ip: key.src_ip,
            dst_ip: key.dst_ip,
            src_port: key.src_port,
            dst_port: key.dst_port,
            payload_offset: 28,
            total_len: 60,
        };
        mgr.track_packet(&parsed, 32);
        assert!(mgr.track_reply(&key, 64));
        let stats = mgr.get_stats(&key).unwrap();
        assert_eq!(stats.packets_recv, 1);
        assert_eq!(stats.bytes_recv, 64);
    }

    #[test]
    fn udp_session_manager_reply_unknown() {
        let mut mgr = UdpSessionManager::new(100, 300);
        let key = UdpSessionKey {
            src_ip: "10.0.0.1".parse().unwrap(),
            dst_ip: "8.8.8.8".parse().unwrap(),
            src_port: 53000,
            dst_port: 53,
        };
        assert!(!mgr.track_reply(&key, 64));
    }

    #[test]
    fn udp_session_manager_remove() {
        let mut mgr = UdpSessionManager::new(100, 300);
        let parsed = ParsedPacket {
            version: 4,
            protocol: IpProtocol::Udp,
            src_ip: "10.0.0.1".parse().unwrap(),
            dst_ip: "8.8.8.8".parse().unwrap(),
            src_port: 53000,
            dst_port: 53,
            payload_offset: 28,
            total_len: 60,
        };
        mgr.track_packet(&parsed, 32);
        let key = UdpSessionKey {
            src_ip: "10.0.0.1".parse().unwrap(),
            dst_ip: "8.8.8.8".parse().unwrap(),
            src_port: 53000,
            dst_port: 53,
        };
        assert!(mgr.remove_session(&key));
        assert_eq!(mgr.session_count(), 0);
    }

    #[test]
    fn udp_session_key_reverse() {
        let key = UdpSessionKey {
            src_ip: "10.0.0.1".parse().unwrap(),
            dst_ip: "8.8.8.8".parse().unwrap(),
            src_port: 53000,
            dst_port: 53,
        };
        let rev = key.reverse();
        assert_eq!(rev.src_ip, key.dst_ip);
        assert_eq!(rev.dst_ip, key.src_ip);
        assert_eq!(rev.src_port, key.dst_port);
        assert_eq!(rev.dst_port, key.src_port);
    }

    // --- IP Fragment Reassembler tests ---

    #[test]
    fn fragment_reassemble_two_parts() {
        let mut reassembler = IpFragmentReassembler::new(100, 30);
        let key = FragmentKey {
            src_ip: "10.0.0.1".parse().unwrap(),
            dst_ip: "1.1.1.1".parse().unwrap(),
            identification: 1234,
        };

        // First fragment: offset=0, MF=1, 8 bytes
        let result = reassembler.add_fragment(key.clone(), 0, vec![1, 2, 3, 4, 5, 6, 7, 8], true, 17);
        assert!(result.is_none());

        // Second fragment: offset=1 (=8 bytes), MF=0, 4 bytes
        let result = reassembler.add_fragment(key.clone(), 1, vec![9, 10, 11, 12], false, 17);
        assert!(result.is_some());
        let data = result.unwrap();
        assert_eq!(data, vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]);
    }

    #[test]
    fn fragment_reassemble_out_of_order() {
        let mut reassembler = IpFragmentReassembler::new(100, 30);
        let key = FragmentKey {
            src_ip: "10.0.0.1".parse().unwrap(),
            dst_ip: "1.1.1.1".parse().unwrap(),
            identification: 5678,
        };

        // Second fragment first: offset=1, MF=0
        let result = reassembler.add_fragment(key.clone(), 1, vec![9, 10, 11, 12, 13, 14, 15, 16], false, 6);
        assert!(result.is_none());

        // First fragment: offset=0, MF=1
        let result = reassembler.add_fragment(key.clone(), 0, vec![1, 2, 3, 4, 5, 6, 7, 8], true, 6);
        assert!(result.is_some());
        let data = result.unwrap();
        assert_eq!(data.len(), 16);
        assert_eq!(&data[0..8], &[1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(&data[8..16], &[9, 10, 11, 12, 13, 14, 15, 16]);
    }

    #[test]
    fn fragment_incomplete() {
        let mut reassembler = IpFragmentReassembler::new(100, 30);
        let key = FragmentKey {
            src_ip: "10.0.0.1".parse().unwrap(),
            dst_ip: "1.1.1.1".parse().unwrap(),
            identification: 9999,
        };

        // Only one fragment with MF=1, missing the last
        let result = reassembler.add_fragment(key.clone(), 0, vec![1, 2, 3, 4, 5, 6, 7, 8], true, 17);
        assert!(result.is_none());
        assert_eq!(reassembler.group_count(), 1);
    }

    #[test]
    fn fragment_remove_group() {
        let mut reassembler = IpFragmentReassembler::new(100, 30);
        let key = FragmentKey {
            src_ip: "10.0.0.1".parse().unwrap(),
            dst_ip: "1.1.1.1".parse().unwrap(),
            identification: 1111,
        };
        reassembler.add_fragment(key.clone(), 0, vec![1, 2, 3, 4, 5, 6, 7, 8], true, 6);
        assert!(reassembler.remove_group(&key));
        assert_eq!(reassembler.group_count(), 0);
    }

    #[test]
    fn parse_ipv4_fragment_info_not_fragment() {
        let pkt = build_ipv4_tcp([10, 0, 0, 1], [1, 1, 1, 1], 50000, 443);
        // Normal packet (no fragmentation flags) should return None
        assert!(IpFragmentReassembler::parse_ipv4_fragment_info(&pkt).is_none());
    }

    #[test]
    fn parse_ipv4_fragment_info_with_mf() {
        let mut pkt = build_ipv4_tcp([10, 0, 0, 1], [1, 1, 1, 1], 50000, 443);
        // Set MF bit (0x2000) in flags_fragment_offset
        pkt[6] = 0x20; // MF=1, offset=0
        pkt[7] = 0x00;
        pkt[4] = 0x00; // identification high
        pkt[5] = 0x42; // identification low = 66

        let result = IpFragmentReassembler::parse_ipv4_fragment_info(&pkt);
        assert!(result.is_some());
        let (key, offset, more_frags, protocol) = result.unwrap();
        assert_eq!(key.identification, 66);
        assert_eq!(offset, 0);
        assert!(more_frags);
        assert_eq!(protocol, 6); // TCP
    }

    // --- System Proxy tests ---

    #[test]
    fn system_proxy_creation() {
        let proxy = SystemProxy::new("127.0.0.1".to_string(), 7890);
        assert_eq!(proxy.proxy_host(), "127.0.0.1");
        assert_eq!(proxy.proxy_port(), 7890);
        assert!(proxy.socks_port().is_none());
        assert!(!proxy.bypass_list().is_empty());
    }

    #[test]
    fn system_proxy_with_socks() {
        let proxy = SystemProxy::new("127.0.0.1".to_string(), 7890)
            .with_socks_port(7891);
        assert_eq!(proxy.socks_port(), Some(7891));
    }

    #[test]
    fn system_proxy_with_bypass() {
        let proxy = SystemProxy::new("127.0.0.1".to_string(), 7890)
            .with_bypass(vec!["example.com".to_string()]);
        assert_eq!(proxy.bypass_list(), &["example.com"]);
    }

    #[test]
    fn system_proxy_enable_commands() {
        let proxy = SystemProxy::new("127.0.0.1".to_string(), 7890);
        let cmds = proxy.enable_commands();
        assert!(!cmds.is_empty());
    }

    #[test]
    fn system_proxy_disable_commands() {
        let proxy = SystemProxy::new("127.0.0.1".to_string(), 7890);
        let cmds = proxy.disable_commands();
        assert!(!cmds.is_empty());
    }

    // --- DNS Hijack tests ---

    #[test]
    fn dns_hijack_creation() {
        let hijack = DnsHijack::new(true);
        assert!(hijack.enabled());
        assert_eq!(hijack.listen_port(), 53);
        assert!(!hijack.upstream_servers().is_empty());
    }

    #[test]
    fn dns_hijack_should_hijack_udp_53() {
        let hijack = DnsHijack::new(true);
        let parsed = ParsedPacket {
            version: 4,
            protocol: IpProtocol::Udp,
            src_ip: "10.0.0.1".parse().unwrap(),
            dst_ip: "8.8.8.8".parse().unwrap(),
            src_port: 53000,
            dst_port: 53,
            payload_offset: 28,
            total_len: 60,
        };
        assert!(hijack.should_hijack(&parsed));
    }

    #[test]
    fn dns_hijack_should_not_hijack_tcp_53() {
        let hijack = DnsHijack::new(true);
        let parsed = ParsedPacket {
            version: 4,
            protocol: IpProtocol::Tcp,
            src_ip: "10.0.0.1".parse().unwrap(),
            dst_ip: "8.8.8.8".parse().unwrap(),
            src_port: 53000,
            dst_port: 53,
            payload_offset: 20,
            total_len: 60,
        };
        assert!(!hijack.should_hijack(&parsed));
    }

    #[test]
    fn dns_hijack_should_not_hijack_disabled() {
        let hijack = DnsHijack::new(false);
        let parsed = ParsedPacket {
            version: 4,
            protocol: IpProtocol::Udp,
            src_ip: "10.0.0.1".parse().unwrap(),
            dst_ip: "8.8.8.8".parse().unwrap(),
            src_port: 53000,
            dst_port: 53,
            payload_offset: 28,
            total_len: 60,
        };
        assert!(!hijack.should_hijack(&parsed));
    }

    #[test]
    fn dns_hijack_should_not_hijack_other_port() {
        let hijack = DnsHijack::new(true);
        let parsed = ParsedPacket {
            version: 4,
            protocol: IpProtocol::Udp,
            src_ip: "10.0.0.1".parse().unwrap(),
            dst_ip: "8.8.8.8".parse().unwrap(),
            src_port: 53000,
            dst_port: 443,
            payload_offset: 28,
            total_len: 60,
        };
        assert!(!hijack.should_hijack(&parsed));
    }

    #[test]
    fn dns_hijack_with_upstream() {
        let hijack = DnsHijack::new(true)
            .with_upstream(vec!["1.1.1.1".to_string()]);
        assert_eq!(hijack.upstream_servers(), &["1.1.1.1"]);
    }

    #[test]
    fn dns_hijack_redirect_rules() {
        let hijack = DnsHijack::new(true);
        let rules = hijack.generate_redirect_rules("tun0");
        // On Linux, should have iptables rules; on other platforms may be empty or different
        let _ = rules;
    }

    // --- ICMP Policy tests ---

    #[test]
    fn icmp_policy_passthrough() {
        let policy = IcmpPolicy::Passthrough;
        let parsed = ParsedPacket {
            version: 4,
            protocol: IpProtocol::Icmp,
            src_ip: "10.0.0.1".parse().unwrap(),
            dst_ip: "10.0.0.2".parse().unwrap(),
            src_port: 0,
            dst_port: 0,
            payload_offset: 20,
            total_len: 60,
        };
        assert!(policy.should_process(&parsed));
    }

    #[test]
    fn icmp_policy_drop() {
        let policy = IcmpPolicy::Drop;
        let parsed = ParsedPacket {
            version: 4,
            protocol: IpProtocol::Icmp,
            src_ip: "10.0.0.1".parse().unwrap(),
            dst_ip: "10.0.0.2".parse().unwrap(),
            src_port: 0,
            dst_port: 0,
            payload_offset: 20,
            total_len: 60,
        };
        assert!(!policy.should_process(&parsed));
    }

    #[test]
    fn icmp_policy_non_icmp_always_processed() {
        let policy = IcmpPolicy::Drop;
        let parsed = ParsedPacket {
            version: 4,
            protocol: IpProtocol::Tcp,
            src_ip: "10.0.0.1".parse().unwrap(),
            dst_ip: "10.0.0.2".parse().unwrap(),
            src_port: 50000,
            dst_port: 443,
            payload_offset: 20,
            total_len: 60,
        };
        assert!(policy.should_process(&parsed));
    }

    #[test]
    fn icmp_policy_from_str() {
        assert_eq!(IcmpPolicy::from_str("passthrough"), IcmpPolicy::Passthrough);
        assert_eq!(IcmpPolicy::from_str("pass"), IcmpPolicy::Passthrough);
        assert_eq!(IcmpPolicy::from_str("drop"), IcmpPolicy::Drop);
        assert_eq!(IcmpPolicy::from_str("reject"), IcmpPolicy::Drop);
        assert_eq!(IcmpPolicy::from_str("unknown"), IcmpPolicy::Drop);
    }

    #[test]
    fn icmp_type_v4_echo_request() {
        let mut pkt = build_ipv4_tcp([10, 0, 0, 1], [10, 0, 0, 2], 0, 0);
        pkt[9] = 1; // ICMP
        pkt[20] = 8; // Echo Request type
        let parsed = parse_ip_packet(&pkt).unwrap();
        let icmp = parse_icmp_type(&parsed, &pkt).unwrap();
        assert_eq!(icmp, IcmpType::EchoRequest);
    }

    #[test]
    fn icmp_type_v4_echo_reply() {
        let mut pkt = build_ipv4_tcp([10, 0, 0, 1], [10, 0, 0, 2], 0, 0);
        pkt[9] = 1; // ICMP
        pkt[20] = 0; // Echo Reply type
        let parsed = parse_ip_packet(&pkt).unwrap();
        let icmp = parse_icmp_type(&parsed, &pkt).unwrap();
        assert_eq!(icmp, IcmpType::EchoReply);
    }

    #[test]
    fn icmp_type_v6_echo_request() {
        let src = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        let dst = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
        let mut pkt = vec![0u8; 48];
        pkt[0] = 0x60;
        pkt[4] = 0; pkt[5] = 8;
        pkt[6] = 58; // ICMPv6
        pkt[8..24].copy_from_slice(&src);
        pkt[24..40].copy_from_slice(&dst);
        pkt[40] = 128; // ICMPv6 Echo Request
        let parsed = parse_ip_packet(&pkt).unwrap();
        let icmp = parse_icmp_type(&parsed, &pkt).unwrap();
        assert_eq!(icmp, IcmpType::EchoRequest);
    }

    #[test]
    fn icmp_type_non_icmp_returns_none() {
        let pkt = build_ipv4_tcp([10, 0, 0, 1], [10, 0, 0, 2], 50000, 443);
        let parsed = parse_ip_packet(&pkt).unwrap();
        assert!(parse_icmp_type(&parsed, &pkt).is_none());
    }

    // --- Platform-specific device tests ---

    #[cfg(target_os = "windows")]
    #[test]
    fn wintun_device_creation() {
        let config = TunConfig::default();
        let device = WintunDevice::new(&config).unwrap();
        assert_eq!(device.ring_capacity(), 0x400000);
        assert!(device.guid().is_none());
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn wintun_device_adapter_params() {
        let config = TunConfig::default();
        let device = WintunDevice::new(&config).unwrap()
            .with_guid("test-guid".to_string())
            .with_ring_capacity(0x200000);
        let params = device.adapter_params();
        assert_eq!(params.name, config.name);
        assert_eq!(params.tunnel_type, "OpenWorld");
        assert_eq!(params.guid.as_deref(), Some("test-guid"));
        assert_eq!(params.ring_capacity, 0x200000);
        assert_eq!(params.mtu, 1500);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_tun_device_creation() {
        let config = TunConfig::default();
        let device = LinuxTunDevice::new(&config).unwrap();
        let flags = device.flags();
        assert!(flags.tun);
        assert!(flags.no_pi);
        assert!(!flags.multi_queue);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_tun_flags_to_bits() {
        let flags = LinuxTunFlags::default();
        let bits = flags.to_bits();
        assert_eq!(bits, LinuxTunFlags::IFF_TUN | LinuxTunFlags::IFF_NO_PI);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_tun_ioctl_params() {
        let config = TunConfig::default();
        let device = LinuxTunDevice::new(&config).unwrap();
        let params = device.ioctl_params();
        assert_eq!(params.name, config.name);
        assert_eq!(params.flags, LinuxTunFlags::IFF_TUN | LinuxTunFlags::IFF_NO_PI);
        assert_eq!(params.mtu, 1500);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_tun_ip_config_commands() {
        let config = TunConfig::default();
        let device = LinuxTunDevice::new(&config).unwrap();
        let cmds = device.ip_config_commands("198.18.0.1", 15);
        assert_eq!(cmds.len(), 3);
        assert!(cmds[0].contains("ip link set"));
        assert!(cmds[1].contains("ip addr add 198.18.0.1/15"));
        assert!(cmds[2].contains("mtu 1500"));
    }
}
