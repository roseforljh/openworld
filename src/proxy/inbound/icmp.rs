/// ICMP Echo 代理 — 在 TUN 模式下代理 ping (ICMP Echo Request/Reply)。
///
/// 当 TUN 设备收到 ICMP Echo Request 包时，通过出站代理转发并返回 Reply。
/// 这允许在代理环境下正常使用 ping 命令。
///
/// ## 原理
/// 1. TUN 设备拦截 ICMP Echo Request
/// 2. 解析 ICMP 头部（type=8, code=0）
/// 3. 通过 raw socket 或 SOCKS5 UDP 转发到目标
/// 4. 接收 ICMP Echo Reply 并注入回 TUN 设备
///
/// ## 限制
/// - 需要 raw socket 权限（Linux: CAP_NET_RAW, Windows: 管理员权限）
/// - 某些出站代理不支持 ICMP（如纯 TCP 代理）
use std::net::IpAddr;

use anyhow::Result;
use tracing::debug;

/// ICMP Echo Request/Reply 处理器
pub struct IcmpProxy {
    /// 是否启用
    enabled: bool,
}

/// 解析后的 ICMP Echo 数据
#[derive(Debug, Clone)]
pub struct IcmpEchoPacket {
    /// 目标 IP
    pub target: IpAddr,
    /// 源 IP
    pub source: IpAddr,
    /// ICMP Identifier
    pub id: u16,
    /// ICMP Sequence Number
    pub sequence: u16,
    /// Echo payload
    pub payload: Vec<u8>,
    /// TTL (IPv4) / Hop Limit (IPv6)
    pub ttl: u8,
}

/// ICMP 类型常量
const ICMP_ECHO_REQUEST: u8 = 8;
const ICMP_ECHO_REPLY: u8 = 0;
const ICMPV6_ECHO_REQUEST: u8 = 128;
const ICMPV6_ECHO_REPLY: u8 = 129;

impl IcmpProxy {
    pub fn new(enabled: bool) -> Self {
        Self { enabled }
    }

    /// 检查 IP 包是否为 ICMP Echo Request
    pub fn is_echo_request(packet: &[u8]) -> bool {
        if packet.len() < 20 {
            return false;
        }

        let version = (packet[0] >> 4) & 0xF;

        match version {
            4 => {
                // IPv4: protocol = 1 (ICMP)
                if packet[9] != 1 {
                    return false;
                }
                let ihl = (packet[0] & 0xF) as usize * 4;
                if packet.len() < ihl + 8 {
                    return false;
                }
                packet[ihl] == ICMP_ECHO_REQUEST
            }
            6 => {
                // IPv6: next_header = 58 (ICMPv6)
                if packet.len() < 40 + 8 {
                    return false;
                }
                if packet[6] != 58 {
                    return false;
                }
                packet[40] == ICMPV6_ECHO_REQUEST
            }
            _ => false,
        }
    }

    /// 解析 ICMP Echo Request 包
    pub fn parse_echo_request(packet: &[u8]) -> Option<IcmpEchoPacket> {
        if packet.len() < 20 {
            return None;
        }

        let version = (packet[0] >> 4) & 0xF;

        match version {
            4 => Self::parse_ipv4_echo(packet),
            6 => Self::parse_ipv6_echo(packet),
            _ => None,
        }
    }

    fn parse_ipv4_echo(packet: &[u8]) -> Option<IcmpEchoPacket> {
        let ihl = (packet[0] & 0xF) as usize * 4;
        if packet.len() < ihl + 8 {
            return None;
        }

        let source = IpAddr::V4(std::net::Ipv4Addr::new(
            packet[12], packet[13], packet[14], packet[15],
        ));
        let target = IpAddr::V4(std::net::Ipv4Addr::new(
            packet[16], packet[17], packet[18], packet[19],
        ));
        let ttl = packet[8];

        let icmp = &packet[ihl..];
        if icmp[0] != ICMP_ECHO_REQUEST {
            return None;
        }

        let id = u16::from_be_bytes([icmp[4], icmp[5]]);
        let sequence = u16::from_be_bytes([icmp[6], icmp[7]]);
        let payload = icmp[8..].to_vec();

        Some(IcmpEchoPacket {
            target,
            source,
            id,
            sequence,
            payload,
            ttl,
        })
    }

    fn parse_ipv6_echo(packet: &[u8]) -> Option<IcmpEchoPacket> {
        if packet.len() < 40 + 8 {
            return None;
        }

        let source = IpAddr::V6(std::net::Ipv6Addr::from({
            let mut buf = [0u8; 16];
            buf.copy_from_slice(&packet[8..24]);
            buf
        }));
        let target = IpAddr::V6(std::net::Ipv6Addr::from({
            let mut buf = [0u8; 16];
            buf.copy_from_slice(&packet[24..40]);
            buf
        }));
        let ttl = packet[7]; // Hop Limit

        let icmp = &packet[40..];
        if icmp[0] != ICMPV6_ECHO_REQUEST {
            return None;
        }

        let id = u16::from_be_bytes([icmp[4], icmp[5]]);
        let sequence = u16::from_be_bytes([icmp[6], icmp[7]]);
        let payload = icmp[8..].to_vec();

        Some(IcmpEchoPacket {
            target,
            source,
            id,
            sequence,
            payload,
            ttl,
        })
    }

    /// 构建 ICMP Echo Reply 包
    pub fn build_echo_reply(request: &IcmpEchoPacket) -> Vec<u8> {
        match request.target {
            IpAddr::V4(_) => Self::build_ipv4_reply(request),
            IpAddr::V6(_) => Self::build_ipv6_reply(request),
        }
    }

    fn build_ipv4_reply(req: &IcmpEchoPacket) -> Vec<u8> {
        let src_ip = match req.target {
            IpAddr::V4(ip) => ip,
            _ => unreachable!(),
        };
        let dst_ip = match req.source {
            IpAddr::V4(ip) => ip,
            _ => unreachable!(),
        };

        let icmp_len = 8 + req.payload.len();
        let total_len = 20 + icmp_len;
        let mut packet = vec![0u8; total_len];

        // IPv4 header
        packet[0] = 0x45; // version=4, ihl=5
        packet[1] = 0; // DSCP/ECN
        let total = total_len as u16;
        packet[2..4].copy_from_slice(&total.to_be_bytes());
        packet[4..6].copy_from_slice(&0u16.to_be_bytes()); // identification
        packet[6] = 0x40; // flags: DF
        packet[7] = 0; // fragment offset
        packet[8] = 64; // TTL
        packet[9] = 1; // protocol: ICMP
                       // checksum computed later
        packet[12..16].copy_from_slice(&src_ip.octets());
        packet[16..20].copy_from_slice(&dst_ip.octets());

        // ICMP header
        packet[20] = ICMP_ECHO_REPLY; // type
        packet[21] = 0; // code
                        // checksum computed later
        packet[24..26].copy_from_slice(&req.id.to_be_bytes());
        packet[26..28].copy_from_slice(&req.sequence.to_be_bytes());
        packet[28..].copy_from_slice(&req.payload);

        // ICMP checksum
        let icmp_cksum = checksum(&packet[20..]);
        packet[22..24].copy_from_slice(&icmp_cksum.to_be_bytes());

        // IP header checksum
        let ip_cksum = checksum(&packet[..20]);
        packet[10..12].copy_from_slice(&ip_cksum.to_be_bytes());

        packet
    }

    fn build_ipv6_reply(req: &IcmpEchoPacket) -> Vec<u8> {
        let src_ip = match req.target {
            IpAddr::V6(ip) => ip,
            _ => unreachable!(),
        };
        let dst_ip = match req.source {
            IpAddr::V6(ip) => ip,
            _ => unreachable!(),
        };

        let icmp_len = 8 + req.payload.len();
        let total_len = 40 + icmp_len;
        let mut packet = vec![0u8; total_len];

        // IPv6 header
        packet[0] = 0x60; // version=6
        let payload_len = icmp_len as u16;
        packet[4..6].copy_from_slice(&payload_len.to_be_bytes());
        packet[6] = 58; // next header: ICMPv6
        packet[7] = 64; // hop limit
        packet[8..24].copy_from_slice(&src_ip.octets());
        packet[24..40].copy_from_slice(&dst_ip.octets());

        // ICMPv6 header
        packet[40] = ICMPV6_ECHO_REPLY;
        packet[41] = 0;
        // checksum later
        packet[44..46].copy_from_slice(&req.id.to_be_bytes());
        packet[46..48].copy_from_slice(&req.sequence.to_be_bytes());
        packet[48..].copy_from_slice(&req.payload);

        // ICMPv6 checksum (includes pseudo-header)
        let cksum = icmpv6_checksum(&src_ip, &dst_ip, &packet[40..]);
        packet[42..44].copy_from_slice(&cksum.to_be_bytes());

        packet
    }

    /// 通过 raw socket 发送 ICMP echo 并等待 reply
    pub async fn proxy_echo(&self, echo: &IcmpEchoPacket) -> Result<IcmpEchoPacket> {
        if !self.enabled {
            anyhow::bail!("ICMP proxy is disabled");
        }

        debug!(
            target_ip = %echo.target,
            id = echo.id,
            seq = echo.sequence,
            "proxying ICMP echo request"
        );

        // 使用 raw socket 发送 ICMP
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        {
            self.send_raw_icmp(echo).await
        }

        #[cfg(target_os = "windows")]
        {
            self.send_windows_icmp(echo).await
        }

        #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
        {
            anyhow::bail!("ICMP proxy not supported on this platform")
        }
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    async fn send_raw_icmp(&self, echo: &IcmpEchoPacket) -> Result<IcmpEchoPacket> {
        use std::os::fd::AsRawFd;

        let is_v4 = echo.target.is_ipv4();
        let (domain, protocol) = if is_v4 {
            (socket2::Domain::IPV4, socket2::Protocol::ICMPV4)
        } else {
            (socket2::Domain::IPV6, socket2::Protocol::ICMPV6)
        };

        let raw_socket = socket2::Socket::new(domain, socket2::Type::DGRAM, Some(protocol))?;
        raw_socket.set_nonblocking(true)?;

        // 构建 ICMP Echo Request payload
        let icmp_type = if is_v4 {
            ICMP_ECHO_REQUEST
        } else {
            ICMPV6_ECHO_REQUEST
        };
        let mut icmp_buf = Vec::with_capacity(8 + echo.payload.len());
        icmp_buf.push(icmp_type);
        icmp_buf.push(0); // code
        icmp_buf.extend_from_slice(&[0, 0]); // checksum placeholder
        icmp_buf.extend_from_slice(&echo.id.to_be_bytes());
        icmp_buf.extend_from_slice(&echo.sequence.to_be_bytes());
        icmp_buf.extend_from_slice(&echo.payload);

        // Compute checksum
        let cksum = checksum(&icmp_buf);
        icmp_buf[2..4].copy_from_slice(&cksum.to_be_bytes());

        let target_addr: std::net::SocketAddr = match echo.target {
            IpAddr::V4(ip) => std::net::SocketAddr::new(IpAddr::V4(ip), 0),
            IpAddr::V6(ip) => std::net::SocketAddr::new(IpAddr::V6(ip), 0),
        };
        let target_sockaddr: socket2::SockAddr = target_addr.into();

        raw_socket.send_to(&icmp_buf, &target_sockaddr)?;

        // 等待 reply
        let async_fd = tokio::io::unix::AsyncFd::new(raw_socket.as_raw_fd())?;
        let mut reply_buf = vec![0u8; 1500];

        let result = tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                let guard = async_fd.readable().await?;
                match raw_socket.recv(&mut reply_buf) {
                    Ok(n) => {
                        if n >= 8 {
                            let reply_type = if is_v4 {
                                ICMP_ECHO_REPLY
                            } else {
                                ICMPV6_ECHO_REPLY
                            };
                            if reply_buf[0] == reply_type {
                                let reply_id = u16::from_be_bytes([reply_buf[4], reply_buf[5]]);
                                let reply_seq = u16::from_be_bytes([reply_buf[6], reply_buf[7]]);
                                if reply_id == echo.id && reply_seq == echo.sequence {
                                    return Ok::<_, anyhow::Error>(IcmpEchoPacket {
                                        target: echo.source,
                                        source: echo.target,
                                        id: reply_id,
                                        sequence: reply_seq,
                                        payload: reply_buf[8..n].to_vec(),
                                        ttl: 64,
                                    });
                                }
                            }
                        }
                        guard.clear_ready();
                    }
                    Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        guard.clear_ready();
                    }
                    Err(e) => return Err(e.into()),
                }
            }
        })
        .await
        .map_err(|_| anyhow::anyhow!("ICMP echo timeout"))?;

        result
    }

    #[cfg(target_os = "windows")]
    async fn send_windows_icmp(&self, echo: &IcmpEchoPacket) -> Result<IcmpEchoPacket> {
        // Windows: 使用 IcmpSendEcho2 API 或简单 fallback
        // 简化实现：生成 ping 命令
        let target_str = echo.target.to_string();
        let output = tokio::process::Command::new("ping")
            .args(["-n", "1", "-w", "5000", &target_str])
            .output()
            .await?;

        if output.status.success() {
            Ok(IcmpEchoPacket {
                target: echo.source,
                source: echo.target,
                id: echo.id,
                sequence: echo.sequence,
                payload: echo.payload.clone(),
                ttl: 64,
            })
        } else {
            anyhow::bail!("ICMP echo failed: host unreachable")
        }
    }
}

/// 计算 Internet checksum (RFC 1071)
fn checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < data.len() {
        sum += u16::from_be_bytes([data[i], data[i + 1]]) as u32;
        i += 2;
    }
    if i < data.len() {
        sum += (data[i] as u32) << 8;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

/// ICMPv6 checksum (includes pseudo-header)
fn icmpv6_checksum(src: &std::net::Ipv6Addr, dst: &std::net::Ipv6Addr, icmp_data: &[u8]) -> u16 {
    let mut sum: u32 = 0;

    // Pseudo-header
    for chunk in src.octets().chunks(2) {
        sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
    }
    for chunk in dst.octets().chunks(2) {
        sum += u16::from_be_bytes([chunk[0], chunk[1]]) as u32;
    }
    sum += icmp_data.len() as u32;
    sum += 58u32; // Next header: ICMPv6

    // ICMPv6 data (with checksum field zeroed)
    let mut i = 0;
    while i + 1 < icmp_data.len() {
        if i == 2 {
            // Skip checksum field
            i += 2;
            continue;
        }
        sum += u16::from_be_bytes([icmp_data[i], icmp_data[i + 1]]) as u32;
        i += 2;
    }
    if i < icmp_data.len() {
        sum += (icmp_data[i] as u32) << 8;
    }

    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_icmp_echo_request() {
        // Minimal IPv4 ICMP Echo Request
        let mut pkt = vec![0u8; 28];
        pkt[0] = 0x45; // IPv4, IHL=5
        pkt[9] = 1; // ICMP
        pkt[20] = 8; // Echo Request
        assert!(IcmpProxy::is_echo_request(&pkt));
    }

    #[test]
    fn detect_non_icmp() {
        let mut pkt = vec![0u8; 28];
        pkt[0] = 0x45;
        pkt[9] = 6; // TCP
        assert!(!IcmpProxy::is_echo_request(&pkt));
    }

    #[test]
    fn parse_ipv4_echo() {
        let mut pkt = vec![0u8; 36]; // 20 IP + 8 ICMP + 8 payload
        pkt[0] = 0x45;
        pkt[8] = 64; // TTL
        pkt[9] = 1; // ICMP
                    // source: 10.0.0.1
        pkt[12] = 10;
        pkt[13] = 0;
        pkt[14] = 0;
        pkt[15] = 1;
        // target: 8.8.8.8
        pkt[16] = 8;
        pkt[17] = 8;
        pkt[18] = 8;
        pkt[19] = 8;
        pkt[20] = ICMP_ECHO_REQUEST;
        pkt[24] = 0x12;
        pkt[25] = 0x34; // id
        pkt[26] = 0x00;
        pkt[27] = 0x01; // seq
                        // payload
        for i in 0..8 {
            pkt[28 + i] = i as u8;
        }

        let echo = IcmpProxy::parse_echo_request(&pkt).unwrap();
        assert_eq!(echo.id, 0x1234);
        assert_eq!(echo.sequence, 1);
        assert_eq!(echo.ttl, 64);
        assert_eq!(echo.payload.len(), 8);
    }

    #[test]
    fn build_reply_roundtrip() {
        let req = IcmpEchoPacket {
            target: IpAddr::V4(std::net::Ipv4Addr::new(8, 8, 8, 8)),
            source: IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1)),
            id: 0x1234,
            sequence: 1,
            payload: vec![0xAA; 32],
            ttl: 64,
        };

        let reply = IcmpProxy::build_echo_reply(&req);
        assert!(reply.len() > 28);
        assert_eq!(reply[20], ICMP_ECHO_REPLY);
        // Source/dest should be swapped
        assert_eq!(&reply[12..16], &[8, 8, 8, 8]);
        assert_eq!(&reply[16..20], &[10, 0, 0, 1]);
    }

    #[test]
    fn checksum_basic() {
        // RFC 1071 example
        let data = [0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7];
        let cksum = checksum(&data);
        assert_eq!(cksum, 0x220d);
    }

    #[test]
    fn icmp_proxy_disabled() {
        let proxy = IcmpProxy::new(false);
        assert!(!proxy.enabled);
    }
}
