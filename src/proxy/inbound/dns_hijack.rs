//! DNS 劫持模块
//!
//! 拦截 TUN 设备上 UDP 端口 53 的 DNS 查询，
//! 使用内置 DNS resolver 解析后直接构建响应包写回 TUN 设备。

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use tracing::debug;

use super::tun_device::{IpProtocol, ParsedPacket};
use crate::dns::DnsResolver;

/// 解析出的 DNS 查询信息
pub struct DnsQuery {
    /// Transaction ID
    pub id: u16,
    /// 查询的域名
    pub name: String,
    /// 查询类型 (1=A, 28=AAAA)
    pub qtype: u16,
    /// 原始 question section（header 之后、answer 之前的完整内容）
    pub raw_question: Vec<u8>,
}

/// 从 DNS payload 中解析查询
pub fn parse_dns_query(data: &[u8]) -> Option<DnsQuery> {
    // DNS header 至少 12 字节
    if data.len() < 12 {
        return None;
    }

    let id = u16::from_be_bytes([data[0], data[1]]);
    let flags = u16::from_be_bytes([data[2], data[3]]);

    // QR 位必须为 0（查询）
    if flags & 0x8000 != 0 {
        return None;
    }

    let qdcount = u16::from_be_bytes([data[4], data[5]]);
    if qdcount == 0 {
        return None;
    }

    // 解析 QNAME
    let mut pos = 12;
    let mut name_parts: Vec<String> = Vec::new();

    loop {
        if pos >= data.len() {
            return None;
        }
        let label_len = data[pos] as usize;
        if label_len == 0 {
            pos += 1; // 跳过终止的 0x00
            break;
        }
        // 防止指针压缩（在 query 中不应出现，但以防万一）
        if label_len & 0xC0 == 0xC0 {
            return None;
        }
        pos += 1;
        if pos + label_len > data.len() {
            return None;
        }
        let label = std::str::from_utf8(&data[pos..pos + label_len]).ok()?;
        name_parts.push(label.to_string());
        pos += label_len;
    }

    if name_parts.is_empty() {
        return None;
    }

    // QTYPE + QCLASS 各 2 字节
    if pos + 4 > data.len() {
        return None;
    }
    let qtype = u16::from_be_bytes([data[pos], data[pos + 1]]);
    pos += 4; // 跳过 QTYPE + QCLASS

    let name = name_parts.join(".");
    let raw_question = data[12..pos].to_vec();

    Some(DnsQuery {
        id,
        name,
        qtype,
        raw_question,
    })
}

/// 构建 DNS 响应 payload
pub fn build_dns_response(query: &DnsQuery, addrs: &[IpAddr]) -> Vec<u8> {
    // 筛选匹配 qtype 的地址
    let matched: Vec<&IpAddr> = addrs
        .iter()
        .filter(|addr| match (query.qtype, addr) {
            (1, IpAddr::V4(_)) => true,  // A 记录
            (28, IpAddr::V6(_)) => true, // AAAA 记录
            _ => false,
        })
        .collect();

    let ancount = matched.len() as u16;

    // 计算响应大小
    let answer_size: usize = matched
        .iter()
        .map(|addr| {
            2 + 2
                + 2
                + 4
                + 2
                + match addr {
                    IpAddr::V4(_) => 4,
                    IpAddr::V6(_) => 16,
                }
        })
        .sum();

    let total_size = 12 + query.raw_question.len() + answer_size;
    let mut resp = Vec::with_capacity(total_size);

    // Header (12 bytes)
    resp.extend_from_slice(&query.id.to_be_bytes()); // Transaction ID
    resp.extend_from_slice(&0x8180u16.to_be_bytes()); // Flags: QR=1, RD=1, RA=1
    resp.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT = 1
    resp.extend_from_slice(&ancount.to_be_bytes()); // ANCOUNT
    resp.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT = 0
    resp.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT = 0

    // Question section（原样复制）
    resp.extend_from_slice(&query.raw_question);

    // Answer section
    for addr in &matched {
        // NAME: 指针压缩，指向 offset 0x0C（question 中的域名）
        resp.extend_from_slice(&0xC00Cu16.to_be_bytes());

        match addr {
            IpAddr::V4(v4) => {
                resp.extend_from_slice(&1u16.to_be_bytes()); // TYPE = A
                resp.extend_from_slice(&1u16.to_be_bytes()); // CLASS = IN
                resp.extend_from_slice(&60u32.to_be_bytes()); // TTL = 60s
                resp.extend_from_slice(&4u16.to_be_bytes()); // RDLENGTH = 4
                resp.extend_from_slice(&v4.octets()); // RDATA
            }
            IpAddr::V6(v6) => {
                resp.extend_from_slice(&28u16.to_be_bytes()); // TYPE = AAAA
                resp.extend_from_slice(&1u16.to_be_bytes()); // CLASS = IN
                resp.extend_from_slice(&60u32.to_be_bytes()); // TTL = 60s
                resp.extend_from_slice(&16u16.to_be_bytes()); // RDLENGTH = 16
                resp.extend_from_slice(&v6.octets()); // RDATA
            }
        }
    }

    resp
}

/// 计算 IPv4 header checksum
fn ipv4_checksum(header: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    for i in (0..header.len()).step_by(2) {
        let word = if i + 1 < header.len() {
            u16::from_be_bytes([header[i], header[i + 1]])
        } else {
            u16::from_be_bytes([header[i], 0])
        };
        sum += word as u32;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

/// 构建 UDP 响应的 IPv4 包（20 + 8 + payload）
pub fn build_ipv4_udp_packet(
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Vec<u8> {
    let udp_len = 8 + payload.len();
    let total_len = 20 + udp_len;
    let mut pkt = vec![0u8; total_len];

    // IPv4 header (20 bytes)
    pkt[0] = 0x45; // version=4, IHL=5
    pkt[1] = 0x00; // DSCP/ECN
    pkt[2..4].copy_from_slice(&(total_len as u16).to_be_bytes()); // Total Length
    pkt[4..6].copy_from_slice(&0u16.to_be_bytes()); // Identification
    pkt[6..8].copy_from_slice(&0x4000u16.to_be_bytes()); // Flags: Don't Fragment
    pkt[8] = 64; // TTL
    pkt[9] = 17; // Protocol: UDP
                 // pkt[10..12] = checksum, 先置零后计算
    pkt[12..16].copy_from_slice(&src_ip.octets());
    pkt[16..20].copy_from_slice(&dst_ip.octets());

    // 计算 IP header checksum
    let checksum = ipv4_checksum(&pkt[..20]);
    pkt[10..12].copy_from_slice(&checksum.to_be_bytes());

    // UDP header (8 bytes)
    let udp_offset = 20;
    pkt[udp_offset..udp_offset + 2].copy_from_slice(&src_port.to_be_bytes());
    pkt[udp_offset + 2..udp_offset + 4].copy_from_slice(&dst_port.to_be_bytes());
    pkt[udp_offset + 4..udp_offset + 6].copy_from_slice(&(udp_len as u16).to_be_bytes());
    // pkt[udp_offset + 6..udp_offset + 8] = UDP checksum = 0（IPv4 中可选）

    // Payload
    pkt[28..].copy_from_slice(payload);

    pkt
}

/// 构建 UDP 响应的 IPv6 包（40 + 8 + payload）
pub fn build_ipv6_udp_packet(
    src_ip: Ipv6Addr,
    dst_ip: Ipv6Addr,
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
) -> Vec<u8> {
    let udp_len = 8 + payload.len();
    let total_len = 40 + udp_len;
    let mut pkt = vec![0u8; total_len];

    // IPv6 header (40 bytes)
    pkt[0] = 0x60; // version=6
                   // pkt[1..4] = traffic class + flow label = 0
    pkt[4..6].copy_from_slice(&(udp_len as u16).to_be_bytes()); // Payload Length
    pkt[6] = 17; // Next Header: UDP
    pkt[7] = 64; // Hop Limit
    pkt[8..24].copy_from_slice(&src_ip.octets());
    pkt[24..40].copy_from_slice(&dst_ip.octets());

    // UDP header (8 bytes)
    let udp_offset = 40;
    pkt[udp_offset..udp_offset + 2].copy_from_slice(&src_port.to_be_bytes());
    pkt[udp_offset + 2..udp_offset + 4].copy_from_slice(&dst_port.to_be_bytes());
    pkt[udp_offset + 4..udp_offset + 6].copy_from_slice(&(udp_len as u16).to_be_bytes());
    // pkt[udp_offset + 6..udp_offset + 8] = UDP checksum = 0

    // Payload
    pkt[48..].copy_from_slice(payload);

    pkt
}

/// 检查 parsed packet 是否是 DNS 查询（UDP port 53）
pub fn is_dns_query(parsed: &ParsedPacket) -> bool {
    parsed.protocol == IpProtocol::Udp && parsed.dst_port == 53
}

/// 处理 DNS 劫持：解析查询，用 resolver 解析，构建响应 IP 包
///
/// 返回要写回 TUN 设备的完整 IP 响应包，或 None（如果解析失败）
pub async fn handle_dns_hijack(
    parsed: &ParsedPacket,
    raw_packet: &[u8],
    resolver: &dyn DnsResolver,
) -> Option<Vec<u8>> {
    // 提取 UDP payload：跳过 IP header (payload_offset) + UDP header (8 bytes)
    let udp_payload_offset = parsed.payload_offset + 8;
    if raw_packet.len() <= udp_payload_offset {
        debug!("DNS hijack: packet too short for UDP payload");
        return None;
    }
    let dns_payload = &raw_packet[udp_payload_offset..];

    // 解析 DNS 查询
    let query = parse_dns_query(dns_payload)?;

    debug!(
        name = %query.name,
        qtype = query.qtype,
        id = query.id,
        "DNS hijack: resolving"
    );

    // 调用 resolver 解析域名
    let addrs = match resolver.resolve(&query.name).await {
        Ok(addrs) => addrs,
        Err(e) => {
            debug!(
                name = %query.name,
                error = %e,
                "DNS hijack: resolve failed, returning empty response"
            );
            vec![]
        }
    };

    // 构建 DNS 响应 payload
    let dns_response = build_dns_response(&query, &addrs);

    // 构建 IP 包（swap src/dst）
    let ip_packet = match (parsed.src_ip, parsed.dst_ip) {
        (IpAddr::V4(client_ip), IpAddr::V4(dns_ip)) => {
            build_ipv4_udp_packet(
                dns_ip,          // 响应包的 src = 原来的 dst（DNS 服务器）
                client_ip,       // 响应包的 dst = 原来的 src（客户端）
                parsed.dst_port, // src_port = 53
                parsed.src_port, // dst_port = 客户端端口
                &dns_response,
            )
        }
        (IpAddr::V6(client_ip), IpAddr::V6(dns_ip)) => build_ipv6_udp_packet(
            dns_ip,
            client_ip,
            parsed.dst_port,
            parsed.src_port,
            &dns_response,
        ),
        _ => {
            debug!("DNS hijack: mismatched IP versions");
            return None;
        }
    };

    Some(ip_packet)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 构建一个标准的 DNS A 查询 payload（查询 google.com）
    fn build_dns_a_query(id: u16, name: &str) -> Vec<u8> {
        let mut data = Vec::new();

        // Header (12 bytes)
        data.extend_from_slice(&id.to_be_bytes()); // Transaction ID
        data.extend_from_slice(&0x0100u16.to_be_bytes()); // Flags: RD=1
        data.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT = 1
        data.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT = 0
        data.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT = 0
        data.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT = 0

        // QNAME
        for label in name.split('.') {
            data.push(label.len() as u8);
            data.extend_from_slice(label.as_bytes());
        }
        data.push(0x00); // 终止

        // QTYPE = A (1)
        data.extend_from_slice(&1u16.to_be_bytes());
        // QCLASS = IN (1)
        data.extend_from_slice(&1u16.to_be_bytes());

        data
    }

    /// 构建一个 DNS AAAA 查询 payload
    fn build_dns_aaaa_query(id: u16, name: &str) -> Vec<u8> {
        let mut data = Vec::new();

        // Header
        data.extend_from_slice(&id.to_be_bytes());
        data.extend_from_slice(&0x0100u16.to_be_bytes());
        data.extend_from_slice(&1u16.to_be_bytes());
        data.extend_from_slice(&0u16.to_be_bytes());
        data.extend_from_slice(&0u16.to_be_bytes());
        data.extend_from_slice(&0u16.to_be_bytes());

        for label in name.split('.') {
            data.push(label.len() as u8);
            data.extend_from_slice(label.as_bytes());
        }
        data.push(0x00);

        // QTYPE = AAAA (28)
        data.extend_from_slice(&28u16.to_be_bytes());
        // QCLASS = IN (1)
        data.extend_from_slice(&1u16.to_be_bytes());

        data
    }

    #[test]
    fn parse_dns_query_a_record() {
        let payload = build_dns_a_query(0x1234, "google.com");
        let query = parse_dns_query(&payload).unwrap();

        assert_eq!(query.id, 0x1234);
        assert_eq!(query.name, "google.com");
        assert_eq!(query.qtype, 1); // A record
        assert!(!query.raw_question.is_empty());
    }

    #[test]
    fn parse_dns_query_aaaa_record() {
        let payload = build_dns_aaaa_query(0xABCD, "example.org");
        let query = parse_dns_query(&payload).unwrap();

        assert_eq!(query.id, 0xABCD);
        assert_eq!(query.name, "example.org");
        assert_eq!(query.qtype, 28); // AAAA record
    }

    #[test]
    fn parse_dns_query_subdomain() {
        let payload = build_dns_a_query(0x5678, "www.example.com");
        let query = parse_dns_query(&payload).unwrap();

        assert_eq!(query.name, "www.example.com");
        assert_eq!(query.qtype, 1);
    }

    #[test]
    fn parse_dns_query_too_short() {
        assert!(parse_dns_query(&[0; 5]).is_none());
    }

    #[test]
    fn parse_dns_query_response_rejected() {
        // QR=1 的响应包应该被拒绝
        let mut payload = build_dns_a_query(0x1234, "google.com");
        payload[2] = 0x81; // 设置 QR=1
        assert!(parse_dns_query(&payload).is_none());
    }

    #[test]
    fn parse_dns_query_zero_qdcount() {
        let mut payload = build_dns_a_query(0x1234, "google.com");
        payload[4] = 0;
        payload[5] = 0; // QDCOUNT = 0
        assert!(parse_dns_query(&payload).is_none());
    }

    #[test]
    fn build_dns_response_a_record() {
        let payload = build_dns_a_query(0x1234, "google.com");
        let query = parse_dns_query(&payload).unwrap();

        let addrs = vec![
            IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
            IpAddr::V6(Ipv6Addr::LOCALHOST), // 应该被过滤掉
        ];

        let resp = build_dns_response(&query, &addrs);

        // 验证 header
        assert_eq!(u16::from_be_bytes([resp[0], resp[1]]), 0x1234); // ID
        assert_eq!(u16::from_be_bytes([resp[2], resp[3]]), 0x8180); // Flags
        assert_eq!(u16::from_be_bytes([resp[4], resp[5]]), 1); // QDCOUNT
        assert_eq!(u16::from_be_bytes([resp[6], resp[7]]), 1); // ANCOUNT (只有1个 IPv4)
        assert_eq!(u16::from_be_bytes([resp[8], resp[9]]), 0); // NSCOUNT
        assert_eq!(u16::from_be_bytes([resp[10], resp[11]]), 0); // ARCOUNT

        // 验证 question section 被原样复制
        let q_end = 12 + query.raw_question.len();
        assert_eq!(&resp[12..q_end], &query.raw_question);

        // 验证 answer section
        let ans_start = q_end;
        // NAME pointer
        assert_eq!(
            u16::from_be_bytes([resp[ans_start], resp[ans_start + 1]]),
            0xC00C
        );
        // TYPE = A
        assert_eq!(
            u16::from_be_bytes([resp[ans_start + 2], resp[ans_start + 3]]),
            1
        );
        // CLASS = IN
        assert_eq!(
            u16::from_be_bytes([resp[ans_start + 4], resp[ans_start + 5]]),
            1
        );
        // TTL = 60
        assert_eq!(
            u32::from_be_bytes([
                resp[ans_start + 6],
                resp[ans_start + 7],
                resp[ans_start + 8],
                resp[ans_start + 9]
            ]),
            60
        );
        // RDLENGTH = 4
        assert_eq!(
            u16::from_be_bytes([resp[ans_start + 10], resp[ans_start + 11]]),
            4
        );
        // RDATA = 1.2.3.4
        assert_eq!(&resp[ans_start + 12..ans_start + 16], &[1, 2, 3, 4]);
    }

    #[test]
    fn build_dns_response_aaaa_record() {
        let payload = build_dns_aaaa_query(0x5678, "example.com");
        let query = parse_dns_query(&payload).unwrap();

        let v6 = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let addrs = vec![
            IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), // 应该被过滤
            IpAddr::V6(v6),
        ];

        let resp = build_dns_response(&query, &addrs);

        // ANCOUNT = 1 (只有 AAAA)
        assert_eq!(u16::from_be_bytes([resp[6], resp[7]]), 1);

        let q_end = 12 + query.raw_question.len();
        let ans_start = q_end;
        // TYPE = AAAA (28)
        assert_eq!(
            u16::from_be_bytes([resp[ans_start + 2], resp[ans_start + 3]]),
            28
        );
        // RDLENGTH = 16
        assert_eq!(
            u16::from_be_bytes([resp[ans_start + 10], resp[ans_start + 11]]),
            16
        );
        // RDATA = IPv6 address
        assert_eq!(&resp[ans_start + 12..ans_start + 28], &v6.octets());
    }

    #[test]
    fn build_dns_response_no_matching_addrs() {
        let payload = build_dns_a_query(0x1234, "google.com");
        let query = parse_dns_query(&payload).unwrap();

        // 只有 AAAA 地址，但查询 A 记录
        let addrs = vec![IpAddr::V6(Ipv6Addr::LOCALHOST)];
        let resp = build_dns_response(&query, &addrs);

        // ANCOUNT = 0
        assert_eq!(u16::from_be_bytes([resp[6], resp[7]]), 0);
    }

    #[test]
    fn build_dns_response_empty_addrs() {
        let payload = build_dns_a_query(0x1234, "nonexist.local");
        let query = parse_dns_query(&payload).unwrap();

        let resp = build_dns_response(&query, &[]);
        assert_eq!(u16::from_be_bytes([resp[6], resp[7]]), 0);
    }

    #[test]
    fn is_dns_query_udp_53() {
        let parsed = ParsedPacket {
            version: 4,
            protocol: IpProtocol::Udp,
            src_ip: "10.0.0.1".parse().unwrap(),
            dst_ip: "8.8.8.8".parse().unwrap(),
            src_port: 50000,
            dst_port: 53,
            payload_offset: 20,
            total_len: 60,
        };
        assert!(is_dns_query(&parsed));
    }

    #[test]
    fn is_dns_query_tcp_53_false() {
        let parsed = ParsedPacket {
            version: 4,
            protocol: IpProtocol::Tcp,
            src_ip: "10.0.0.1".parse().unwrap(),
            dst_ip: "8.8.8.8".parse().unwrap(),
            src_port: 50000,
            dst_port: 53,
            payload_offset: 20,
            total_len: 60,
        };
        assert!(!is_dns_query(&parsed));
    }

    #[test]
    fn is_dns_query_udp_443_false() {
        let parsed = ParsedPacket {
            version: 4,
            protocol: IpProtocol::Udp,
            src_ip: "10.0.0.1".parse().unwrap(),
            dst_ip: "1.1.1.1".parse().unwrap(),
            src_port: 50000,
            dst_port: 443,
            payload_offset: 20,
            total_len: 60,
        };
        assert!(!is_dns_query(&parsed));
    }

    #[test]
    fn ipv4_checksum_correct() {
        // 构建一个已知 header 验证 checksum
        let pkt = build_ipv4_udp_packet(
            Ipv4Addr::new(8, 8, 8, 8),
            Ipv4Addr::new(10, 0, 0, 1),
            53,
            50000,
            &[0u8; 10],
        );

        // 对 header 重新计算 checksum 应该为 0
        let mut sum: u32 = 0;
        for i in (0..20).step_by(2) {
            sum += u16::from_be_bytes([pkt[i], pkt[i + 1]]) as u32;
        }
        while sum >> 16 != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        assert_eq!(sum as u16, 0xFFFF);
    }

    #[test]
    fn build_ipv4_udp_packet_structure() {
        let payload = b"hello dns";
        let pkt = build_ipv4_udp_packet(
            Ipv4Addr::new(8, 8, 8, 8),
            Ipv4Addr::new(10, 0, 0, 1),
            53,
            50000,
            payload,
        );

        // 总长度
        assert_eq!(pkt.len(), 20 + 8 + payload.len());

        // IP version + IHL
        assert_eq!(pkt[0], 0x45);
        // Protocol = UDP
        assert_eq!(pkt[9], 17);
        // Total Length
        assert_eq!(
            u16::from_be_bytes([pkt[2], pkt[3]]),
            (20 + 8 + payload.len()) as u16
        );
        // TTL
        assert_eq!(pkt[8], 64);
        // Src IP
        assert_eq!(&pkt[12..16], &[8, 8, 8, 8]);
        // Dst IP
        assert_eq!(&pkt[16..20], &[10, 0, 0, 1]);

        // UDP src port
        assert_eq!(u16::from_be_bytes([pkt[20], pkt[21]]), 53);
        // UDP dst port
        assert_eq!(u16::from_be_bytes([pkt[22], pkt[23]]), 50000);
        // UDP length
        assert_eq!(
            u16::from_be_bytes([pkt[24], pkt[25]]),
            (8 + payload.len()) as u16
        );

        // Payload
        assert_eq!(&pkt[28..], payload);
    }

    #[test]
    fn build_ipv6_udp_packet_structure() {
        let payload = b"hello v6";
        let src = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);
        let dst = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2);
        let pkt = build_ipv6_udp_packet(src, dst, 53, 50000, payload);

        // 总长度
        assert_eq!(pkt.len(), 40 + 8 + payload.len());

        // Version = 6
        assert_eq!(pkt[0] >> 4, 6);
        // Next Header = UDP
        assert_eq!(pkt[6], 17);
        // Hop Limit
        assert_eq!(pkt[7], 64);
        // Payload Length
        assert_eq!(
            u16::from_be_bytes([pkt[4], pkt[5]]),
            (8 + payload.len()) as u16
        );

        // Src addr
        assert_eq!(&pkt[8..24], &src.octets());
        // Dst addr
        assert_eq!(&pkt[24..40], &dst.octets());

        // UDP src port
        assert_eq!(u16::from_be_bytes([pkt[40], pkt[41]]), 53);
        // UDP dst port
        assert_eq!(u16::from_be_bytes([pkt[42], pkt[43]]), 50000);

        // Payload
        assert_eq!(&pkt[48..], payload);
    }

    #[test]
    fn build_dns_response_multiple_a_records() {
        let payload = build_dns_a_query(0x9999, "multi.example.com");
        let query = parse_dns_query(&payload).unwrap();

        let addrs = vec![
            IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
            IpAddr::V4(Ipv4Addr::new(2, 2, 2, 2)),
            IpAddr::V4(Ipv4Addr::new(3, 3, 3, 3)),
        ];

        let resp = build_dns_response(&query, &addrs);

        // ANCOUNT = 3
        assert_eq!(u16::from_be_bytes([resp[6], resp[7]]), 3);
    }
}
