// MASQUE 出站 — CONNECT-IP 协议层 (RFC 9484)
//
// 实现 IP Capsule 编解码和路由通告协议。
// CONNECT-IP 通过 HTTP/3 Extended CONNECT 建立 IP 隧道，
// IP 包经 Capsule Protocol 封装后在 HTTP/3 stream/datagram 上传输。

use std::net::IpAddr;

use anyhow::Result;
use bytes::{Buf, BufMut, BytesMut};

/// CONNECT-IP Capsule 类型（RFC 9484 Section 4）
#[repr(u64)]
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum CapsuleType {
    /// 分配地址给客户端
    AddressAssign = 0x01,
    /// 请求特定地址
    AddressRequest = 0x02,
    /// 通告可达路由
    RouteAdvertisement = 0x03,
}

/// IP 路由条目
#[derive(Debug, Clone)]
pub struct IpRoute {
    /// IP 协议号（0 = 所有协议）
    pub ip_protocol: u8,
    /// 起始 IP
    pub start_ip: IpAddr,
    /// 结束 IP
    pub end_ip: IpAddr,
}

impl IpRoute {
    /// 创建匹配所有 IPv4 的路由
    pub fn all_ipv4() -> Self {
        IpRoute {
            ip_protocol: 0,
            start_ip: IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0)),
            end_ip: IpAddr::V4(std::net::Ipv4Addr::new(255, 255, 255, 255)),
        }
    }

    /// 创建匹配所有 IPv6 的路由
    pub fn all_ipv6() -> Self {
        IpRoute {
            ip_protocol: 0,
            start_ip: IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED),
            end_ip: IpAddr::V6(std::net::Ipv6Addr::new(
                0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff,
            )),
        }
    }

    /// 编码为 wire format
    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8(self.ip_protocol);
        match self.start_ip {
            IpAddr::V4(v4) => {
                buf.put_u16(4); // IP 地址长度
                buf.put_slice(&v4.octets());
            }
            IpAddr::V6(v6) => {
                buf.put_u16(16);
                buf.put_slice(&v6.octets());
            }
        }
        match self.end_ip {
            IpAddr::V4(v4) => {
                buf.put_u16(4);
                buf.put_slice(&v4.octets());
            }
            IpAddr::V6(v6) => {
                buf.put_u16(16);
                buf.put_slice(&v6.octets());
            }
        }
    }
}

/// QUIC Variable-Length Integer 编码 (RFC 9000 Section 16)
pub fn encode_varint(value: u64, buf: &mut BytesMut) {
    if value <= 0x3f {
        buf.put_u8(value as u8);
    } else if value <= 0x3fff {
        buf.put_u16(0x4000 | value as u16);
    } else if value <= 0x3fff_ffff {
        buf.put_u32(0x8000_0000 | value as u32);
    } else {
        buf.put_u64(0xc000_0000_0000_0000 | value);
    }
}

/// QUIC Variable-Length Integer 解码
pub fn decode_varint(buf: &mut &[u8]) -> Result<u64> {
    if buf.is_empty() {
        anyhow::bail!("varint: buffer empty");
    }
    let first = buf[0];
    let len = 1 << (first >> 6);
    if buf.len() < len {
        anyhow::bail!("varint: buffer too short");
    }
    let value = match len {
        1 => {
            let v = buf[0] as u64 & 0x3f;
            buf.advance(1);
            v
        }
        2 => {
            let v = u16::from_be_bytes([buf[0], buf[1]]) as u64 & 0x3fff;
            buf.advance(2);
            v
        }
        4 => {
            let v = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as u64 & 0x3fff_ffff;
            buf.advance(4);
            v
        }
        8 => {
            let v = u64::from_be_bytes([
                buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7],
            ]) & 0x3fff_ffff_ffff_ffff;
            buf.advance(8);
            v
        }
        _ => unreachable!(),
    };
    Ok(value)
}

/// 编码 Capsule 帧
///
/// Capsule {
///   Capsule Type (i),
///   Capsule Length (i),
///   Capsule Value (..),
/// }
pub fn encode_capsule(capsule_type: u64, payload: &[u8], buf: &mut BytesMut) {
    encode_varint(capsule_type, buf);
    encode_varint(payload.len() as u64, buf);
    buf.put_slice(payload);
}

/// 编码路由通告 Capsule
///
/// 通告客户端希望路由的 IP 范围。
/// 通常发送 0.0.0.0/0 和 ::/0 表示全量路由。
pub fn encode_route_advertisement(routes: &[IpRoute]) -> BytesMut {
    let mut payload = BytesMut::new();
    for route in routes {
        route.encode(&mut payload);
    }
    let mut buf = BytesMut::new();
    encode_capsule(CapsuleType::RouteAdvertisement as u64, &payload, &mut buf);
    buf
}

/// Context ID 编码 — CONNECT-IP datagram 需要前缀 context ID
///
/// Context ID 0 表示隧道 IP 包。
pub fn encode_context_id(context_id: u64, buf: &mut BytesMut) {
    encode_varint(context_id, buf);
}

/// 将 IP 包封装为 CONNECT-IP datagram
///
/// 格式：[Context ID (varint)] [IP Packet]
pub fn encode_ip_datagram(ip_packet: &[u8]) -> BytesMut {
    let mut buf = BytesMut::with_capacity(1 + ip_packet.len());
    encode_context_id(0, &mut buf); // context_id = 0 → IP packet
    buf.put_slice(ip_packet);
    buf
}

/// 从 CONNECT-IP datagram 解码 IP 包
///
/// 返回 (context_id, ip_packet)
pub fn decode_ip_datagram(mut data: &[u8]) -> Result<(u64, &[u8])> {
    let ctx = decode_varint(&mut data)?;
    Ok((ctx, data))
}

/// HTTP/3 CONNECT-IP 请求 URI 默认值
pub const DEFAULT_CONNECT_URI: &str = "https://cloudflareaccess.com";
/// HTTP/3 CONNECT-IP 默认 SNI
pub const DEFAULT_CONNECT_SNI: &str = "consumer-masque.cloudflareclient.com";

/// Cloudflare 协议扩展 — SETTINGS_H3_DATAGRAM_00
pub const SETTINGS_H3_DATAGRAM_00: u64 = 0x276;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_varint_roundtrip() {
        let test_values = [0u64, 1, 63, 64, 16383, 16384, 0x3fff_ffff, 0x4000_0000];
        for val in test_values {
            let mut buf = BytesMut::new();
            encode_varint(val, &mut buf);
            let mut slice = buf.as_ref();
            let decoded = decode_varint(&mut slice).unwrap();
            assert_eq!(val, decoded, "varint roundtrip failed for {}", val);
        }
    }

    #[test]
    fn test_encode_ip_datagram() {
        let ip_packet = [0x45, 0x00, 0x00, 0x3c]; // IPv4 header start
        let datagram = encode_ip_datagram(&ip_packet);
        let mut data = datagram.as_ref();
        let (ctx, payload) = decode_ip_datagram(&mut data).unwrap();
        assert_eq!(ctx, 0);
        assert_eq!(payload, &ip_packet);
    }

    #[test]
    fn test_route_advertisement() {
        let routes = vec![IpRoute::all_ipv4(), IpRoute::all_ipv6()];
        let buf = encode_route_advertisement(&routes);
        // 验证编码不为空
        assert!(!buf.is_empty());
        // 第一个字节应该是 capsule type (0x03 = RouteAdvertisement)
        assert_eq!(buf[0], 0x03);
    }

    #[test]
    fn test_varint_edge_cases() {
        // 单字节最大值 (63)
        let mut buf = BytesMut::new();
        encode_varint(63, &mut buf);
        assert_eq!(buf.len(), 1);

        // 双字节最小值 (64)
        buf.clear();
        encode_varint(64, &mut buf);
        assert_eq!(buf.len(), 2);
    }
}
