use std::net::SocketAddr;
use std::sync::atomic::{AtomicU16, Ordering};

use anyhow::Result;

use crate::common::Address;

/// XUDP frame types
const XUDP_NEW: u8 = 0x01;
const XUDP_DATA: u8 = 0x02;
const XUDP_CLOSE: u8 = 0x03;
const XUDP_KEEPALIVE: u8 = 0x04;

/// XUDP address types
const ADDR_IPV4: u8 = 0x01;
const ADDR_DOMAIN: u8 = 0x03;
const ADDR_IPV6: u8 = 0x04;

#[derive(Debug, Clone)]
pub struct XudpFrame {
    pub frame_type: u8,
    pub session_id: u16,
    pub address: Option<Address>,
    pub payload: Vec<u8>,
}

impl XudpFrame {
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.push(self.frame_type);
        buf.extend_from_slice(&self.session_id.to_be_bytes());

        if let Some(ref addr) = self.address {
            match addr {
                Address::Ip(sock) => match sock {
                    SocketAddr::V4(v4) => {
                        buf.push(ADDR_IPV4);
                        buf.extend_from_slice(&v4.ip().octets());
                        buf.extend_from_slice(&v4.port().to_be_bytes());
                    }
                    SocketAddr::V6(v6) => {
                        buf.push(ADDR_IPV6);
                        buf.extend_from_slice(&v6.ip().octets());
                        buf.extend_from_slice(&v6.port().to_be_bytes());
                    }
                },
                Address::Domain(domain, port) => {
                    buf.push(ADDR_DOMAIN);
                    let domain_bytes = domain.as_bytes();
                    buf.push(domain_bytes.len() as u8);
                    buf.extend_from_slice(domain_bytes);
                    buf.extend_from_slice(&port.to_be_bytes());
                }
            }
        }

        let payload_len = self.payload.len() as u16;
        buf.extend_from_slice(&payload_len.to_be_bytes());
        buf.extend_from_slice(&self.payload);
        buf
    }

    pub fn decode(data: &[u8]) -> Result<(Self, usize)> {
        if data.len() < 3 {
            anyhow::bail!("insufficient data for xudp frame header");
        }
        let frame_type = data[0];
        let session_id = u16::from_be_bytes([data[1], data[2]]);
        let mut pos = 3;

        let address = if frame_type == XUDP_NEW || frame_type == XUDP_DATA {
            if pos >= data.len() {
                anyhow::bail!("insufficient data for xudp address type");
            }
            let addr_type = data[pos];
            pos += 1;
            match addr_type {
                ADDR_IPV4 => {
                    if pos + 6 > data.len() {
                        anyhow::bail!("insufficient data for xudp ipv4 address");
                    }
                    let ip = std::net::Ipv4Addr::new(data[pos], data[pos + 1], data[pos + 2], data[pos + 3]);
                    let port = u16::from_be_bytes([data[pos + 4], data[pos + 5]]);
                    pos += 6;
                    Some(Address::Ip(SocketAddr::from((ip, port))))
                }
                ADDR_IPV6 => {
                    if pos + 18 > data.len() {
                        anyhow::bail!("insufficient data for xudp ipv6 address");
                    }
                    let mut octets = [0u8; 16];
                    octets.copy_from_slice(&data[pos..pos + 16]);
                    let ip = std::net::Ipv6Addr::from(octets);
                    let port = u16::from_be_bytes([data[pos + 16], data[pos + 17]]);
                    pos += 18;
                    Some(Address::Ip(SocketAddr::from((ip, port))))
                }
                ADDR_DOMAIN => {
                    if pos >= data.len() {
                        anyhow::bail!("insufficient data for xudp domain length");
                    }
                    let domain_len = data[pos] as usize;
                    pos += 1;
                    if pos + domain_len + 2 > data.len() {
                        anyhow::bail!("insufficient data for xudp domain");
                    }
                    let domain = String::from_utf8_lossy(&data[pos..pos + domain_len]).to_string();
                    pos += domain_len;
                    let port = u16::from_be_bytes([data[pos], data[pos + 1]]);
                    pos += 2;
                    Some(Address::Domain(domain, port))
                }
                _ => anyhow::bail!("unknown xudp address type: {}", addr_type),
            }
        } else {
            None
        };

        if pos + 2 > data.len() {
            anyhow::bail!("insufficient data for xudp payload length");
        }
        let payload_len = u16::from_be_bytes([data[pos], data[pos + 1]]) as usize;
        pos += 2;
        if pos + payload_len > data.len() {
            anyhow::bail!("insufficient data for xudp payload");
        }
        let payload = data[pos..pos + payload_len].to_vec();
        pos += payload_len;

        Ok((
            XudpFrame {
                frame_type,
                session_id,
                address,
                payload,
            },
            pos,
        ))
    }

    pub fn new_session(session_id: u16, addr: Address) -> Self {
        XudpFrame {
            frame_type: XUDP_NEW,
            session_id,
            address: Some(addr),
            payload: Vec::new(),
        }
    }

    pub fn data(session_id: u16, addr: Address, payload: Vec<u8>) -> Self {
        XudpFrame {
            frame_type: XUDP_DATA,
            session_id,
            address: Some(addr),
            payload,
        }
    }

    pub fn close(session_id: u16) -> Self {
        XudpFrame {
            frame_type: XUDP_CLOSE,
            session_id,
            address: None,
            payload: Vec::new(),
        }
    }

    pub fn keepalive() -> Self {
        XudpFrame {
            frame_type: XUDP_KEEPALIVE,
            session_id: 0,
            address: None,
            payload: Vec::new(),
        }
    }
}

/// XUDP multiplexer for UDP-over-TCP
pub struct XudpMux {
    next_session_id: AtomicU16,
}

impl XudpMux {
    pub fn new() -> Self {
        Self {
            next_session_id: AtomicU16::new(1),
        }
    }

    pub fn allocate_session_id(&self) -> u16 {
        self.next_session_id.fetch_add(1, Ordering::Relaxed)
    }

    pub fn encode_frames(frames: &[XudpFrame]) -> Vec<u8> {
        let mut buf = Vec::new();
        for frame in frames {
            buf.extend_from_slice(&frame.encode());
        }
        buf
    }

    pub fn decode_frames(data: &[u8]) -> Result<(Vec<XudpFrame>, usize)> {
        let mut frames = Vec::new();
        let mut consumed = 0;
        while consumed < data.len() {
            match XudpFrame::decode(&data[consumed..]) {
                Ok((frame, size)) => {
                    consumed += size;
                    frames.push(frame);
                }
                Err(_) => break,
            }
        }
        Ok((frames, consumed))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xudp_frame_data_ipv4_roundtrip() {
        let addr = Address::Ip("1.2.3.4:8080".parse().unwrap());
        let frame = XudpFrame::data(42, addr, b"hello udp".to_vec());
        let encoded = frame.encode();
        let (decoded, size) = XudpFrame::decode(&encoded).unwrap();
        assert_eq!(size, encoded.len());
        assert_eq!(decoded.session_id, 42);
        assert_eq!(decoded.payload, b"hello udp");
        match decoded.address.unwrap() {
            Address::Ip(sock) => assert_eq!(sock.to_string(), "1.2.3.4:8080"),
            _ => panic!("expected ip address"),
        }
    }

    #[test]
    fn xudp_frame_data_domain_roundtrip() {
        let addr = Address::Domain("example.com".to_string(), 443);
        let frame = XudpFrame::data(7, addr, b"domain data".to_vec());
        let encoded = frame.encode();
        let (decoded, size) = XudpFrame::decode(&encoded).unwrap();
        assert_eq!(size, encoded.len());
        assert_eq!(decoded.session_id, 7);
        match decoded.address.unwrap() {
            Address::Domain(domain, port) => {
                assert_eq!(domain, "example.com");
                assert_eq!(port, 443);
            }
            _ => panic!("expected domain address"),
        }
    }

    #[test]
    fn xudp_frame_ipv6_roundtrip() {
        let addr = Address::Ip("[::1]:53".parse().unwrap());
        let frame = XudpFrame::data(3, addr, b"v6".to_vec());
        let encoded = frame.encode();
        let (decoded, _) = XudpFrame::decode(&encoded).unwrap();
        match decoded.address.unwrap() {
            Address::Ip(sock) => assert!(sock.is_ipv6()),
            _ => panic!("expected ipv6 address"),
        }
    }

    #[test]
    fn xudp_frame_new_session() {
        let addr = Address::Ip("10.0.0.1:1234".parse().unwrap());
        let frame = XudpFrame::new_session(100, addr);
        let encoded = frame.encode();
        let (decoded, _) = XudpFrame::decode(&encoded).unwrap();
        assert_eq!(decoded.frame_type, XUDP_NEW);
        assert_eq!(decoded.session_id, 100);
        assert!(decoded.address.is_some());
    }

    #[test]
    fn xudp_frame_close() {
        let frame = XudpFrame::close(55);
        let encoded = frame.encode();
        let (decoded, _) = XudpFrame::decode(&encoded).unwrap();
        assert_eq!(decoded.frame_type, XUDP_CLOSE);
        assert_eq!(decoded.session_id, 55);
        assert!(decoded.address.is_none());
    }

    #[test]
    fn xudp_frame_keepalive() {
        let frame = XudpFrame::keepalive();
        let encoded = frame.encode();
        let (decoded, _) = XudpFrame::decode(&encoded).unwrap();
        assert_eq!(decoded.frame_type, XUDP_KEEPALIVE);
        assert_eq!(decoded.session_id, 0);
    }

    #[test]
    fn xudp_mux_allocate_ids() {
        let mux = XudpMux::new();
        assert_eq!(mux.allocate_session_id(), 1);
        assert_eq!(mux.allocate_session_id(), 2);
        assert_eq!(mux.allocate_session_id(), 3);
    }

    #[test]
    fn xudp_multiple_frames_roundtrip() {
        let addr1 = Address::Ip("1.1.1.1:53".parse().unwrap());
        let addr2 = Address::Domain("dns.google".to_string(), 853);
        let frames = vec![
            XudpFrame::data(1, addr1, b"query1".to_vec()),
            XudpFrame::data(2, addr2, b"query2".to_vec()),
        ];
        let buf = XudpMux::encode_frames(&frames);
        let (decoded, consumed) = XudpMux::decode_frames(&buf).unwrap();
        assert_eq!(consumed, buf.len());
        assert_eq!(decoded.len(), 2);
        assert_eq!(decoded[0].session_id, 1);
        assert_eq!(decoded[1].session_id, 2);
    }
}
