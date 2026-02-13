use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;

use anyhow::Result;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info};

use crate::app::dispatcher::Dispatcher;
use crate::common::Address;
use crate::proxy::inbound::tun_device::{
    IcmpPolicy, IpProtocol, TunConfig, create_platform_tun_device, parse_ip_packet,
};
use crate::proxy::{Network, Session};
use crate::router::Router;

pub struct TunInbound {
    tag: String,
    name: String,
    icmp_policy: IcmpPolicy,
    dns_hijack_enabled: bool,
}

pub struct TunRouteDecision {
    pub session: Session,
    pub outbound_tag: String,
    pub route_tag: String,
}

impl TunInbound {
    pub fn new(tag: String, name: String) -> Self {
        Self {
            tag,
            name,
            icmp_policy: IcmpPolicy::Drop,
            dns_hijack_enabled: true,
        }
    }

    pub fn with_dns_hijack(mut self, enabled: bool) -> Self {
        self.dns_hijack_enabled = enabled;
        self
    }

    pub fn with_icmp_policy(mut self, icmp_policy: IcmpPolicy) -> Self {
        self.icmp_policy = icmp_policy;
        self
    }

    pub fn tag(&self) -> &str {
        &self.tag
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn dns_hijack_enabled(&self) -> bool {
        self.dns_hijack_enabled
    }

    pub fn session_from_packet(&self, packet: &[u8]) -> Result<Session> {
        if packet.is_empty() {
            anyhow::bail!("tun packet is empty");
        }

        match packet[0] >> 4 {
            4 => self.session_from_ipv4(packet),
            6 => self.session_from_ipv6(packet),
            other => anyhow::bail!("unsupported ip version: {}", other),
        }
    }

    fn session_from_ipv4(&self, packet: &[u8]) -> Result<Session> {
        if packet.len() < 20 {
            anyhow::bail!("tun packet too short for ipv4 header");
        }

        let ihl_words = packet[0] & 0x0f;
        let ihl = (ihl_words as usize) * 4;
        if ihl < 20 || packet.len() < ihl + 4 {
            anyhow::bail!("invalid ipv4 header length");
        }

        let protocol = packet[9];
        let src_ip = Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]);
        let dst_ip = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);

        let src_port = u16::from_be_bytes([packet[ihl], packet[ihl + 1]]);
        let dst_port = u16::from_be_bytes([packet[ihl + 2], packet[ihl + 3]]);

        let network = match protocol {
            6 => Network::Tcp,
            17 => Network::Udp,
            other => anyhow::bail!("unsupported ipv4 protocol: {}", other),
        };

        Ok(Session {
            target: Address::Ip(SocketAddr::new(IpAddr::V4(dst_ip), dst_port)),
            source: Some(SocketAddr::new(IpAddr::V4(src_ip), src_port)),
            inbound_tag: self.tag.clone(),
            network,
            sniff: false,
            detected_protocol: None,
        })
    }

    fn session_from_ipv6(&self, packet: &[u8]) -> Result<Session> {
        if packet.len() < 44 {
            anyhow::bail!("tun packet too short for ipv6 header");
        }

        let next_header = packet[6];

        let mut src_octets = [0u8; 16];
        src_octets.copy_from_slice(&packet[8..24]);
        let src_ip = Ipv6Addr::from(src_octets);

        let mut dst_octets = [0u8; 16];
        dst_octets.copy_from_slice(&packet[24..40]);
        let dst_ip = Ipv6Addr::from(dst_octets);

        let l4_offset = 40;
        let src_port = u16::from_be_bytes([packet[l4_offset], packet[l4_offset + 1]]);
        let dst_port = u16::from_be_bytes([packet[l4_offset + 2], packet[l4_offset + 3]]);

        let network = match next_header {
            6 => Network::Tcp,
            17 => Network::Udp,
            other => anyhow::bail!("unsupported ipv6 next-header: {}", other),
        };

        Ok(Session {
            target: Address::Ip(SocketAddr::new(IpAddr::V6(dst_ip), dst_port)),
            source: Some(SocketAddr::new(IpAddr::V6(src_ip), src_port)),
            inbound_tag: self.tag.clone(),
            network,
            sniff: false,
            detected_protocol: None,
        })
    }

    pub fn route_packet(&self, router: &Router, packet: &[u8]) -> Result<TunRouteDecision> {
        let session = self.session_from_packet(packet)?;
        let (outbound_tag, matched_rule) = router.route_with_rule(&session);
        let route_tag = matched_rule
            .as_deref()
            .unwrap_or("MATCH")
            .to_string();

        Ok(TunRouteDecision {
            session,
            outbound_tag: outbound_tag.to_string(),
            route_tag,
        })
    }

    pub async fn run(&self, dispatcher: Arc<Dispatcher>, cancel: CancellationToken) -> Result<()> {
        let mut tun_config = TunConfig::default();
        tun_config.name = self.name.clone();
        let tun_device = create_platform_tun_device(&tun_config)?;

        info!(
            tag = self.tag(),
            device = tun_device.name(),
            mtu = tun_device.mtu(),
            "tun inbound started"
        );

        let mut read_buf = vec![0u8; 65535];
        let mut consecutive_errors: u32 = 0;
        const MAX_CONSECUTIVE_ERRORS: u32 = 50;

        loop {
            tokio::select! {
                _ = cancel.cancelled() => {
                    debug!(tag = self.tag(), "tun inbound cancellation received");
                    break;
                }
                read_result = tun_device.read_packet(&mut read_buf) => {
                    let packet_len = match read_result {
                        Ok(len) => {
                            consecutive_errors = 0;
                            len
                        }
                        Err(err) => {
                            consecutive_errors += 1;
                            if consecutive_errors >= MAX_CONSECUTIVE_ERRORS {
                                tracing::error!(
                                    tag = self.tag(),
                                    errors = consecutive_errors,
                                    error = %err,
                                    "tun device: too many consecutive read errors, stopping"
                                );
                                break;
                            }
                            // 指数退避（1ms→2ms→...→128ms）
                            let delay_ms = 1u64 << consecutive_errors.min(7);
                            debug!(
                                tag = self.tag(),
                                error = %err,
                                consecutive = consecutive_errors,
                                backoff_ms = delay_ms,
                                "tun read error, backing off"
                            );
                            tokio::time::sleep(std::time::Duration::from_millis(delay_ms)).await;
                            continue;
                        }
                    };

                    if packet_len == 0 {
                        continue;
                    }

                    let packet = &read_buf[..packet_len];
                    let parsed = match parse_ip_packet(packet) {
                        Ok(parsed) => parsed,
                        Err(err) => {
                            debug!(tag = self.tag(), error = %err, "failed to parse IP packet");
                            continue;
                        }
                    };

                    if !self.icmp_policy.should_process(&parsed) {
                        continue;
                    }

                    // DNS 劫持：拦截 UDP:53 包
                    if self.dns_hijack_enabled && super::dns_hijack::is_dns_query(&parsed) {
                        let resolver = dispatcher.resolver().await;
                        if let Some(response) = super::dns_hijack::handle_dns_hijack(
                            &parsed,
                            packet,
                            resolver.as_ref(),
                        ).await {
                            if let Err(e) = tun_device.write_packet(&response).await {
                                debug!(error = %e, "failed to write DNS response");
                            } else {
                                debug!(
                                    domain = %parsed.dst_ip,
                                    src = %parsed.src_ip,
                                    "DNS hijack: responded"
                                );
                            }
                        }
                        continue;
                    }

                    match parsed.protocol {
                        IpProtocol::Tcp | IpProtocol::Udp => {
                            let session = match self.session_from_packet(packet) {
                                Ok(s) => s,
                                Err(err) => {
                                    debug!(tag = self.tag(), error = %err, "failed to build session from packet");
                                    continue;
                                }
                            };

                            let router = dispatcher.router().await;
                            let (outbound_tag, _) = router.route_with_rule(&session);
                            debug!(
                                tag = self.tag(),
                                target = %session.target,
                                network = ?session.network,
                                outbound = outbound_tag,
                                "tun packet routed"
                            );
                        }
                        IpProtocol::Icmp => {
                            if self.icmp_policy == IcmpPolicy::Passthrough {
                                let _ = tun_device.write_packet(packet).await;
                            }
                        }
                        IpProtocol::Other(protocol) => {
                            debug!(tag = self.tag(), protocol, "unsupported transport protocol in tun packet");
                        }
                    }
                }
            }
        }

        if let Err(err) = tun_device.close().await {
            debug!(tag = self.tag(), error = %err, "failed to close tun device");
        }
        info!(tag = self.tag(), device = self.name(), "tun inbound stopped");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use crate::config::types::{
        RouterConfig, RuleConfig,
    };

    use super::*;

    fn build_ipv4_packet(protocol: u8, src: [u8; 4], dst: [u8; 4], src_port: u16, dst_port: u16) -> Vec<u8> {
        let mut pkt = vec![0u8; 40];
        pkt[0] = 0x45; // IPv4 + IHL=5
        pkt[9] = protocol;
        pkt[12..16].copy_from_slice(&src);
        pkt[16..20].copy_from_slice(&dst);
        pkt[20..22].copy_from_slice(&src_port.to_be_bytes());
        pkt[22..24].copy_from_slice(&dst_port.to_be_bytes());
        pkt
    }

    fn build_ipv6_packet(next_header: u8, src: [u8; 16], dst: [u8; 16], src_port: u16, dst_port: u16) -> Vec<u8> {
        let mut pkt = vec![0u8; 60];
        pkt[0] = 0x60; // IPv6
        pkt[6] = next_header;
        pkt[8..24].copy_from_slice(&src);
        pkt[24..40].copy_from_slice(&dst);
        pkt[40..42].copy_from_slice(&src_port.to_be_bytes());
        pkt[42..44].copy_from_slice(&dst_port.to_be_bytes());
        pkt
    }

    #[test]
    fn tun_session_from_ipv4_tcp_packet() {
        let tun = TunInbound::new("tun-in".to_string(), "openworld-utun0".to_string());
        let pkt = build_ipv4_packet(6, [10, 0, 0, 2], [1, 1, 1, 1], 50000, 443);

        let session = tun.session_from_packet(&pkt).unwrap();
        assert_eq!(session.network, Network::Tcp);
        assert_eq!(session.inbound_tag, "tun-in");
        assert_eq!(session.target, Address::Ip("1.1.1.1:443".parse().unwrap()));
        assert_eq!(session.source, Some("10.0.0.2:50000".parse().unwrap()));
    }

    #[test]
    fn tun_session_from_ipv4_udp_packet() {
        let tun = TunInbound::new("tun-in".to_string(), "openworld-utun0".to_string());
        let pkt = build_ipv4_packet(17, [10, 0, 0, 3], [8, 8, 8, 8], 53000, 53);

        let session = tun.session_from_packet(&pkt).unwrap();
        assert_eq!(session.network, Network::Udp);
        assert_eq!(session.target, Address::Ip("8.8.8.8:53".parse().unwrap()));
    }

    #[test]
    fn tun_route_packet_uses_router_snapshot() {
        let tun = TunInbound::new("tun-in".to_string(), "openworld-utun0".to_string());
        let router_cfg = RouterConfig {
            rules: vec![RuleConfig {
                rule_type: "ip-cidr".to_string(),
                values: vec!["1.1.1.0/24".to_string()],
                outbound: "proxy-a".to_string(),
            ..Default::default()
            }],
            default: "direct".to_string(),
            geoip_db: None,
            geosite_db: None,
            rule_providers: Default::default(),
            geoip_url: None,
            geosite_url: None,
            geo_update_interval: 7 * 24 * 3600,
            geo_auto_update: false,
        };
        let router = Router::new(&router_cfg).unwrap();
        let pkt = build_ipv4_packet(6, [10, 0, 0, 2], [1, 1, 1, 1], 50000, 443);

        let decision = tun.route_packet(&router, &pkt).unwrap();
        assert_eq!(decision.outbound_tag, "proxy-a");
        assert_eq!(decision.route_tag, "ip-cidr(1.1.1.0/24)");
    }

    #[test]
    fn tun_session_from_ipv6_tcp_packet() {
        let tun = TunInbound::new("tun-in".to_string(), "openworld-utun0".to_string());
        let pkt = build_ipv6_packet(
            6,
            [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
            [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2],
            51000,
            443,
        );

        let session = tun.session_from_packet(&pkt).unwrap();
        assert_eq!(session.network, Network::Tcp);
        assert_eq!(
            session.target,
            Address::Ip("[2001:db8::2]:443".parse().unwrap())
        );
        assert_eq!(
            session.source,
            Some("[2001:db8::1]:51000".parse().unwrap())
        );
    }

    #[test]
    fn tun_session_from_ipv6_udp_packet() {
        let tun = TunInbound::new("tun-in".to_string(), "openworld-utun0".to_string());
        let pkt = build_ipv6_packet(
            17,
            [0x24, 0x08, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
            [0x20, 0x01, 0x48, 0x60, 0x48, 0x60, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x88],
            53000,
            53,
        );

        let session = tun.session_from_packet(&pkt).unwrap();
        assert_eq!(session.network, Network::Udp);
        assert_eq!(
            session.target,
            Address::Ip("[2001:4860:4860::88]:53".parse().unwrap())
        );
    }
}
