use std::sync::Arc;

use async_trait::async_trait;
use openworld::app::dispatcher::Dispatcher;
use openworld::app::outbound_manager::OutboundManager;
use openworld::app::tracker::ConnectionTracker;
use openworld::common::{Address, UdpPacket};
use openworld::config::types::{
    Config, InboundConfig, InboundSettings, LogConfig, OutboundConfig, OutboundSettings,
    RouterConfig, SniffingConfig,
};
use openworld::dns::DnsResolver;
use openworld::proxy::outbound::direct::DirectOutbound;
use openworld::proxy::{InboundResult, Network, OutboundHandler, Session};
use openworld::router::Router;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

struct MockResolver;

#[async_trait::async_trait]
impl DnsResolver for MockResolver {
    async fn resolve(&self, _host: &str) -> anyhow::Result<Vec<std::net::IpAddr>> {
        Ok(vec![std::net::IpAddr::V4(std::net::Ipv4Addr::new(
            127, 0, 0, 1,
        ))])
    }
}

struct PendingStream;

impl AsyncRead for PendingStream {
    fn poll_read(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        _buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Poll::Pending
    }
}

impl AsyncWrite for PendingStream {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        _buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Poll::Pending
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Pending
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Pending
    }
}

struct MockUnsupportedUdpOutbound;

#[async_trait]
impl OutboundHandler for MockUnsupportedUdpOutbound {
    fn tag(&self) -> &str {
        "mock-udp-unsupported"
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }

    async fn connect(&self, _session: &Session) -> anyhow::Result<openworld::common::ProxyStream> {
        anyhow::bail!("not used")
    }
}

#[test]
fn phase3_config_validate_baseline_ok() {
    let config = Config {
        log: LogConfig {
            level: "info".to_string(),
        },
        profile: None,
        inbounds: vec![InboundConfig {
            tag: "socks-in".to_string(),
            protocol: "socks5".to_string(),
            listen: "127.0.0.1".to_string(),
            port: 1080,
            sniffing: SniffingConfig::default(),
            settings: InboundSettings::default(),
        }],
        outbounds: vec![OutboundConfig {
            tag: "direct".to_string(),
            protocol: "direct".to_string(),
            settings: OutboundSettings::default(),
        }],
        router: RouterConfig {
            rules: vec![],
            default: "direct".to_string(),
            geoip_db: None,
            geosite_db: None,
            rule_providers: Default::default(),
        },
        api: None,
        dns: None,
        subscriptions: vec![],
        proxy_groups: vec![],
    };

    assert!(config.validate().is_ok());
}

#[test]
fn phase3_router_default_route_baseline() {
    let router_cfg = RouterConfig {
        rules: vec![],
        default: "direct".to_string(),
        geoip_db: None,
        geosite_db: None,
        rule_providers: Default::default(),
    };
    let router = Router::new(&router_cfg).unwrap();

    let session = Session {
        target: Address::Domain("example.com".to_string(), 443),
        source: None,
        inbound_tag: "test-in".to_string(),
        network: Network::Tcp,
        sniff: false,
    };

    assert_eq!(router.route(&session), "direct");
}

#[test]
fn phase3_outbound_manager_registers_direct() {
    let outbounds = vec![OutboundConfig {
        tag: "direct".to_string(),
        protocol: "direct".to_string(),
        settings: OutboundSettings::default(),
    }];

    let manager = OutboundManager::new(&outbounds, &[]).unwrap();
    assert!(manager.get("direct").is_some());
    assert!(manager.get("missing").is_none());
}

#[tokio::test]
async fn phase3_direct_udp_send_recv_loopback_baseline() {
    let outbound = DirectOutbound::new("direct".to_string());

    let session = Session {
        target: Address::Ip("127.0.0.1:53".parse().unwrap()),
        source: None,
        inbound_tag: "test-in".to_string(),
        network: Network::Udp,
        sniff: false,
    };

    let transport = outbound.connect_udp(&session).await.unwrap();

    let server = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let server_addr = server.local_addr().unwrap();

    let payload = bytes::Bytes::from_static(b"phase3-udp-baseline");
    transport
        .send(UdpPacket {
            addr: Address::Ip(server_addr),
            data: payload.clone(),
        })
        .await
        .unwrap();

    let mut buf = [0u8; 256];
    let (n, from) = server.recv_from(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], payload.as_ref());

    server.send_to(b"phase3-udp-reply", from).await.unwrap();

    let reply = transport.recv().await.unwrap();
    assert_eq!(reply.addr, Address::Ip(server_addr));
    assert_eq!(reply.data.as_ref(), b"phase3-udp-reply");
}

#[tokio::test]
async fn phase3_dispatcher_udp_requires_inbound_transport() {
    let router_cfg = RouterConfig {
        rules: vec![],
        default: "direct".to_string(),
        geoip_db: None,
        geosite_db: None,
        rule_providers: Default::default(),
    };
    let router = Arc::new(Router::new(&router_cfg).unwrap());

    let outbounds = vec![OutboundConfig {
        tag: "direct".to_string(),
        protocol: "direct".to_string(),
        settings: OutboundSettings::default(),
    }];
    let outbound_manager = Arc::new(OutboundManager::new(&outbounds, &[]).unwrap());
    let tracker = Arc::new(ConnectionTracker::new());
    let dispatcher = Dispatcher::new(router, outbound_manager, tracker, Arc::new(MockResolver) as Arc<dyn DnsResolver>);

    let session = Session {
        target: Address::Domain("example.com".to_string(), 53),
        source: None,
        inbound_tag: "test-in".to_string(),
        network: Network::Udp,
        sniff: false,
    };

    let inbound = InboundResult {
        session,
        stream: Box::new(PendingStream),
        udp_transport: None,
    };

    let err = dispatcher.dispatch(inbound).await.unwrap_err();
    assert!(
        err.to_string()
            .contains("udp session missing inbound transport"),
        "unexpected error: {err}"
    );
}

#[tokio::test]
async fn phase3_outbound_default_udp_not_supported_returns_error() {
    let outbound = MockUnsupportedUdpOutbound;
    let session = Session {
        target: Address::Domain("example.com".to_string(), 53),
        source: None,
        inbound_tag: "test-in".to_string(),
        network: Network::Udp,
        sniff: false,
    };

    let err_text = match outbound.connect_udp(&session).await {
        Ok(_) => panic!("expected UDP unsupported error"),
        Err(e) => e.to_string(),
    };
    assert!(
        err_text.contains("UDP not supported by outbound 'mock-udp-unsupported'"),
        "unexpected error: {err_text}"
    );
}

#[test]
fn phase3_inbound_result_udp_field_wiring_baseline() {
    let session = Session {
        target: Address::Domain("example.com".to_string(), 443),
        source: None,
        inbound_tag: "test-in".to_string(),
        network: Network::Tcp,
        sniff: false,
    };

    let stream: openworld::common::ProxyStream = Box::new(tokio::io::empty());
    let result = InboundResult {
        session,
        stream,
        udp_transport: None,
    };

    assert!(result.udp_transport.is_none());
}

#[test]
fn phase3_dispatcher_construction_baseline() {
    let router_cfg = RouterConfig {
        rules: vec![],
        default: "direct".to_string(),
        geoip_db: None,
        geosite_db: None,
        rule_providers: Default::default(),
    };
    let router = Arc::new(Router::new(&router_cfg).unwrap());

    let outbounds = vec![OutboundConfig {
        tag: "direct".to_string(),
        protocol: "direct".to_string(),
        settings: OutboundSettings::default(),
    }];
    let outbound_manager = Arc::new(OutboundManager::new(&outbounds, &[]).unwrap());

    let tracker = Arc::new(ConnectionTracker::new());
    let _dispatcher = Dispatcher::new(router, outbound_manager, tracker, Arc::new(MockResolver) as Arc<dyn DnsResolver>);
}
