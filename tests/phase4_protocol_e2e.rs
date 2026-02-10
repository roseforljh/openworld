//! Phase 4 协议级端到端测试
//!
//! 覆盖：
//! - VLESS over TLS TCP echo
//! - VLESS + XTLS-Vision TCP echo
//! - VLESS + Reality(X.509 fallback) TCP echo
//! - Hysteria2 TCP echo
//! - Hysteria2 UDP Datagram echo

use std::net::SocketAddr;
use std::sync::{Arc, Once};
use std::time::Duration;

use anyhow::{Context, Result};
use bytes::{Bytes, Bytes as H3Bytes};
use http::{Method, Response, StatusCode};
use openworld::common::{Address, ProxyStream, UdpPacket};
use openworld::config::types::{OutboundConfig, OutboundSettings};
use openworld::proxy::outbound::hysteria2::{protocol as hy2_protocol, Hysteria2Outbound};
use openworld::proxy::outbound::vless::protocol as vless_protocol;
use openworld::proxy::outbound::vless::reality::{
    build_reality_config_with_roots, RealityConfig,
};
use openworld::proxy::outbound::vless::tls::build_tls_config_with_roots;
use openworld::proxy::outbound::vless::vision::VisionStream;
use openworld::proxy::outbound::vless::{VlessOutbound, XRV};
use openworld::proxy::{Network, OutboundHandler, Session};
use rand::RngCore;
use rcgen::{
    BasicConstraints, CertificateParams, IsCa, KeyPair, KeyUsagePurpose, PKCS_ED25519,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use rustls::ServerConfig;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;
use tokio_rustls::{TlsAcceptor, TlsConnector};

const TEST_UUID_STR: &str = "550e8400-e29b-41d4-a716-446655440000";

static INIT_CRYPTO_PROVIDER: Once = Once::new();

fn ensure_crypto_provider() {
    INIT_CRYPTO_PROVIDER.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

// ============================================================
// 辅助函数
// ============================================================

fn test_session(target: Address, network: Network) -> Session {
    Session {
        target,
        source: None,
        inbound_tag: "phase4-test".to_string(),
        network,
    }
}

fn build_vless_config(server: SocketAddr, flow: Option<String>) -> OutboundConfig {
    OutboundConfig {
        tag: "vless-test".to_string(),
        protocol: "vless".to_string(),
        settings: OutboundSettings {
            address: Some(server.ip().to_string()),
            port: Some(server.port()),
            uuid: Some(TEST_UUID_STR.to_string()),
            security: Some("tls".to_string()),
            sni: Some("localhost".to_string()),
            allow_insecure: true,
            flow,
            ..Default::default()
        },
    }
}

fn build_hysteria2_config(server: SocketAddr, password: &str) -> OutboundConfig {
    OutboundConfig {
        tag: "hy2-test".to_string(),
        protocol: "hysteria2".to_string(),
        settings: OutboundSettings {
            address: Some(server.ip().to_string()),
            port: Some(server.port()),
            password: Some(password.to_string()),
            sni: Some("localhost".to_string()),
            allow_insecure: true,
            ..Default::default()
        },
    }
}

fn build_tls_acceptor(
    cert_chain: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
) -> Result<TlsAcceptor> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let server_config = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()?
        .with_no_client_auth()
        .with_single_cert(cert_chain, key)?;
    Ok(TlsAcceptor::from(Arc::new(server_config)))
}

fn generate_test_tls_cert(
    domain: &str,
) -> Result<(
    Vec<CertificateDer<'static>>,
    PrivateKeyDer<'static>,
    CertificateDer<'static>,
)> {
    let mut ca_params = CertificateParams::new(Vec::<String>::new())?;
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    ca_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "OpenWorld Phase4 Test CA");

    let ca_key = KeyPair::generate_for(&PKCS_ED25519)?;
    let ca_cert = ca_params.self_signed(&ca_key)?;

    let mut server_params = CertificateParams::new(vec![domain.to_string()])?;
    server_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, domain);
    server_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];

    let server_key = KeyPair::generate_for(&PKCS_ED25519)?;
    let server_cert = server_params.signed_by(&server_key, &ca_cert, &ca_key)?;

    let ca_der = CertificateDer::from(ca_cert.der().to_vec());
    let cert_chain = vec![CertificateDer::from(server_cert.der().to_vec()), ca_der.clone()];
    let key = PrivateKeyDer::from(PrivatePkcs8KeyDer::from(server_key.serialize_der()));

    Ok((cert_chain, key, ca_der))
}

async fn read_vless_request<S>(stream: &mut S) -> Result<(uuid::Uuid, u8, Address, Option<String>)>
where
    S: AsyncRead + Unpin,
{
    let version = stream.read_u8().await?;
    if version != 0x00 {
        anyhow::bail!("unexpected VLESS version: 0x{version:02x}");
    }

    let mut uuid_bytes = [0u8; 16];
    stream.read_exact(&mut uuid_bytes).await?;
    let user_uuid = uuid::Uuid::from_bytes(uuid_bytes);

    let addons_len = stream.read_u8().await? as usize;
    let mut addons = vec![0u8; addons_len];
    if addons_len > 0 {
        stream.read_exact(&mut addons).await?;
    }

    let flow = if addons_len >= 2 && addons[0] == 0x0A {
        let flow_len = addons[1] as usize;
        if 2 + flow_len <= addons_len {
            Some(String::from_utf8(addons[2..2 + flow_len].to_vec())?)
        } else {
            None
        }
    } else {
        None
    };

    let command = stream.read_u8().await?;
    let port = stream.read_u16().await?;

    let atyp = stream.read_u8().await?;
    let target = match atyp {
        0x01 => {
            let mut ip = [0u8; 4];
            stream.read_exact(&mut ip).await?;
            Address::Ip(SocketAddr::from((ip, port)))
        }
        0x02 => {
            let len = stream.read_u8().await? as usize;
            let mut domain = vec![0u8; len];
            stream.read_exact(&mut domain).await?;
            Address::Domain(String::from_utf8(domain)?, port)
        }
        0x03 => {
            let mut ip = [0u8; 16];
            stream.read_exact(&mut ip).await?;
            Address::Ip(SocketAddr::from((std::net::Ipv6Addr::from(ip), port)))
        }
        _ => anyhow::bail!("unsupported VLESS address type: 0x{atyp:02x}"),
    };

    Ok((user_uuid, command, target, flow))
}

async fn write_vless_response<S>(stream: &mut S) -> Result<()>
where
    S: AsyncWrite + Unpin,
{
    stream.write_all(&[0x00, 0x00]).await?;
    stream.flush().await?;
    Ok(())
}

async fn echo_once<S>(stream: &mut S) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut buf = [0u8; 4096];
    let n = tokio::time::timeout(Duration::from_secs(10), stream.read(&mut buf))
        .await
        .context("echo read timeout")??;

    if n == 0 {
        return Ok(());
    }

    stream.write_all(&buf[..n]).await?;
    stream.flush().await?;
    Ok(())
}

async fn start_mock_vless_tls_server(
    cert_chain: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
    use_vision: bool,
) -> Result<(SocketAddr, JoinHandle<Result<()>>)> {
    let acceptor = build_tls_acceptor(cert_chain, key)?;
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;

    let task = tokio::spawn(async move {
        let (tcp, _) = listener.accept().await?;
        let mut tls = acceptor.accept(tcp).await?;

        let (user_uuid, command, _target, flow) = read_vless_request(&mut tls).await?;
        if command != vless_protocol::CMD_TCP {
            anyhow::bail!("unexpected VLESS command: {command}");
        }

        if use_vision && flow.as_deref() != Some(XRV) {
            anyhow::bail!("expected Vision flow in addons, got {flow:?}");
        }

        write_vless_response(&mut tls).await?;

        if use_vision {
            let inner: ProxyStream = Box::new(tls);
            let mut vision = VisionStream::new(inner, user_uuid);
            echo_once(&mut vision).await?;
        } else {
            echo_once(&mut tls).await?;
        }

        Ok(())
    });

    Ok((addr, task))
}

async fn read_exact_quinn(recv: &mut quinn::RecvStream, buf: &mut [u8]) -> Result<()> {
    let mut offset = 0;
    while offset < buf.len() {
        let n = recv
            .read(&mut buf[offset..])
            .await?
            .ok_or_else(|| anyhow::anyhow!("QUIC stream closed unexpectedly"))?;
        offset += n;
    }
    Ok(())
}

async fn read_hy2_varint(recv: &mut quinn::RecvStream) -> Result<u64> {
    let mut first = [0u8; 1];
    read_exact_quinn(recv, &mut first).await?;

    let len = match first[0] >> 6 {
        0 => 1,
        1 => 2,
        2 => 4,
        3 => 8,
        _ => unreachable!(),
    };

    let mut buf = vec![0u8; len];
    buf[0] = first[0];
    if len > 1 {
        read_exact_quinn(recv, &mut buf[1..]).await?;
    }

    let (v, consumed) = hy2_protocol::decode_varint_from_buf(&buf)?;
    if consumed != len {
        anyhow::bail!("invalid varint consumed size: expected {len}, got {consumed}");
    }
    Ok(v)
}

async fn handle_hysteria2_auth(conn: &quinn::Connection, password: &str) -> Result<()> {
    let h3_conn = h3_quinn::Connection::new(conn.clone());
    let mut h3_server = h3::server::builder()
        .build::<_, H3Bytes>(h3_conn)
        .await?;

    let resolver = tokio::time::timeout(Duration::from_secs(10), h3_server.accept())
        .await
        .context("h3 auth request timeout")??
        .ok_or_else(|| anyhow::anyhow!("h3 connection closed before auth request"))?;

    let (req, mut stream) = resolver.resolve_request().await?;

    let auth_ok = req.method() == Method::POST
        && req.uri().path() == "/auth"
        && req
            .headers()
            .get("Hysteria-Auth")
            .and_then(|v| v.to_str().ok())
            == Some(password);

    let status = if auth_ok { 233 } else { 401 };
    let response = Response::builder()
        .status(StatusCode::from_u16(status)?)
        .body(())?;

    stream.send_response(response).await?;
    stream.finish().await?;

    if !auth_ok {
        anyhow::bail!("hysteria2 auth failed");
    }

    // 避免 h3 连接析构触发 QUIC 连接关闭
    std::mem::forget(h3_server);

    Ok(())
}

async fn handle_hysteria2_udp(conn: quinn::Connection) -> Result<()> {
    let datagram = tokio::time::timeout(Duration::from_secs(10), conn.read_datagram())
        .await
        .context("hysteria2 udp datagram timeout")??;

    let (sid, pid, addr, payload) = hy2_protocol::decode_udp_message(&datagram)?;
    let reply = hy2_protocol::encode_udp_message(sid, pid, &addr, &payload);
    conn.send_datagram(Bytes::from(reply))?;

    Ok(())
}

async fn start_mock_hysteria2_server(
    cert_chain: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
    password: String,
) -> Result<(SocketAddr, JoinHandle<Result<()>>)> {
    let mut server_config = quinn::ServerConfig::with_single_cert(cert_chain, key)?;

    let mut transport = quinn::TransportConfig::default();
    transport.max_idle_timeout(Some(
        quinn::IdleTimeout::try_from(Duration::from_secs(30)).unwrap(),
    ));
    transport.keep_alive_interval(Some(Duration::from_secs(5)));
    transport.datagram_receive_buffer_size(Some(1350 * 256));
    server_config.transport = Arc::new(transport);

    let endpoint = quinn::Endpoint::server(server_config, "127.0.0.1:0".parse()?)?;
    let addr = endpoint.local_addr()?;

    let task = tokio::spawn(async move {
        let connecting = endpoint
            .accept()
            .await
            .ok_or_else(|| anyhow::anyhow!("no incoming QUIC connection"))?;
        let conn = connecting.await?;

        handle_hysteria2_auth(&conn, &password).await?;

        // 并发处理 TCP/UDP，两者任一完成即结束（另一个任务 abort）
        let tcp_conn = conn.clone();
        let udp_conn = conn.clone();

        let mut tcp_task = tokio::spawn(async move {
            let (mut send, mut recv) = tokio::time::timeout(Duration::from_secs(10), tcp_conn.accept_bi())
                .await
                .context("accept_bi timeout")??;

            let req_id = read_hy2_varint(&mut recv).await?;
            if req_id != 0x401 {
                anyhow::bail!("unexpected hysteria2 request id: {req_id:#x}");
            }

            let addr_len = read_hy2_varint(&mut recv).await? as usize;
            let mut addr_buf = vec![0u8; addr_len];
            read_exact_quinn(&mut recv, &mut addr_buf).await?;
            let _addr = String::from_utf8(addr_buf)?;

            let padding_len = read_hy2_varint(&mut recv).await? as usize;
            if padding_len > 0 {
                let mut padding = vec![0u8; padding_len];
                read_exact_quinn(&mut recv, &mut padding).await?;
            }

            send.write_all(&[0x00, 0x00, 0x00]).await?;
            send.flush().await?;

            let mut payload = [0u8; 4096];
            let n = tokio::time::timeout(Duration::from_secs(10), recv.read(&mut payload))
                .await
                .context("hysteria2 tcp echo read timeout")??
                .ok_or_else(|| anyhow::anyhow!("hysteria2 tcp stream closed before payload"))?;

            send.write_all(&payload[..n]).await?;
            send.flush().await?;

            Ok::<_, anyhow::Error>("tcp")
        });

        let mut udp_task = tokio::spawn(async move {
            handle_hysteria2_udp(udp_conn).await?;
            Ok::<_, anyhow::Error>("udp")
        });

        tokio::select! {
            res = &mut tcp_task => {
                udp_task.abort();
                res.context("tcp task join failed")??;
            }
            res = &mut udp_task => {
                tcp_task.abort();
                res.context("udp task join failed")??;
            }
        }

        Ok(())
    });

    Ok((addr, task))
}

// ============================================================
// 测试用例
// ============================================================

#[tokio::test]
async fn e2e_vless_tls_tcp_echo() -> Result<()> {
    ensure_crypto_provider();
    let (cert_chain, key, _ca_root) = generate_test_tls_cert("localhost")?;
    let (server_addr, server_task) = start_mock_vless_tls_server(cert_chain, key, false).await?;

    let outbound = VlessOutbound::new(&build_vless_config(server_addr, None))?;
    let session = test_session(Address::Domain("example.com".to_string(), 443), Network::Tcp);

    let mut stream = tokio::time::timeout(Duration::from_secs(10), outbound.connect(&session))
        .await
        .context("vless tls connect timeout")??;

    let payload = b"phase4-vless-tls";
    stream.write_all(payload).await?;
    stream.flush().await?;

    let mut reply = vec![0u8; payload.len()];
    tokio::time::timeout(Duration::from_secs(10), stream.read_exact(&mut reply))
        .await
        .context("vless tls echo timeout")??;

    assert_eq!(reply, payload);

    drop(stream);
    tokio::time::timeout(Duration::from_secs(10), server_task)
        .await
        .context("wait vless tls server timeout")??
        .context("vless tls server task failed")?;

    Ok(())
}

#[tokio::test]
async fn e2e_vless_vision_tcp_echo() -> Result<()> {
    ensure_crypto_provider();
    let (cert_chain, key, _ca_root) = generate_test_tls_cert("localhost")?;
    let (server_addr, server_task) = start_mock_vless_tls_server(cert_chain, key, true).await?;

    let outbound = VlessOutbound::new(&build_vless_config(server_addr, Some(XRV.to_string())))?;
    let session = test_session(Address::Domain("vision.test".to_string(), 8443), Network::Tcp);

    let mut stream = tokio::time::timeout(Duration::from_secs(10), outbound.connect(&session))
        .await
        .context("vless vision connect timeout")??;

    let payload = b"phase4-vless-vision";
    stream.write_all(payload).await?;
    stream.flush().await?;

    let mut reply = vec![0u8; payload.len()];
    tokio::time::timeout(Duration::from_secs(10), stream.read_exact(&mut reply))
        .await
        .context("vless vision echo timeout")??;

    assert_eq!(reply, payload);

    drop(stream);
    tokio::time::timeout(Duration::from_secs(10), server_task)
        .await
        .context("wait vless vision server timeout")??
        .context("vless vision server task failed")?;

    Ok(())
}

#[tokio::test]
async fn e2e_vless_reality_tcp_echo() -> Result<()> {
    ensure_crypto_provider();
    let (cert_chain, key, ca_root) = generate_test_tls_cert("reality.test")?;
    let (server_addr, server_task) = start_mock_vless_tls_server(cert_chain, key, false).await?;

    // 验证可见性调整后的 TLS roots 构建函数可用于测试
    let _tls_cfg_for_test = build_tls_config_with_roots(vec![ca_root.clone()], false)?;

    let mut random_pubkey = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut random_pubkey);

    let reality_cfg = RealityConfig {
        server_public_key: random_pubkey,
        short_id: vec![0x11, 0x22, 0x33, 0x44],
        server_name: "reality.test".to_string(),
    };

    let (client_cfg, handshake_ctx) =
        build_reality_config_with_roots(&reality_cfg, Some(vec![ca_root]))?;

    let connector = TlsConnector::from(Arc::new(client_cfg));
    let tcp = TcpStream::connect(server_addr).await?;
    let sni = ServerName::try_from("reality.test".to_string())?;

    let tls = handshake_ctx.scope(|| connector.connect(sni, tcp)).await?;
    let mut stream: ProxyStream = Box::new(tls);

    let user_uuid = uuid::Uuid::parse_str(TEST_UUID_STR)?;
    let target = Address::Domain("reality-target.test".to_string(), 443);

    vless_protocol::write_request(
        &mut stream,
        &user_uuid,
        &target,
        None,
        vless_protocol::CMD_TCP,
    )
    .await?;
    vless_protocol::read_response(&mut stream).await?;

    let payload = b"phase4-vless-reality";
    stream.write_all(payload).await?;
    stream.flush().await?;

    let mut reply = vec![0u8; payload.len()];
    tokio::time::timeout(Duration::from_secs(10), stream.read_exact(&mut reply))
        .await
        .context("vless reality echo timeout")??;

    assert_eq!(reply, payload);

    drop(stream);
    tokio::time::timeout(Duration::from_secs(10), server_task)
        .await
        .context("wait vless reality server timeout")??
        .context("vless reality server task failed")?;

    Ok(())
}

#[tokio::test]
async fn e2e_hysteria2_tcp_echo() -> Result<()> {
    ensure_crypto_provider();
    let password = "phase4-password".to_string();
    let (cert_chain, key, _ca_root) = generate_test_tls_cert("localhost")?;
    let (server_addr, server_task) =
        start_mock_hysteria2_server(cert_chain, key, password.clone()).await?;

    let outbound = Hysteria2Outbound::new(&build_hysteria2_config(server_addr, &password))?;
    let session = test_session(Address::Domain("hy2-target.test".to_string(), 443), Network::Tcp);

    let mut stream = tokio::time::timeout(Duration::from_secs(10), outbound.connect(&session))
        .await
        .context("hysteria2 tcp connect timeout")??;

    let payload = b"phase4-hy2-tcp";
    stream.write_all(payload).await?;
    stream.flush().await?;

    let mut reply = vec![0u8; payload.len()];
    tokio::time::timeout(Duration::from_secs(10), stream.read_exact(&mut reply))
        .await
        .context("hysteria2 tcp echo timeout")??;

    assert_eq!(reply, payload);

    drop(stream);
    drop(outbound);

    tokio::time::timeout(Duration::from_secs(10), server_task)
        .await
        .context("wait hysteria2 tcp server timeout")??
        .context("hysteria2 tcp server task failed")?;

    Ok(())
}

#[tokio::test]
async fn e2e_hysteria2_udp_echo() -> Result<()> {
    ensure_crypto_provider();
    let password = "phase4-password".to_string();
    let (cert_chain, key, _ca_root) = generate_test_tls_cert("localhost")?;
    let (server_addr, server_task) =
        start_mock_hysteria2_server(cert_chain, key, password.clone()).await?;

    let outbound = Hysteria2Outbound::new(&build_hysteria2_config(server_addr, &password))?;

    let target = Address::Ip("1.1.1.1:53".parse().unwrap());
    let session = test_session(target.clone(), Network::Udp);

    let transport = tokio::time::timeout(Duration::from_secs(10), outbound.connect_udp(&session))
        .await
        .context("hysteria2 udp connect timeout")??;

    let payload = b"phase4-hy2-udp";
    transport
        .send(UdpPacket {
            addr: target.clone(),
            data: Bytes::from_static(payload),
        })
        .await?;

    let reply = tokio::time::timeout(Duration::from_secs(10), transport.recv())
        .await
        .context("hysteria2 udp recv timeout")??;

    assert_eq!(reply.data.as_ref(), payload);
    assert_eq!(reply.addr, target);

    drop(transport);
    drop(outbound);

    tokio::time::timeout(Duration::from_secs(10), server_task)
        .await
        .context("wait hysteria2 udp server timeout")??
        .context("hysteria2 udp server task failed")?;

    Ok(())
}
