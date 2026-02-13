pub mod anytls;
pub mod brutal;
pub mod ech;
pub mod fingerprint;
pub mod fragment;
pub mod grpc;
pub mod h2;
pub mod httpupgrade;
pub mod reality;
pub mod shadowtls;
pub mod sudoku;
pub mod tcp;
pub mod tls;
pub mod ws;

use anyhow::Result;
use async_trait::async_trait;

use crate::common::{Address, DialerConfig, ProxyStream};
use crate::config::types::{TlsConfig, TransportConfig};
use crate::dns::DnsResolver;
use std::sync::Arc;

/// 传输层抽象 trait
///
/// 负责建立到远端服务器的底层连接（TCP/TLS/Reality/WS/H2/gRPC 等），
/// 上层协议（VLESS 等）在此连接之上发送协议头和数据。
#[async_trait]
pub trait StreamTransport: Send + Sync {
    async fn connect(&self, addr: &Address) -> Result<ProxyStream>;
}

/// 根据配置构建传输层实例
pub fn build_transport(
    server_addr: &str,
    server_port: u16,
    transport_config: &TransportConfig,
    tls_config: &TlsConfig,
) -> Result<Box<dyn StreamTransport>> {
    build_transport_with_dialer(server_addr, server_port, transport_config, tls_config, None)
}

/// 根据配置构建传输层实例，支持统一 Dialer 配置
pub fn build_transport_with_dialer(
    server_addr: &str,
    server_port: u16,
    transport_config: &TransportConfig,
    tls_config: &TlsConfig,
    dialer_config: Option<DialerConfig>,
) -> Result<Box<dyn StreamTransport>> {
    match transport_config.transport_type.as_str() {
        "tcp" | "" => {
            if tls_config.enabled || tls_config.security == "reality" {
                match tls_config.security.as_str() {
                    "reality" => {
                        let transport = reality::RealityTransport::new(
                            server_addr.to_string(),
                            server_port,
                            tls_config,
                            dialer_config,
                        )?;
                        Ok(Box::new(transport))
                    }
                    _ => {
                        let transport = tls::TlsTransport::new(
                            server_addr.to_string(),
                            server_port,
                            tls_config,
                            dialer_config,
                        )?;
                        Ok(Box::new(transport))
                    }
                }
            } else {
                let transport =
                    tcp::TcpTransport::new(server_addr.to_string(), server_port, dialer_config);
                Ok(Box::new(transport))
            }
        }
        "ws" => {
            let tls = if tls_config.enabled {
                Some(tls_config.clone())
            } else {
                None
            };
            let transport = ws::WsTransport::new(
                server_addr.to_string(),
                server_port,
                transport_config,
                tls,
                dialer_config,
            );
            Ok(Box::new(transport))
        }
        "h2" => {
            let tls = if tls_config.enabled {
                Some(tls_config.clone())
            } else {
                None
            };
            let transport = h2::H2Transport::new(
                server_addr.to_string(),
                server_port,
                transport_config.path.clone(),
                transport_config.host.clone(),
                tls,
                dialer_config,
            );
            Ok(Box::new(transport))
        }
        "grpc" => {
            let tls = if tls_config.enabled {
                Some(tls_config.clone())
            } else {
                None
            };
            let transport = grpc::GrpcTransport::new(
                server_addr.to_string(),
                server_port,
                transport_config.service_name.clone(),
                transport_config.host.clone(),
                tls,
                dialer_config,
            );
            Ok(Box::new(transport))
        }
        "httpupgrade" | "xhttp" => {
            let tls = if tls_config.enabled || tls_config.security == "reality" {
                Some(tls_config.clone())
            } else {
                None
            };
            let transport = httpupgrade::HttpUpgradeTransport::new(
                server_addr.to_string(),
                server_port,
                transport_config,
                tls,
                dialer_config,
            );
            Ok(Box::new(transport))
        }
        "shadow-tls" => {
            let password = transport_config
                .shadow_tls_password
                .clone()
                .unwrap_or_default();
            let sni = transport_config
                .shadow_tls_sni
                .clone()
                .unwrap_or_else(|| server_addr.to_string());
            let transport = shadowtls::ShadowTlsTransport::new(
                server_addr.to_string(),
                server_port,
                password,
                sni,
                dialer_config,
            );
            Ok(Box::new(transport))
        }
        "anytls" | "any-tls" => {
            let password = transport_config
                .shadow_tls_password
                .clone()
                .unwrap_or_default();
            let padding = true; // 默认启用
            let tls = if tls_config.enabled || tls_config.security == "reality" {
                Some(tls_config.clone())
            } else {
                None
            };
            let transport = anytls::AnyTlsTransport::new(
                server_addr.to_string(),
                server_port,
                password,
                padding,
                tls,
                dialer_config,
            );
            Ok(Box::new(transport))
        }
        other => anyhow::bail!("unsupported transport type: {}", other),
    }
}

/// 使用 Dialer 建立 TCP 连接的辅助函数。
/// 所有传输层共用此函数，确保 socket 选项和 DNS 解析器统一应用。
pub(crate) async fn dial_tcp(
    server_addr: &str,
    server_port: u16,
    dialer_config: &Option<DialerConfig>,
    resolver: Option<Arc<dyn DnsResolver>>,
) -> Result<tokio::net::TcpStream> {
    use crate::common::Dialer;
    let dialer = match (dialer_config, resolver) {
        (Some(cfg), Some(r)) => Dialer::with_resolver(cfg.clone(), r),
        (Some(cfg), None) => Dialer::new(cfg.clone()),
        (None, Some(r)) => Dialer::with_resolver(DialerConfig::default(), r),
        (None, None) => Dialer::default_dialer(),
    };
    dialer.connect_host(server_addr, server_port).await
}
