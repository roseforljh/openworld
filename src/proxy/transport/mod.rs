pub mod ech;
pub mod fingerprint;
pub mod grpc;
pub mod h2;
pub mod reality;
pub mod tcp;
pub mod tls;
pub mod ws;

use anyhow::Result;
use async_trait::async_trait;

use crate::common::{Address, ProxyStream};
use crate::config::types::{TlsConfig, TransportConfig};

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
    match transport_config.transport_type.as_str() {
        "tcp" | "" => {
            if tls_config.enabled || tls_config.security == "reality" {
                match tls_config.security.as_str() {
                    "reality" => {
                        let transport = reality::RealityTransport::new(
                            server_addr.to_string(),
                            server_port,
                            tls_config,
                        )?;
                        Ok(Box::new(transport))
                    }
                    _ => {
                        let transport = tls::TlsTransport::new(
                            server_addr.to_string(),
                            server_port,
                            tls_config,
                        )?;
                        Ok(Box::new(transport))
                    }
                }
            } else {
                let transport = tcp::TcpTransport::new(server_addr.to_string(), server_port);
                Ok(Box::new(transport))
            }
        }
        "ws" => {
            let tls = if tls_config.enabled {
                Some(tls_config.clone())
            } else {
                None
            };
            let transport =
                ws::WsTransport::new(server_addr.to_string(), server_port, transport_config, tls);
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
            );
            Ok(Box::new(transport))
        }
        other => anyhow::bail!("unsupported transport type: {}", other),
    }
}
