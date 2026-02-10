use anyhow::Result;
use rustls::pki_types::CertificateDer;
use rustls::ClientConfig;

/// 构建 TLS ClientConfig（VLESS 专用入口）
pub fn build_tls_config(_sni: &str, allow_insecure: bool, with_alpn: bool) -> Result<ClientConfig> {
    let alpn: Option<&[&str]> = if with_alpn {
        Some(&["h2", "http/1.1"])
    } else {
        None
    };
    crate::common::tls::build_tls_config(allow_insecure, alpn)
}

/// 构建 TLS ClientConfig，接受自定义根证书（供测试使用）
pub fn build_tls_config_with_roots(
    roots: Vec<CertificateDer<'static>>,
    with_alpn: bool,
) -> Result<ClientConfig> {
    let alpn: Option<&[&str]> = if with_alpn {
        Some(&["h2", "http/1.1"])
    } else {
        None
    };
    crate::common::tls::build_tls_config_with_roots(roots, alpn)
}
