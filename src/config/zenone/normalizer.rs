use super::error::{DiagCode, Diagnostics};
use super::types::ZenOneDoc;

/// 对 ZenOneDoc 执行智能推断，填充默认值
pub fn normalize(doc: &mut ZenOneDoc, diags: &mut Diagnostics) {
    for (i, node) in doc.nodes.iter_mut().enumerate() {
        let path = format!("nodes[{}]", i);
        normalize_node(node, &path, diags);
    }
}

fn normalize_node(node: &mut super::types::ZenNode, path: &str, diags: &mut Diagnostics) {
    let t = node.node_type.as_str();

    // 跳过 direct/reject，无需推断
    if matches!(t, "direct" | "reject") {
        return;
    }

    // 端口推断
    if node.port.is_none() {
        let inferred = match t {
            "trojan" | "vless" | "vmess" | "hysteria2" | "tuic" | "naive" => Some(443u16),
            "shadowsocks" => Some(8388),
            "wireguard" => Some(51820),
            "ssh" => Some(22),
            "hysteria" => Some(443),
            _ => None,
        };
        if let Some(p) = inferred {
            node.port = Some(p);
            diags.info(
                DiagCode::ValueInferred,
                format!("{}.port", path),
                format!("推断端口为 {}", p),
            );
        }
    }

    // TLS enabled 推断
    let needs_tls_default = matches!(
        t,
        "trojan" | "vless" | "tuic" | "hysteria2" | "hysteria" | "naive"
    );
    if needs_tls_default {
        let tls = node.tls.get_or_insert_with(|| super::types::ZenTls {
            enabled: None,
            sni: None,
            alpn: None,
            insecure: None,
            fingerprint: None,
            reality: None,
            ech: None,
            fragment: None,
        });
        if tls.enabled.is_none() {
            tls.enabled = Some(true);
            diags.info(
                DiagCode::ValueInferred,
                format!("{}.tls.enabled", path),
                format!("{} 协议默认启用 TLS", t),
            );
        }
    }

    // TLS SNI 推断：从 address 推断（仅当 address 是域名时）
    if let Some(ref tls) = node.tls {
        if tls.enabled == Some(true) && tls.sni.is_none() && tls.reality.is_none() {
            if let Some(ref addr) = node.address {
                if !addr.is_empty() && !is_ip_address(addr) {
                    let sni = addr.clone();
                    if let Some(ref mut tls) = node.tls {
                        tls.sni = Some(sni.clone());
                        diags.info(
                            DiagCode::ValueInferred,
                            format!("{}.tls.sni", path),
                            format!("从 address 推断 SNI: {}", sni),
                        );
                    }
                }
            }
        }
    }

    // VMess alter-id 推断
    if t == "vmess" && node.alter_id.is_none() {
        node.alter_id = Some(0);
        diags.info(
            DiagCode::ValueInferred,
            format!("{}.alter-id", path),
            "默认 alter-id=0 (AEAD)".to_string(),
        );
    }

    // TUIC congestion-control 推断
    if t == "tuic" && node.congestion_control.is_none() {
        node.congestion_control = Some("cubic".to_string());
        diags.info(
            DiagCode::ValueInferred,
            format!("{}.congestion-control", path),
            "默认拥塞控制: cubic".to_string(),
        );
    }

    // WireGuard MTU 推断
    if t == "wireguard" && node.mtu.is_none() {
        node.mtu = Some(1280);
        diags.info(
            DiagCode::ValueInferred,
            format!("{}.mtu", path),
            "默认 MTU: 1280".to_string(),
        );
    }

    // Shadowsocks method 推断
    if t == "shadowsocks" && node.method.is_none() {
        node.method = Some("aes-256-gcm".to_string());
        diags.info(
            DiagCode::ValueInferred,
            format!("{}.method", path),
            "默认加密方法: aes-256-gcm".to_string(),
        );
    }
}

fn is_ip_address(s: &str) -> bool {
    s.parse::<std::net::IpAddr>().is_ok() || (s.starts_with('[') && s.ends_with(']'))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::zenone::types::*;

    fn make_doc(nodes: Vec<ZenNode>) -> ZenOneDoc {
        ZenOneDoc {
            zen_version: 1,
            metadata: None,
            nodes,
            groups: vec![],
            router: None,
            dns: None,
            inbounds: vec![],
            settings: None,
            signature: None,
        }
    }

    fn make_node(name: &str, node_type: &str) -> ZenNode {
        ZenNode {
            name: name.to_string(),
            node_type: node_type.to_string(),
            address: Some("example.com".to_string()),
            port: None,
            uuid: None,
            password: None,
            method: None,
            flow: None,
            alter_id: None,
            plugin: None,
            plugin_opts: None,
            identity_key: None,
            up_mbps: None,
            down_mbps: None,
            obfs: None,
            obfs_password: None,
            congestion_control: None,
            private_key: None,
            peer_public_key: None,
            preshared_key: None,
            local_address: None,
            mtu: None,
            keepalive: None,
            peers: None,
            username: None,
            private_key_passphrase: None,
            chain: None,
            tls: None,
            transport: None,
            mux: None,
            dialer: None,
            health_check: None,
        }
    }

    #[test]
    fn infer_vless_port_and_tls() {
        let mut doc = make_doc(vec![make_node("n1", "vless")]);
        let mut diags = Diagnostics::new();
        normalize(&mut doc, &mut diags);
        assert_eq!(doc.nodes[0].port, Some(443));
        assert_eq!(doc.nodes[0].tls.as_ref().unwrap().enabled, Some(true));
        assert_eq!(
            doc.nodes[0].tls.as_ref().unwrap().sni.as_deref(),
            Some("example.com")
        );
        assert!(!diags.has_errors());
    }

    #[test]
    fn infer_ss_defaults() {
        let mut doc = make_doc(vec![make_node("ss1", "shadowsocks")]);
        let mut diags = Diagnostics::new();
        normalize(&mut doc, &mut diags);
        assert_eq!(doc.nodes[0].port, Some(8388));
        assert_eq!(doc.nodes[0].method.as_deref(), Some("aes-256-gcm"));
    }

    #[test]
    fn infer_vmess_alter_id() {
        let mut doc = make_doc(vec![make_node("vm1", "vmess")]);
        let mut diags = Diagnostics::new();
        normalize(&mut doc, &mut diags);
        assert_eq!(doc.nodes[0].alter_id, Some(0));
    }

    #[test]
    fn no_sni_for_ip_address() {
        let mut node = make_node("n1", "trojan");
        node.address = Some("1.2.3.4".to_string());
        let mut doc = make_doc(vec![node]);
        let mut diags = Diagnostics::new();
        normalize(&mut doc, &mut diags);
        assert!(doc.nodes[0].tls.as_ref().unwrap().sni.is_none());
    }

    #[test]
    fn skip_direct_reject() {
        let mut doc = make_doc(vec![make_node("d", "direct"), make_node("r", "reject")]);
        let mut diags = Diagnostics::new();
        normalize(&mut doc, &mut diags);
        assert!(doc.nodes[0].port.is_none());
        assert!(doc.nodes[1].port.is_none());
    }
}
