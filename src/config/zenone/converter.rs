use super::error::{DiagCode, Diagnostics};
use super::types::*;
use crate::config::types::OutboundConfig;

/// 从 OutboundConfig 列表转换为 ZenOne 节点列表
pub fn from_outbound_configs(configs: &[OutboundConfig], diags: &mut Diagnostics) -> Vec<ZenNode> {
    configs
        .iter()
        .enumerate()
        .filter_map(|(i, c)| convert_outbound(c, i, diags))
        .collect()
}

fn convert_outbound(ob: &OutboundConfig, idx: usize, diags: &mut Diagnostics) -> Option<ZenNode> {
    let path = format!("outbounds[{}]", idx);
    let s = &ob.settings;

    let node_type = match ob.protocol.as_str() {
        "vmess" | "vless" | "trojan" | "shadowsocks" | "hysteria2" | "hysteria" | "tuic"
        | "wireguard" | "ssh" | "naive" | "chain" | "direct" | "reject" => ob.protocol.clone(),
        "block" => "reject".to_string(),
        other => {
            diags.warn(
                DiagCode::UnsupportedProtocol,
                &path,
                format!("不支持的协议 {} 已跳过", other),
            );
            return None;
        }
    };

    // TLS 转换
    let tls = s.tls.as_ref().map(|t| {
        let reality = if t.security == "reality" {
            Some(ZenReality {
                public_key: t.public_key.clone().unwrap_or_default(),
                short_id: t.short_id.clone(),
            })
        } else {
            None
        };
        ZenTls {
            enabled: Some(t.enabled),
            sni: t.sni.clone().or_else(|| s.sni.clone()),
            alpn: t.alpn.clone(),
            insecure: if t.allow_insecure { Some(true) } else { None },
            fingerprint: t.fingerprint.clone().or_else(|| s.fingerprint.clone()),
            reality,
            ech: if t.ech_config.is_some() || t.ech_grease || t.ech_auto {
                Some(ZenEch {
                    config: t.ech_config.clone(),
                    grease: t.ech_grease,
                    auto: t.ech_auto,
                })
            } else {
                None
            },
            fragment: t.fragment.as_ref().map(|f| ZenTlsFragment {
                min_length: f.min_length,
                max_length: f.max_length,
                min_delay_ms: f.min_delay_ms,
                max_delay_ms: f.max_delay_ms,
            }),
        }
    });

    // Transport 转换
    let transport = s.transport.as_ref().and_then(|t| {
        if t.transport_type == "tcp" || t.transport_type.is_empty() {
            return None;
        }
        Some(ZenTransport {
            transport_type: t.transport_type.clone(),
            path: t.path.clone(),
            host: t.host.clone(),
            headers: t.headers.clone(),
            service_name: t.service_name.clone(),
            shadow_tls_password: t.shadow_tls_password.clone(),
            shadow_tls_sni: t.shadow_tls_sni.clone(),
        })
    });

    // Mux 转换
    let mux = s.mux.as_ref().map(|m| ZenMux {
        protocol: m.protocol.clone(),
        max_connections: m.max_connections,
        max_streams: m.max_streams_per_connection,
        padding: m.padding,
    });

    // Dialer 转换
    let dialer = s.dialer.as_ref().map(|d| ZenDialer {
        interface: d.interface_name.clone(),
        fwmark: d.routing_mark,
        tcp_fast_open: d.tcp_fast_open,
        mptcp: d.mptcp,
        domain_resolver: d.domain_resolver.clone(),
    });

    // WireGuard peers
    let peers = s.peers.as_ref().map(|ps| {
        ps.iter()
            .map(|p| ZenWireGuardPeer {
                public_key: p.public_key.clone(),
                endpoint: p.endpoint.clone(),
                allowed_ips: p.allowed_ips.clone(),
            })
            .collect()
    });

    Some(ZenNode {
        name: ob.tag.clone(),
        node_type,
        address: s.address.clone(),
        port: s.port,
        uuid: s.uuid.clone(),
        password: s.password.clone(),
        method: s.method.clone(),
        flow: s.flow.clone(),
        alter_id: s.alter_id,
        plugin: s.plugin.clone(),
        plugin_opts: s.plugin_opts.clone(),
        identity_key: s.identity_key.clone(),
        up_mbps: s.up_mbps,
        down_mbps: s.down_mbps,
        obfs: s.obfs.clone(),
        obfs_password: s.obfs_password.clone(),
        congestion_control: s.congestion_control.clone(),
        private_key: s.private_key.clone(),
        peer_public_key: s.peer_public_key.clone(),
        preshared_key: s.preshared_key.clone(),
        local_address: s.local_address.clone(),
        mtu: s.mtu,
        keepalive: s.keepalive,
        peers,
        username: s.username.clone(),
        private_key_passphrase: s.private_key_passphrase.clone(),
        chain: s.chain.clone(),
        tls,
        transport,
        mux,
        dialer,
        health_check: None,
    })
}

/// 从任意订阅内容自动检测并转换为 ZenOneDoc
pub fn convert_subscription_to_zenone(
    content: &str,
    diags: &mut Diagnostics,
) -> anyhow::Result<ZenOneDoc> {
    let configs = crate::config::subscription::parse_subscription(content)?;
    let nodes = from_outbound_configs(&configs, diags);

    if nodes.is_empty() {
        anyhow::bail!("转换后无可用节点");
    }

    Ok(ZenOneDoc {
        zen_version: 1,
        metadata: None,
        nodes,
        groups: vec![],
        router: None,
        dns: None,
        inbounds: vec![],
        settings: None,
        signature: None,
    })
}

/// 从完整订阅内容转换为完整的 ZenOneDoc（包含 groups/router/dns）
pub fn convert_full_subscription_to_zenone(
    content: &str,
    diags: &mut Diagnostics,
) -> anyhow::Result<ZenOneDoc> {
    let outbounds = crate::config::subscription::parse_subscription(content)?;

    if outbounds.is_empty() {
        anyhow::bail!("转换后无可用节点");
    }

    let nodes = from_outbound_configs(&outbounds, diags);

    Ok(ZenOneDoc {
        zen_version: 1,
        metadata: None,
        nodes,
        groups: vec![],
        router: None,
        dns: None,
        inbounds: vec![],
        settings: None,
        signature: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::types::{OutboundConfig, OutboundSettings, TlsConfig, TransportConfig};

    #[test]
    fn convert_vless_outbound() {
        let ob = OutboundConfig {
            tag: "vless1".to_string(),
            protocol: "vless".to_string(),
            settings: OutboundSettings {
                address: Some("example.com".to_string()),
                port: Some(443),
                uuid: Some("test-uuid".to_string()),
                flow: Some("xtls-rprx-vision".to_string()),
                tls: Some(TlsConfig {
                    enabled: true,
                    security: "reality".to_string(),
                    sni: Some("example.com".to_string()),
                    public_key: Some("pk123".to_string()),
                    short_id: Some("sid".to_string()),
                    fingerprint: Some("chrome".to_string()),
                    ..Default::default()
                }),
                ..Default::default()
            },
        };
        let mut diags = Diagnostics::new();
        let nodes = from_outbound_configs(&[ob], &mut diags);
        assert_eq!(nodes.len(), 1);
        let n = &nodes[0];
        assert_eq!(n.name, "vless1");
        assert_eq!(n.node_type, "vless");
        assert_eq!(n.uuid.as_deref(), Some("test-uuid"));
        let tls = n.tls.as_ref().unwrap();
        assert!(tls.reality.is_some());
        assert_eq!(tls.reality.as_ref().unwrap().public_key, "pk123");
    }

    #[test]
    fn convert_ss_outbound() {
        let ob = OutboundConfig {
            tag: "ss1".to_string(),
            protocol: "shadowsocks".to_string(),
            settings: OutboundSettings {
                address: Some("1.2.3.4".to_string()),
                port: Some(8388),
                method: Some("aes-256-gcm".to_string()),
                password: Some("pass".to_string()),
                ..Default::default()
            },
        };
        let mut diags = Diagnostics::new();
        let nodes = from_outbound_configs(&[ob], &mut diags);
        assert_eq!(nodes.len(), 1);
        assert_eq!(nodes[0].method.as_deref(), Some("aes-256-gcm"));
        assert!(nodes[0].tls.is_none());
    }

    #[test]
    fn convert_with_transport() {
        let ob = OutboundConfig {
            tag: "vmess-ws".to_string(),
            protocol: "vmess".to_string(),
            settings: OutboundSettings {
                address: Some("cdn.com".to_string()),
                port: Some(443),
                uuid: Some("uuid".to_string()),
                transport: Some(TransportConfig {
                    transport_type: "ws".to_string(),
                    path: Some("/ws".to_string()),
                    host: Some("cdn.com".to_string()),
                    ..Default::default()
                }),
                ..Default::default()
            },
        };
        let mut diags = Diagnostics::new();
        let nodes = from_outbound_configs(&[ob], &mut diags);
        let t = nodes[0].transport.as_ref().unwrap();
        assert_eq!(t.transport_type, "ws");
        assert_eq!(t.path.as_deref(), Some("/ws"));
    }

    #[test]
    fn skip_unsupported_protocol() {
        let ob = OutboundConfig {
            tag: "dns".to_string(),
            protocol: "dns".to_string(),
            settings: OutboundSettings::default(),
        };
        let mut diags = Diagnostics::new();
        let nodes = from_outbound_configs(&[ob], &mut diags);
        assert!(nodes.is_empty());
        assert!(!diags.warnings().is_empty());
    }

    #[test]
    fn convert_subscription_clash_yaml() {
        let yaml = r#"
proxies:
  - name: "node1"
    type: trojan
    server: server.com
    port: 443
    password: "pass"
    sni: "server.com"
"#;
        let mut diags = Diagnostics::new();
        let doc = convert_subscription_to_zenone(yaml, &mut diags).unwrap();
        assert_eq!(doc.zen_version, 1);
        assert_eq!(doc.nodes.len(), 1);
        assert_eq!(doc.nodes[0].name, "node1");
        assert_eq!(doc.nodes[0].node_type, "trojan");
    }

    /// 真实 Clash 订阅端到端测试：解析 -> ZenOne 转换 -> 推断 -> 校验 -> 编码 -> 桥接
    #[test]
    fn e2e_real_clash_subscription_to_zenone() {
        let clash_yaml = r#"
port: 7890
socks-port: 7891
allow-lan: true
mode: Rule
log-level: info
external-controller: 127.0.0.1:9090

proxies:
  - name: "TW VL | Taiwan Reality"
    type: vless
    server: 35.234.14.177
    port: 39885
    uuid: 5ea25ac3-ad00-43b6-ab93-a669f0a28453
    cipher: auto
    tls: true
    flow: xtls-rprx-vision
    servername: apple.com
    network: tcp
    reality-opts:
      public-key: 411x8RtvqUqO9uLFkaYWZKFt5wgPCwZZFfsiblS-Sm0
      short-id: 903b6445
    client-fingerprint: chrome

  - name: "TW HY2 | Taiwan Hy2"
    type: hysteria2
    server: 35.234.14.177
    port: 30118
    password: "5ea25ac3-ad00-43b6-ab93-a669f0a28453"
    sni: www.bing.com
    skip-cert-verify: true
    alpn:
      - h3

  - name: "SG VL | Singapore"
    type: vless
    server: 47.84.78.71
    port: 17725
    uuid: 9eb3fc24-6163-4098-8b16-175842c96e17
    cipher: auto
    tls: true
    flow: xtls-rprx-vision
    servername: apple.com
    network: tcp
    reality-opts:
      public-key: vmAXCJAXggpsVHrRTR-ukCUgqDfZL14ocoUkGtDqekc
      short-id: d1f6654e
    client-fingerprint: chrome

  - name: "US VL | USA Reality"
    type: vless
    server: 158.51.78.209
    port: 14081
    uuid: b7963331-369f-4b6e-b82f-795248915074
    cipher: auto
    tls: true
    flow: xtls-rprx-vision
    servername: apple.com
    network: tcp
    reality-opts:
      public-key: TIbQaYqAsy4iHtrxKD0PqONnVA0MyvN4BZWW1fExPCE
      short-id: 71c32986
    client-fingerprint: chrome

  - name: "US VL | USA WS"
    type: vless
    server: cdns.doon.eu.org
    port: 443
    uuid: f7783275-7ee0-4755-a962-6ae0e779d955
    network: ws
    tls: true
    servername: koybe-us.5945946.xyz
    client-fingerprint: firefox
    ws-opts:
      path: "/vless-argo?ed=2560"
      headers:
        Host: koybe-us.5945946.xyz

  - name: "DE VL | Germany"
    type: vless
    server: 104.25.240.201
    port: 443
    uuid: 8670bf75-c9e9-479d-8d73-5a85e75bc933
    network: ws
    tls: true
    servername: koybe.5945946.xyz
    client-fingerprint: firefox
    ws-opts:
      path: "/vless-argo?ed=2560"
      headers:
        Host: koybe.5945946.xyz

  - name: "NL VL | Netherlands"
    type: vless
    server: 104.25.240.201
    port: 443
    uuid: e751011a-74da-4c16-ab22-44635286b301
    network: ws
    tls: true
    servername: nf.5945946.xyz
    client-fingerprint: firefox
    ws-opts:
      path: "/vless-argo?ed=2560"
      headers:
        Host: nf.5945946.xyz

  - name: "SG HY2 | Singapore Hy2"
    type: hysteria2
    server: 47.84.78.71
    port: 19567
    password: "71323366-d8c7-489f-a4d0-0cbd95ac0ba1"
    sni: www.bing.com
    skip-cert-verify: true
    alpn:
      - h3

  - name: "SG VL | SG-railway"
    type: vless
    server: 104.17.110.235
    port: 443
    uuid: ae8756a6-cdbd-4e60-bbf9-f90ef77c4e31
    network: ws
    tls: true
    servername: railway.5945946.xyz
    client-fingerprint: firefox
    skip-cert-verify: true
    ws-opts:
      path: "/vless-argo?ed=2560"
      headers:
        Host: railway.5945946.xyz

  - name: "ID VL | Indonesia"
    type: vless
    server: 104.17.110.235
    port: 443
    uuid: 11621706-6323-4ec0-8bc7-8792a822e185
    network: ws
    tls: true
    servername: zeabur.5945946.xyz
    client-fingerprint: firefox
    ws-opts:
      path: "/vless-argo?ed=2560"
      headers:
        Host: zeabur.5945946.xyz

  - name: "HK HY2 | HongKong"
    type: hysteria2
    server: 47.242.162.33
    port: 18535
    password: "081b7ffd-0bf1-4ffb-b8bf-79a4b138565b"
    sni: www.bing.com
    skip-cert-verify: true
    alpn:
      - h3

proxy-groups:
  - name: "Proxy Select"
    type: selector
    proxies:
      - "Auto Test"
      - "TW VL | Taiwan Reality"
      - "TW HY2 | Taiwan Hy2"
      - "SG VL | Singapore"
      - "US VL | USA Reality"
      - "US VL | USA WS"
      - "HK HY2 | HongKong"
      - "DE VL | Germany"
      - "NL VL | Netherlands"
      - "SG HY2 | Singapore Hy2"
      - "SG VL | SG-railway"
      - "ID VL | Indonesia"

  - name: "Auto Test"
    type: url-test
    url: http://www.gstatic.com/generate_204
    interval: 1800
    proxies:
      - "TW VL | Taiwan Reality"
      - "TW HY2 | Taiwan Hy2"
      - "SG VL | Singapore"
      - "US VL | USA Reality"
      - "US VL | USA WS"
      - "HK HY2 | HongKong"
      - "DE VL | Germany"
      - "NL VL | Netherlands"
      - "SG HY2 | Singapore Hy2"
      - "SG VL | SG-railway"
      - "ID VL | Indonesia"

rules:
  - DOMAIN-KEYWORD,ad,REJECT
  - GEOIP,CN,DIRECT
  - MATCH,Proxy Select
"#;

        // 1) parse_subscription 解析 Clash YAML
        let configs = crate::config::subscription::parse_subscription(clash_yaml).unwrap();
        assert_eq!(configs.len(), 11, "应解析出 11 个节点");

        // 2) 转换为 ZenOne 节点
        let mut diags = Diagnostics::new();
        let nodes = from_outbound_configs(&configs, &mut diags);
        assert_eq!(nodes.len(), 11, "应转换出 11 个 ZenNode");

        // 验证各协议类型
        assert_eq!(nodes[0].node_type, "vless");
        assert_eq!(nodes[0].name, "TW VL | Taiwan Reality");
        assert_eq!(nodes[0].flow.as_deref(), Some("xtls-rprx-vision"));

        assert_eq!(nodes[1].node_type, "hysteria2");
        assert_eq!(nodes[1].name, "TW HY2 | Taiwan Hy2");
        assert_eq!(
            nodes[1].password.as_deref(),
            Some("5ea25ac3-ad00-43b6-ab93-a669f0a28453")
        );

        // WS 传输层
        assert_eq!(nodes[4].node_type, "vless");
        let ws_transport = nodes[4].transport.as_ref().expect("应有 ws transport");
        assert_eq!(ws_transport.transport_type, "ws");
        assert_eq!(ws_transport.path.as_deref(), Some("/vless-argo?ed=2560"));

        // 3) 构建完整 ZenOneDoc
        let mut doc = ZenOneDoc {
            zen_version: 1,
            metadata: None,
            nodes,
            groups: vec![],
            router: None,
            dns: None,
            inbounds: vec![],
            settings: None,
            signature: None,
        };

        // 4) normalize 推断
        super::super::normalizer::normalize(&mut doc, &mut diags);

        // 5) 编码为 YAML
        let yaml_out = super::super::encoder::encode_yaml(&doc).unwrap();
        assert!(yaml_out.contains("zen-version"), "输出应包含 zen-version");
        assert!(
            yaml_out.contains("TW VL | Taiwan Reality"),
            "输出应包含节点名"
        );
        assert!(yaml_out.contains("vless"), "输出应包含协议类型");

        // 6) 编码为 JSON
        let json_out = super::super::encoder::encode_json(&doc).unwrap();
        assert!(
            json_out.contains("\"zen-version\""),
            "JSON 应包含 zen-version"
        );

        // 7) 从 YAML 回解析验证 roundtrip
        let reparsed: ZenOneDoc = serde_yml::from_str(&yaml_out).unwrap();
        assert_eq!(reparsed.nodes.len(), 11);
        assert_eq!(reparsed.nodes[0].name, "TW VL | Taiwan Reality");
        assert_eq!(reparsed.nodes[1].node_type, "hysteria2");

        // 8) 桥接到 Config
        let config = super::super::bridge::zenone_to_config(&doc, &mut diags);
        assert_eq!(config.outbounds.len(), 11);
        assert_eq!(config.outbounds[0].tag, "TW VL | Taiwan Reality");
        assert_eq!(config.outbounds[0].protocol, "vless");
        assert_eq!(config.outbounds[1].protocol, "hysteria2");

        // 确认无错误诊断
        assert!(!diags.has_errors(), "不应有错误诊断: {:?}", diags.errors());

        println!("=== ZenOne YAML 输出 (前 500 字符) ===");
        println!("{}", &yaml_out[..yaml_out.len().min(500)]);
    }
}
