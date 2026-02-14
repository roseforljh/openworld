use anyhow::Result;

use super::types::ZenOneDoc;

/// 将 ZenOneDoc 编码为 YAML 字符串
pub fn encode_yaml(doc: &ZenOneDoc) -> Result<String> {
    Ok(serde_yml::to_string(doc)?)
}

/// 将 ZenOneDoc 编码为 JSON 字符串（美化格式）
pub fn encode_json(doc: &ZenOneDoc) -> Result<String> {
    Ok(serde_json::to_string_pretty(doc)?)
}

/// 将 ZenOneDoc 编码为紧凑 JSON
pub fn encode_json_compact(doc: &ZenOneDoc) -> Result<String> {
    Ok(serde_json::to_string(doc)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::zenone::types::*;

    fn sample_doc() -> ZenOneDoc {
        ZenOneDoc {
            zen_version: 1,
            metadata: Some(ZenMetadata {
                name: Some("test".to_string()),
                ..Default::default()
            }),
            nodes: vec![ZenNode {
                name: "direct".to_string(),
                node_type: "direct".to_string(),
                address: None, port: None, uuid: None, password: None,
                method: None, flow: None, alter_id: None, plugin: None,
                plugin_opts: None, identity_key: None, up_mbps: None,
                down_mbps: None, obfs: None, obfs_password: None,
                congestion_control: None, private_key: None,
                peer_public_key: None, preshared_key: None,
                local_address: None, mtu: None, keepalive: None,
                peers: None, username: None, private_key_passphrase: None,
                chain: None, tls: None, transport: None, mux: None,
                dialer: None, health_check: None,
            }],
            groups: vec![],
            router: None,
            dns: None,
            inbounds: vec![],
            settings: None,
            signature: None,
        }
    }

    #[test]
    fn roundtrip_yaml() {
        let doc = sample_doc();
        let yaml = encode_yaml(&doc).unwrap();
        assert!(yaml.contains("zen-version"));
        assert!(yaml.contains("direct"));
        let parsed: ZenOneDoc = serde_yml::from_str(&yaml).unwrap();
        assert_eq!(parsed.zen_version, 1);
        assert_eq!(parsed.nodes[0].name, "direct");
    }

    #[test]
    fn roundtrip_json() {
        let doc = sample_doc();
        let json = encode_json(&doc).unwrap();
        assert!(json.contains("\"zen-version\""));
        let parsed: ZenOneDoc = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.zen_version, 1);
    }

    #[test]
    fn compact_json() {
        let doc = sample_doc();
        let json = encode_json_compact(&doc).unwrap();
        assert!(!json.contains('\n'));
    }
}
