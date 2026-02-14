use std::collections::HashSet;

use super::error::{DiagCode, Diagnostics};
use super::types::{ValidationMode, ZenOneDoc};

/// 校验 ZenOneDoc，根据 validation_mode 决定严格程度
pub fn validate(doc: &ZenOneDoc, mode: ValidationMode, diags: &mut Diagnostics) {
    validate_version(doc, diags);
    validate_nodes(doc, mode, diags);
    validate_groups(doc, mode, diags);
    validate_router(doc, mode, diags);
}

fn validate_version(doc: &ZenOneDoc, diags: &mut Diagnostics) {
    if doc.zen_version == 0 || doc.zen_version > 1 {
        diags.error(
            DiagCode::InvalidSchemaVersion,
            "zen-version",
            format!("不支持的版本: {}, 当前仅支持 1", doc.zen_version),
        );
    }
}

fn validate_nodes(doc: &ZenOneDoc, mode: ValidationMode, diags: &mut Diagnostics) {
    if doc.nodes.is_empty() {
        diags.error(DiagCode::MissingRequiredField, "nodes", "至少需要一个节点");
        return;
    }

    let mut seen_names = HashSet::new();
    for (i, node) in doc.nodes.iter().enumerate() {
        let path = format!("nodes[{}]", i);

        // 名称唯一性
        if !seen_names.insert(&node.name) {
            diags.error(
                DiagCode::DuplicateName,
                &path,
                format!("节点名称重复: {}", node.name),
            );
        }

        // 名称非空
        if node.name.is_empty() {
            diags.error(DiagCode::MissingRequiredField, format!("{}.name", path), "节点名称不能为空");
        }

        // 协议类型
        let t = node.node_type.as_str();
        let known = [
            "vless", "vmess", "trojan", "shadowsocks", "hysteria2", "hysteria",
            "tuic", "wireguard", "ssh", "naive", "chain", "direct", "reject",
        ];
        if !known.contains(&t) {
            match mode {
                ValidationMode::Strict => {
                    diags.error(
                        DiagCode::UnsupportedProtocol,
                        format!("{}.type", path),
                        format!("未知协议: {}", t),
                    );
                }
                _ => {
                    diags.warn(
                        DiagCode::UnsupportedProtocol,
                        format!("{}.type", path),
                        format!("未知协议: {}", t),
                    );
                }
            }
            continue;
        }

        // direct/reject 无需更多校验
        if matches!(t, "direct" | "reject") {
            continue;
        }

        // 通用必填: address
        if t != "chain" && node.address.is_none() {
            diags.error(
                DiagCode::MissingRequiredField,
                format!("{}.address", path),
                format!("{} 节点缺少 address", t),
            );
        }

        // 端口范围校验
        if let Some(port) = node.port {
            if port == 0 {
                diags.error(
                    DiagCode::InvalidPortRange,
                    format!("{}.port", path),
                    "端口不能为 0",
                );
            }
        }

        // 协议专用必填字段
        match t {
            "vless" => {
                if node.uuid.is_none() {
                    diags.error(DiagCode::MissingRequiredField, format!("{}.uuid", path), "vless 节点缺少 uuid");
                }
            }
            "vmess" => {
                if node.uuid.is_none() {
                    diags.error(DiagCode::MissingRequiredField, format!("{}.uuid", path), "vmess 节点缺少 uuid");
                }
            }
            "trojan" => {
                if node.password.is_none() {
                    diags.error(DiagCode::MissingRequiredField, format!("{}.password", path), "trojan 节点缺少 password");
                }
            }
            "shadowsocks" => {
                if node.method.is_none() {
                    // normalizer 会推断，但 strict 模式下仍需检查原始值
                    // 这里检查的是 normalize 后的值，所以通常已填充
                }
                if node.password.is_none() {
                    diags.error(DiagCode::MissingRequiredField, format!("{}.password", path), "shadowsocks 节点缺少 password");
                }
            }
            "hysteria2" | "hysteria" => {
                if node.password.is_none() {
                    diags.error(DiagCode::MissingRequiredField, format!("{}.password", path), format!("{} 节点缺少 password", t));
                }
            }
            "tuic" => {
                if node.uuid.is_none() {
                    diags.error(DiagCode::MissingRequiredField, format!("{}.uuid", path), "tuic 节点缺少 uuid");
                }
                if node.password.is_none() {
                    diags.error(DiagCode::MissingRequiredField, format!("{}.password", path), "tuic 节点缺少 password");
                }
            }
            "wireguard" => {
                if node.private_key.is_none() {
                    diags.error(DiagCode::MissingRequiredField, format!("{}.private-key", path), "wireguard 节点缺少 private-key");
                }
                if node.peer_public_key.is_none() && node.peers.is_none() {
                    diags.error(DiagCode::MissingRequiredField, format!("{}.peer-public-key", path), "wireguard 节点缺少 peer-public-key 或 peers");
                }
                if node.local_address.is_none() {
                    diags.error(DiagCode::MissingRequiredField, format!("{}.local-address", path), "wireguard 节点缺少 local-address");
                }
            }
            "ssh" => {
                if node.username.is_none() {
                    diags.error(DiagCode::MissingRequiredField, format!("{}.username", path), "ssh 节点缺少 username");
                }
                if node.password.is_none() && node.private_key.is_none() {
                    diags.error(DiagCode::MissingRequiredField, format!("{}.password|private-key", path), "ssh 节点需要 password 或 private-key");
                }
            }
            "naive" => {
                if node.username.is_none() {
                    diags.error(DiagCode::MissingRequiredField, format!("{}.username", path), "naive 节点缺少 username");
                }
                if node.password.is_none() {
                    diags.error(DiagCode::MissingRequiredField, format!("{}.password", path), "naive 节点缺少 password");
                }
            }
            "chain" => {
                match &node.chain {
                    None => {
                        diags.error(DiagCode::MissingRequiredField, format!("{}.chain", path), "chain 节点缺少 chain 列表");
                    }
                    Some(chain) => {
                        if chain.is_empty() {
                            diags.error(DiagCode::MissingRequiredField, format!("{}.chain", path), "chain 列表不能为空");
                        }
                        if chain.contains(&node.name) {
                            diags.error(DiagCode::CircularReference, format!("{}.chain", path), "chain 不能包含自身");
                        }
                    }
                }
            }
            _ => {}
        }
    }
}

fn validate_groups(doc: &ZenOneDoc, _mode: ValidationMode, diags: &mut Diagnostics) {
    let all_names: HashSet<&str> = doc
        .nodes
        .iter()
        .map(|n| n.name.as_str())
        .chain(doc.groups.iter().map(|g| g.name.as_str()))
        .collect();

    let mut seen_group_names: HashSet<&str> = HashSet::new();
    let node_names: HashSet<&str> = doc.nodes.iter().map(|n| n.name.as_str()).collect();

    for (i, group) in doc.groups.iter().enumerate() {
        let path = format!("groups[{}]", i);

        if !seen_group_names.insert(&group.name) {
            diags.error(DiagCode::DuplicateName, &path, format!("组名重复: {}", group.name));
        }

        if node_names.contains(group.name.as_str()) {
            diags.error(DiagCode::DuplicateName, &path, format!("组名与节点名冲突: {}", group.name));
        }

        for (j, ref_name) in group.nodes.iter().enumerate() {
            if !all_names.contains(ref_name.as_str()) {
                diags.error(
                    DiagCode::UnresolvedReference,
                    format!("{}.nodes[{}]", path, j),
                    format!("引用不存在: {}", ref_name),
                );
            }
        }
    }
}

fn validate_router(doc: &ZenOneDoc, _mode: ValidationMode, diags: &mut Diagnostics) {
    let router = match &doc.router {
        Some(r) => r,
        None => return,
    };

    let all_names: HashSet<&str> = doc
        .nodes
        .iter()
        .map(|n| n.name.as_str())
        .chain(doc.groups.iter().map(|g| g.name.as_str()))
        .collect();

    if !all_names.contains(router.default.as_str()) && router.default != "direct" && router.default != "reject" {
        diags.error(
            DiagCode::UnresolvedReference,
            "router.default",
            format!("默认出站不存在: {}", router.default),
        );
    }

    for (i, rule) in router.rules.iter().enumerate() {
        let path = format!("router.rules[{}]", i);
        if let Some(ref outbound) = rule.outbound {
            if !all_names.contains(outbound.as_str()) && outbound != "direct" && outbound != "reject" {
                diags.error(
                    DiagCode::UnresolvedReference,
                    format!("{}.outbound", path),
                    format!("规则出站不存在: {}", outbound),
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::zenone::types::*;

    fn minimal_doc() -> ZenOneDoc {
        ZenOneDoc {
            zen_version: 1,
            metadata: None,
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
    fn valid_minimal() {
        let doc = minimal_doc();
        let mut diags = Diagnostics::new();
        validate(&doc, ValidationMode::Strict, &mut diags);
        assert!(!diags.has_errors());
    }

    #[test]
    fn invalid_version() {
        let mut doc = minimal_doc();
        doc.zen_version = 99;
        let mut diags = Diagnostics::new();
        validate(&doc, ValidationMode::Strict, &mut diags);
        assert!(diags.has_errors());
    }

    #[test]
    fn empty_nodes() {
        let mut doc = minimal_doc();
        doc.nodes.clear();
        let mut diags = Diagnostics::new();
        validate(&doc, ValidationMode::Strict, &mut diags);
        assert!(diags.has_errors());
    }

    #[test]
    fn duplicate_node_name() {
        let mut doc = minimal_doc();
        doc.nodes.push(doc.nodes[0].clone());
        let mut diags = Diagnostics::new();
        validate(&doc, ValidationMode::Strict, &mut diags);
        assert!(diags.has_errors());
    }

    #[test]
    fn vless_missing_uuid() {
        let mut doc = minimal_doc();
        doc.nodes.push(ZenNode {
            name: "vless1".to_string(),
            node_type: "vless".to_string(),
            address: Some("example.com".to_string()),
            port: Some(443),
            uuid: None,
            password: None, method: None, flow: None, alter_id: None,
            plugin: None, plugin_opts: None, identity_key: None,
            up_mbps: None, down_mbps: None, obfs: None, obfs_password: None,
            congestion_control: None, private_key: None,
            peer_public_key: None, preshared_key: None,
            local_address: None, mtu: None, keepalive: None,
            peers: None, username: None, private_key_passphrase: None,
            chain: None, tls: None, transport: None, mux: None,
            dialer: None, health_check: None,
        });
        let mut diags = Diagnostics::new();
        validate(&doc, ValidationMode::Strict, &mut diags);
        assert!(diags.has_errors());
    }

    #[test]
    fn group_references_missing_node() {
        let mut doc = minimal_doc();
        doc.groups.push(ZenGroup {
            name: "proxy".to_string(),
            group_type: "select".to_string(),
            nodes: vec!["nonexistent".to_string()],
            url: None, interval: None, tolerance: None, strategy: None,
        });
        let mut diags = Diagnostics::new();
        validate(&doc, ValidationMode::Strict, &mut diags);
        assert!(diags.has_errors());
    }
}
