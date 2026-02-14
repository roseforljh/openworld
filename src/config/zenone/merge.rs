use super::error::{DiagCode, Diagnostics};
use super::types::ZenOneDoc;

/// 处理 ZenOne 文档中的 !include 指令
/// 注意：实际的文件级 include 在 enhance.rs 中已处理
/// 这里处理的是 ZenOne 特有的数组级合并逻辑
pub fn merge_included_docs(
    base: &mut ZenOneDoc,
    included: ZenOneDoc,
    diags: &mut Diagnostics,
) {
    // 合并 nodes（按 name 去重，后者覆盖前者）
    for new_node in included.nodes {
        if let Some(pos) = base.nodes.iter().position(|n| n.name == new_node.name) {
            diags.info(
                DiagCode::ValueInferred,
                format!("nodes.{}", new_node.name),
                format!("节点 {} 被覆盖", new_node.name),
            );
            base.nodes[pos] = new_node;
        } else {
            base.nodes.push(new_node);
        }
    }

    // 合并 groups（按 name 去重）
    for new_group in included.groups {
        if let Some(pos) = base.groups.iter().position(|g| g.name == new_group.name) {
            diags.info(
                DiagCode::ValueInferred,
                format!("groups.{}", new_group.name),
                format!("组 {} 被覆盖", new_group.name),
            );
            base.groups[pos] = new_group;
        } else {
            base.groups.push(new_group);
        }
    }

    // 合并 router rule-providers（按 key 去重）
    if let Some(ref inc_router) = included.router {
        let router = base.router.get_or_insert_with(|| super::types::ZenRouter {
            default: "direct".to_string(),
            geoip_db: None,
            geosite_db: None,
            geo_auto_update: false,
            geoip_url: None,
            geosite_url: None,
            rule_providers: Default::default(),
            rules: vec![],
        });
        for (k, v) in &inc_router.rule_providers {
            router.rule_providers.insert(k.clone(), v.clone());
        }
        router.rules.extend(inc_router.rules.clone());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::zenone::types::*;

    fn make_node(name: &str) -> ZenNode {
        ZenNode {
            name: name.to_string(),
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
        }
    }

    fn empty_doc() -> ZenOneDoc {
        ZenOneDoc {
            zen_version: 1,
            metadata: None,
            nodes: vec![],
            groups: vec![],
            router: None,
            dns: None,
            inbounds: vec![],
            settings: None,
            signature: None,
        }
    }

    #[test]
    fn merge_nodes_no_conflict() {
        let mut base = empty_doc();
        base.nodes.push(make_node("a"));
        let mut inc = empty_doc();
        inc.nodes.push(make_node("b"));
        let mut diags = Diagnostics::new();
        merge_included_docs(&mut base, inc, &mut diags);
        assert_eq!(base.nodes.len(), 2);
    }

    #[test]
    fn merge_nodes_override() {
        let mut base = empty_doc();
        base.nodes.push(make_node("a"));
        let mut inc = empty_doc();
        let mut node_a = make_node("a");
        node_a.node_type = "reject".to_string();
        inc.nodes.push(node_a);
        let mut diags = Diagnostics::new();
        merge_included_docs(&mut base, inc, &mut diags);
        assert_eq!(base.nodes.len(), 1);
        assert_eq!(base.nodes[0].node_type, "reject");
    }
}
