use anyhow::Result;

use super::error::Diagnostics;
use super::types::{ValidationMode, ZenOneDoc};

/// 检测内容格式并解析为 ZenOneDoc
pub fn parse(content: &str, diags: &mut Diagnostics) -> Result<ZenOneDoc> {
    let trimmed = content.trim();

    // 自动检测 JSON vs YAML
    if trimmed.starts_with('{') {
        parse_json(trimmed, diags)
    } else {
        parse_yaml(trimmed, diags)
    }
}

fn parse_yaml(content: &str, _diags: &mut Diagnostics) -> Result<ZenOneDoc> {
    let doc: ZenOneDoc = serde_yml::from_str(content)?;
    Ok(doc)
}

fn parse_json(content: &str, _diags: &mut Diagnostics) -> Result<ZenOneDoc> {
    let doc: ZenOneDoc = serde_json::from_str(content)?;
    Ok(doc)
}

/// 检测内容是否为 ZenOne 格式（含 zen-version 字段）
pub fn is_zenone(content: &str) -> bool {
    let trimmed = content.trim();
    if trimmed.starts_with('{') {
        // JSON: 检查 zen-version 键
        trimmed.contains("\"zen-version\"")
    } else {
        // YAML: 检查 zen-version 行
        trimmed.contains("zen-version:")
    }
}

/// 完整流程：解析 -> 推断 -> 校验
pub fn parse_and_validate(
    content: &str,
    mode: Option<ValidationMode>,
) -> Result<(ZenOneDoc, Diagnostics)> {
    let mut diags = Diagnostics::new();

    let mut doc = parse(content, &mut diags)?;

    // 从文档中读取 validation mode，命令行参数优先
    let effective_mode = mode.unwrap_or_else(|| {
        doc.settings
            .as_ref()
            .and_then(|s| s.validation_mode)
            .unwrap_or(ValidationMode::Strict)
    });

    // 智能推断
    super::normalizer::normalize(&mut doc, &mut diags);

    // 校验
    super::validator::validate(&doc, effective_mode, &mut diags);

    Ok((doc, diags))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_minimal_yaml() {
        let yaml = r#"
zen-version: 1
nodes:
  - name: direct
    type: direct
"#;
        let mut diags = Diagnostics::new();
        let doc = parse(yaml, &mut diags).unwrap();
        assert_eq!(doc.zen_version, 1);
        assert_eq!(doc.nodes.len(), 1);
        assert_eq!(doc.nodes[0].name, "direct");
    }

    #[test]
    fn parse_minimal_json() {
        let json = r#"{"zen-version": 1, "nodes": [{"name": "direct", "type": "direct"}]}"#;
        let mut diags = Diagnostics::new();
        let doc = parse(json, &mut diags).unwrap();
        assert_eq!(doc.zen_version, 1);
        assert_eq!(doc.nodes.len(), 1);
    }

    #[test]
    fn detect_zenone_yaml() {
        assert!(is_zenone("zen-version: 1\nnodes: []"));
        assert!(!is_zenone("proxies:\n  - name: test"));
    }

    #[test]
    fn detect_zenone_json() {
        assert!(is_zenone(r#"{"zen-version": 1}"#));
        assert!(!is_zenone(r#"{"outbounds": []}"#));
    }

    #[test]
    fn parse_and_validate_full() {
        let yaml = r#"
zen-version: 1
nodes:
  - name: vless1
    type: vless
    address: example.com
    uuid: "550e8400-e29b-41d4-a716-446655440000"
  - name: direct
    type: direct
groups:
  - name: proxy
    type: select
    nodes: [vless1, direct]
router:
  default: proxy
  rules:
    - type: geoip
      values: [cn]
      outbound: direct
"#;
        let (doc, diags) = parse_and_validate(yaml, None).unwrap();
        assert!(!diags.has_errors(), "errors: {:?}", diags.errors());
        assert_eq!(doc.nodes[0].port, Some(443)); // 推断
        assert!(doc.nodes[0].tls.as_ref().unwrap().enabled == Some(true)); // 推断
    }

    #[test]
    fn parse_and_validate_catches_errors() {
        let yaml = r#"
zen-version: 1
nodes:
  - name: bad-vless
    type: vless
    address: example.com
"#;
        let (_, diags) = parse_and_validate(yaml, None).unwrap();
        assert!(diags.has_errors()); // 缺少 uuid
    }

    #[test]
    fn parse_full_example() {
        let yaml = r#"
zen-version: 1
metadata:
  name: "测试订阅"
  source-url: "https://sub.example.com/api"
  update-interval: 3600
  expire-at: "2026-12-31T23:59:59Z"
  upload: 1073741824
  download: 5368709120
  total: 107374182400
nodes:
  - name: "HK-VLESS"
    type: vless
    address: hk.example.com
    port: 443
    uuid: "550e8400-e29b-41d4-a716-446655440000"
    flow: xtls-rprx-vision
    tls:
      fingerprint: chrome
      reality:
        public-key: abc123
        short-id: def456
  - name: "US-HY2"
    type: hysteria2
    address: us.example.com
    port: 443
    password: my-pass
    up-mbps: 100
    down-mbps: 200
  - name: direct
    type: direct
  - name: reject
    type: reject
groups:
  - name: Auto
    type: url-test
    nodes: [HK-VLESS, US-HY2]
    url: "https://www.gstatic.com/generate_204"
    interval: 300
    tolerance: 150
  - name: Proxy
    type: select
    nodes: [Auto, HK-VLESS, US-HY2]
router:
  default: Proxy
  rules:
    - type: geosite
      values: [cn]
      outbound: direct
    - type: geoip
      values: [cn, private]
      outbound: direct
    - type: domain-keyword
      values: [ads, tracking]
      action: reject
dns:
  mode: split
  cache-size: 2048
  servers:
    - address: "https://dns.alidns.com/dns-query"
      domains: [cn, baidu.com]
    - address: "tls://8.8.8.8"
  fake-ip:
    ipv4-range: "198.18.0.0/15"
    exclude: ["*.lan"]
"#;
        let (doc, diags) = parse_and_validate(yaml, None).unwrap();
        assert!(!diags.has_errors(), "errors: {:?}", diags.errors());
        assert_eq!(doc.nodes.len(), 4);
        assert_eq!(doc.groups.len(), 2);
        assert!(doc.dns.is_some());
        assert!(doc.metadata.is_some());
        assert_eq!(doc.metadata.as_ref().unwrap().name.as_deref(), Some("测试订阅"));
    }
}
