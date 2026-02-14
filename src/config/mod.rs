pub mod compat;
pub mod encryption;
pub mod enhance;
pub mod json_compat;
pub mod profile;
pub mod subscription;
pub mod types;
pub mod zenone;

use anyhow::Result;
use std::path::Path;

pub use types::Config;

fn ensure_tls_security(settings: &mut types::OutboundSettings, security: &str) {
    settings.security = Some(security.to_string());

    let tls = settings.tls.get_or_insert_with(types::TlsConfig::default);
    tls.enabled = true;
    tls.security = security.to_string();
}

fn set_transport_type(settings: &mut types::OutboundSettings, transport_type: &str) {
    let transport = settings
        .transport
        .get_or_insert_with(types::TransportConfig::default);
    transport.transport_type = transport_type.to_string();
}

pub fn normalize_outbound_alias(outbound: &mut types::OutboundConfig) {
    let protocol = outbound.protocol.trim().to_ascii_lowercase();
    match protocol.as_str() {
        "vless-tcp-reality-vision" => {
            outbound.protocol = "vless".to_string();
            outbound.settings.flow = Some("xtls-rprx-vision".to_string());
            ensure_tls_security(&mut outbound.settings, "reality");
        }
        "vless-xhttp-reality-enc" => {
            outbound.protocol = "vless".to_string();
            set_transport_type(&mut outbound.settings, "xhttp");
            ensure_tls_security(&mut outbound.settings, "reality");
        }
        "vless-xhttp-enc" => {
            outbound.protocol = "vless".to_string();
            set_transport_type(&mut outbound.settings, "xhttp");
            ensure_tls_security(&mut outbound.settings, "tls");
        }
        "vless-ws-enc" => {
            outbound.protocol = "vless".to_string();
            set_transport_type(&mut outbound.settings, "ws");
            ensure_tls_security(&mut outbound.settings, "tls");
        }

        "anytls" | "any-tls" => {
            outbound.protocol = "vless".to_string();
            set_transport_type(&mut outbound.settings, "anytls");
            if outbound.settings.security.is_none() {
                ensure_tls_security(&mut outbound.settings, "tls");
            }
        }
        "any-reality" | "anytls-reality" => {
            outbound.protocol = "vless".to_string();
            set_transport_type(&mut outbound.settings, "anytls");
            ensure_tls_security(&mut outbound.settings, "reality");
        }
        "shadowsocks-2022" | "ss-2022" => {
            outbound.protocol = "shadowsocks".to_string();
        }

        "vmess-ws" => {
            outbound.protocol = "vmess".to_string();
            set_transport_type(&mut outbound.settings, "ws");
        }
        "socks" => {
            outbound.protocol = "socks5".to_string();
        }
        _ => {}
    }
}

fn normalize_protocol_aliases(config: &mut Config) {
    for outbound in &mut config.outbounds {
        normalize_outbound_alias(outbound);
    }
}

fn has_enhance_markers(content: &str) -> bool {
    content.contains("\nmerge:") || content.starts_with("merge:")
}

fn apply_merge_if_present(content: &str) -> Result<String> {
    let mut root: serde_json::Value = serde_yml::from_str(content)?;
    let Some(obj) = root.as_object_mut() else {
        return Ok(content.to_string());
    };

    let Some(merge_value) = obj.remove("merge") else {
        return Ok(content.to_string());
    };

    let strategy = match obj
        .remove("merge_strategy")
        .and_then(|v| v.as_str().map(|s| s.to_lowercase()))
        .as_deref()
    {
        Some("append") => enhance::MergeStrategy::Append,
        _ => enhance::MergeStrategy::Override,
    };

    let mut base = serde_json::from_value::<std::collections::HashMap<String, serde_json::Value>>(
        serde_json::Value::Object(obj.clone()),
    )?;

    let overlays = match merge_value {
        serde_json::Value::Object(_) => vec![merge_value],
        serde_json::Value::Array(items) => items,
        _ => anyhow::bail!("merge must be an object or array of objects"),
    };

    for overlay in overlays {
        let overlay_map = serde_json::from_value::<
            std::collections::HashMap<String, serde_json::Value>,
        >(overlay)?;
        enhance::merge_maps(&mut base, &overlay_map, strategy.clone());
    }

    Ok(serde_yml::to_string(&base)?)
}

pub fn load_config(path: &str) -> Result<Config> {
    let content = load_config_content(path)?;

    // Try OpenWorld native format first, fall back to Clash compat
    let mut config: Config = match serde_yml::from_str(&content) {
        Ok(c) => c,
        Err(_) => {
            let compat_result = compat::parse_clash_config(&content)?;
            for w in &compat_result.warnings {
                tracing::warn!(warning = w.as_str(), "clash compat");
            }
            compat_result.config
        }
    };

    if let Some(profile_name) = config.profile.clone() {
        let profile_mgr = profile::ProfileManager::new();
        profile_mgr.apply_to_config(&profile_name, &mut config)?;
    }

    normalize_protocol_aliases(&mut config);

    config.validate()?;
    Ok(config)
}

pub fn load_config_content(path: &str) -> Result<String> {
    let raw_content = std::fs::read_to_string(Path::new(path))?;
    let base_dir = Path::new(path)
        .parent()
        .and_then(|p| p.to_str())
        .unwrap_or(".");

    let mut transformed = enhance::process_includes(&raw_content, base_dir)?;
    transformed = enhance::expand_env_vars(&transformed);

    if has_enhance_markers(&transformed) {
        apply_merge_if_present(&transformed)
    } else {
        Ok(transformed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn load_config_content_applies_include_and_env_without_merge_marker() {
        let dir = tempfile::tempdir().unwrap();
        let include_path = dir.path().join("inbounds.yaml");
        std::fs::write(
            &include_path,
            "inbounds:\n  - tag: socks-in\n    protocol: socks5\n    listen: \"127.0.0.1\"\n    port: 1080\n",
        )
        .unwrap();

        std::env::set_var("OW_TEST_DEFAULT_OUTBOUND", "direct");

        let config_path = dir.path().join("config.yaml");
        std::fs::write(
            &config_path,
            format!(
                "!include {}\noutbounds:\n  - tag: direct\n    protocol: direct\nrouter:\n  default: $OW_TEST_DEFAULT_OUTBOUND\n",
                include_path.display()
            ),
        )
        .unwrap();

        let loaded = load_config_content(config_path.to_str().unwrap()).unwrap();
        assert!(loaded.contains("socks-in"));
        assert!(loaded.contains("default: direct"));

        std::env::remove_var("OW_TEST_DEFAULT_OUTBOUND");
    }

    #[test]
    fn load_config_normalizes_panel_protocol_aliases() {
        let dir = tempfile::tempdir().unwrap();
        let config_path = dir.path().join("config.yaml");
        std::fs::write(
            &config_path,
            r#"
inbounds:
  - tag: socks-in
    protocol: socks5
    listen: "127.0.0.1"
    port: 1080

outbounds:
  - tag: vless-rv
    protocol: vless-tcp-reality-vision
    settings:
      address: example.com
      port: 443
      uuid: 550e8400-e29b-41d4-a716-446655440000
  - tag: any-r
    protocol: any-reality
    settings:
      address: example.com
      port: 443
      uuid: 550e8400-e29b-41d4-a716-446655440000
      public_key: 3R9vK-TEST-PUBKEY-PLACEHOLDER
      short_id: 6ba85179e30d4fc2
  - tag: vmess-ws-node
    protocol: vmess-ws
    settings:
      address: vm.example.com
      port: 443
      uuid: 550e8400-e29b-41d4-a716-446655440001
  - tag: direct
    protocol: direct

router:
  default: direct
"#,
        )
        .unwrap();

        let config = load_config(config_path.to_str().unwrap()).unwrap();
        let vless_rv = config
            .outbounds
            .iter()
            .find(|o| o.tag == "vless-rv")
            .unwrap();
        assert_eq!(vless_rv.protocol, "vless");
        assert_eq!(vless_rv.settings.flow.as_deref(), Some("xtls-rprx-vision"));
        assert_eq!(vless_rv.settings.security.as_deref(), Some("reality"));

        let any_r = config.outbounds.iter().find(|o| o.tag == "any-r").unwrap();
        assert_eq!(any_r.protocol, "vless");
        assert_eq!(
            any_r
                .settings
                .transport
                .as_ref()
                .map(|t| t.transport_type.as_str()),
            Some("anytls")
        );
        assert_eq!(any_r.settings.security.as_deref(), Some("reality"));

        let vmess_ws = config
            .outbounds
            .iter()
            .find(|o| o.tag == "vmess-ws-node")
            .unwrap();
        assert_eq!(vmess_ws.protocol, "vmess");
        assert_eq!(
            vmess_ws
                .settings
                .transport
                .as_ref()
                .map(|t| t.transport_type.as_str()),
            Some("ws")
        );
    }
}
