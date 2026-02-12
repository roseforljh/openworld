pub mod compat;
pub mod encryption;
pub mod enhance;
pub mod json_compat;
pub mod profile;
pub mod subscription;
pub mod types;

use anyhow::Result;
use std::path::Path;

pub use types::Config;

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
}
