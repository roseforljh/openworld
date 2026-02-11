pub mod compat;
pub mod encryption;
pub mod enhance;
pub mod profile;
pub mod subscription;
pub mod types;

use anyhow::Result;
use std::path::Path;

pub use types::Config;

fn has_enhance_markers(content: &str) -> bool {
    content.contains("${")
        || content.contains("!include ")
        || content.contains("#include ")
        || content.contains("\nmerge:")
        || content.starts_with("merge:")
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
    let raw_content = std::fs::read_to_string(Path::new(path))?;
    let content = if has_enhance_markers(&raw_content) {
        let base_dir = Path::new(path)
            .parent()
            .and_then(|p| p.to_str())
            .unwrap_or(".");
        let included = enhance::process_includes(&raw_content, base_dir)?;
        let expanded = enhance::expand_env_vars(&included);
        apply_merge_if_present(&expanded)?
    } else {
        raw_content
    };

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
