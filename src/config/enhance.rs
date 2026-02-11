use std::collections::HashMap;

use anyhow::Result;

/// Expand environment variables in a string.
/// Supports ${VAR_NAME} and $VAR_NAME syntax.
pub fn expand_env_vars(input: &str) -> String {
    let mut result = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();

    while let Some(c) = chars.next() {
        if c == '$' {
            if chars.peek() == Some(&'{') {
                chars.next(); // consume '{'
                let mut var_name = String::new();
                for c in chars.by_ref() {
                    if c == '}' {
                        break;
                    }
                    var_name.push(c);
                }
                // Support ${VAR:-default} syntax
                if let Some((name, default)) = var_name.split_once(":-") {
                    match std::env::var(name) {
                        Ok(val) if !val.is_empty() => result.push_str(&val),
                        _ => result.push_str(default),
                    }
                } else {
                    match std::env::var(&var_name) {
                        Ok(val) => result.push_str(&val),
                        Err(_) => {} // empty for undefined vars
                    }
                }
            } else {
                // $VAR_NAME (terminated by non-alphanumeric/underscore)
                let mut var_name = String::new();
                while let Some(&c) = chars.peek() {
                    if c.is_ascii_alphanumeric() || c == '_' {
                        var_name.push(c);
                        chars.next();
                    } else {
                        break;
                    }
                }
                if var_name.is_empty() {
                    result.push('$');
                } else {
                    match std::env::var(&var_name) {
                        Ok(val) => result.push_str(&val),
                        Err(_) => {}
                    }
                }
            }
        } else {
            result.push(c);
        }
    }
    result
}

/// Process include directives in YAML config.
/// Lines like `!include path/to/file.yaml` are replaced with the file content.
pub fn process_includes(content: &str, base_dir: &str) -> Result<String> {
    let mut result = String::new();
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with("!include ") || trimmed.starts_with("#include ") {
            let path = trimmed.splitn(2, ' ').nth(1).unwrap_or("").trim();
            let full_path = if std::path::Path::new(path).is_absolute() {
                path.to_string()
            } else {
                format!("{}/{}", base_dir, path)
            };
            match std::fs::read_to_string(&full_path) {
                Ok(included) => {
                    result.push_str(&included);
                    result.push('\n');
                }
                Err(e) => {
                    anyhow::bail!("failed to include '{}': {}", full_path, e);
                }
            }
        } else {
            result.push_str(line);
            result.push('\n');
        }
    }
    Ok(result)
}

/// Merge strategy for config sections
#[derive(Debug, Clone, PartialEq)]
pub enum MergeStrategy {
    Override,
    Append,
}

/// Merge two YAML-like key-value maps with a given strategy.
/// For Override: base values are replaced by overlay values.
/// For Append: overlay values are appended to base values (for lists).
pub fn merge_maps(
    base: &mut HashMap<String, serde_json::Value>,
    overlay: &HashMap<String, serde_json::Value>,
    strategy: MergeStrategy,
) {
    for (key, value) in overlay {
        match strategy {
            MergeStrategy::Override => {
                base.insert(key.clone(), value.clone());
            }
            MergeStrategy::Append => {
                if let Some(existing) = base.get_mut(key) {
                    if let (
                        serde_json::Value::Array(ref mut arr),
                        serde_json::Value::Array(ref new_arr),
                    ) = (existing, value)
                    {
                        arr.extend(new_arr.iter().cloned());
                        continue;
                    }
                }
                base.insert(key.clone(), value.clone());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expand_env_var_braces() {
        std::env::set_var("TEST_OPENWORLD_VAR", "hello");
        let result = expand_env_vars("value=${TEST_OPENWORLD_VAR}");
        assert_eq!(result, "value=hello");
        std::env::remove_var("TEST_OPENWORLD_VAR");
    }

    #[test]
    fn expand_env_var_no_braces() {
        std::env::set_var("TEST_OW_PORT", "8080");
        let result = expand_env_vars("port=$TEST_OW_PORT end");
        assert_eq!(result, "port=8080 end");
        std::env::remove_var("TEST_OW_PORT");
    }

    #[test]
    fn expand_env_var_default() {
        std::env::remove_var("TEST_OW_MISSING");
        let result = expand_env_vars("val=${TEST_OW_MISSING:-default_value}");
        assert_eq!(result, "val=default_value");
    }

    #[test]
    fn expand_env_var_default_overridden() {
        std::env::set_var("TEST_OW_SET", "actual");
        let result = expand_env_vars("val=${TEST_OW_SET:-default}");
        assert_eq!(result, "val=actual");
        std::env::remove_var("TEST_OW_SET");
    }

    #[test]
    fn expand_env_var_undefined_empty() {
        std::env::remove_var("TEST_OW_UNDEFINED");
        let result = expand_env_vars("val=${TEST_OW_UNDEFINED}");
        assert_eq!(result, "val=");
    }

    #[test]
    fn expand_no_vars() {
        let input = "just a normal string";
        assert_eq!(expand_env_vars(input), "just a normal string");
    }

    #[test]
    fn expand_dollar_sign_alone() {
        assert_eq!(expand_env_vars("price is $"), "price is $");
    }

    #[test]
    fn merge_override() {
        let mut base = HashMap::new();
        base.insert("key1".to_string(), serde_json::json!("old"));
        base.insert("key2".to_string(), serde_json::json!("keep"));

        let mut overlay = HashMap::new();
        overlay.insert("key1".to_string(), serde_json::json!("new"));
        overlay.insert("key3".to_string(), serde_json::json!("added"));

        merge_maps(&mut base, &overlay, MergeStrategy::Override);

        assert_eq!(base.get("key1").unwrap(), &serde_json::json!("new"));
        assert_eq!(base.get("key2").unwrap(), &serde_json::json!("keep"));
        assert_eq!(base.get("key3").unwrap(), &serde_json::json!("added"));
    }

    #[test]
    fn merge_append_arrays() {
        let mut base = HashMap::new();
        base.insert("list".to_string(), serde_json::json!([1, 2]));

        let mut overlay = HashMap::new();
        overlay.insert("list".to_string(), serde_json::json!([3, 4]));

        merge_maps(&mut base, &overlay, MergeStrategy::Append);

        assert_eq!(base.get("list").unwrap(), &serde_json::json!([1, 2, 3, 4]));
    }

    #[test]
    fn merge_append_non_array_overrides() {
        let mut base = HashMap::new();
        base.insert("key".to_string(), serde_json::json!("old"));

        let mut overlay = HashMap::new();
        overlay.insert("key".to_string(), serde_json::json!("new"));

        merge_maps(&mut base, &overlay, MergeStrategy::Append);

        assert_eq!(base.get("key").unwrap(), &serde_json::json!("new"));
    }
}
