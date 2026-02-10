pub mod types;

use anyhow::Result;
use std::path::Path;

pub use types::Config;

pub fn load_config(path: &str) -> Result<Config> {
    let content = std::fs::read_to_string(Path::new(path))?;
    let config: Config = serde_yml::from_str(&content)?;
    config.validate()?;
    Ok(config)
}
