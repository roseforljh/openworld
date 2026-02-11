use std::collections::HashMap;
use std::fs;

use anyhow::Result;
use tracing::info;

/// GeoSite 数据库
///
/// 支持纯文本域名列表文件格式，每行一条规则:
/// - `domain:example.com` -- 完全匹配
/// - `domain_suffix:example.com` -- 后缀匹配
/// - `domain_keyword:google` -- 关键字匹配
/// - `example.com` -- 默认为后缀匹配
pub struct GeoSiteDb {
    /// 分类名 -> 规则列表
    categories: HashMap<String, Vec<SiteRule>>,
}

#[derive(Debug, Clone)]
enum SiteRule {
    Domain(String),
    DomainSuffix(String),
    DomainKeyword(String),
}

impl GeoSiteDb {
    /// 从文本文件加载
    ///
    /// 文件格式: 每行一条规则，支持 `domain:`, `domain_suffix:`, `domain_keyword:` 前缀。
    /// 无前缀默认为 domain_suffix。
    /// 以 `#` 开头的行为注释。
    pub fn load(path: &str, category: &str) -> Result<Self> {
        let content = fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("failed to read geosite file '{}': {}", path, e))?;

        let rules = Self::parse_rules(&content)?;
        let count = rules.len();

        let mut categories = HashMap::new();
        categories.insert(category.to_lowercase(), rules);

        info!(
            path = path,
            category = category,
            count = count,
            "GeoSite database loaded"
        );
        Ok(Self { categories })
    }

    /// 从多个文件加载多个分类
    pub fn load_multiple(entries: &[(String, String)]) -> Result<Self> {
        let mut categories = HashMap::new();
        for (path, category) in entries {
            let content = fs::read_to_string(path)
                .map_err(|e| anyhow::anyhow!("failed to read geosite file '{}': {}", path, e))?;
            let rules = Self::parse_rules(&content)?;
            let count = rules.len();
            info!(
                path = path.as_str(),
                category = category.as_str(),
                count = count,
                "GeoSite category loaded"
            );
            categories.insert(category.to_lowercase(), rules);
        }
        Ok(Self { categories })
    }

    fn parse_rules(content: &str) -> Result<Vec<SiteRule>> {
        let mut rules = Vec::new();
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }

            let rule = if let Some(domain) = line.strip_prefix("domain:") {
                SiteRule::Domain(domain.to_lowercase())
            } else if let Some(suffix) = line.strip_prefix("domain_suffix:") {
                SiteRule::DomainSuffix(suffix.to_lowercase())
            } else if let Some(keyword) = line.strip_prefix("domain_keyword:") {
                SiteRule::DomainKeyword(keyword.to_lowercase())
            } else {
                // 默认为后缀匹配
                SiteRule::DomainSuffix(line.to_lowercase())
            };
            rules.push(rule);
        }
        Ok(rules)
    }

    /// 检查域名是否匹配指定分类
    pub fn matches(&self, domain: &str, category: &str) -> bool {
        let category_lower = category.to_lowercase();
        if let Some(rules) = self.categories.get(&category_lower) {
            let domain_lower = domain.to_lowercase();
            rules.iter().any(|rule| match rule {
                SiteRule::Domain(d) => domain_lower == *d,
                SiteRule::DomainSuffix(suffix) => {
                    domain_lower == *suffix || domain_lower.ends_with(&format!(".{}", suffix))
                }
                SiteRule::DomainKeyword(keyword) => domain_lower.contains(keyword.as_str()),
            })
        } else {
            false
        }
    }

    /// 获取所有已加载的分类名
    pub fn categories(&self) -> Vec<&str> {
        self.categories.keys().map(|s| s.as_str()).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_and_match_domain() {
        let content = "domain:example.com\ndomain:test.org\n";
        let rules = GeoSiteDb::parse_rules(content).unwrap();
        let mut categories = HashMap::new();
        categories.insert("test".to_string(), rules);
        let db = GeoSiteDb { categories };

        assert!(db.matches("example.com", "test"));
        assert!(db.matches("EXAMPLE.COM", "test"));
        assert!(!db.matches("sub.example.com", "test"));
        assert!(!db.matches("notexample.com", "test"));
    }

    #[test]
    fn parse_and_match_suffix() {
        let content = "domain_suffix:example.com\n";
        let rules = GeoSiteDb::parse_rules(content).unwrap();
        let mut categories = HashMap::new();
        categories.insert("test".to_string(), rules);
        let db = GeoSiteDb { categories };

        assert!(db.matches("example.com", "test"));
        assert!(db.matches("sub.example.com", "test"));
        assert!(!db.matches("notexample.com", "test"));
    }

    #[test]
    fn parse_and_match_keyword() {
        let content = "domain_keyword:google\n";
        let rules = GeoSiteDb::parse_rules(content).unwrap();
        let mut categories = HashMap::new();
        categories.insert("test".to_string(), rules);
        let db = GeoSiteDb { categories };

        assert!(db.matches("www.google.com", "test"));
        assert!(db.matches("google.co.jp", "test"));
        assert!(!db.matches("example.com", "test"));
    }

    #[test]
    fn default_is_suffix() {
        let content = "example.com\ntest.org\n";
        let rules = GeoSiteDb::parse_rules(content).unwrap();
        let mut categories = HashMap::new();
        categories.insert("cn".to_string(), rules);
        let db = GeoSiteDb { categories };

        assert!(db.matches("example.com", "cn"));
        assert!(db.matches("sub.example.com", "cn"));
        assert!(db.matches("test.org", "cn"));
    }

    #[test]
    fn comments_and_empty_lines() {
        let content = "# comment\n\nexample.com\n  # another comment\n";
        let rules = GeoSiteDb::parse_rules(content).unwrap();
        assert_eq!(rules.len(), 1);
    }

    #[test]
    fn case_insensitive_category() {
        let content = "example.com\n";
        let rules = GeoSiteDb::parse_rules(content).unwrap();
        let mut categories = HashMap::new();
        categories.insert("cn".to_string(), rules);
        let db = GeoSiteDb { categories };

        assert!(db.matches("example.com", "CN"));
        assert!(db.matches("example.com", "cn"));
        assert!(db.matches("example.com", "Cn"));
    }

    #[test]
    fn unknown_category_returns_false() {
        let db = GeoSiteDb {
            categories: HashMap::new(),
        };
        assert!(!db.matches("example.com", "nonexistent"));
    }
}
