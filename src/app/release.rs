use std::fmt;

/// Semantic version representation
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SemVer {
    pub major: u32,
    pub minor: u32,
    pub patch: u32,
    pub pre: Option<String>,
}

impl SemVer {
    pub fn parse(s: &str) -> Option<Self> {
        let s = s.strip_prefix('v').unwrap_or(s);
        let (version_part, pre) = if let Some((v, p)) = s.split_once('-') {
            (v, Some(p.to_string()))
        } else {
            (s, None)
        };

        let parts: Vec<&str> = version_part.split('.').collect();
        if parts.len() != 3 {
            return None;
        }

        Some(Self {
            major: parts[0].parse().ok()?,
            minor: parts[1].parse().ok()?,
            patch: parts[2].parse().ok()?,
            pre,
        })
    }

    pub fn current() -> Self {
        Self::parse(env!("CARGO_PKG_VERSION")).unwrap_or(Self {
            major: 0,
            minor: 0,
            patch: 0,
            pre: None,
        })
    }

    pub fn is_compatible_with(&self, other: &SemVer) -> bool {
        if self.major == 0 && other.major == 0 {
            self.minor == other.minor
        } else {
            self.major == other.major
        }
    }
}

impl fmt::Display for SemVer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(ref pre) = self.pre {
            write!(f, "{}.{}.{}-{}", self.major, self.minor, self.patch, pre)
        } else {
            write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
        }
    }
}

/// Change type for release checklist
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChangeType {
    Feature,
    BugFix,
    Breaking,
    Security,
    Performance,
    Internal,
}

impl fmt::Display for ChangeType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ChangeType::Feature => write!(f, "feature"),
            ChangeType::BugFix => write!(f, "bugfix"),
            ChangeType::Breaking => write!(f, "breaking"),
            ChangeType::Security => write!(f, "security"),
            ChangeType::Performance => write!(f, "performance"),
            ChangeType::Internal => write!(f, "internal"),
        }
    }
}

/// A single change entry for the release checklist
#[derive(Debug, Clone)]
pub struct ChangeEntry {
    pub change_type: ChangeType,
    pub description: String,
    pub tested: bool,
    pub rollback_plan: Option<String>,
}

/// Release checklist for validating readiness
pub struct ReleaseChecklist {
    pub version: SemVer,
    pub changes: Vec<ChangeEntry>,
}

/// Validation issue found during checklist review
#[derive(Debug)]
pub struct ChecklistIssue {
    pub severity: IssueSeverity,
    pub message: String,
}

#[derive(Debug, PartialEq, Eq)]
pub enum IssueSeverity {
    Block,
    Warn,
}

impl ReleaseChecklist {
    pub fn new(version: SemVer) -> Self {
        Self {
            version,
            changes: Vec::new(),
        }
    }

    pub fn add(&mut self, entry: ChangeEntry) {
        self.changes.push(entry);
    }

    /// Validate the checklist and return any issues
    pub fn validate(&self) -> Vec<ChecklistIssue> {
        let mut issues = Vec::new();

        let has_breaking = self.changes.iter().any(|c| c.change_type == ChangeType::Breaking);
        if has_breaking && self.version.major == 0 && self.version.minor == 0 {
            issues.push(ChecklistIssue {
                severity: IssueSeverity::Warn,
                message: "breaking change in 0.0.x version".to_string(),
            });
        }

        let untested: Vec<_> = self.changes.iter().filter(|c| !c.tested).collect();
        if !untested.is_empty() {
            issues.push(ChecklistIssue {
                severity: IssueSeverity::Block,
                message: format!("{} change(s) not yet tested", untested.len()),
            });
        }

        let security_changes: Vec<_> = self
            .changes
            .iter()
            .filter(|c| c.change_type == ChangeType::Security)
            .collect();
        for sc in &security_changes {
            if sc.rollback_plan.is_none() {
                issues.push(ChecklistIssue {
                    severity: IssueSeverity::Block,
                    message: format!(
                        "security change '{}' has no rollback plan",
                        sc.description
                    ),
                });
            }
        }

        let breaking_no_rollback: Vec<_> = self
            .changes
            .iter()
            .filter(|c| c.change_type == ChangeType::Breaking && c.rollback_plan.is_none())
            .collect();
        for bc in &breaking_no_rollback {
            issues.push(ChecklistIssue {
                severity: IssueSeverity::Warn,
                message: format!(
                    "breaking change '{}' has no rollback plan",
                    bc.description
                ),
            });
        }

        issues
    }

    pub fn is_ready(&self) -> bool {
        self.validate()
            .iter()
            .all(|i| i.severity != IssueSeverity::Block)
    }

    pub fn summary(&self) -> String {
        let mut out = format!("Release {} checklist:\n", self.version);
        for (i, c) in self.changes.iter().enumerate() {
            let status = if c.tested { "[x]" } else { "[ ]" };
            out.push_str(&format!(
                "  {} {}. [{}] {}\n",
                status,
                i + 1,
                c.change_type,
                c.description
            ));
        }

        let issues = self.validate();
        if !issues.is_empty() {
            out.push_str("\nIssues:\n");
            for issue in &issues {
                let marker = match issue.severity {
                    IssueSeverity::Block => "BLOCK",
                    IssueSeverity::Warn => "WARN",
                };
                out.push_str(&format!("  [{}] {}\n", marker, issue.message));
            }
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn semver_parse_basic() {
        let v = SemVer::parse("1.2.3").unwrap();
        assert_eq!(v.major, 1);
        assert_eq!(v.minor, 2);
        assert_eq!(v.patch, 3);
        assert!(v.pre.is_none());
    }

    #[test]
    fn semver_parse_with_v_prefix_and_pre() {
        let v = SemVer::parse("v0.5.0-alpha").unwrap();
        assert_eq!(v.major, 0);
        assert_eq!(v.minor, 5);
        assert_eq!(v.patch, 0);
        assert_eq!(v.pre.as_deref(), Some("alpha"));
    }

    #[test]
    fn semver_compatibility() {
        let v1 = SemVer::parse("1.2.0").unwrap();
        let v2 = SemVer::parse("1.3.0").unwrap();
        let v3 = SemVer::parse("2.0.0").unwrap();
        assert!(v1.is_compatible_with(&v2));
        assert!(!v1.is_compatible_with(&v3));

        let v4 = SemVer::parse("0.1.0").unwrap();
        let v5 = SemVer::parse("0.1.1").unwrap();
        let v6 = SemVer::parse("0.2.0").unwrap();
        assert!(v4.is_compatible_with(&v5));
        assert!(!v4.is_compatible_with(&v6));
    }

    #[test]
    fn semver_display() {
        assert_eq!(SemVer::parse("1.2.3").unwrap().to_string(), "1.2.3");
        assert_eq!(
            SemVer::parse("0.1.0-beta").unwrap().to_string(),
            "0.1.0-beta"
        );
    }

    #[test]
    fn semver_current() {
        let v = SemVer::current();
        assert!(v.major < 100);
    }

    #[test]
    fn checklist_blocks_on_untested() {
        let mut cl = ReleaseChecklist::new(SemVer::parse("0.5.0").unwrap());
        cl.add(ChangeEntry {
            change_type: ChangeType::Feature,
            description: "new feature".to_string(),
            tested: false,
            rollback_plan: None,
        });
        assert!(!cl.is_ready());
        let issues = cl.validate();
        assert!(issues.iter().any(|i| i.severity == IssueSeverity::Block));
    }

    #[test]
    fn checklist_blocks_on_security_no_rollback() {
        let mut cl = ReleaseChecklist::new(SemVer::parse("0.5.0").unwrap());
        cl.add(ChangeEntry {
            change_type: ChangeType::Security,
            description: "fix TLS validation".to_string(),
            tested: true,
            rollback_plan: None,
        });
        assert!(!cl.is_ready());
    }

    #[test]
    fn checklist_ready_when_all_ok() {
        let mut cl = ReleaseChecklist::new(SemVer::parse("0.5.0").unwrap());
        cl.add(ChangeEntry {
            change_type: ChangeType::Feature,
            description: "add new protocol".to_string(),
            tested: true,
            rollback_plan: None,
        });
        cl.add(ChangeEntry {
            change_type: ChangeType::Security,
            description: "fix auth bypass".to_string(),
            tested: true,
            rollback_plan: Some("revert commit abc123".to_string()),
        });
        assert!(cl.is_ready());
    }

    #[test]
    fn checklist_summary_includes_all_info() {
        let mut cl = ReleaseChecklist::new(SemVer::parse("0.5.0").unwrap());
        cl.add(ChangeEntry {
            change_type: ChangeType::BugFix,
            description: "fix memory leak".to_string(),
            tested: true,
            rollback_plan: None,
        });
        cl.add(ChangeEntry {
            change_type: ChangeType::Breaking,
            description: "remove deprecated API".to_string(),
            tested: false,
            rollback_plan: None,
        });
        let summary = cl.summary();
        assert!(summary.contains("0.5.0"));
        assert!(summary.contains("fix memory leak"));
        assert!(summary.contains("remove deprecated API"));
        assert!(summary.contains("BLOCK"));
    }
}
