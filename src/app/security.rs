use anyhow::Result;

use crate::config::types::Config;

#[derive(Debug, Clone)]
pub struct SecurityWarning {
    pub severity: Severity,
    pub code: &'static str,
    pub message: String,
    pub fix_hint: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Severity {
    Block,
    Warn,
    Info,
}

pub struct SecurityReport {
    pub warnings: Vec<SecurityWarning>,
    pub blocked: bool,
}

pub fn audit_config(config: &Config) -> SecurityReport {
    let mut warnings = Vec::new();

    // Check allow-insecure on outbounds
    for ob in &config.outbounds {
        if ob.settings.allow_insecure {
            warnings.push(SecurityWarning {
                severity: Severity::Warn,
                code: "SEC_TLS_INSECURE",
                message: format!("outbound '{}' has allow_insecure=true", ob.tag),
                fix_hint: "Set allow_insecure to false and use a valid TLS certificate".to_string(),
            });
        }
    }

    // Check API without secret
    if let Some(ref api) = config.api {
        if api.secret.is_none() {
            let listen_external = api.listen != "127.0.0.1" && api.listen != "localhost";
            if listen_external {
                warnings.push(SecurityWarning {
                    severity: Severity::Block,
                    code: "SEC_API_NO_SECRET",
                    message: format!("API listens on {} without a secret", api.listen),
                    fix_hint: "Set api.secret or bind API to 127.0.0.1".to_string(),
                });
            } else {
                warnings.push(SecurityWarning {
                    severity: Severity::Info,
                    code: "SEC_API_LOCAL_NO_SECRET",
                    message: "API has no secret (localhost only)".to_string(),
                    fix_hint: "Consider setting api.secret for defense in depth".to_string(),
                });
            }
        }
    }

    // Check for empty passwords
    for ob in &config.outbounds {
        if let Some(ref pwd) = ob.settings.password {
            if pwd.is_empty() {
                warnings.push(SecurityWarning {
                    severity: Severity::Warn,
                    code: "SEC_EMPTY_PASSWORD",
                    message: format!("outbound '{}' has an empty password", ob.tag),
                    fix_hint: "Set a strong password for this outbound".to_string(),
                });
            }
        }
    }

    // Check for weak Shadowsocks ciphers
    for ob in &config.outbounds {
        if ob.protocol == "shadowsocks" || ob.protocol == "ss" {
            if let Some(ref method) = ob.settings.method {
                let weak = matches!(
                    method.as_str(),
                    "rc4"
                        | "rc4-md5"
                        | "aes-128-cfb"
                        | "aes-256-cfb"
                        | "chacha20"
                        | "table"
                        | "none"
                );
                if weak {
                    warnings.push(SecurityWarning {
                        severity: Severity::Warn,
                        code: "SEC_WEAK_CIPHER",
                        message: format!("outbound '{}' uses weak cipher '{}'", ob.tag, method),
                        fix_hint: "Use aes-256-gcm or chacha20-ietf-poly1305".to_string(),
                    });
                }
            }
        }
    }

    let blocked = warnings.iter().any(|w| w.severity == Severity::Block);

    SecurityReport { warnings, blocked }
}

pub fn mask_sensitive(value: &str) -> String {
    if value.len() <= 4 {
        "****".to_string()
    } else {
        let visible = &value[..2];
        format!("{}****{}", visible, &value[value.len() - 2..])
    }
}

pub fn validate_and_warn(config: &Config) -> Result<()> {
    let report = audit_config(config);

    for w in &report.warnings {
        match w.severity {
            Severity::Block => {
                tracing::error!(code = w.code, fix = w.fix_hint.as_str(), "{}", w.message);
            }
            Severity::Warn => {
                tracing::warn!(code = w.code, fix = w.fix_hint.as_str(), "{}", w.message);
            }
            Severity::Info => {
                tracing::info!(code = w.code, fix = w.fix_hint.as_str(), "{}", w.message);
            }
        }
    }

    if report.blocked {
        anyhow::bail!(
            "security audit blocked startup: {}",
            report
                .warnings
                .iter()
                .filter(|w| w.severity == Severity::Block)
                .map(|w| w.message.as_str())
                .collect::<Vec<_>>()
                .join("; ")
        );
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::types::*;

    fn minimal_config() -> Config {
        Config {
            log: LogConfig::default(),
            profile: None,
            inbounds: vec![InboundConfig {
                tag: "socks-in".to_string(),
                protocol: "socks5".to_string(),
                listen: "127.0.0.1".to_string(),
                port: 1080,
                sniffing: SniffingConfig::default(),
                settings: InboundSettings::default(),
                max_connections: None,
            }],
            outbounds: vec![OutboundConfig {
                tag: "direct".to_string(),
                protocol: "direct".to_string(),
                settings: OutboundSettings::default(),
            }],
            proxy_groups: vec![],
            router: RouterConfig::default(),
            subscriptions: vec![],
            api: None,
            dns: None,
            derp: None,
            max_connections: 10000,
        }
    }

    #[test]
    fn audit_clean_config_no_warnings() {
        let config = minimal_config();
        let report = audit_config(&config);
        assert!(report.warnings.is_empty());
        assert!(!report.blocked);
    }

    #[test]
    fn audit_allow_insecure_warns() {
        let mut config = minimal_config();
        config.outbounds.push(OutboundConfig {
            tag: "insecure-vless".to_string(),
            protocol: "vless".to_string(),
            settings: OutboundSettings {
                allow_insecure: true,
                ..Default::default()
            },
        });
        let report = audit_config(&config);
        assert!(report.warnings.iter().any(|w| w.code == "SEC_TLS_INSECURE"));
        assert!(!report.blocked);
    }

    #[test]
    fn audit_api_external_no_secret_blocks() {
        let mut config = minimal_config();
        config.api = Some(ApiConfig {
            listen: "0.0.0.0".to_string(),
            port: 9090,
            secret: None,
            external_ui: None,
        });
        let report = audit_config(&config);
        assert!(report.blocked);
        assert!(report
            .warnings
            .iter()
            .any(|w| w.code == "SEC_API_NO_SECRET"));
    }

    #[test]
    fn audit_api_localhost_no_secret_info_only() {
        let mut config = minimal_config();
        config.api = Some(ApiConfig {
            listen: "127.0.0.1".to_string(),
            port: 9090,
            secret: None,
            external_ui: None,
        });
        let report = audit_config(&config);
        assert!(!report.blocked);
        assert!(report
            .warnings
            .iter()
            .any(|w| w.code == "SEC_API_LOCAL_NO_SECRET"));
    }

    #[test]
    fn audit_weak_cipher_warns() {
        let mut config = minimal_config();
        config.outbounds.push(OutboundConfig {
            tag: "weak-ss".to_string(),
            protocol: "shadowsocks".to_string(),
            settings: OutboundSettings {
                method: Some("rc4-md5".to_string()),
                ..Default::default()
            },
        });
        let report = audit_config(&config);
        assert!(report.warnings.iter().any(|w| w.code == "SEC_WEAK_CIPHER"));
    }

    #[test]
    fn mask_sensitive_hides_middle() {
        assert_eq!(mask_sensitive("my-super-secret-password"), "my****rd");
        assert_eq!(mask_sensitive("ab"), "****");
        assert_eq!(mask_sensitive("abcde"), "ab****de");
    }
}
