//! 统一认证框架
//!
//! 为所有入站协议提供统一的用户认证抽象，支持：
//! - 用户名/密码认证
//! - UUID 认证（VLESS/VMess）
//! - 多用户管理
//! - 认证事件审计

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};

use tokio::sync::RwLock;
use tracing::{debug, warn};

/// 认证凭据类型
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Credential {
    /// 用户名 + 密码（SOCKS5, HTTP, Trojan, Shadowsocks）
    UserPass { username: String, password: String },
    /// UUID（VLESS, VMess）
    Uuid(String),
    /// 仅密码（Trojan, Shadowsocks）
    Password(String),
    /// 无认证
    None,
}

/// 认证结果
#[derive(Debug, Clone)]
pub struct AuthResult {
    /// 是否认证成功
    pub success: bool,
    /// 匹配的用户名（如果有）
    pub user: Option<String>,
    /// 拒绝原因（如果失败）
    pub reason: Option<String>,
}

impl AuthResult {
    pub fn ok(user: impl Into<String>) -> Self {
        Self {
            success: true,
            user: Some(user.into()),
            reason: None,
        }
    }

    pub fn anonymous() -> Self {
        Self {
            success: true,
            user: None,
            reason: None,
        }
    }

    pub fn denied(reason: impl Into<String>) -> Self {
        Self {
            success: false,
            user: None,
            reason: Some(reason.into()),
        }
    }
}

/// 用户信息
#[derive(Debug, Clone)]
pub struct UserInfo {
    pub name: String,
    pub credential: Credential,
    /// 可选的流量限制（字节/秒）
    pub speed_limit: Option<u64>,
    /// 可选的最大连接数
    pub max_connections: Option<u32>,
    /// 是否启用
    pub enabled: bool,
}

/// 认证统计
#[derive(Debug, Default)]
pub struct AuthStats {
    pub total_attempts: AtomicU64,
    pub success_count: AtomicU64,
    pub failure_count: AtomicU64,
}

impl AuthStats {
    pub fn record_success(&self) {
        self.total_attempts.fetch_add(1, Ordering::Relaxed);
        self.success_count.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_failure(&self) {
        self.total_attempts.fetch_add(1, Ordering::Relaxed);
        self.failure_count.fetch_add(1, Ordering::Relaxed);
    }

    pub fn snapshot(&self) -> (u64, u64, u64) {
        (
            self.total_attempts.load(Ordering::Relaxed),
            self.success_count.load(Ordering::Relaxed),
            self.failure_count.load(Ordering::Relaxed),
        )
    }
}

/// 统一认证管理器
pub struct Authenticator {
    /// 按入站 tag 分组的用户列表
    users: RwLock<HashMap<String, Vec<UserInfo>>>,
    /// 认证统计
    stats: AuthStats,
    /// 是否允许无认证访问（当没有配置用户时）
    allow_anonymous: bool,
}

impl Authenticator {
    pub fn new(allow_anonymous: bool) -> Self {
        Self {
            users: RwLock::new(HashMap::new()),
            stats: AuthStats::default(),
            allow_anonymous,
        }
    }

    /// 为指定入站注册用户列表
    pub async fn register_users(&self, inbound_tag: &str, users: Vec<UserInfo>) {
        let mut map = self.users.write().await;
        debug!(
            tag = inbound_tag,
            count = users.len(),
            "registered auth users"
        );
        map.insert(inbound_tag.to_string(), users);
    }

    /// 认证请求
    pub async fn authenticate(&self, inbound_tag: &str, credential: &Credential) -> AuthResult {
        let map = self.users.read().await;

        let users = match map.get(inbound_tag) {
            Some(u) => u,
            None => {
                // 没有配置用户
                if self.allow_anonymous {
                    self.stats.record_success();
                    return AuthResult::anonymous();
                } else {
                    self.stats.record_failure();
                    return AuthResult::denied("no users configured");
                }
            }
        };

        if users.is_empty() && self.allow_anonymous {
            self.stats.record_success();
            return AuthResult::anonymous();
        }

        // 匹配凭据
        for user in users {
            if !user.enabled {
                continue;
            }
            if credentials_match(&user.credential, credential) {
                self.stats.record_success();
                debug!(user = user.name.as_str(), tag = inbound_tag, "auth success");
                return AuthResult::ok(&user.name);
            }
        }

        self.stats.record_failure();
        warn!(tag = inbound_tag, "auth failed: invalid credentials");
        AuthResult::denied("invalid credentials")
    }

    /// 获取认证统计
    pub fn stats(&self) -> (u64, u64, u64) {
        self.stats.snapshot()
    }
}

/// 比较凭据是否匹配
fn credentials_match(stored: &Credential, provided: &Credential) -> bool {
    match (stored, provided) {
        (Credential::UserPass { username: su, password: sp }, Credential::UserPass { username: pu, password: pp }) => {
            su == pu && sp == pp
        }
        (Credential::Uuid(stored_uuid), Credential::Uuid(provided_uuid)) => {
            stored_uuid.eq_ignore_ascii_case(provided_uuid)
        }
        (Credential::Password(stored_pw), Credential::Password(provided_pw)) => {
            stored_pw == provided_pw
        }
        // Password-only stored can match UserPass if password matches
        (Credential::Password(stored_pw), Credential::UserPass { password: pp, .. }) => {
            stored_pw == pp
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn auth_anonymous_when_no_users() {
        let auth = Authenticator::new(true);
        let result = auth.authenticate("socks-in", &Credential::None).await;
        assert!(result.success);
        assert!(result.user.is_none());
    }

    #[tokio::test]
    async fn auth_denied_when_no_users_strict() {
        let auth = Authenticator::new(false);
        let result = auth.authenticate("socks-in", &Credential::None).await;
        assert!(!result.success);
    }

    #[tokio::test]
    async fn auth_userpass_success() {
        let auth = Authenticator::new(false);
        auth.register_users("socks-in", vec![UserInfo {
            name: "alice".to_string(),
            credential: Credential::UserPass {
                username: "alice".to_string(),
                password: "secret".to_string(),
            },
            speed_limit: None,
            max_connections: None,
            enabled: true,
        }]).await;

        let result = auth.authenticate("socks-in", &Credential::UserPass {
            username: "alice".to_string(),
            password: "secret".to_string(),
        }).await;
        assert!(result.success);
        assert_eq!(result.user.as_deref(), Some("alice"));
    }

    #[tokio::test]
    async fn auth_userpass_wrong_password() {
        let auth = Authenticator::new(false);
        auth.register_users("socks-in", vec![UserInfo {
            name: "alice".to_string(),
            credential: Credential::UserPass {
                username: "alice".to_string(),
                password: "secret".to_string(),
            },
            speed_limit: None,
            max_connections: None,
            enabled: true,
        }]).await;

        let result = auth.authenticate("socks-in", &Credential::UserPass {
            username: "alice".to_string(),
            password: "wrong".to_string(),
        }).await;
        assert!(!result.success);
    }

    #[tokio::test]
    async fn auth_uuid_case_insensitive() {
        let auth = Authenticator::new(false);
        auth.register_users("vless-in", vec![UserInfo {
            name: "user1".to_string(),
            credential: Credential::Uuid("550e8400-e29b-41d4-a716-446655440000".to_string()),
            speed_limit: None,
            max_connections: None,
            enabled: true,
        }]).await;

        let result = auth.authenticate("vless-in", &Credential::Uuid(
            "550E8400-E29B-41D4-A716-446655440000".to_string()
        )).await;
        assert!(result.success);
    }

    #[tokio::test]
    async fn auth_disabled_user_rejected() {
        let auth = Authenticator::new(false);
        auth.register_users("socks-in", vec![UserInfo {
            name: "disabled".to_string(),
            credential: Credential::Password("pw".to_string()),
            speed_limit: None,
            max_connections: None,
            enabled: false,
        }]).await;

        let result = auth.authenticate("socks-in", &Credential::Password("pw".to_string())).await;
        assert!(!result.success);
    }

    #[tokio::test]
    async fn auth_stats_tracking() {
        let auth = Authenticator::new(true);
        auth.authenticate("test", &Credential::None).await;
        auth.authenticate("test", &Credential::None).await;

        let (total, success, _failure) = auth.stats();
        assert_eq!(total, 2);
        assert_eq!(success, 2);
    }

    #[test]
    fn credentials_match_password_to_userpass() {
        let stored = Credential::Password("secret".to_string());
        let provided = Credential::UserPass {
            username: "any".to_string(),
            password: "secret".to_string(),
        };
        assert!(credentials_match(&stored, &provided));
    }

    #[test]
    fn credentials_mismatch_different_types() {
        let stored = Credential::Uuid("abc".to_string());
        let provided = Credential::Password("abc".to_string());
        assert!(!credentials_match(&stored, &provided));
    }
}
