/// Android JNI 接口定义
///
/// 在 Android 平台上通过 jni crate 导出 Java native 方法。
/// 非 Android 平台提供接口定义和方法签名验证。

/// JNI 方法签名
#[derive(Debug, Clone)]
pub struct JniMethodSignature {
    pub class: String,
    pub method: String,
    pub signature: String,
    pub is_static: bool,
}

impl JniMethodSignature {
    pub fn new(class: &str, method: &str, signature: &str, is_static: bool) -> Self {
        Self {
            class: class.to_string(),
            method: method.to_string(),
            signature: signature.to_string(),
            is_static,
        }
    }

    /// 验证 JNI 签名格式
    ///
    /// JNI 签名以 `(` 开头，包含参数类型，以 `)` 结束参数部分，
    /// 然后跟随返回类型。基本类型: V, Z, B, C, S, I, J, F, D;
    /// 对象类型: Lclass/path;  数组类型: [type
    pub fn validate(&self) -> Result<(), String> {
        if self.class.is_empty() {
            return Err("class name cannot be empty".to_string());
        }
        if self.method.is_empty() {
            return Err("method name cannot be empty".to_string());
        }
        if self.signature.is_empty() {
            return Err("signature cannot be empty".to_string());
        }
        if !self.signature.starts_with('(') {
            return Err(format!(
                "signature must start with '(', got: {}",
                self.signature
            ));
        }
        if !self.signature.contains(')') {
            return Err(format!(
                "signature must contain ')', got: {}",
                self.signature
            ));
        }
        // Check that there is a return type after ')'
        let after_paren = self.signature.split(')').last().unwrap_or("");
        if after_paren.is_empty() {
            return Err("signature must have a return type after ')'".to_string());
        }
        // Validate return type starts with a valid JNI type descriptor
        let first_char = after_paren.chars().next().unwrap();
        let valid_type_chars = ['V', 'Z', 'B', 'C', 'S', 'I', 'J', 'F', 'D', 'L', '['];
        if !valid_type_chars.contains(&first_char) {
            return Err(format!(
                "invalid return type descriptor: {}",
                after_paren
            ));
        }
        Ok(())
    }

    /// 获取 JNI 导出函数名（Java_com_openworld_Core_methodName 格式）
    ///
    /// 将 Java 类路径中的 `.` 和 `/` 替换为 `_`。
    pub fn export_name(&self) -> String {
        let class_part = self.class.replace(['/', '.'], "_");
        format!("Java_{}_{}", class_part, self.method)
    }
}

/// 核心 JNI 接口定义
pub fn core_jni_methods() -> Vec<JniMethodSignature> {
    vec![
        JniMethodSignature::new("com/openworld/Core", "start", "(Ljava/lang/String;)V", true),
        JniMethodSignature::new("com/openworld/Core", "stop", "()V", true),
        JniMethodSignature::new("com/openworld/Core", "isRunning", "()Z", true),
        JniMethodSignature::new(
            "com/openworld/Core",
            "getVersion",
            "()Ljava/lang/String;",
            true,
        ),
        JniMethodSignature::new("com/openworld/Core", "configureTunFd", "(I)V", true),
    ]
}

/// VPN Service 辅助
#[derive(Debug, Clone)]
pub struct VpnServiceHelper {
    pub tun_fd: Option<i32>,
    pub dns_servers: Vec<String>,
    pub routes: Vec<String>,
}

impl VpnServiceHelper {
    pub fn new() -> Self {
        Self {
            tun_fd: None,
            dns_servers: Vec::new(),
            routes: Vec::new(),
        }
    }

    pub fn set_tun_fd(&mut self, fd: i32) {
        self.tun_fd = Some(fd);
    }

    pub fn add_dns_server(&mut self, server: &str) {
        self.dns_servers.push(server.to_string());
    }

    pub fn add_route(&mut self, route: &str) {
        self.routes.push(route.to_string());
    }

    pub fn is_configured(&self) -> bool {
        self.tun_fd.is_some() && !self.dns_servers.is_empty()
    }
}

impl Default for VpnServiceHelper {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jni_signature_valid() {
        let sig = JniMethodSignature::new("com/openworld/Core", "start", "(Ljava/lang/String;)V", true);
        assert!(sig.validate().is_ok());
    }

    #[test]
    fn jni_signature_valid_boolean_return() {
        let sig = JniMethodSignature::new("com/openworld/Core", "isRunning", "()Z", true);
        assert!(sig.validate().is_ok());
    }

    #[test]
    fn jni_signature_valid_int_param() {
        let sig = JniMethodSignature::new("com/openworld/Core", "configureTunFd", "(I)V", true);
        assert!(sig.validate().is_ok());
    }

    #[test]
    fn jni_signature_invalid_no_paren() {
        let sig = JniMethodSignature::new("com/openworld/Core", "bad", "V", false);
        assert!(sig.validate().is_err());
    }

    #[test]
    fn jni_signature_invalid_empty_class() {
        let sig = JniMethodSignature::new("", "method", "()V", false);
        let err = sig.validate().unwrap_err();
        assert!(err.contains("class name"));
    }

    #[test]
    fn jni_signature_invalid_empty_method() {
        let sig = JniMethodSignature::new("com/openworld/Core", "", "()V", false);
        let err = sig.validate().unwrap_err();
        assert!(err.contains("method name"));
    }

    #[test]
    fn jni_signature_invalid_empty_signature() {
        let sig = JniMethodSignature::new("com/openworld/Core", "method", "", false);
        let err = sig.validate().unwrap_err();
        assert!(err.contains("signature"));
    }

    #[test]
    fn jni_signature_invalid_no_closing_paren() {
        let sig = JniMethodSignature::new("com/openworld/Core", "method", "(IV", false);
        let err = sig.validate().unwrap_err();
        assert!(err.contains(")"));
    }

    #[test]
    fn jni_signature_invalid_return_type() {
        let sig = JniMethodSignature::new("com/openworld/Core", "method", "()X", false);
        let err = sig.validate().unwrap_err();
        assert!(err.contains("invalid return type"));
    }

    #[test]
    fn export_name_generation() {
        let sig = JniMethodSignature::new("com/openworld/Core", "start", "(Ljava/lang/String;)V", true);
        assert_eq!(sig.export_name(), "Java_com_openworld_Core_start");
    }

    #[test]
    fn export_name_with_dots() {
        let sig = JniMethodSignature::new("com.openworld.Core", "stop", "()V", true);
        assert_eq!(sig.export_name(), "Java_com_openworld_Core_stop");
    }

    #[test]
    fn export_name_all_methods() {
        let methods = core_jni_methods();
        let names: Vec<String> = methods.iter().map(|m| m.export_name()).collect();
        assert!(names.contains(&"Java_com_openworld_Core_start".to_string()));
        assert!(names.contains(&"Java_com_openworld_Core_stop".to_string()));
        assert!(names.contains(&"Java_com_openworld_Core_isRunning".to_string()));
        assert!(names.contains(&"Java_com_openworld_Core_getVersion".to_string()));
        assert!(names.contains(&"Java_com_openworld_Core_configureTunFd".to_string()));
    }

    #[test]
    fn core_jni_methods_contains_all() {
        let methods = core_jni_methods();
        assert_eq!(methods.len(), 5);

        let method_names: Vec<&str> = methods.iter().map(|m| m.method.as_str()).collect();
        assert!(method_names.contains(&"start"));
        assert!(method_names.contains(&"stop"));
        assert!(method_names.contains(&"isRunning"));
        assert!(method_names.contains(&"getVersion"));
        assert!(method_names.contains(&"configureTunFd"));
    }

    #[test]
    fn core_jni_methods_all_static() {
        let methods = core_jni_methods();
        for m in &methods {
            assert!(m.is_static, "method {} should be static", m.method);
        }
    }

    #[test]
    fn core_jni_methods_all_valid() {
        let methods = core_jni_methods();
        for m in &methods {
            assert!(m.validate().is_ok(), "method {} has invalid signature", m.method);
        }
    }

    #[test]
    fn vpn_service_helper_new() {
        let helper = VpnServiceHelper::new();
        assert!(helper.tun_fd.is_none());
        assert!(helper.dns_servers.is_empty());
        assert!(helper.routes.is_empty());
        assert!(!helper.is_configured());
    }

    #[test]
    fn vpn_service_helper_set_tun_fd() {
        let mut helper = VpnServiceHelper::new();
        helper.set_tun_fd(42);
        assert_eq!(helper.tun_fd, Some(42));
    }

    #[test]
    fn vpn_service_helper_add_dns() {
        let mut helper = VpnServiceHelper::new();
        helper.add_dns_server("8.8.8.8");
        helper.add_dns_server("1.1.1.1");
        assert_eq!(helper.dns_servers.len(), 2);
        assert_eq!(helper.dns_servers[0], "8.8.8.8");
    }

    #[test]
    fn vpn_service_helper_add_route() {
        let mut helper = VpnServiceHelper::new();
        helper.add_route("0.0.0.0/0");
        helper.add_route("::/0");
        assert_eq!(helper.routes.len(), 2);
    }

    #[test]
    fn vpn_service_helper_is_configured() {
        let mut helper = VpnServiceHelper::new();
        assert!(!helper.is_configured());

        helper.set_tun_fd(10);
        assert!(!helper.is_configured(), "needs dns_servers too");

        helper.add_dns_server("8.8.8.8");
        assert!(helper.is_configured());
    }

    #[test]
    fn vpn_service_helper_not_configured_without_fd() {
        let mut helper = VpnServiceHelper::new();
        helper.add_dns_server("8.8.8.8");
        assert!(!helper.is_configured(), "needs tun_fd too");
    }

    #[test]
    fn vpn_service_helper_default() {
        let helper = VpnServiceHelper::default();
        assert!(helper.tun_fd.is_none());
        assert!(helper.dns_servers.is_empty());
    }
}
