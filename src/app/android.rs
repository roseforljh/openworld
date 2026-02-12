//! Android JNI 桥接层
//!
//! 通过 `jni` crate 导出 Java native 方法，供 KunBox (Android) 直接调用。
//! Java 类路径: `com.openworld.core.OpenWorldCore`

#[cfg(target_os = "android")]
mod jni_exports {
    use jni::JNIEnv;
    use jni::objects::{JClass, JString};
    use jni::sys::{jboolean, jint, jlong, jstring, JNI_FALSE, JNI_TRUE};
    use super::super::ffi;

    fn jb(b: bool) -> jboolean { if b { JNI_TRUE } else { JNI_FALSE } }
    fn ok(code: i32) -> jboolean { jb(code == 0) }

    fn ffi_str_to_jstring(env: &JNIEnv, ptr: *mut std::os::raw::c_char) -> jstring {
        if ptr.is_null() { return std::ptr::null_mut(); }
        let c = unsafe { std::ffi::CStr::from_ptr(ptr) };
        let r = match env.new_string(c.to_str().unwrap_or("")) {
            Ok(s) => s.into_raw(), Err(_) => std::ptr::null_mut(),
        };
        unsafe { ffi::openworld_free_string(ptr) }; r
    }

    #[no_mangle]
    pub extern "system" fn Java_com_openworld_core_OpenWorldCore_start(
        mut env: JNIEnv, _c: JClass, config: JString,
    ) -> jint {
        let s: String = match env.get_string(&config) { Ok(s) => s.into(), Err(_) => return -3 };
        let cs = match std::ffi::CString::new(s) { Ok(s) => s, Err(_) => return -3 };
        unsafe { ffi::openworld_start(cs.as_ptr()) }
    }

    #[no_mangle]
    pub extern "system" fn Java_com_openworld_core_OpenWorldCore_stop(_e: JNIEnv, _c: JClass) -> jint { ffi::openworld_stop() }

    #[no_mangle]
    pub extern "system" fn Java_com_openworld_core_OpenWorldCore_isRunning(_e: JNIEnv, _c: JClass) -> jboolean { jb(ffi::openworld_is_running() == 1) }

    #[no_mangle]
    pub extern "system" fn Java_com_openworld_core_OpenWorldCore_version(env: JNIEnv, _c: JClass) -> jstring { ffi_str_to_jstring(&env, ffi::openworld_version()) }

    #[no_mangle]
    pub extern "system" fn Java_com_openworld_core_OpenWorldCore_pause(_e: JNIEnv, _c: JClass) -> jboolean { ok(ffi::openworld_pause()) }

    #[no_mangle]
    pub extern "system" fn Java_com_openworld_core_OpenWorldCore_resume(_e: JNIEnv, _c: JClass) -> jboolean { ok(ffi::openworld_resume()) }

    #[no_mangle]
    pub extern "system" fn Java_com_openworld_core_OpenWorldCore_isPaused(_e: JNIEnv, _c: JClass) -> jboolean { jb(ffi::openworld_is_paused() == 1) }

    #[no_mangle]
    pub extern "system" fn Java_com_openworld_core_OpenWorldCore_selectOutbound(mut env: JNIEnv, _c: JClass, tag: JString) -> jboolean {
        let s: String = match env.get_string(&tag) { Ok(s) => s.into(), Err(_) => return JNI_FALSE };
        let cs = match std::ffi::CString::new(s) { Ok(s) => s, Err(_) => return JNI_FALSE };
        ok(unsafe { ffi::openworld_select_outbound(cs.as_ptr()) })
    }

    #[no_mangle]
    pub extern "system" fn Java_com_openworld_core_OpenWorldCore_getSelectedOutbound(env: JNIEnv, _c: JClass) -> jstring { ffi_str_to_jstring(&env, ffi::openworld_get_selected_outbound()) }

    #[no_mangle]
    pub extern "system" fn Java_com_openworld_core_OpenWorldCore_listOutbounds(env: JNIEnv, _c: JClass) -> jstring { ffi_str_to_jstring(&env, ffi::openworld_list_outbounds()) }

    #[no_mangle]
    pub extern "system" fn Java_com_openworld_core_OpenWorldCore_hasSelector(_e: JNIEnv, _c: JClass) -> jboolean { jb(ffi::openworld_has_selector() == 1) }

    #[no_mangle]
    pub extern "system" fn Java_com_openworld_core_OpenWorldCore_getTrafficTotalUplink(_e: JNIEnv, _c: JClass) -> jlong { ffi::openworld_get_upload_total() }

    #[no_mangle]
    pub extern "system" fn Java_com_openworld_core_OpenWorldCore_getTrafficTotalDownlink(_e: JNIEnv, _c: JClass) -> jlong { ffi::openworld_get_download_total() }

    #[no_mangle]
    pub extern "system" fn Java_com_openworld_core_OpenWorldCore_resetTrafficStats(_e: JNIEnv, _c: JClass) -> jboolean { ok(ffi::openworld_reset_traffic()) }

    #[no_mangle]
    pub extern "system" fn Java_com_openworld_core_OpenWorldCore_getConnectionCount(_e: JNIEnv, _c: JClass) -> jlong { ffi::openworld_get_connection_count() as jlong }

    #[no_mangle]
    pub extern "system" fn Java_com_openworld_core_OpenWorldCore_resetAllConnections(_e: JNIEnv, _c: JClass, sys: jboolean) -> jboolean { ok(ffi::openworld_reset_all_connections(sys as i32)) }

    #[no_mangle]
    pub extern "system" fn Java_com_openworld_core_OpenWorldCore_closeIdleConnections(_e: JNIEnv, _c: JClass, secs: jlong) -> jlong { ffi::openworld_close_idle_connections(secs) as jlong }

    #[no_mangle]
    pub extern "system" fn Java_com_openworld_core_OpenWorldCore_recoverNetworkAuto(_e: JNIEnv, _c: JClass) -> jboolean { ok(ffi::openworld_recover_network_auto()) }

    #[no_mangle]
    pub extern "system" fn Java_com_openworld_core_OpenWorldCore_setTunFd(_e: JNIEnv, _c: JClass, fd: jint) -> jint { ffi::openworld_set_tun_fd(fd) }
}

// ═══════════════════════════════════════════════════════════════════════════
// 跨平台：方法签名验证 + 辅助结构体
// ═══════════════════════════════════════════════════════════════════════════

#[derive(Debug, Clone)]
pub struct JniMethodSignature {
    pub class: String,
    pub method: String,
    pub signature: String,
    pub is_static: bool,
}

impl JniMethodSignature {
    pub fn new(class: &str, method: &str, signature: &str, is_static: bool) -> Self {
        Self { class: class.into(), method: method.into(), signature: signature.into(), is_static }
    }
    pub fn validate(&self) -> Result<(), String> {
        if self.class.is_empty() { return Err("empty class".into()); }
        if self.method.is_empty() { return Err("empty method".into()); }
        if !self.signature.starts_with('(') { return Err("sig must start with '('".into()); }
        let close = self.signature.find(')').ok_or("sig must contain ')'")?;
        let ret = &self.signature[close + 1..];
        if ret.is_empty() { return Err("missing return type".into()); }
        if !"VZBCSIJFDL[".contains(ret.chars().next().unwrap()) { return Err(format!("bad return: {ret}")); }
        Ok(())
    }
    pub fn export_name(&self) -> String {
        format!("Java_{}_{}", self.class.replace('.', "_").replace('/', "_"), self.method)
    }
}

pub fn core_jni_methods() -> Vec<JniMethodSignature> {
    let c = "com/openworld/core/OpenWorldCore";
    vec![
        JniMethodSignature::new(c, "start", "(Ljava/lang/String;)I", true),
        JniMethodSignature::new(c, "stop", "()I", true),
        JniMethodSignature::new(c, "isRunning", "()Z", true),
        JniMethodSignature::new(c, "version", "()Ljava/lang/String;", true),
        JniMethodSignature::new(c, "pause", "()Z", true),
        JniMethodSignature::new(c, "resume", "()Z", true),
        JniMethodSignature::new(c, "isPaused", "()Z", true),
        JniMethodSignature::new(c, "selectOutbound", "(Ljava/lang/String;)Z", true),
        JniMethodSignature::new(c, "getSelectedOutbound", "()Ljava/lang/String;", true),
        JniMethodSignature::new(c, "listOutbounds", "()Ljava/lang/String;", true),
        JniMethodSignature::new(c, "hasSelector", "()Z", true),
        JniMethodSignature::new(c, "getTrafficTotalUplink", "()J", true),
        JniMethodSignature::new(c, "getTrafficTotalDownlink", "()J", true),
        JniMethodSignature::new(c, "resetTrafficStats", "()Z", true),
        JniMethodSignature::new(c, "getConnectionCount", "()J", true),
        JniMethodSignature::new(c, "resetAllConnections", "(Z)Z", true),
        JniMethodSignature::new(c, "closeIdleConnections", "(J)J", true),
        JniMethodSignature::new(c, "recoverNetworkAuto", "()Z", true),
        JniMethodSignature::new(c, "setTunFd", "(I)I", true),
    ]
}

#[derive(Debug, Clone)]
pub struct VpnServiceHelper {
    pub tun_fd: Option<i32>,
    pub dns_servers: Vec<String>,
    pub routes: Vec<String>,
}
impl VpnServiceHelper {
    pub fn new() -> Self { Self { tun_fd: None, dns_servers: vec![], routes: vec![] } }
    pub fn set_tun_fd(&mut self, fd: i32) { self.tun_fd = Some(fd); }
    pub fn add_dns_server(&mut self, s: &str) { self.dns_servers.push(s.into()); }
    pub fn add_route(&mut self, r: &str) { self.routes.push(r.into()); }
    pub fn is_configured(&self) -> bool { self.tun_fd.is_some() }
}
impl Default for VpnServiceHelper { fn default() -> Self { Self::new() } }

#[cfg(test)]
mod tests {
    use super::*;

    #[test] fn jni_sig_valid() { assert!(JniMethodSignature::new("com/Test", "m", "()V", true).validate().is_ok()); }
    #[test] fn jni_sig_empty_class() { assert!(JniMethodSignature::new("", "m", "()V", true).validate().is_err()); }
    #[test] fn jni_sig_empty_method() { assert!(JniMethodSignature::new("C", "", "()V", true).validate().is_err()); }
    #[test] fn jni_sig_no_paren() { assert!(JniMethodSignature::new("C", "m", "V", true).validate().is_err()); }
    #[test] fn jni_sig_bad_ret() { assert!(JniMethodSignature::new("C", "m", "()X", true).validate().is_err()); }

    #[test]
    fn export_name_gen() {
        let s = JniMethodSignature::new("com/openworld/core/OpenWorldCore", "start", "(Ljava/lang/String;)I", true);
        assert_eq!(s.export_name(), "Java_com_openworld_core_OpenWorldCore_start");
    }

    #[test]
    fn all_methods_valid() {
        for m in core_jni_methods() {
            assert!(m.validate().is_ok(), "method {} invalid", m.method);
            assert!(m.is_static);
        }
    }

    #[test]
    fn vpn_helper() {
        let mut h = VpnServiceHelper::new();
        assert!(!h.is_configured());
        h.set_tun_fd(42);
        assert!(h.is_configured());
        h.add_dns_server("8.8.8.8");
        h.add_route("0.0.0.0/0");
        assert_eq!(h.dns_servers.len(), 1);
        assert_eq!(h.routes.len(), 1);
    }
}
