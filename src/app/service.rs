/// Windows SCM 服务支持
///
/// 提供 Windows Service Control Manager 集成能力，
/// 包括服务安装、卸载、启动、停止。

/// 服务配置
#[derive(Debug, Clone)]
pub struct ServiceConfig {
    pub name: String,
    pub display_name: String,
    pub description: String,
    pub binary_path: String,
    pub start_type: ServiceStartType,
    pub config_path: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ServiceStartType {
    Auto,
    Manual,
    Disabled,
}

impl ServiceStartType {
    pub fn as_str(&self) -> &'static str {
        match self {
            ServiceStartType::Auto => "auto",
            ServiceStartType::Manual => "demand",
            ServiceStartType::Disabled => "disabled",
        }
    }

    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "auto" | "automatic" => ServiceStartType::Auto,
            "manual" | "demand" => ServiceStartType::Manual,
            "disabled" => ServiceStartType::Disabled,
            _ => ServiceStartType::Manual,
        }
    }
}

impl Default for ServiceConfig {
    fn default() -> Self {
        Self {
            name: "OpenWorld".to_string(),
            display_name: "OpenWorld Proxy Service".to_string(),
            description: "High-performance proxy kernel service".to_string(),
            binary_path: std::env::current_exe()
                .unwrap_or_default()
                .to_string_lossy()
                .to_string(),
            start_type: ServiceStartType::Auto,
            config_path: None,
        }
    }
}

impl ServiceConfig {
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            ..Default::default()
        }
    }

    pub fn with_config_path(mut self, path: &str) -> Self {
        self.config_path = Some(path.to_string());
        self
    }

    pub fn with_start_type(mut self, start_type: ServiceStartType) -> Self {
        self.start_type = start_type;
        self
    }

    /// 生成 sc.exe 创建服务的命令
    pub fn install_command(&self) -> String {
        let bin_path = if let Some(ref config) = self.config_path {
            format!("\"{}\" \"{}\"", self.binary_path, config)
        } else {
            format!("\"{}\"", self.binary_path)
        };
        format!(
            "sc create {} binPath= {} DisplayName= \"{}\" start= {} description= \"{}\"",
            self.name, bin_path, self.display_name, self.start_type.as_str(), self.description
        )
    }

    /// 生成 sc.exe 删除服务的命令
    pub fn uninstall_command(&self) -> String {
        format!("sc delete {}", self.name)
    }

    /// 生成启动服务的命令
    pub fn start_command(&self) -> String {
        format!("sc start {}", self.name)
    }

    /// 生成停止服务的命令
    pub fn stop_command(&self) -> String {
        format!("sc stop {}", self.name)
    }

    /// 生成查询服务状态的命令
    pub fn query_command(&self) -> String {
        format!("sc query {}", self.name)
    }

    /// 生成 Windows 注册表自启命令 (reg add)
    pub fn autostart_registry_command(&self) -> String {
        let exe_path = if let Some(ref config) = self.config_path {
            format!("\"{}\" \"{}\"", self.binary_path, config)
        } else {
            format!("\"{}\"", self.binary_path)
        };
        format!(
            "reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\" /v {} /t REG_SZ /d {} /f",
            self.name, exe_path
        )
    }

    /// 生成删除自启的命令
    pub fn remove_autostart_command(&self) -> String {
        format!(
            "reg delete \"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\" /v {} /f",
            self.name
        )
    }

    /// 生成 Linux systemd enable 命令
    pub fn systemd_enable_command(&self) -> String {
        format!("systemctl enable {}", self.name.to_lowercase())
    }

    /// 生成 Linux systemd disable 命令
    pub fn systemd_disable_command(&self) -> String {
        format!("systemctl disable {}", self.name.to_lowercase())
    }

    /// 生成 systemd unit 内容 (Linux)
    pub fn systemd_unit(&self) -> String {
        let exec_start = if let Some(ref config) = self.config_path {
            format!("{} {}", self.binary_path, config)
        } else {
            self.binary_path.clone()
        };
        format!(
            r#"[Unit]
Description={description}
After=network.target nss-lookup.target

[Service]
Type=simple
ExecStart={exec_start}
Restart=on-failure
RestartSec=5
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
"#,
            description = self.description,
            exec_start = exec_start,
        )
    }
}

/// 服务状态
#[derive(Debug, Clone, PartialEq)]
pub enum ServiceStatus {
    Running,
    Stopped,
    Paused,
    StartPending,
    StopPending,
    Unknown,
}

impl ServiceStatus {
    pub fn from_str(s: &str) -> Self {
        let s = s.to_uppercase();
        if s.contains("RUNNING") {
            ServiceStatus::Running
        } else if s.contains("STOPPED") {
            ServiceStatus::Stopped
        } else if s.contains("PAUSED") {
            ServiceStatus::Paused
        } else if s.contains("START_PENDING") {
            ServiceStatus::StartPending
        } else if s.contains("STOP_PENDING") {
            ServiceStatus::StopPending
        } else {
            ServiceStatus::Unknown
        }
    }

    pub fn is_running(&self) -> bool {
        matches!(self, ServiceStatus::Running)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn service_config_default() {
        let config = ServiceConfig::default();
        assert_eq!(config.name, "OpenWorld");
        assert_eq!(config.start_type, ServiceStartType::Auto);
    }

    #[test]
    fn service_config_custom() {
        let config = ServiceConfig::new("MyProxy")
            .with_config_path("C:\\config.yaml")
            .with_start_type(ServiceStartType::Manual);
        assert_eq!(config.name, "MyProxy");
        assert_eq!(config.config_path.as_deref(), Some("C:\\config.yaml"));
        assert_eq!(config.start_type, ServiceStartType::Manual);
    }

    #[test]
    fn install_command_no_config() {
        let config = ServiceConfig::new("TestSvc");
        let cmd = config.install_command();
        assert!(cmd.contains("sc create TestSvc"));
        assert!(cmd.contains("start= auto"));
    }

    #[test]
    fn install_command_with_config() {
        let config = ServiceConfig::new("TestSvc").with_config_path("C:\\cfg.yaml");
        let cmd = config.install_command();
        assert!(cmd.contains("C:\\cfg.yaml"));
    }

    #[test]
    fn uninstall_command() {
        let config = ServiceConfig::new("TestSvc");
        assert_eq!(config.uninstall_command(), "sc delete TestSvc");
    }

    #[test]
    fn start_stop_query_commands() {
        let config = ServiceConfig::new("TestSvc");
        assert_eq!(config.start_command(), "sc start TestSvc");
        assert_eq!(config.stop_command(), "sc stop TestSvc");
        assert_eq!(config.query_command(), "sc query TestSvc");
    }

    #[test]
    fn systemd_unit_content() {
        let config = ServiceConfig::new("OpenWorld")
            .with_config_path("/etc/openworld/config.yaml");
        let unit = config.systemd_unit();
        assert!(unit.contains("[Unit]"));
        assert!(unit.contains("[Service]"));
        assert!(unit.contains("[Install]"));
        assert!(unit.contains("/etc/openworld/config.yaml"));
    }

    #[test]
    fn service_start_type_from_str() {
        assert_eq!(ServiceStartType::from_str("auto"), ServiceStartType::Auto);
        assert_eq!(ServiceStartType::from_str("automatic"), ServiceStartType::Auto);
        assert_eq!(ServiceStartType::from_str("manual"), ServiceStartType::Manual);
        assert_eq!(ServiceStartType::from_str("demand"), ServiceStartType::Manual);
        assert_eq!(ServiceStartType::from_str("disabled"), ServiceStartType::Disabled);
        assert_eq!(ServiceStartType::from_str("unknown"), ServiceStartType::Manual);
    }

    #[test]
    fn service_status_from_str() {
        assert_eq!(ServiceStatus::from_str("RUNNING"), ServiceStatus::Running);
        assert_eq!(ServiceStatus::from_str("STOPPED"), ServiceStatus::Stopped);
        assert_eq!(ServiceStatus::from_str("STATE: RUNNING"), ServiceStatus::Running);
        assert_eq!(ServiceStatus::from_str("???"), ServiceStatus::Unknown);
    }

    #[test]
    fn service_status_is_running() {
        assert!(ServiceStatus::Running.is_running());
        assert!(!ServiceStatus::Stopped.is_running());
        assert!(!ServiceStatus::Unknown.is_running());
    }

    #[test]
    fn autostart_registry_command_no_config() {
        let mut config = ServiceConfig::new("OpenWorld");
        config.binary_path = "C:\\Program Files\\OpenWorld\\openworld.exe".to_string();
        let cmd = config.autostart_registry_command();
        assert!(cmd.contains("reg add"));
        assert!(cmd.contains("HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"));
        assert!(cmd.contains("/v OpenWorld"));
        assert!(cmd.contains("C:\\Program Files\\OpenWorld\\openworld.exe"));
        assert!(cmd.contains("/f"));
    }

    #[test]
    fn autostart_registry_command_with_config() {
        let mut config = ServiceConfig::new("OpenWorld")
            .with_config_path("C:\\config.yaml");
        config.binary_path = "C:\\openworld.exe".to_string();
        let cmd = config.autostart_registry_command();
        assert!(cmd.contains("C:\\openworld.exe"));
        assert!(cmd.contains("C:\\config.yaml"));
    }

    #[test]
    fn remove_autostart_command_format() {
        let config = ServiceConfig::new("OpenWorld");
        let cmd = config.remove_autostart_command();
        assert!(cmd.contains("reg delete"));
        assert!(cmd.contains("HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"));
        assert!(cmd.contains("/v OpenWorld"));
        assert!(cmd.contains("/f"));
    }

    #[test]
    fn systemd_enable_command_format() {
        let config = ServiceConfig::new("OpenWorld");
        assert_eq!(config.systemd_enable_command(), "systemctl enable openworld");
    }

    #[test]
    fn systemd_disable_command_format() {
        let config = ServiceConfig::new("OpenWorld");
        assert_eq!(config.systemd_disable_command(), "systemctl disable openworld");
    }
}
