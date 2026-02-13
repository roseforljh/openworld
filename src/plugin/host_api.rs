//! Host API — 插件与宿主交互的上下文和动作定义

use std::net::IpAddr;

/// 插件获取的请求上下文（只读、沙盒隔离）
#[derive(Debug, Clone)]
pub struct HostContext {
    /// 目标域名（如果已知）
    pub domain: Option<String>,
    /// 目标 IP（如果已解析）
    pub dest_ip: Option<IpAddr>,
    /// 来源 IP
    pub source_ip: Option<IpAddr>,
    /// 目标端口
    pub dest_port: u16,
    /// 入站标签
    pub inbound_tag: String,
    /// 进程名（如果可探测）
    pub process_name: Option<String>,
    /// 当前小时（0-23），用于时间段规则
    pub hour: u8,
    /// 嗅探检测到的协议
    pub detected_protocol: Option<String>,
}

impl HostContext {
    /// 从 Session 构造上下文
    pub fn from_session(
        session: &crate::proxy::Session,
        dest_ip: Option<IpAddr>,
    ) -> Self {
        let (domain, port) = match &session.target {
            crate::common::Address::Domain(host, port) => {
                (Some(host.clone()), *port)
            }
            crate::common::Address::Ip(addr) => {
                (None, addr.port())
            }
        };

        // 获取当前小时（避免引入 chrono 依赖）
        let hour = {
            use std::time::{SystemTime, UNIX_EPOCH};
            let secs = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs();
            // UTC 小时，对路由规则足够用
            ((secs % 86400) / 3600) as u8
        };

        Self {
            domain,
            dest_ip: dest_ip.or_else(|| {
                if let crate::common::Address::Ip(addr) = &session.target {
                    Some(addr.ip())
                } else {
                    None
                }
            }),
            source_ip: session.source.map(|s| s.ip()),
            dest_port: port,
            inbound_tag: session.inbound_tag.clone(),
            process_name: None, // 由调用方在可用时填充
            hour,
            detected_protocol: session.detected_protocol.clone(),
        }
    }
}

/// 插件的路由决策
#[derive(Debug, Clone, PartialEq)]
pub enum RoutingDecision {
    /// 使用指定出站
    UseOutbound(String),
    /// 不做决策，交给下游规则
    Pass,
}

/// 插件可执行的动作
#[derive(Debug, Clone)]
pub enum PluginAction {
    /// 路由决策
    Route(RoutingDecision),
    /// 修改 DNS 响应
    OverrideDns {
        domain: String,
        ip: IpAddr,
    },
    /// 记录日志
    Log(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn routing_decision_eq() {
        let a = RoutingDecision::UseOutbound("proxy".into());
        let b = RoutingDecision::UseOutbound("proxy".into());
        assert_eq!(a, b);
        assert_ne!(a, RoutingDecision::Pass);
    }

    #[test]
    fn host_context_defaults() {
        let ctx = HostContext {
            domain: Some("example.com".into()),
            dest_ip: None,
            source_ip: None,
            dest_port: 443,
            inbound_tag: "socks-in".into(),
            process_name: None,
            hour: 14,
            detected_protocol: None,
        };
        assert_eq!(ctx.dest_port, 443);
        assert!(ctx.domain.is_some());
    }

    #[test]
    fn plugin_action_variants() {
        let action = PluginAction::Route(RoutingDecision::Pass);
        match action {
            PluginAction::Route(RoutingDecision::Pass) => {}
            _ => panic!("unexpected"),
        }

        let dns_action = PluginAction::OverrideDns {
            domain: "example.com".into(),
            ip: "1.2.3.4".parse().unwrap(),
        };
        match dns_action {
            PluginAction::OverrideDns { domain, ip } => {
                assert_eq!(domain, "example.com");
                assert_eq!(ip, "1.2.3.4".parse::<IpAddr>().unwrap());
            }
            _ => panic!("unexpected"),
        }
    }
}
