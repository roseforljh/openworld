//! 插件系统
//!
//! 为 OpenWorld 提供可扩展的脚本化路由决策和流量处理能力。
//! 采用轻量级内置脚本引擎，支持：
//! - 路由决策脚本（基于域名/IP/进程/时间段等）
//! - DNS 响应覆盖
//! - 流量统计钩子
//!
//! 设计原则：
//! - 零外部依赖（不引入 wasmtime/wasmer/rlua 等重依赖）
//! - 沙盒隔离（插件无法访问文件系统/网络）
//! - 热重载（运行时加载/卸载插件）

pub mod engine;
pub mod host_api;
pub mod manager;

pub use engine::{PluginScript, ScriptEngine, ScriptError};
pub use host_api::{HostContext, PluginAction, RoutingDecision};
pub use manager::{PluginConfig, PluginManager, PluginMeta};
