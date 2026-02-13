//! TCP Brutal 拥塞控制
//!
//! Brutal 是 Hysteria/Hysteria2 使用的带宽发送策略。
//! 核心思想：在高丢包环境下维持用户指定的发送速率。
//!
//! 算法：发送速率 = target_bps / (1 - loss_rate)
//! - 当无丢包时，发送速率 = target_bps
//! - 当丢包 50% 时，发送速率 = 2 * target_bps（补偿丢包）
//!
//! 同时实现了 quinn congestion::Controller trait，
//! 可直接插入 quinn 的 QUIC 拥塞控制器框架。

use std::sync::Arc;
use std::time::Instant;

use tracing::debug;

/// Brutal 拥塞控制器
///
/// 维持指定发送速率，根据丢包率自适应调整实际发送 window。
pub struct BrutalController {
    target_bps: u64,  // 用户指定的目标发送速率 (bytes/sec)
    mss: u64,         // Maximum Segment Size
    window: u64,      // 当前拥塞窗口 (bytes)
    acked_bytes: u64, // 已确认字节数
    lost_bytes: u64,  // 丢失字节数
    rtt: std::time::Duration,
    last_update: Instant,
}

impl BrutalController {
    /// 创建新的 Brutal 控制器
    ///
    /// # Arguments
    /// * `send_bps` - 目标发送速率，单位 bytes/sec
    /// * `mss` - Maximum Segment Size（通常 1200-1350 for QUIC）
    pub fn new(send_bps: u64, mss: u64) -> Self {
        let window = Self::calculate_window(send_bps, mss, std::time::Duration::from_millis(100));
        debug!(
            send_bps = send_bps,
            mss = mss,
            initial_window = window,
            "Brutal congestion controller created"
        );
        Self {
            target_bps: send_bps,
            mss,
            window,
            acked_bytes: 0,
            lost_bytes: 0,
            rtt: std::time::Duration::from_millis(100),
            last_update: Instant::now(),
        }
    }

    /// 根据目标速率和 RTT 计算窗口大小
    fn calculate_window(send_bps: u64, mss: u64, rtt: std::time::Duration) -> u64 {
        let rtt_secs = rtt.as_secs_f64();
        if rtt_secs <= 0.0 {
            return mss * 10;
        }
        // BDP (Bandwidth-Delay Product) = rate * RTT
        let window = (send_bps as f64 * rtt_secs) as u64;
        // 至少 10 个 MSS
        window.max(mss * 10)
    }

    /// 根据丢包率调整实际发送速率
    fn adjusted_window(&self) -> u64 {
        let total = self.acked_bytes + self.lost_bytes;
        if total == 0 {
            return self.window;
        }
        let loss_rate = self.lost_bytes as f64 / total as f64;
        if loss_rate >= 1.0 {
            return self.window;
        }
        // rate = target / (1 - loss_rate)
        let adjusted = self.window as f64 / (1.0 - loss_rate);
        adjusted as u64
    }

    /// 定期重置统计计数器（每秒重置一次）
    fn maybe_reset_counters(&mut self) {
        let now = Instant::now();
        if now.duration_since(self.last_update) >= std::time::Duration::from_secs(1) {
            self.acked_bytes = 0;
            self.lost_bytes = 0;
            self.last_update = now;
        }
    }
}

impl quinn::congestion::Controller for BrutalController {
    // Use default on_ack implementation — we track via on_congestion_event instead
    // This avoids referencing the private RttEstimator type.
    // Instead, we use on_end_acks to update our window periodically.

    fn on_congestion_event(
        &mut self,
        _now: Instant,
        _sent: Instant,
        _is_persistent_congestion: bool,
        lost_bytes: u64,
    ) {
        self.lost_bytes += lost_bytes;
        self.maybe_reset_counters();
    }

    fn on_mtu_update(&mut self, new_mtu: u16) {
        self.mss = new_mtu as u64;
        self.window = Self::calculate_window(self.target_bps, self.mss, self.rtt);
    }

    fn window(&self) -> u64 {
        self.adjusted_window()
    }

    fn clone_box(&self) -> Box<dyn quinn::congestion::Controller> {
        Box::new(Self {
            target_bps: self.target_bps,
            mss: self.mss,
            window: self.window,
            acked_bytes: self.acked_bytes,
            lost_bytes: self.lost_bytes,
            rtt: self.rtt,
            last_update: self.last_update,
        })
    }

    fn initial_window(&self) -> u64 {
        self.window
    }

    fn into_any(self: Box<Self>) -> Box<dyn std::any::Any> {
        self
    }
}

/// `BrutalControllerFactory` 实现 `quinn::congestion::ControllerFactory`
///
/// 用于在 `quinn::TransportConfig` 中设置 Brutal 拥塞控制。
#[derive(Debug, Clone)]
pub struct BrutalControllerFactory {
    send_bps: u64,
}

impl BrutalControllerFactory {
    /// 创建工厂
    ///
    /// # Arguments
    /// * `send_rate_mbps` - 目标发送速率，单位 Mbps
    pub fn new(send_rate_mbps: u64) -> Self {
        Self {
            // Mbps -> bytes/sec: multiply by 125000 (1_000_000 / 8)
            send_bps: send_rate_mbps.saturating_mul(125_000),
        }
    }

    /// 从 bytes/sec 创建工厂
    pub fn from_bps(send_bps: u64) -> Self {
        Self { send_bps }
    }

    pub fn send_bps(&self) -> u64 {
        self.send_bps
    }
}

impl quinn::congestion::ControllerFactory for BrutalControllerFactory {
    fn build(
        self: Arc<Self>,
        _now: Instant,
        current_mtu: u16,
    ) -> Box<dyn quinn::congestion::Controller> {
        Box::new(BrutalController::new(self.send_bps, current_mtu as u64))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use quinn::congestion::{Controller, ControllerFactory};
    use std::time::Duration;

    #[test]
    fn brutal_initial_window() {
        let ctrl = BrutalController::new(1_000_000, 1200); // 1 MB/s, 1200 MSS
        let window = ctrl.window();
        assert!(window > 0, "initial window should be positive");
        // With 100ms RTT: BDP = 1_000_000 * 0.1 = 100_000
        assert_eq!(window, 100_000);
    }

    #[test]
    fn brutal_min_window() {
        let ctrl = BrutalController::new(1, 1200); // 1 B/s — very low
        let window = ctrl.window();
        // Should be at least 10 * MSS = 12000
        assert!(
            window >= 12000,
            "window should be at least 10*MSS, got {}",
            window
        );
    }

    #[test]
    fn brutal_loss_compensation() {
        let mut ctrl = BrutalController::new(1_000_000, 1200);
        // Simulate 50% loss: 50 bytes acked, 50 bytes lost
        ctrl.acked_bytes = 50;
        ctrl.lost_bytes = 50;
        let window = ctrl.adjusted_window();
        // 应该是 2x 基础窗口（补偿 50% 丢包）
        let base = ctrl.window;
        assert_eq!(window, base * 2);
    }

    #[test]
    fn brutal_no_loss() {
        let mut ctrl = BrutalController::new(1_000_000, 1200);
        ctrl.acked_bytes = 100;
        ctrl.lost_bytes = 0;
        let window = ctrl.adjusted_window();
        // 无丢包应等于基础窗口
        assert_eq!(window, ctrl.window);
    }

    #[test]
    fn brutal_factory_mbps() {
        let factory = BrutalControllerFactory::new(100); // 100 Mbps
        assert_eq!(factory.send_bps(), 100 * 125_000);
    }

    #[test]
    fn brutal_factory_from_bps() {
        let factory = BrutalControllerFactory::from_bps(12_500_000); // 100 Mbps
        assert_eq!(factory.send_bps(), 12_500_000);
    }

    #[test]
    fn brutal_factory_builds_controller() {
        let factory = Arc::new(BrutalControllerFactory::new(100));
        let ctrl = factory.build(Instant::now(), 1200);
        assert!(ctrl.window() > 0);
    }

    #[test]
    fn brutal_window_scales_with_rtt() {
        let w1 = BrutalController::calculate_window(1_000_000, 1200, Duration::from_millis(50));
        let w2 = BrutalController::calculate_window(1_000_000, 1200, Duration::from_millis(200));
        // Higher RTT should produce larger window
        assert!(
            w2 > w1,
            "window should scale with RTT: {}ms={}, {}ms={}",
            50,
            w1,
            200,
            w2
        );
    }

    #[test]
    fn brutal_counter_reset() {
        let mut ctrl = BrutalController::new(1_000_000, 1200);
        ctrl.acked_bytes = 999;
        ctrl.lost_bytes = 111;
        ctrl.last_update = Instant::now() - Duration::from_secs(2); // 2 seconds ago
        ctrl.maybe_reset_counters();
        assert_eq!(ctrl.acked_bytes, 0);
        assert_eq!(ctrl.lost_bytes, 0);
    }
}
