use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use anyhow::Result;
use tracing::{debug, warn};

/// Exponential backoff retry configuration
#[derive(Debug, Clone)]
pub struct RetryPolicy {
    pub max_retries: u32,
    pub base_delay: Duration,
    pub max_delay: Duration,
    pub jitter: bool,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self {
            max_retries: 3,
            base_delay: Duration::from_millis(200),
            max_delay: Duration::from_secs(10),
            jitter: true,
        }
    }
}

impl RetryPolicy {
    pub fn delay_for(&self, attempt: u32) -> Duration {
        let base_ms = self.base_delay.as_millis() as u64;
        let exp_ms = base_ms.saturating_mul(1u64 << attempt.min(16));
        let capped_ms = exp_ms.min(self.max_delay.as_millis() as u64);

        if self.jitter {
            let jitter_range = capped_ms / 4;
            let jitter = simple_hash(attempt as u64) % (jitter_range.max(1));
            Duration::from_millis(capped_ms.saturating_add(jitter))
        } else {
            Duration::from_millis(capped_ms)
        }
    }
}

fn simple_hash(val: u64) -> u64 {
    let mut h = val.wrapping_mul(6364136223846793005);
    h = h.wrapping_add(1442695040888963407);
    h ^ (h >> 33)
}

/// Execute an async closure with exponential backoff retry.
pub async fn retry_with_backoff<F, Fut, T>(policy: &RetryPolicy, mut f: F) -> Result<T>
where
    F: FnMut(u32) -> Fut,
    Fut: std::future::Future<Output = Result<T>>,
{
    let mut last_err = None;

    for attempt in 0..=policy.max_retries {
        match f(attempt).await {
            Ok(val) => {
                if attempt > 0 {
                    debug!(attempt = attempt, "retry succeeded");
                }
                return Ok(val);
            }
            Err(e) => {
                if attempt < policy.max_retries {
                    let delay = policy.delay_for(attempt);
                    debug!(
                        attempt = attempt,
                        max = policy.max_retries,
                        delay_ms = delay.as_millis() as u64,
                        error = %e,
                        "retrying after backoff"
                    );
                    tokio::time::sleep(delay).await;
                }
                last_err = Some(e);
            }
        }
    }

    Err(last_err.unwrap())
}

/// Circuit breaker states
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CircuitState {
    Closed,
    Open,
    HalfOpen,
}

/// Circuit breaker configuration
#[derive(Debug, Clone)]
pub struct CircuitBreakerConfig {
    pub failure_threshold: u32,
    pub success_threshold: u32,
    pub open_duration: Duration,
}

impl Default for CircuitBreakerConfig {
    fn default() -> Self {
        Self {
            failure_threshold: 5,
            success_threshold: 2,
            open_duration: Duration::from_secs(30),
        }
    }
}

/// Circuit breaker for outbound connections
pub struct CircuitBreaker {
    config: CircuitBreakerConfig,
    state: Mutex<CircuitState>,
    failure_count: AtomicU64,
    success_count: AtomicU64,
    last_failure_time: Mutex<Option<Instant>>,
    tag: String,
}

impl CircuitBreaker {
    pub fn new(tag: String, config: CircuitBreakerConfig) -> Self {
        Self {
            config,
            state: Mutex::new(CircuitState::Closed),
            failure_count: AtomicU64::new(0),
            success_count: AtomicU64::new(0),
            last_failure_time: Mutex::new(None),
            tag,
        }
    }

    pub fn state(&self) -> CircuitState {
        *self.state.lock().unwrap()
    }

    pub fn tag(&self) -> &str {
        &self.tag
    }

    /// Check if a request is allowed through the circuit breaker.
    pub fn allow_request(&self) -> bool {
        let mut state = self.state.lock().unwrap();

        match *state {
            CircuitState::Closed => true,
            CircuitState::Open => {
                let should_half_open = self
                    .last_failure_time
                    .lock()
                    .unwrap()
                    .map(|t| t.elapsed() >= self.config.open_duration)
                    .unwrap_or(false);

                if should_half_open {
                    *state = CircuitState::HalfOpen;
                    self.success_count.store(0, Ordering::Relaxed);
                    debug!(tag = self.tag, "circuit breaker: open -> half-open");
                    true
                } else {
                    false
                }
            }
            CircuitState::HalfOpen => true,
        }
    }

    /// Record a successful request.
    pub fn record_success(&self) {
        let mut state = self.state.lock().unwrap();

        match *state {
            CircuitState::HalfOpen => {
                let count = self.success_count.fetch_add(1, Ordering::Relaxed) + 1;
                if count >= self.config.success_threshold as u64 {
                    *state = CircuitState::Closed;
                    self.failure_count.store(0, Ordering::Relaxed);
                    self.success_count.store(0, Ordering::Relaxed);
                    debug!(tag = self.tag, "circuit breaker: half-open -> closed");
                }
            }
            CircuitState::Closed => {
                self.failure_count.store(0, Ordering::Relaxed);
            }
            CircuitState::Open => {}
        }
    }

    /// Record a failed request.
    pub fn record_failure(&self) {
        let mut state = self.state.lock().unwrap();

        match *state {
            CircuitState::Closed => {
                let count = self.failure_count.fetch_add(1, Ordering::Relaxed) + 1;
                if count >= self.config.failure_threshold as u64 {
                    *state = CircuitState::Open;
                    *self.last_failure_time.lock().unwrap() = Some(Instant::now());
                    warn!(
                        tag = self.tag,
                        failures = count,
                        "circuit breaker: closed -> open"
                    );
                }
            }
            CircuitState::HalfOpen => {
                *state = CircuitState::Open;
                *self.last_failure_time.lock().unwrap() = Some(Instant::now());
                self.success_count.store(0, Ordering::Relaxed);
                warn!(
                    tag = self.tag,
                    "circuit breaker: half-open -> open (probe failed)"
                );
            }
            CircuitState::Open => {}
        }
    }

    pub fn failure_count(&self) -> u64 {
        self.failure_count.load(Ordering::Relaxed)
    }

    pub fn success_count(&self) -> u64 {
        self.success_count.load(Ordering::Relaxed)
    }

    /// Reset the circuit breaker to closed state.
    pub fn reset(&self) {
        *self.state.lock().unwrap() = CircuitState::Closed;
        self.failure_count.store(0, Ordering::Relaxed);
        self.success_count.store(0, Ordering::Relaxed);
        *self.last_failure_time.lock().unwrap() = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retry_policy_exponential_delay() {
        let policy = RetryPolicy {
            max_retries: 5,
            base_delay: Duration::from_millis(100),
            max_delay: Duration::from_secs(5),
            jitter: false,
        };

        assert_eq!(policy.delay_for(0), Duration::from_millis(100));
        assert_eq!(policy.delay_for(1), Duration::from_millis(200));
        assert_eq!(policy.delay_for(2), Duration::from_millis(400));
        assert_eq!(policy.delay_for(3), Duration::from_millis(800));
        // capped at max_delay
        assert_eq!(policy.delay_for(10), Duration::from_secs(5));
    }

    #[test]
    fn retry_policy_jitter_adds_variation() {
        let policy = RetryPolicy {
            max_retries: 3,
            base_delay: Duration::from_millis(100),
            max_delay: Duration::from_secs(5),
            jitter: true,
        };

        let d0 = policy.delay_for(0);
        assert!(d0 >= Duration::from_millis(100));
        assert!(d0 <= Duration::from_millis(150));
    }

    #[tokio::test]
    async fn retry_with_backoff_succeeds_first_try() {
        let policy = RetryPolicy {
            max_retries: 3,
            base_delay: Duration::from_millis(1),
            max_delay: Duration::from_millis(10),
            jitter: false,
        };

        let result = retry_with_backoff(&policy, |_attempt| async { Ok(42) }).await;
        assert_eq!(result.unwrap(), 42);
    }

    #[tokio::test]
    async fn retry_with_backoff_succeeds_after_failures() {
        let policy = RetryPolicy {
            max_retries: 3,
            base_delay: Duration::from_millis(1),
            max_delay: Duration::from_millis(10),
            jitter: false,
        };

        let counter = std::sync::Arc::new(AtomicU64::new(0));
        let counter_clone = counter.clone();

        let result = retry_with_backoff(&policy, move |_attempt| {
            let c = counter_clone.clone();
            async move {
                let n = c.fetch_add(1, Ordering::Relaxed);
                if n < 2 {
                    Err(anyhow::anyhow!("fail #{}", n))
                } else {
                    Ok(99)
                }
            }
        })
        .await;

        assert_eq!(result.unwrap(), 99);
        assert_eq!(counter.load(Ordering::Relaxed), 3);
    }

    #[tokio::test]
    async fn retry_with_backoff_exhausts_retries() {
        let policy = RetryPolicy {
            max_retries: 2,
            base_delay: Duration::from_millis(1),
            max_delay: Duration::from_millis(10),
            jitter: false,
        };

        let result: Result<i32> =
            retry_with_backoff(&policy, |_| async { Err(anyhow::anyhow!("always fail")) }).await;

        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("always fail"));
    }

    #[test]
    fn circuit_breaker_starts_closed() {
        let cb = CircuitBreaker::new("test".to_string(), CircuitBreakerConfig::default());
        assert_eq!(cb.state(), CircuitState::Closed);
        assert!(cb.allow_request());
    }

    #[test]
    fn circuit_breaker_opens_after_threshold() {
        let cb = CircuitBreaker::new(
            "test".to_string(),
            CircuitBreakerConfig {
                failure_threshold: 3,
                success_threshold: 2,
                open_duration: Duration::from_secs(30),
            },
        );

        cb.record_failure();
        cb.record_failure();
        assert_eq!(cb.state(), CircuitState::Closed);
        assert!(cb.allow_request());

        cb.record_failure();
        assert_eq!(cb.state(), CircuitState::Open);
        assert!(!cb.allow_request());
    }

    #[test]
    fn circuit_breaker_half_open_after_duration() {
        let cb = CircuitBreaker::new(
            "test".to_string(),
            CircuitBreakerConfig {
                failure_threshold: 2,
                success_threshold: 1,
                open_duration: Duration::from_millis(1),
            },
        );

        cb.record_failure();
        cb.record_failure();
        assert_eq!(cb.state(), CircuitState::Open);

        std::thread::sleep(Duration::from_millis(5));
        assert!(cb.allow_request());
        assert_eq!(cb.state(), CircuitState::HalfOpen);
    }

    #[test]
    fn circuit_breaker_closes_on_success_in_half_open() {
        let cb = CircuitBreaker::new(
            "test".to_string(),
            CircuitBreakerConfig {
                failure_threshold: 1,
                success_threshold: 2,
                open_duration: Duration::from_millis(1),
            },
        );

        cb.record_failure();
        assert_eq!(cb.state(), CircuitState::Open);

        std::thread::sleep(Duration::from_millis(5));
        cb.allow_request(); // transitions to half-open
        assert_eq!(cb.state(), CircuitState::HalfOpen);

        cb.record_success();
        assert_eq!(cb.state(), CircuitState::HalfOpen);
        cb.record_success();
        assert_eq!(cb.state(), CircuitState::Closed);
    }

    #[test]
    fn circuit_breaker_reopens_on_failure_in_half_open() {
        let cb = CircuitBreaker::new(
            "test".to_string(),
            CircuitBreakerConfig {
                failure_threshold: 1,
                success_threshold: 2,
                open_duration: Duration::from_millis(1),
            },
        );

        cb.record_failure();
        std::thread::sleep(Duration::from_millis(5));
        cb.allow_request();
        assert_eq!(cb.state(), CircuitState::HalfOpen);

        cb.record_failure();
        assert_eq!(cb.state(), CircuitState::Open);
    }

    #[test]
    fn circuit_breaker_reset() {
        let cb = CircuitBreaker::new(
            "test".to_string(),
            CircuitBreakerConfig {
                failure_threshold: 1,
                ..Default::default()
            },
        );

        cb.record_failure();
        assert_eq!(cb.state(), CircuitState::Open);

        cb.reset();
        assert_eq!(cb.state(), CircuitState::Closed);
        assert_eq!(cb.failure_count(), 0);
    }

    #[test]
    fn success_resets_failure_count_in_closed() {
        let cb = CircuitBreaker::new(
            "test".to_string(),
            CircuitBreakerConfig {
                failure_threshold: 3,
                ..Default::default()
            },
        );

        cb.record_failure();
        cb.record_failure();
        assert_eq!(cb.failure_count(), 2);

        cb.record_success();
        assert_eq!(cb.failure_count(), 0);
    }
}
