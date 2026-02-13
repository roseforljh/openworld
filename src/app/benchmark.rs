use std::collections::HashMap;
use std::time::{Duration, Instant};

pub struct BenchmarkResult {
    pub name: String,
    pub iterations: u64,
    pub total_duration: Duration,
    pub avg_ns: u64,
    pub p50_ns: u64,
    pub p95_ns: u64,
    pub p99_ns: u64,
    pub throughput_ops_per_sec: f64,
}

impl std::fmt::Display for BenchmarkResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}: iters={} avg={:.1}us p50={:.1}us p95={:.1}us p99={:.1}us ops/s={:.0}",
            self.name,
            self.iterations,
            self.avg_ns as f64 / 1000.0,
            self.p50_ns as f64 / 1000.0,
            self.p95_ns as f64 / 1000.0,
            self.p99_ns as f64 / 1000.0,
            self.throughput_ops_per_sec,
        )
    }
}

pub fn run_benchmark<F: FnMut()>(name: &str, iterations: u64, mut f: F) -> BenchmarkResult {
    let mut latencies = Vec::with_capacity(iterations as usize);

    // warmup
    for _ in 0..std::cmp::min(100, iterations / 10) {
        f();
    }

    let total_start = Instant::now();
    for _ in 0..iterations {
        let start = Instant::now();
        f();
        latencies.push(start.elapsed().as_nanos() as u64);
    }
    let total_duration = total_start.elapsed();

    latencies.sort_unstable();

    let avg_ns = latencies.iter().sum::<u64>() / iterations;
    let p50_ns = percentile(&latencies, 0.50);
    let p95_ns = percentile(&latencies, 0.95);
    let p99_ns = percentile(&latencies, 0.99);
    let throughput = iterations as f64 / total_duration.as_secs_f64();

    BenchmarkResult {
        name: name.to_string(),
        iterations,
        total_duration,
        avg_ns,
        p50_ns,
        p95_ns,
        p99_ns,
        throughput_ops_per_sec: throughput,
    }
}

fn percentile(sorted: &[u64], p: f64) -> u64 {
    if sorted.is_empty() {
        return 0;
    }
    let idx = ((sorted.len() as f64 - 1.0) * p).round() as usize;
    sorted[idx]
}

#[derive(Default)]
pub struct BenchmarkSuite {
    pub results: Vec<BenchmarkResult>,
}

impl BenchmarkSuite {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn add(&mut self, result: BenchmarkResult) {
        self.results.push(result);
    }

    pub fn summary(&self) -> String {
        let mut out = String::new();
        out.push_str("=== Benchmark Summary ===\n");
        for r in &self.results {
            out.push_str(&format!("{}\n", r));
        }
        out
    }
}

pub struct VersionComparison {
    pub baseline: HashMap<String, BenchmarkResult>,
    pub current: HashMap<String, BenchmarkResult>,
}

#[derive(Debug)]
pub struct RegressionReport {
    pub name: String,
    pub baseline_avg_ns: u64,
    pub current_avg_ns: u64,
    pub regression_pct: f64,
    pub passed: bool,
}

impl VersionComparison {
    pub fn check_regressions(&self, max_regression_pct: f64) -> Vec<RegressionReport> {
        let mut reports = Vec::new();
        for (name, current) in &self.current {
            if let Some(baseline) = self.baseline.get(name) {
                let regression = if baseline.avg_ns > 0 {
                    ((current.avg_ns as f64 - baseline.avg_ns as f64) / baseline.avg_ns as f64)
                        * 100.0
                } else {
                    0.0
                };
                reports.push(RegressionReport {
                    name: name.clone(),
                    baseline_avg_ns: baseline.avg_ns,
                    current_avg_ns: current.avg_ns,
                    regression_pct: regression,
                    passed: regression <= max_regression_pct,
                });
            }
        }
        reports
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn benchmark_basic_runs() {
        let mut counter = 0u64;
        let result = run_benchmark("noop", 1000, || {
            counter += 1;
        });
        assert_eq!(result.iterations, 1000);
        assert!(result.avg_ns > 0);
        assert!(result.throughput_ops_per_sec > 0.0);
    }

    #[test]
    fn benchmark_suite_summary() {
        let mut suite = BenchmarkSuite::new();
        suite.add(run_benchmark("test1", 100, || {}));
        suite.add(run_benchmark("test2", 100, || {}));
        let summary = suite.summary();
        assert!(summary.contains("test1"));
        assert!(summary.contains("test2"));
    }

    #[test]
    fn version_comparison_detects_regression() {
        let mut baseline = HashMap::new();
        baseline.insert(
            "test".to_string(),
            BenchmarkResult {
                name: "test".to_string(),
                iterations: 1000,
                total_duration: Duration::from_millis(10),
                avg_ns: 10000,
                p50_ns: 9000,
                p95_ns: 15000,
                p99_ns: 20000,
                throughput_ops_per_sec: 100000.0,
            },
        );

        let mut current = HashMap::new();
        current.insert(
            "test".to_string(),
            BenchmarkResult {
                name: "test".to_string(),
                iterations: 1000,
                total_duration: Duration::from_millis(12),
                avg_ns: 12000, // 20% regression
                p50_ns: 11000,
                p95_ns: 18000,
                p99_ns: 25000,
                throughput_ops_per_sec: 83333.0,
            },
        );

        let comparison = VersionComparison { baseline, current };
        let reports = comparison.check_regressions(10.0);
        assert_eq!(reports.len(), 1);
        assert!(!reports[0].passed); // 20% > 10% threshold
    }
}
