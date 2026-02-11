$ErrorActionPreference = "Stop"

Write-Host "[OpenWorld] Performance baseline start"

cargo test --test phase11_performance_baseline -- --ignored --nocapture

Write-Host "[OpenWorld] Performance baseline done"
