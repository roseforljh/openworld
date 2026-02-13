# OpenWorld Android 构建脚本
# 编译 Rust 内核为 Android .so 并复制到 jniLibs

param(
    [switch]$Release,
    [switch]$Clean
)

$ErrorActionPreference = "Stop"

$NDK_BIN = "C:/Users/33039/AppData/Local/Android/Sdk/ndk/29.0.14206865/toolchains/llvm/prebuilt/windows-x86_64/bin"
$ProjectRoot = Split-Path -Parent $PSScriptRoot
$Target = "aarch64-linux-android"
$JniLibsDir = "$PSScriptRoot\app\src\main\jniLibs\arm64-v8a"

# 设置交叉编译环境变量
$env:CARGO_BUILD_JOBS = 2
$env:CC_aarch64_linux_android = "$NDK_BIN/aarch64-linux-android24-clang.cmd"
$env:AR_aarch64_linux_android = "$NDK_BIN/llvm-ar.exe"
$env:RANLIB_aarch64_linux_android = "$NDK_BIN/llvm-ranlib.exe"

Write-Host "=== OpenWorld Android Build ===" -ForegroundColor Cyan
Write-Host "Project: $ProjectRoot"
Write-Host "Target:  $Target"
Write-Host "NDK:     $NDK_BIN"

# 清理
if ($Clean) {
    Write-Host "Cleaning..." -ForegroundColor Yellow
    Push-Location $ProjectRoot
    cargo clean
    Pop-Location
    if (Test-Path $JniLibsDir) { Remove-Item -Recurse -Force $JniLibsDir }
    Write-Host "Clean done." -ForegroundColor Green
    exit 0
}

# 检查 Rust target
$installed = rustup target list --installed 2>&1
if ($installed -notmatch $Target) {
    Write-Host "Installing Rust target: $Target" -ForegroundColor Yellow
    rustup target add $Target
}

# 编译
$buildArgs = @(
    "build",
    "--lib",
    "--target", $Target,
    "--no-default-features",
    "--features", "android"
)
if ($Release) {
    $buildArgs += "--release"
    $Profile = "release"
    Write-Host "Building RELEASE..." -ForegroundColor Green
} else {
    $Profile = "debug"
    Write-Host "Building DEBUG..." -ForegroundColor Yellow
}

Push-Location $ProjectRoot
try {
    & cargo @buildArgs
    if ($LASTEXITCODE -ne 0) {
        Write-Host "Cargo build failed!" -ForegroundColor Red
        exit 1
    }
} finally {
    Pop-Location
}

# 复制 .so
$SoPath = "$ProjectRoot\target\$Target\$Profile\libopenworld.so"
if (-not (Test-Path $SoPath)) {
    Write-Host "ERROR: $SoPath not found!" -ForegroundColor Red
    exit 1
}

if (-not (Test-Path $JniLibsDir)) {
    New-Item -ItemType Directory -Path $JniLibsDir -Force | Out-Null
}

Copy-Item -Force $SoPath "$JniLibsDir\libopenworld.so"
$size = (Get-Item "$JniLibsDir\libopenworld.so").Length
$sizeMB = [math]::Round($size / 1MB, 2)

Write-Host ""
Write-Host "=== Build Complete ===" -ForegroundColor Green
Write-Host "Output: $JniLibsDir\libopenworld.so ($sizeMB MB)"
