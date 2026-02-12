# OpenWorld Android 交叉编译脚本
# 用法: .\scripts\build_android.ps1 [-Release]

param(
    [switch]$Release
)

$ErrorActionPreference = "Stop"

# NDK 路径
$ndkBase = "$env:LOCALAPPDATA\Android\Sdk\ndk"
if (-not (Test-Path $ndkBase)) {
    Write-Error "Android NDK not found at $ndkBase"
    exit 1
}

# 使用最新版本的 NDK
$ndkVersion = (Get-ChildItem $ndkBase | Sort-Object Name -Descending | Select-Object -First 1).Name
$ndkPath = "$ndkBase\$ndkVersion"
$ndkBin = "$ndkPath\toolchains\llvm\prebuilt\windows-x86_64\bin"

Write-Host "Using NDK $ndkVersion at $ndkPath" -ForegroundColor Cyan

# 设置环境变量
$env:PATH = "$ndkBin;$env:PATH"
$env:CC_aarch64_linux_android = "$ndkBin\aarch64-linux-android24-clang.cmd"
$env:AR_aarch64_linux_android = "$ndkBin\llvm-ar.exe"
$env:CARGO_BUILD_JOBS = 2

$target = "aarch64-linux-android"
$buildType = if ($Release) { "--release" } else { "" }
$profile = if ($Release) { "release" } else { "debug" }

Write-Host "Building libopenworld.so for $target ($profile)..." -ForegroundColor Yellow

$buildCmd = "cargo build --target $target --lib --no-default-features --features android $buildType"
Invoke-Expression $buildCmd

$soFile = "target\$target\$profile\libopenworld.so"
if (Test-Path $soFile) {
    $size = [math]::Round((Get-Item $soFile).Length / 1MB, 2)
    Write-Host "`n✅ Build successful: $soFile ($size MB)" -ForegroundColor Green

    # 复制到 KunBox jniLibs
    $jniDest = "..\..\KunBox\app\src\main\jniLibs\arm64-v8a"
    if (Test-Path (Split-Path $jniDest -Parent -ErrorAction SilentlyContinue)) {
        New-Item -ItemType Directory -Path $jniDest -Force | Out-Null
        Copy-Item $soFile $jniDest -Force
        Write-Host "Copied to $jniDest" -ForegroundColor Green
    }
    else {
        Write-Host "KunBox jniLibs dir not found, skipping copy" -ForegroundColor Yellow
    }
}
else {
    Write-Error "Build failed: $soFile not found"
    exit 1
}
