param(
    [string]$ProjectRoot = "C:\Users\33039\Desktop\OpenWorld",
    [string]$ReportPath = "C:\Users\33039\Desktop\OpenWorld\android\JNI_ALIGNMENT_REPORT.md"
)

$ErrorActionPreference = "Stop"

$kotlinPath = Join-Path $ProjectRoot "android\app\src\main\java\com\openworld\core\OpenWorldCore.kt"
$rustPath = Join-Path $ProjectRoot "src\app\android.rs"

if (!(Test-Path $kotlinPath)) { throw "Kotlin file not found: $kotlinPath" }
if (!(Test-Path $rustPath)) { throw "Rust file not found: $rustPath" }

$kotlinText = Get-Content -Raw -Encoding UTF8 $kotlinPath
$rustText = Get-Content -Raw -Encoding UTF8 $rustPath

function Convert-KotlinTypeToJni([string]$typeName) {
    $t = ""
    if ($null -ne $typeName) { $t = $typeName.Trim() }
    switch ($t) {
        "" { return "V" }
        "Unit" { return "V" }
        "Int" { return "I" }
        "Long" { return "J" }
        "Boolean" { return "Z" }
        "String" { return "Ljava/lang/String;" }
        "String?" { return "Ljava/lang/String;" }
        default { throw "Unknown Kotlin type: '$t'" }
    }
}

function Convert-RustTypeToJni([string]$typeName, [bool]$isReturn) {
    $t = ""
    if ($null -ne $typeName) { $t = $typeName.Trim() }
    if ($isReturn -and [string]::IsNullOrWhiteSpace($t)) { return "V" }
    switch ($t) {
        "jint" { return "I" }
        "jlong" { return "J" }
        "jboolean" { return "Z" }
        "jstring" { return "Ljava/lang/String;" }
        "JNIEnv" { return "<ENV>" }
        "JClass" { return "<CLASS>" }
        "JString" { return "Ljava/lang/String;" }
        default { throw "Unknown Rust JNI type: '$t'" }
    }
}

function Build-KotlinMethodMap {
    param([string]$text)

    $map = @{}
    $regex = [regex]'@JvmStatic\s+external\s+fun\s+([A-Za-z0-9_]+)\s*\(([^)]*)\)\s*(?::\s*([^\s\{]+))?'
    $matches = $regex.Matches($text)

    foreach ($m in $matches) {
        $name = $m.Groups[1].Value
        $paramText = $m.Groups[2].Value.Trim()
        $retType = $m.Groups[3].Value.Trim()

        $paramSig = ""
        if ($paramText.Length -gt 0) {
            $parts = $paramText.Split(',') | ForEach-Object { $_.Trim() } | Where-Object { $_.Length -gt 0 }
            foreach ($p in $parts) {
                $idx = $p.LastIndexOf(':')
                if ($idx -lt 0) { throw "Param parse failed: $name -> $p" }
                $ptype = $p.Substring($idx + 1).Trim()
                $paramSig += (Convert-KotlinTypeToJni $ptype)
            }
        }

        $retSig = Convert-KotlinTypeToJni $retType
        $descriptor = "($paramSig)$retSig"

        if ($map.ContainsKey($name)) { throw "Kotlin duplicate declaration: $name" }
        $map[$name] = $descriptor
    }

    return $map
}

function Build-RustExportMap {
    param([string]$text)

    $map = @{}
    $dups = @{}

    $regex = [regex]::new(
        'pub\s+extern\s+"system"\s+fn\s+Java_com_openworld_core_OpenWorldCore_([A-Za-z0-9_]+)\s*\((.*?)\)\s*(?:->\s*([A-Za-z0-9_]+))?\s*\{',
        [System.Text.RegularExpressions.RegexOptions]::Singleline
    )
    $matches = $regex.Matches($text)

    foreach ($m in $matches) {
        $name = $m.Groups[1].Value
        $argBlock = $m.Groups[2].Value
        $retType = $m.Groups[3].Value

        $argTypeRegex = [regex]':\s*([A-Za-z0-9_]+)'
        $argTypeMatches = $argTypeRegex.Matches($argBlock)
        $argTypes = @()
        foreach ($am in $argTypeMatches) {
            $argTypes += $am.Groups[1].Value
        }

        if ($argTypes.Count -lt 2) { throw "Rust export arg error: $name" }
        if ($argTypes.Count -eq 2) {
            $realArgTypes = @()
        } else {
            $realArgTypes = $argTypes[2..($argTypes.Count - 1)]
        }

        $paramSig = ""
        foreach ($rt in $realArgTypes) {
            $paramSig += (Convert-RustTypeToJni $rt $false)
        }
        $retSig = Convert-RustTypeToJni $retType $true
        $descriptor = "($paramSig)$retSig"

        if ($map.ContainsKey($name)) {
            if (!$dups.ContainsKey($name)) { $dups[$name] = @($map[$name]) }
            $dups[$name] += $descriptor
        } else {
            $map[$name] = $descriptor
        }
    }

    return @{
        map = $map
        duplicates = $dups
    }
}

function Build-CoreSignatureMap {
    param([string]$text)

    $map = @{}
    $dups = @{}

    $regex = [regex]::new(
        'JniMethodSignature::new\(\s*c,\s*"([A-Za-z0-9_]+)",\s*"([^"]+)",\s*true\s*\)',
        [System.Text.RegularExpressions.RegexOptions]::Singleline
    )
    $matches = $regex.Matches($text)

    foreach ($m in $matches) {
        $name = $m.Groups[1].Value
        $sig = $m.Groups[2].Value

        if ($map.ContainsKey($name)) {
            if (!$dups.ContainsKey($name)) { $dups[$name] = @($map[$name]) }
            $dups[$name] += $sig
        } else {
            $map[$name] = $sig
        }
    }

    return @{
        map = $map
        duplicates = $dups
    }
}

$kotlinMap = Build-KotlinMethodMap $kotlinText
$rustResult = Build-RustExportMap $rustText
$rustMap = $rustResult.map
$rustDup = $rustResult.duplicates
$coreResult = Build-CoreSignatureMap $rustText
$coreMap = $coreResult.map
$coreDup = $coreResult.duplicates

$kotlinOnly = @($kotlinMap.Keys | Where-Object { -not $rustMap.ContainsKey($_) } | Sort-Object)
$rustOnly = @($rustMap.Keys | Where-Object { -not $kotlinMap.ContainsKey($_) } | Sort-Object)

$signatureMismatch = @()
foreach ($name in ($kotlinMap.Keys | Where-Object { $rustMap.ContainsKey($_) } | Sort-Object)) {
    if ($kotlinMap[$name] -ne $rustMap[$name]) {
        $signatureMismatch += [pscustomobject]@{
            Method = $name
            Kotlin = $kotlinMap[$name]
            RustExport = $rustMap[$name]
        }
    }
}

$coreMismatch = @()
foreach ($name in ($kotlinMap.Keys | Where-Object { $coreMap.ContainsKey($_) } | Sort-Object)) {
    if ($kotlinMap[$name] -ne $coreMap[$name]) {
        $coreMismatch += [pscustomobject]@{
            Method = $name
            Kotlin = $kotlinMap[$name]
            CoreTable = $coreMap[$name]
        }
    }
}

$allOk = (
    $kotlinOnly.Count -eq 0 -and
    $rustOnly.Count -eq 0 -and
    $signatureMismatch.Count -eq 0 -and
    $rustDup.Keys.Count -eq 0 -and
    $coreMismatch.Count -eq 0 -and
    $coreDup.Keys.Count -eq 0
)

$time = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
$lines = New-Object System.Collections.Generic.List[string]
$lines.Add("# JNI alignment report")
$lines.Add("")
$lines.Add("- Time: $time")
$lines.Add("- Kotlin declarations: $($kotlinMap.Count)")
$lines.Add("- Rust exports: $($rustMap.Count)")
$lines.Add("- core_jni_methods items: $($coreMap.Count)")
$lines.Add("- Result: " + ($(if ($allOk) { "PASS" } else { "FAIL" })))
$lines.Add("")

$lines.Add("## A. Kotlin only")
if ($kotlinOnly.Count -eq 0) { $lines.Add("- None") } else { foreach ($x in $kotlinOnly) { $lines.Add("- $x") } }
$lines.Add("")

$lines.Add("## B. Rust export only")
if ($rustOnly.Count -eq 0) { $lines.Add("- None") } else { foreach ($x in $rustOnly) { $lines.Add("- $x") } }
$lines.Add("")

$lines.Add("## C1. Kotlin vs Rust export signature mismatches")
if ($signatureMismatch.Count -eq 0) {
    $lines.Add("- None")
} else {
    foreach ($m in $signatureMismatch) {
        $lines.Add("- $($m.Method): Kotlin=$($m.Kotlin), Rust=$($m.RustExport)")
    }
}
$lines.Add("")

$lines.Add("## C2. Kotlin vs core_jni_methods signature mismatches")
if ($coreMismatch.Count -eq 0) {
    $lines.Add("- None")
} else {
    foreach ($m in $coreMismatch) {
        $lines.Add("- $($m.Method): Kotlin=$($m.Kotlin), Core=$($m.CoreTable)")
    }
}
$lines.Add("")

$lines.Add("## D1. Duplicate Rust exports")
if ($rustDup.Keys.Count -eq 0) {
    $lines.Add("- None")
} else {
    foreach ($k in ($rustDup.Keys | Sort-Object)) {
        $vals = ($rustDup[$k] | Select-Object -Unique) -join ", "
        $lines.Add("- ${k}: $vals")
    }
}
$lines.Add("")

$lines.Add("## D2. Duplicate core_jni_methods items")
if ($coreDup.Keys.Count -eq 0) {
    $lines.Add("- None")
} else {
    foreach ($k in ($coreDup.Keys | Sort-Object)) {
        $vals = ($coreDup[$k] | Select-Object -Unique) -join ", "
        $lines.Add("- ${k}: $vals")
    }
}
$lines.Add("")

$dir = Split-Path -Parent $ReportPath
if (!(Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
Set-Content -Path $ReportPath -Value $lines -Encoding UTF8

Write-Host "JNI scan completed"
Write-Host "Report: $ReportPath"
Write-Host "Result: $(if ($allOk) { "PASS" } else { "FAIL" })"
