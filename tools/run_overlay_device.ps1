param(
    [Parameter(Mandatory = $true)][string]$Key,
    [string]$Serial = '',
    [int]$Iterations = 100,
    [int]$Cycles = 1,
    [switch]$SkipBuild
)
$ErrorActionPreference = 'Stop'
$here = $PSScriptRoot
$lab = [IO.Path]::GetFullPath((Join-Path $here '..'))
$out = Join-Path $lab 'out'
$remote = '/data/local/tmp'
$script:adbPrefix = @()
if ($Serial) { $script:adbPrefix = @('-s', $Serial) }

function Invoke-Adb([string[]]$argv) {
    & adb @script:adbPrefix @argv
    if ($LASTEXITCODE -ne 0) { throw "adb failed: $($argv -join ' ')" }
    return
}
function AdbShell([string]$command) {
    & adb @script:adbPrefix shell $command
    if ($LASTEXITCODE -ne 0) { throw "adb shell failed: $command" }
}
function AdbShellCapture([string]$command) {
    $value = & adb @script:adbPrefix shell $command
    if ($LASTEXITCODE -ne 0) { throw "adb shell failed: $command" }
    return ($value | Out-String)
}
function AdbPush([string]$local, [string]$remotePath) {
    & adb @script:adbPrefix push $local $remotePath | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "adb push failed: $local" }
}

if (-not $SkipBuild) {
    & powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $lab 'build.ps1')
    if ($LASTEXITCODE -ne 0) { throw 'build failed' }
}
foreach ($file in @('urov-lab.kpm', 'urov_overlay_test', 'urov_hold_test', 'urov_hold2_test')) {
    $path = Join-Path $out $file
    if (!(Test-Path -LiteralPath $path)) { throw "missing artifact: $path" }
    AdbPush $path $remote
}
AdbShell "chmod 755 $remote/urov_overlay_test $remote/urov_hold_test $remote/urov_hold2_test"

function Run-Kpatch([string]$arguments) {
    AdbShell "$remote/kpatch $Key $arguments"
}
function Unload-Module {
    try { Run-Kpatch 'kpm unload urov-lab' } catch { }
}
function Cleanup-Stale {
    $list = AdbShellCapture "$remote/kpatch $Key kpm list"
    if ($list -match 'urov-lab') {
        try { Run-Kpatch "kpm ctl0 urov-lab status" } catch { }
        try { AdbShell "$remote/kpatch $Key su -c '$remote/urov_overlay_test --cleanup'" } catch { }
        Unload-Module
    }
}

Cleanup-Stale
$failed = $false
try {
    for ($i = 1; $i -le $Cycles; ++$i) {
        Run-Kpatch "kpm load $remote/urov-lab.kpm active"
        $result = AdbShellCapture "$remote/kpatch $Key su -c '$remote/urov_overlay_test --iterations $Iterations'"
        Write-Output $result.Trim()
        if ($result -notmatch 'PASS scope=standalone_active_overlay') {
            throw "overlay test failed in cycle $i"
        }
        Run-Kpatch "kpm unload urov-lab"
        $list = AdbShellCapture "$remote/kpatch $Key kpm list"
        if ($list -match 'urov-lab') { throw "module still loaded after cycle $i" }
        Write-Output "cycle $i PASS"
    }
} catch {
    $failed = $true
    Write-Error $_
} finally {
    if ($failed) { Unload-Module }
}
if ($failed) { exit 1 }
Write-Output 'ALL_CYCLES_PASS'
exit 0
