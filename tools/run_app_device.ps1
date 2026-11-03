param(
    [Parameter(Mandatory = $true)][string]$Key,
    [string]$Serial = '',
    [int]$Iterations = 3,
    [switch]$SkipBuild
)
$ErrorActionPreference = 'Stop'
$here = $PSScriptRoot
$lab = [IO.Path]::GetFullPath((Join-Path $here '..'))
$out = Join-Path $lab 'out'
$appDir = Join-Path $lab 'apps\urov-app'
$appOut = Join-Path $appDir 'out'
$remote = '/data/local/tmp'
$script:adbPrefix = @()
if ($Serial) { $script:adbPrefix = @('-s', $Serial) }
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$logPath = Join-Path $lab "results\app-device-$stamp.log"
New-Item -ItemType Directory -Force -Path (Split-Path $logPath) | Out-Null
$transcript = New-Object System.Collections.Generic.List[string]

function Write-Both([string]$text) {
    Write-Output $text
    $transcript.Add($text)
}
function Invoke-Adb([string[]]$argv) {
    $old = $ErrorActionPreference
    $ErrorActionPreference = 'SilentlyContinue'
    $output = & adb @script:adbPrefix @argv 2>&1
    $code = $LASTEXITCODE
    $ErrorActionPreference = $old
    if ($code -ne 0) { throw "adb failed: $($argv -join ' ')" }
    return ($output | Out-String)
}
function AdbShell([string]$command) {
    return (Invoke-Adb @('shell', $command)).Trim()
}
function AdbPush([string]$local, [string]$remotePath) {
    Invoke-Adb @('push', $local, $remotePath) | Out-Null
}

if (-not $SkipBuild) {
    & powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $lab 'build.ps1')
    if ($LASTEXITCODE -ne 0) { throw 'KPM build failed' }
    & powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $appDir 'build-app.ps1') -Source app.c
    if ($LASTEXITCODE -ne 0) { throw 'app build failed' }
}
foreach ($path in @((Join-Path $out 'urov-lab.kpm'), (Join-Path $appOut 'urovapp.apk'))) {
    if (!(Test-Path -LiteralPath $path)) { throw "missing artifact: $path" }
}
AdbPush (Join-Path $out 'urov-lab.kpm') $remote
Write-Both ("install: " + (Invoke-Adb @('install', '-r', '-g', (Join-Path $appOut 'urovapp.apk'))).Trim())

function Run-Kpatch([string]$arguments) {
    return (Invoke-Adb @('shell', "$remote/kpatch $Key $arguments")).Trim()
}
function Stop-App {
    try { AdbShell 'am force-stop com.example.urovapp' | Out-Null } catch { }
}
function Unload-Module {
    try { Run-Kpatch 'kpm unload urov-lab' | Out-Null } catch { }
}

Unload-Module
Stop-App
$moduleCtl = Run-Kpatch 'kpm load /data/local/tmp/urov-lab.kpm active'
Write-Both ("load: " + $moduleCtl)
$status = Run-Kpatch 'kpm ctl0 urov-lab status'
Write-Both ("status: " + $status)
if ($status -notmatch 'caps=0x[0-9a-f]+' -or $status -notmatch 'state=inactive') {
    throw 'module did not start inactive'
}
if ($status -notmatch 'prctl_option=0x55524f56') { throw 'prctl control channel missing' }

$failed = $false
try {
    for ($i = 1; $i -le $Iterations; ++$i) {
        AdbShell 'logcat -c' | Out-Null
        Stop-App
        AdbShell 'am start -n com.example.urovapp/android.app.NativeActivity' | Out-Null
        $deadline = (Get-Date).AddSeconds(20)
        $line = $null
        $all = ''
        while ((Get-Date) -lt $deadline) {
            Start-Sleep -Milliseconds 400
            $all = AdbShell 'logcat -d -s urovapp:*'
            $match = [regex]::Match($all, 'RESULT (PASS|FAIL)')
            if ($match.Success) { $line = $match.Value; break }
        }
        if (-not $line) { throw "run ${i}: no RESULT in logcat`n$all" }
        Write-Both "run $i : $line"
        $all -split "`n" | Where-Object { $_ -match 'urovapp' } | ForEach-Object { $transcript.Add($_.TrimEnd()) }
        if ($line -ne 'RESULT PASS') { throw "run ${i}: $line" }
        $status = Run-Kpatch 'kpm ctl0 urov-lab status'
        Write-Both "run $i status: $status"
        if ($status -notmatch 'state=inactive') { throw "run ${i}: session left active" }
        if ($status -notmatch 'hits=0 failures=0') { throw "run ${i}: session counters not cleared" }
    }
} catch {
    $failed = $true
    Write-Both ("ERROR: " + $_.Exception.Message)
} finally {
    Unload-Module
    Stop-App
    $list = ''
    try { $list = Run-Kpatch 'kpm list' } catch { }
    Write-Both ("final modules: " + $list)
    if ($list -match 'urov-lab') { $failed = $true }
}
[IO.File]::WriteAllLines($logPath, $transcript, [Text.Encoding]::UTF8)
Write-Both ("log: " + $logPath)
if ($failed) { [Environment]::Exit(1) }
Write-Both 'APP_ALL_PASS'
[Environment]::Exit(0)
