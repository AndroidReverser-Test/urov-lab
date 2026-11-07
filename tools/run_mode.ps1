param(
    [Parameter(Mandatory=$true)][string]$Mode,
    [int]$Repeats = 3,
    [string]$Key = '',
    [switch]$Keep
)
$ErrorActionPreference = 'Stop'
$kp = 'Test6666'
$pkg = 'com.example.urovdetect'
$lab = 'E:\KernelPatch\kpms\urov-lab'
$apk = Join-Path $lab 'apps\urov-detect\out\urovdetect.apk'
$kpm = Join-Path $lab 'out\urov-y.kpm'

adb install --no-incremental -r $apk 2>&1 | Out-Null
if (-not $Keep) { adb shell "/data/local/tmp/kpatch $kp kpm unload urov-y" 2>&1 | Out-Null }
if (-not $Key) { $Key = -join ((1..32) | ForEach-Object { '{0:x}' -f (Get-Random -Max 16) }) }
adb push $kpm /data/local/tmp/urov-y-run.kpm | Out-Null
$load = adb shell "/data/local/tmp/kpatch $kp kpm load /data/local/tmp/urov-y-run.kpm key=$Key" 2>&1
Write-Host "load: $load"
adb shell "/data/local/tmp/kpatch $kp kpm ctl0 urov-y status"
adb shell "am force-stop $pkg"
adb shell "am start -W -n $pkg/.MainActivity --es mode $Mode --ei repeats $Repeats --es key $Key" | Out-Null
Start-Sleep -Seconds 10
$appPid = (adb shell "pidof $pkg").Trim()
$log = adb shell "logcat -d --pid=$appPid -v threadtime -s urovdetect:I AndroidRuntime:E libc:F DEBUG:F"
$run = Join-Path $lab "results\manual-$Mode-$(Get-Date -Format 'HHmmss').log"
$log | Set-Content -Path $run -Encoding utf8
$log | Select-String -Pattern 'DETECT_RESULT|NATIVE_RESULT|FAIL|Fatal signal|CRC_LOCK_GUARD|CRC_RESTORE|DOBBY_DETECT_(LOCK|RESTORE|KMEM|ACCESS)|MP_AUDIT|ELIM_TIMING|ELIM_RESIDUAL' | ForEach-Object { $_.Line }
Write-Host "--- log: $run"
Write-Host "--- status ---"
adb shell "/data/local/tmp/kpatch $kp kpm ctl0 urov-y status"
