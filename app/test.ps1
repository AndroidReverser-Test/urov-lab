param(
    [string]$ModuleKey,
    [switch]$Baseline,
    [int]$TimeoutSeconds = 90
)
$ErrorActionPreference = 'Stop'
if (!$Baseline -and $ModuleKey -notmatch '^[0-9a-fA-F]{32}$') {
    throw 'Pass -ModuleKey <32 hex digits> or -Baseline.'
}
$out = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\out\app'))
New-Item -ItemType Directory -Force -Path $out | Out-Null
& adb shell am force-stop com.example.urovz
if ($LASTEXITCODE -ne 0) { throw 'Cannot stop test App.' }
& adb shell run-as com.example.urovz rm -f files/report.txt
if ($LASTEXITCODE -ne 0) { throw 'Cannot remove previous report; refusing stale test results.' }
$arguments = @('shell','am','start','-W','-n','com.example.urovz/.MainActivity','--ez','autorun','true')
if ($Baseline) { $arguments += @('--ez','baseline','true') }
else { $arguments += @('--es','key',$ModuleKey) }
& adb @arguments
if ($LASTEXITCODE -ne 0) { throw 'Cannot start test App.' }
$deadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
while ([DateTime]::UtcNow -lt $deadline) {
    $report = (& adb shell run-as com.example.urovz cat files/report.txt 2>$null) -join "`n"
    if ($report -match 'RESULT (PASS|FAIL)') {
        $passed = $Matches[1] -eq 'PASS'
        $report | Set-Content -LiteralPath (Join-Path $out 'report.txt') -Encoding utf8
        Write-Output $report
        if (!$passed) { throw 'App regression failed; see out/app/report.txt.' }
        return
    }
    Start-Sleep -Milliseconds 500
}
throw 'No completed report. Inspect adb logcat -s UROVZ and module status before unloading.'
