param(
    [Parameter(Mandatory = $true)][string]$SuperKey,
    [string]$ModuleKey,
    [string]$Serial,
    [switch]$LoadModule,
    [ValidateSet('manual','linker')][string[]]$Backend = @('manual','linker'),
    [ValidateRange(1,20)][int]$Cycles = 3,
    [switch]$Quiesce
)
$ErrorActionPreference = 'Stop'
$adbExe = (Get-Command adb.exe -CommandType Application -ErrorAction Stop | Select-Object -First 1).Source
if ($SuperKey -notmatch '^[A-Za-z0-9_@.+-]+$') { throw 'This runner requires a shell-safe superkey.' }
$repo = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$out = Join-Path $repo 'out\integration'
$run = Join-Path $out ('run-' + (Get-Date -Format 'yyyyMMdd-HHmmss'))
New-Item -ItemType Directory -Force -Path $run | Out-Null
$pkg = 'com.example.urovzinject'
$log = [Collections.Generic.List[string]]::new()
$seq = 0
function Log([string]$text) { $log.Add($text); Write-Host $text }
function Adb([string[]]$argv, [switch]$MayFail) {
    $prefix = @()
    if ($Serial) { $prefix = @('-s',$Serial) }
    $old = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try { $lines = & $adbExe @prefix @argv 2>&1; $code = $LASTEXITCODE }
    finally { $ErrorActionPreference = $old }
    $text = ($lines | ForEach-Object { "$_" }) -join "`n"
    if ($code -ne 0 -and !$MayFail) { throw "adb failed ($code): $text" }
    return $text
}
function Root([string]$command) {
    if ($command.Contains("'")) { throw 'Invalid internal shell quoting.' }
    Adb @('shell', "/data/local/tmp/kpatch $SuperKey su -c '$command'")
}
function Ctl([string]$command) {
    Adb @('shell','/data/local/tmp/kpatch',$SuperKey,'kpm','ctl0','urov-z',$command)
}
function Await-Report([int]$sequence) {
    $deadline = [DateTime]::UtcNow.AddSeconds(60)
    do {
        $text = Adb @('shell','run-as',$pkg,'cat','files/report.txt') -MayFail
        if ($text -match "(?m)^sequence=$sequence ") {
            if ($text -notmatch 'result=PASS') { throw "App assertion failed:`n$text" }
            return $text
        }
        Start-Sleep -Milliseconds 300
    } while ([DateTime]::UtcNow -lt $deadline)
    throw "Timed out waiting for app sequence $sequence : $text"
}
function Command([int]$action, [string]$label) {
    $script:seq++
    Adb @('shell',"run-as $pkg sh -c 'echo $script:seq $action > files/command.tmp; mv files/command.tmp files/command.txt'") | Out-Null
    $text = Await-Report $script:seq
    $text | Set-Content -Encoding utf8 (Join-Path $run "$label.txt")
    Log $text
    return $text
}
function Inject([int]$tid, [string]$path, [string]$kind, [string]$label) {
    Log (Ctl "kclf,inject,$tid,$path,$kind,wake")
    $deadline = [DateTime]::UtcNow.AddSeconds(45)
    do {
        $state = Ctl 'kclf,status'
        if ($state -match 'state=(failed|cancelled)') { throw "Injection failed: $state" }
        if ($state -match 'state=done' -and $state -notmatch 'pending=[1-9]' -and $state -match 'handle=[1-9a-f][0-9a-f]*') {
            $state | Set-Content -Encoding utf8 (Join-Path $run "$label-loader.txt")
            Log $state
            Log (Ctl 'kclf,reap')
            return
        }
        Start-Sleep -Milliseconds 300
    } while ([DateTime]::UtcNow -lt $deadline)
    throw "Injection timed out: $state"
}

try {
    $boot = (Adb @('shell','cat','/proc/sys/kernel/random/boot_id')).Trim()
    Log "boot_id=$boot"
    if ($LoadModule) {
        $count = (Adb @('shell','/data/local/tmp/kpatch',$SuperKey,'kpm','num')).Trim()
        if ($count -ne '0') { throw 'LoadModule requires a fresh device with zero KPMs; do not hot-unload to replace this build.' }
        if (!$ModuleKey) {
            $bytes = New-Object byte[] 16
            $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
            try { $rng.GetBytes($bytes) } finally { $rng.Dispose() }
            $ModuleKey = -join ($bytes | ForEach-Object { $_.ToString('x2') })
        }
        if ($ModuleKey -notmatch '^[0-9a-fA-F]{32}$') { throw 'ModuleKey must contain 32 hex digits.' }
        # This ignored local file is the only saved credential. Never log it.
        [IO.File]::WriteAllText((Join-Path $out 'session.key'), $ModuleKey)
        $kpm = Join-Path $repo 'out\urov-z.kpm'
        $hash = (Get-FileHash $kpm -Algorithm SHA256).Hash.ToLowerInvariant()
        Copy-Item -LiteralPath $kpm -Destination (Join-Path $run 'urov-z.kpm')
        $remote = "/data/local/tmp/urov-integrated-$($hash.Substring(0,12)).kpm"
        Log (Adb @('push',$kpm,$remote))
        Adb @('shell',"/data/local/tmp/kpatch $SuperKey kpm load $remote 'key=$ModuleKey verbose'") | Out-Null
        Log "loaded_sha256=$hash"
    } else {
        if (!$ModuleKey -and (Test-Path (Join-Path $out 'session.key'))) {
            $ModuleKey = [IO.File]::ReadAllText((Join-Path $out 'session.key')).Trim()
        }
        if ($ModuleKey -notmatch '^[0-9a-fA-F]{32}$') { throw 'Supply the loaded module key or use -LoadModule on a fresh device.' }
    }
    $status = Ctl 'status'
    Log $status
    if ($status -notmatch 'state=inactive' -or $status -notmatch 'loader=kclf-1.5.7') { throw 'Integrated UROV must start inactive.' }
    Log (Ctl 'kclf,probe')
    Log (Ctl 'kclf,reap')
    if ((Ctl 'kclf,status') -match 'state=') { throw 'Drain existing loader requests before running this test.' }
    Log (Adb @('push',(Join-Path $out 'native\relro-test'),'/data/local/tmp/uz-relro-test'))
    Adb @('shell','chmod','755','/data/local/tmp/uz-relro-test') | Out-Null
    Log (Adb @('shell','/data/local/tmp/uz-relro-test'))
    Log (Adb @('install','-r',(Join-Path $out 'urov-injection-test.apk')))
    $packageInfo = Adb @('shell','dumpsys','package',$pkg)
    if ($packageInfo -match '(?m)^\s*nativeLibraryDir=(\S+)') { $libdir = $Matches[1] }
    elseif ($packageInfo -match '(?m)^\s*legacyNativeLibraryDir=(\S+)') { $libdir = $Matches[1] + '/arm64' }
    else { throw 'Native library directory missing.' }
    Adb @('shell','run-as',$pkg,'test','-f',"$libdir/libuzpayload.so") | Out-Null
    foreach ($kind in $Backend) {
        Log "BACKEND=$kind cycles=$Cycles"
        Adb @('shell','am','force-stop',$pkg) | Out-Null
        Adb @('shell','run-as',$pkg,'rm','-f','files/report.txt','files/context.txt','files/command.txt','files/command.tmp') | Out-Null
        $script:seq = 0
        Adb @('shell','am','start','-W','-n',"$pkg/.MainActivity",'--es','key',$ModuleKey) | Out-Null
        $baseline = Await-Report 0
        Log $baseline
        $baseline | Set-Content -Encoding utf8 (Join-Path $run "$kind-baseline.txt")
        if ($baseline -notmatch 'pid=(\d+) tid=(\d+)') { throw 'Missing cooperative target thread.' }
        $targetId = [int]$Matches[1]; $targetTid = [int]$Matches[2]
        $maps = Root "cat /proc/$targetId/maps"
        if ($maps -match 'libuzpayload.so|libuzprobe.so') { throw 'Payload unexpectedly preloaded.' }
        $maps | Set-Content -Encoding utf8 (Join-Path $run "$kind-before-maps.txt")
        Inject $targetTid "$libdir/libuzpayload.so" $kind "$kind-payload"
        $report = Command 0 "$kind-injected"
        if ($report -notmatch 'cookie=444f4242594b434c constructors=1') { throw 'Payload constructor not independently observed.' }
        Root "cat /proc/$targetId/maps" | Set-Content -Encoding utf8 (Join-Path $run "$kind-loaded-maps.txt")
        for ($cycle = 1; $cycle -le $Cycles; ++$cycle) {
            $report = Command 1 "$kind-$cycle-hook"
            if ($report -notmatch 'hooked=1 overlay=0' -or $report -notmatch 'observed=13,12 original_return=103 return=1103') { throw 'Hook argument/return assertions missing.' }
            $report = Command 2 "$kind-$cycle-overlay"
            if ($report -notmatch 'hooked=1 overlay=1') { throw 'Overlay inactive.' }
            if ($cycle -eq 1) {
                # Additional injection while the same mm already has an active
                # overlay; EL0 constructors must still see the original CRC.
                Inject $targetTid "$libdir/libuzprobe.so" $kind "$kind-active-probe"
                $report = Command 0 "$kind-active-probe"
                if ($report -notmatch 'baseline_crc=([0-9a-f]+)') { throw 'Missing baseline CRC.' }
                $expectedCrc = $Matches[1]
                if ($report -notmatch "probe_constructors=1 probe_crc=$expectedCrc probe_return=1103") { throw 'Active-overlay injected probe failed.' }
            }
            Command 3 "$kind-$cycle-deactivate" | Out-Null
            Command 4 "$kind-$cycle-unhook" | Out-Null
        }
        $status = Ctl 'status'
        Log $status
        if ($status -notmatch 'state=inactive') { throw 'Overlay did not deactivate.' }
        Adb @('shell','am','force-stop',$pkg) | Out-Null
        Log (Ctl 'kclf,reap')
        $images = Ctl 'kclf,images'
        Log $images
        if ($images -notmatch 'no manual images') { throw 'Resident manual images remain after target exit.' }
        $state = Ctl 'kclf,status'
        Log $state
        if ($state -match 'state=') { throw 'Outstanding loader slots remain.' }
    }
    if ($Quiesce) { Log (Ctl 'kclf,quiesce') }
    $bootAfter = (Adb @('shell','cat','/proc/sys/kernel/random/boot_id')).Trim()
    if ($bootAfter -ne $boot) { throw 'Device rebooted during the test.' }
    Log 'RESULT PASS: injection, Dobby arguments/return, CRC direct/readv/proc, active-overlay injection, cleanup'
} catch {
    Log ("RESULT FAIL: " + $_.Exception.Message)
    # Keep the live process and KPM for diagnosis. Never unload/reload a
    # hooked module or release a payload while its function hook is installed.
    throw
} finally {
    $log | Set-Content -Encoding utf8 (Join-Path $run 'results.txt')
    Write-Host "Evidence: $run"
}
