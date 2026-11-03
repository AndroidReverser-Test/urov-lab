param(
    [string]$Ndk = 'D:\androidSDK\ndk\26.1.10909125',
    [string]$Sdk = 'D:\androidSDK',
    [string]$Source = 'app.c',
    [string]$LibName = 'urovapp',
    [switch]$Hold,
    [switch]$Install,
    [string]$Serial = ''
)
$ErrorActionPreference = 'Stop'
$here = $PSScriptRoot
$out = Join-Path $here 'out'
New-Item -ItemType Directory -Force -Path $out | Out-Null
$bin = Join-Path $Ndk 'toolchains\llvm\prebuilt\windows-x86_64\bin'
$clang = Join-Path $bin 'clang.exe'
$buildTools = Join-Path $Sdk 'build-tools\36.0.0'
$aapt2 = Join-Path $buildTools 'aapt2.exe'
$zipalign = Join-Path $buildTools 'zipalign.exe'
$apksigner = Join-Path $buildTools 'apksigner.bat'
$androidJar = Join-Path $Sdk 'platforms\android-36\android.jar'
$keystore = Join-Path $env:USERPROFILE '.android\debug.keystore'
foreach ($tool in @($clang, $aapt2, $zipalign, $apksigner, $androidJar, $keystore)) {
    if (!(Test-Path -LiteralPath $tool)) { throw "Missing tool: $tool" }
}

$so = Join-Path $out "lib$LibName.so"
$defs = @()
if ($Hold) { $defs += @('-DUROV_HOLD=1', '-Wno-unused-function') }
& $clang --target=aarch64-linux-android31 -shared -fPIC -O2 -g0 -Wall -Wextra -Werror `
    -fno-omit-frame-pointer -pthread '-Wl,--build-id=sha1' '-Wl,-z,noexecstack' `
    @defs -I (Join-Path $here 'include') -I (Resolve-Path (Join-Path $here '..\..')) `
    (Join-Path $here $Source) -o $so -llog -landroid
if ($LASTEXITCODE -ne 0) { throw 'native build failed' }

$base = Join-Path $out 'base.apk'
if (Test-Path -LiteralPath $base) { Remove-Item -LiteralPath $base -Force }
& $aapt2 link -o $base -I $androidJar --manifest (Join-Path $here 'AndroidManifest.xml') `
    --min-sdk-version 31 --target-sdk-version 35
if ($LASTEXITCODE -ne 0) { throw 'aapt2 link failed' }

$unaligned = Join-Path $out 'unaligned.apk'
Copy-Item -LiteralPath $base -Destination $unaligned -Force
Add-Type -AssemblyName System.IO.Compression
Add-Type -AssemblyName System.IO.Compression.FileSystem
$zip = [System.IO.Compression.ZipFile]::Open($unaligned, [System.IO.Compression.ZipArchiveMode]::Update)
$entryName = "lib/arm64-v8a/lib$LibName.so"
$old = $zip.GetEntry($entryName)
if ($old) { $old.Delete() }
$entry = [IO.Compression.ZipFileExtensions]::CreateEntryFromFile(
    $zip, $so, $entryName, [IO.Compression.CompressionLevel]::NoCompression)
$entry.ExternalAttributes = 0x81A40000 # -rw-r--r--
$zip.Dispose()

$aligned = Join-Path $out 'aligned.apk'
if (Test-Path -LiteralPath $aligned) { Remove-Item -LiteralPath $aligned -Force }
& $zipalign -f -p 4 $unaligned $aligned
if ($LASTEXITCODE -ne 0) { throw 'zipalign failed' }

$apkName = if ($Hold) { 'urovapp-hold.apk' } else { 'urovapp.apk' }
$apk = Join-Path $out $apkName
if (Test-Path -LiteralPath $apk) { Remove-Item -LiteralPath $apk -Force }
& $apksigner sign --ks $keystore --ks-pass pass:android --key-pass pass:android `
    --min-sdk-version 31 --out $apk $aligned
if ($LASTEXITCODE -ne 0) { throw 'apksigner failed' }
& $apksigner verify --verbose $apk
if ($LASTEXITCODE -ne 0) { throw 'apksigner verify failed' }

Get-Item -LiteralPath $apk, $so | Select-Object Length, FullName
if ($Install) {
    $adbArgs = @()
    if ($Serial) { $adbArgs += @('-s', $Serial) }
    & adb @adbArgs install -r -g $apk
    if ($LASTEXITCODE -ne 0) { throw 'adb install failed' }
}
