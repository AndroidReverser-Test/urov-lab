param(
    [string]$Ndk = 'D:\androidSDK\ndk\26.1.10909125',
    [string]$Sdk = 'D:\androidSDK',
    [switch]$Observer,
    [switch]$Install,
    [string]$Serial = ''
)
$ErrorActionPreference = 'Stop'
$here = $PSScriptRoot
$lab = [IO.Path]::GetFullPath((Join-Path $here '..\..'))
$out = Join-Path $here 'out'
$classes = Join-Path $out 'classes'
$dex = Join-Path $out 'dex'
$bin = Join-Path $Ndk 'toolchains\llvm\prebuilt\windows-x86_64\bin'
$tools = Join-Path $Sdk 'build-tools\36.0.0'
$jar = Join-Path $Sdk 'platforms\android-36\android.jar'
$key = Join-Path $env:USERPROFILE '.android\debug.keystore'
$manifest = if ($Observer) { 'ObserverManifest.xml' } else { 'AndroidManifest.xml' }
$apkName = if ($Observer) { 'urovobserver.apk' } else { 'urovdetect.apk' }
foreach ($tool in @("$bin\clang.exe", "$tools\aapt2.exe", "$tools\d8.bat", $jar, $key)) {
    if (!(Test-Path -LiteralPath $tool)) { throw "Missing tool: $tool" }
}
New-Item -ItemType Directory -Force -Path $out, $classes, $dex | Out-Null
& "$bin\clang.exe" --target=aarch64-linux-android31 -std=gnu11 -shared -fPIC -O2 -g0 `
    -Wall -Wextra -Werror -Wformat=2 -Wshadow -fno-omit-frame-pointer -pthread `
    '-Wl,--build-id=sha1' '-Wl,-z,noexecstack' '-Wl,-z,max-page-size=16384' `
    -I (Join-Path $lab 'native') (Join-Path $here 'app.c') `
    (Join-Path $lab 'native\urov_detect.c') -o (Join-Path $out 'liburovdetect.so') -llog -ldl
if ($LASTEXITCODE -ne 0) { throw 'Native build failed' }
& javac -encoding UTF-8 -source 8 -target 8 -Xlint:-options `
    -bootclasspath "$jar;$tools\core-lambda-stubs.jar" -d $classes `
    (Join-Path $here 'MainActivity.java') (Join-Path $here 'ObserverActivity.java')
if ($LASTEXITCODE -ne 0) { throw 'Java build failed' }
$classFiles = @(Get-ChildItem -LiteralPath $classes -Recurse -Filter '*.class' | ForEach-Object FullName)
& "$tools\d8.bat" --lib $jar --min-api 31 --output $dex @classFiles
if ($LASTEXITCODE -ne 0) { throw 'D8 failed' }
$base = Join-Path $out 'base.apk'
& "$tools\aapt2.exe" link -o $base -I $jar --manifest (Join-Path $here $manifest)
if ($LASTEXITCODE -ne 0) { throw 'AAPT failed' }
$unsigned = Join-Path $out 'unsigned.apk'
Copy-Item -LiteralPath $base -Destination $unsigned -Force
Add-Type -AssemblyName System.IO.Compression
Add-Type -AssemblyName System.IO.Compression.FileSystem
$zip = [IO.Compression.ZipFile]::Open($unsigned, [IO.Compression.ZipArchiveMode]::Update)
try {
    foreach ($item in @(@('classes.dex', (Join-Path $dex 'classes.dex')),
                       @('lib/arm64-v8a/liburovdetect.so', (Join-Path $out 'liburovdetect.so')))) {
        [IO.Compression.ZipFileExtensions]::CreateEntryFromFile($zip, $item[1], $item[0],
            [IO.Compression.CompressionLevel]::Optimal) | Out-Null
    }
} finally { $zip.Dispose() }
$aligned = Join-Path $out 'aligned.apk'
& "$tools\zipalign.exe" -f -p 4 $unsigned $aligned
if ($LASTEXITCODE -ne 0) { throw 'Zipalign failed' }
$apk = Join-Path $out $apkName
& "$tools\apksigner.bat" sign --ks $key --ks-pass pass:android --key-pass pass:android --out $apk $aligned
if ($LASTEXITCODE -ne 0) { throw 'Signing failed' }
& "$tools\apksigner.bat" verify $apk
if ($LASTEXITCODE -ne 0) { throw 'Signature verification failed' }
Get-FileHash -Algorithm SHA256 -LiteralPath $apk, (Join-Path $out 'liburovdetect.so')
if ($Install) {
    $prefix = @()
    if ($Serial) { $prefix = @('-s', $Serial) }
    & adb @prefix install -r $apk
    if ($LASTEXITCODE -ne 0) { throw 'Install failed' }
}
