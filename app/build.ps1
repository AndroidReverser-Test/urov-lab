param(
    [string]$Sdk = $env:ANDROID_HOME,
    [string]$Ndk = $env:ANDROID_NDK_HOME,
    [string]$BuildTools = '36.0.0',
    [string]$Platform = 'android-36'
)
$ErrorActionPreference = 'Stop'
if (!$Sdk -or !$Ndk) { throw 'Pass -Sdk <Android SDK> and -Ndk <Android NDK>.' }
$out = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\out\app'))
$bin = Join-Path $Sdk "build-tools\$BuildTools"
$android = Join-Path $Sdk "platforms\$Platform\android.jar"
$clang = Join-Path $Ndk 'toolchains\llvm\prebuilt\windows-x86_64\bin\clang.exe'
$api = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\api'))
$apiInclude = '-I' + (Join-Path $api 'include')
$apiSource = Join-Path $api 'src\urov.c'
$pageFlags = @('-Wl,-z,max-page-size=16384', '-Wl,-z,common-page-size=16384')
foreach ($dir in @('classes','dex','lib\arm64-v8a')) {
    New-Item -ItemType Directory -Force -Path (Join-Path $out $dir) | Out-Null
}
function Check([string]$step) { if ($LASTEXITCODE -ne 0) { throw "$step failed ($LASTEXITCODE)" } }
& $clang --target=aarch64-linux-android26 -std=gnu11 -O2 -Wall -Wextra -Werror `
    -fPIC -shared -fno-builtin -fno-omit-frame-pointer -mno-outline-atomics `
    @pageFlags (Join-Path $PSScriptRoot 'app.c') `
    $apiInclude $apiSource (Join-Path $PSScriptRoot 'fixture.S') -llog -lz -o (Join-Path $out 'lib\arm64-v8a\liburovz.so')
Check 'Native compilation'
& $clang --target=aarch64-linux-android26 -std=gnu11 -O2 -Wall -Wextra -Werror `
    @pageFlags $apiInclude $apiSource (Join-Path $PSScriptRoot 'ctl.c') -o (Join-Path $out 'urovz-query')
Check 'QUERY utility'
& $clang --target=aarch64-linux-android26 -std=gnu11 -O2 -Wall -Wextra -Werror -Wno-unused-function `
    @pageFlags (Join-Path $PSScriptRoot 'compat_check.c') -o (Join-Path $out 'compat-check')
Check 'BTF compatibility regression tool'
& javac -encoding UTF-8 -source 8 -target 8 -Xlint:-options -bootclasspath $android `
    -classpath (Join-Path $bin 'core-lambda-stubs.jar') -d (Join-Path $out 'classes') `
    (Join-Path $PSScriptRoot 'MainActivity.java')
Check 'Java compilation'
$classes = @(Get-ChildItem -LiteralPath (Join-Path $out 'classes') -Filter '*.class' -Recurse | ForEach-Object FullName)
& (Join-Path $bin 'd8.bat') --min-api 26 --lib $android --output (Join-Path $out 'dex') @classes
Check 'DEX compilation'
$unsigned = Join-Path $out 'unsigned.apk'
& (Join-Path $bin 'aapt2.exe') link -I $android --manifest (Join-Path $PSScriptRoot 'AndroidManifest.xml') -o $unsigned
Check 'APK manifest'
Add-Type -AssemblyName System.IO.Compression
Add-Type -AssemblyName System.IO.Compression.FileSystem
$zip = [IO.Compression.ZipFile]::Open($unsigned, [IO.Compression.ZipArchiveMode]::Update)
try {
    [IO.Compression.ZipFileExtensions]::CreateEntryFromFile($zip, (Join-Path $out 'dex\classes.dex'), 'classes.dex') | Out-Null
    [IO.Compression.ZipFileExtensions]::CreateEntryFromFile($zip, (Join-Path $out 'lib\arm64-v8a\liburovz.so'), 'lib/arm64-v8a/liburovz.so') | Out-Null
} finally { $zip.Dispose() }
$aligned = Join-Path $out 'aligned.apk'
$apk = Join-Path $out 'urov-z-test.apk'
& (Join-Path $bin 'zipalign.exe') -f -p 4 $unsigned $aligned
Check 'APK alignment'
$keystore = Join-Path $out 'debug.keystore'
if (!(Test-Path -LiteralPath $keystore)) {
    & keytool -genkeypair -keystore $keystore -alias androiddebugkey -storepass android `
        -keypass android -keyalg RSA -keysize 2048 -validity 10000 -dname 'CN=UROV-Z Test,O=Local,C=CN'
    Check 'Local test signing key'
}
& (Join-Path $bin 'apksigner.bat') sign --ks $keystore --ks-key-alias androiddebugkey `
    --ks-pass pass:android --key-pass pass:android --out $apk $aligned
Check 'APK signing'
& (Join-Path $bin 'apksigner.bat') verify $apk
Check 'APK signature verification'
Get-FileHash -Algorithm SHA256 $apk
