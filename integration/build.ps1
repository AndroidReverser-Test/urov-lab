param(
    [string]$Sdk = $env:ANDROID_HOME,
    [string]$Ndk = $env:ANDROID_NDK_HOME,
    [string]$Cmake = '',
    [string]$BuildTools = '36.0.0',
    [string]$Platform = 'android-36'
)
$ErrorActionPreference = 'Stop'
if (!$Sdk -or !$Ndk) { throw 'Pass -Sdk <SDK directory> and -Ndk <NDK directory>.' }
if (!$Cmake) { $Cmake = Join-Path $Sdk 'cmake\3.22.1\bin\cmake.exe' }
$out = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\out\integration'))
$bin = Join-Path $Sdk "build-tools\$BuildTools"
$android = Join-Path $Sdk "platforms\$Platform\android.jar"
foreach ($dir in @('classes','dex','native')) {
    New-Item -ItemType Directory -Force -Path (Join-Path $out $dir) | Out-Null
}
function Check([string]$step) { if ($LASTEXITCODE -ne 0) { throw "$step failed ($LASTEXITCODE)" } }
& $Cmake -S $PSScriptRoot -B (Join-Path $out 'native') -G Ninja `
    ('-DCMAKE_MAKE_PROGRAM=' + (Join-Path (Split-Path $Cmake) 'ninja.exe')) `
    ('-DCMAKE_TOOLCHAIN_FILE=' + (Join-Path $Ndk 'build\cmake\android.toolchain.cmake')) `
    -DANDROID_ABI=arm64-v8a -DANDROID_PLATFORM=android-26 -DANDROID_STL=c++_static -DCMAKE_BUILD_TYPE=Release
Check 'CMake configuration'
& $Cmake --build (Join-Path $out 'native') --target uzhost uzpayload uzprobe relro-test --parallel 8
Check 'Native build'
& javac -encoding UTF-8 -source 8 -target 8 -Xlint:-options -bootclasspath $android `
    -classpath (Join-Path $bin 'core-lambda-stubs.jar') `
    -d (Join-Path $out 'classes') (Join-Path $PSScriptRoot 'MainActivity.java') (Join-Path $PSScriptRoot 'RunnerService.java')
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
    foreach ($lib in @('uzhost','uzpayload','uzprobe')) {
        [IO.Compression.ZipFileExtensions]::CreateEntryFromFile($zip, (Join-Path $out "native\lib$lib.so"), "lib/arm64-v8a/lib$lib.so") | Out-Null
    }
} finally { $zip.Dispose() }
$aligned = Join-Path $out 'aligned.apk'
$apk = Join-Path $out 'urov-injection-test.apk'
& (Join-Path $bin 'zipalign.exe') -f -p 4 $unsigned $aligned
Check 'APK alignment'
$keystore = Join-Path $out 'debug.keystore'
if (!(Test-Path -LiteralPath $keystore)) {
    & keytool -genkeypair -keystore $keystore -alias androiddebugkey -storepass android `
        -keypass android -keyalg RSA -keysize 2048 -validity 10000 -dname 'CN=UROV Integration,O=Local,C=CN'
    Check 'Local signing key'
}
& (Join-Path $bin 'apksigner.bat') sign --ks $keystore --ks-key-alias androiddebugkey `
    --ks-pass pass:android --key-pass pass:android --out $apk $aligned
Check 'APK signing'
& (Join-Path $bin 'apksigner.bat') verify $apk
Check 'APK verification'
Get-FileHash -Algorithm SHA256 $apk, (Join-Path $out 'native\libuzpayload.so')
