param([string]$Ndk = $env:ANDROID_NDK_HOME)
$ErrorActionPreference = 'Stop'
if (!$Ndk) { throw 'Pass -Ndk <Android NDK directory> or set ANDROID_NDK_HOME.' }
$bin = Join-Path $Ndk 'toolchains\llvm\prebuilt\windows-x86_64\bin'
$out = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\out\api'))
New-Item -ItemType Directory -Force -Path $out | Out-Null
$flags = @('--target=aarch64-linux-android26','-std=c11','-O2','-Wall','-Wextra','-Werror',
    '-Wformat=2','-Wshadow','-fPIC',('-I' + (Join-Path $PSScriptRoot 'include')))
function Check([string]$step) { if ($LASTEXITCODE -ne 0) { throw "$step failed ($LASTEXITCODE)" } }
$object = Join-Path $out 'urov.o'
& (Join-Path $bin 'clang.exe') @flags -c (Join-Path $PSScriptRoot 'src\urov.c') -o $object
Check 'API compilation'
& (Join-Path $bin 'llvm-ar.exe') rcs (Join-Path $out 'liburov.a') $object
Check 'API static library'
& (Join-Path $bin 'clang.exe') --target=aarch64-linux-android26 -shared $object `
    '-Wl,-z,max-page-size=16384' '-Wl,-soname,liburov.so' -o (Join-Path $out 'liburov.so')
Check 'API shared library'
& (Join-Path $bin 'clang.exe') @flags (Join-Path $PSScriptRoot 'examples\query.c') `
    (Join-Path $out 'liburov.a') '-Wl,-z,max-page-size=16384' -o (Join-Path $out 'urov-query')
Check 'API example'
Get-FileHash -Algorithm SHA256 (Join-Path $out 'liburov.a'),(Join-Path $out 'liburov.so')
