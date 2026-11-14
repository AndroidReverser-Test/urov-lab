param([string]$Ndk = $env:ANDROID_NDK_HOME)
$ErrorActionPreference = 'Stop'
if (!$Ndk) { throw 'Pass -Ndk <Android NDK directory>.' }
$clang = Join-Path $Ndk 'toolchains/llvm/prebuilt/windows-x86_64/bin/clang.exe'
$root = Split-Path $PSScriptRoot
$out = Join-Path $root 'out/tests'
New-Item -ItemType Directory -Force -Path $out | Out-Null
$flags = @('--target=aarch64-linux-android26','-std=gnu11','-O2','-Wall','-Wextra','-Werror')
& $clang @flags (Join-Path $PSScriptRoot 'insn_scan_test.c') `
    (Join-Path $root 'module/decode.c') (Join-Path $root 'module/emulate.c') `
    (Join-Path $root 'module/core_selftest.c') -o (Join-Path $out 'insn-scan-test')
if ($LASTEXITCODE -ne 0) { throw 'Block scanner test build failed' }
& $clang @flags ('-I' + (Join-Path $root 'api/include')) `
    (Join-Path $PSScriptRoot 'perf_device.c') (Join-Path $PSScriptRoot 'perf_fixture.S') `
    (Join-Path $root 'api/src/urov.c') '-Wl,-z,max-page-size=16384' -o (Join-Path $out 'perf-device')
if ($LASTEXITCODE -ne 0) { throw 'Device regression test build failed' }
