param([string]$Ndk = $env:ANDROID_NDK_HOME)
$ErrorActionPreference = 'Stop'
if (!$Ndk) { throw 'Pass -Ndk <Android NDK directory>.' }
$clang = Join-Path $Ndk 'toolchains/llvm/prebuilt/windows-x86_64/bin/clang.exe'
$root = Split-Path $PSScriptRoot
$out = Join-Path $root 'out/tests'
New-Item -ItemType Directory -Force -Path $out | Out-Null
$flags = @('--target=aarch64-linux-android26','-std=gnu11','-O2','-Wall','-Wextra','-Werror',
    '-Wl,-z,max-page-size=16384','-Wl,-z,common-page-size=4096')
& $clang @flags -pthread (Join-Path $PSScriptRoot 'optimization_test.c') -o (Join-Path $out 'optimization-test')
if ($LASTEXITCODE -ne 0) { throw 'Buffer budget, mapping identity and page lock regression build failed' }
& $clang @flags (Join-Path $PSScriptRoot 'pt_leaf_test.c') -o (Join-Path $out 'pt-leaf-test')
if ($LASTEXITCODE -ne 0) { throw 'Native PTL leaf regression build failed' }
& $clang @flags (Join-Path $PSScriptRoot 'runtime_compat_test.c') `
    (Join-Path $root 'module/decode.c') -o (Join-Path $out 'runtime-compat-test')
if ($LASTEXITCODE -ne 0) { throw 'Runtime compatibility regression build failed' }
& $clang @flags -pthread (Join-Path $PSScriptRoot 'page_index_test.c') `
    -o (Join-Path $out 'page-index-test')
if ($LASTEXITCODE -ne 0) { throw 'Concurrent page index regression build failed' }
& $clang @flags -pthread ('-I' + (Join-Path $root 'api/include')) `
    (Join-Path $PSScriptRoot 'lifecycle_device.c') (Join-Path $root 'api/src/urov.c') `
    -o (Join-Path $out 'lifecycle-device')
if ($LASTEXITCODE -ne 0) { throw 'Device lifecycle regression build failed' }
& $clang @flags -pthread ('-I' + (Join-Path $root 'api/include')) `
    (Join-Path $PSScriptRoot 'resource_device.c') (Join-Path $root 'api/src/urov.c') `
    -o (Join-Path $out 'resource-device')
if ($LASTEXITCODE -ne 0) { throw 'Device resource policy regression build failed' }
& $clang @flags (Join-Path $root 'module/kclf/tests/compat_profile_test.c') `
    -o (Join-Path $out 'kclf-profile-test')
if ($LASTEXITCODE -ne 0) { throw 'KCLF compatibility profile test build failed' }
& $clang @flags (Join-Path $PSScriptRoot 'insn_scan_test.c') `
    (Join-Path $root 'module/decode.c') (Join-Path $root 'module/emulate.c') `
    (Join-Path $root 'module/core_selftest.c') -o (Join-Path $out 'insn-scan-test')
if ($LASTEXITCODE -ne 0) { throw 'Block scanner test build failed' }
& $clang @flags -Wno-unused-function (Join-Path $PSScriptRoot 'window_hint_test.c') `
    -o (Join-Path $out 'window-hint-test')
if ($LASTEXITCODE -ne 0) { throw 'Instruction hint regression test build failed' }
& $clang @flags ('-I' + (Join-Path $root 'api/include')) `
    (Join-Path $PSScriptRoot 'perf_device.c') (Join-Path $PSScriptRoot 'perf_fixture.S') `
    (Join-Path $root 'api/src/urov.c') -o (Join-Path $out 'perf-device')
if ($LASTEXITCODE -ne 0) { throw 'Device regression test build failed' }
