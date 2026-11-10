param([string]$Ndk = 'D:\androidSDK\ndk\26.1.10909125')
$ErrorActionPreference = 'Stop'
$repo = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
$bin = Join-Path $Ndk 'toolchains\llvm\prebuilt\windows-x86_64\bin'
$clang = Join-Path $bin 'clang.exe'
$linker = Join-Path $bin 'ld.lld.exe'
$readelf = Join-Path $bin 'llvm-readelf.exe'
$nm = Join-Path $bin 'llvm-nm.exe'
foreach ($tool in @($clang, $linker, $readelf, $nm)) {
    if (!(Test-Path -LiteralPath $tool)) { throw "Tool missing: $tool" }
}
$out = Join-Path $PSScriptRoot 'out'
New-Item -ItemType Directory -Path $out -Force | Out-Null
$includes = @('include','patch/include','linux/include','linux/arch/arm64/include','linux/tools/arch/arm64/include') |
    ForEach-Object { '-I' + (Join-Path (Join-Path $repo 'kernel') $_) }
$flags = @('--target=aarch64-none-elf','-std=gnu11','-O2','-Wall','-Wextra','-Werror',
    '-Wformat=2','-Wshadow','-ffreestanding','-fno-builtin','-nostdinc','-fno-pic',
    '-fno-pie','-fno-stack-protector','-fno-asynchronous-unwind-tables',
    '-fno-unwind-tables','-mgeneral-regs-only','-mno-outline-atomics','-ffixed-x18')
$objects = @()
foreach ($name in @('decode','emulate','core_selftest','urov_check','fault_signature')) {
    $object = Join-Path $out ($name + '.o')
    $extra = @()
    if ($name -eq 'fault_signature') { $extra = @('-fsanitize=kcfi') }
    & $clang @flags @extra @includes -c (Join-Path $PSScriptRoot ($name + '.c')) -o $object
    if ($LASTEXITCODE -ne 0) { throw "Compile failed: $name" }
    $objects += $object
}
& $linker -r -o (Join-Path $out 'urov-lab-check.kpm') @objects
if ($LASTEXITCODE -ne 0) { throw 'KPM link failed' }
& $readelf -h -s (Join-Path $out 'urov-lab-check.kpm')
if ($LASTEXITCODE -ne 0) { throw 'KPM ELF inspection failed' }
foreach ($name in @('urov_kpm','urov_backend')) {
    & $clang @flags @includes -c (Join-Path $PSScriptRoot ($name + '.c')) -o (Join-Path $out ($name + '.o'))
    if ($LASTEXITCODE -ne 0) { throw "Active KPM compile failed: $name" }
}
& $linker -r -o (Join-Path $out 'urov-lab.kpm') (Join-Path $out 'urov_kpm.o') `
    (Join-Path $out 'urov_backend.o') (Join-Path $out 'decode.o') `
    (Join-Path $out 'emulate.o') (Join-Path $out 'core_selftest.o')
if ($LASTEXITCODE -ne 0) { throw 'Active KPM link failed' }
$imports = & $nm -u (Join-Path $out 'urov-lab.kpm')
if ($LASTEXITCODE -ne 0 -or ($imports -match 'kpm_lifecycle_v2|kp_urov_backend_v1|urov_backend_v1')) {
    throw 'Unexpected strong dependency on the external backend'
}
foreach ($name in @('urov_x','urov_x_backend')) {
    & $clang @flags @includes -c (Join-Path $PSScriptRoot ($name + '.c')) -o (Join-Path $out ($name + '.o'))
    if ($LASTEXITCODE -ne 0) { throw "UROV-X KPM compile failed: $name" }
}
& $linker -r -o (Join-Path $out 'urov-x.kpm') (Join-Path $out 'urov_x.o') `
    (Join-Path $out 'urov_x_backend.o') (Join-Path $out 'decode.o') `
    (Join-Path $out 'emulate.o') (Join-Path $out 'core_selftest.o')
if ($LASTEXITCODE -ne 0) { throw 'UROV-X KPM link failed' }
foreach ($name in @('urov_y','urov_y_backend')) {
    & $clang @flags @includes -c (Join-Path $PSScriptRoot ($name + '.c')) -o (Join-Path $out ($name + '.o'))
    if ($LASTEXITCODE -ne 0) { throw "UROV-Y KPM compile failed: $name" }
}
& $linker -r -o (Join-Path $out 'urov-y.kpm') (Join-Path $out 'urov_y.o') `
    (Join-Path $out 'urov_y_backend.o') (Join-Path $out 'decode.o') `
    (Join-Path $out 'emulate.o') (Join-Path $out 'core_selftest.o')
if ($LASTEXITCODE -ne 0) { throw 'UROV-Y KPM link failed' }
$imports = & $nm -u (Join-Path $out 'urov-y.kpm')
if ($LASTEXITCODE -ne 0 -or ($imports -match '\bU\s+(memcpy|memmove|memset)\s*$')) {
    throw 'UROV-Y contains a compiler-generated memory helper that the KPM loader cannot resolve'
}
$userFlags = @('--target=aarch64-linux-android31','-std=gnu11','-O2','-Wall','-Wextra',
    '-Werror','-Wformat=2','-Wshadow','-fPIE','-pie','-pthread')
$core = @('decode.c','emulate.c','core_selftest.c') | ForEach-Object { Join-Path $PSScriptRoot $_ }
$direct = @('urov_overlay_test','urov_hold_test','urov_hold2_test','urov_foreign_test','urov_y_test')
foreach ($test in @('emulate_test','native_test','kpm_check_test','copy_probe','vector_fault_probe',
                    'urov_overlay_test','urov_hold_test','urov_hold2_test','urov_foreign_test',
                    'urov_y_test')) {
    $filename = if ($direct -contains $test) { $test } else { 'urov_' + $test }
    $sources = @()
    if ($test -notmatch '^urov_(hold|foreign|y_test)') { $sources += $core }
    & $clang @userFlags ('-I' + $repo) ('-I' + (Join-Path $repo 'kernel/patch/include')) `
        -idirafter (Join-Path $repo 'kernel/include') @sources `
        (Join-Path $PSScriptRoot ('tests/' + $test + '.c')) -o (Join-Path $out $filename)
    if ($LASTEXITCODE -ne 0) { throw "Android compile failed: $test" }
}
# Root-only residual probe (the app's seccomp policy blocks remap_file_pages).
& $clang @userFlags ('-I' + $repo) ('-I' + $PSScriptRoot) `
    (Join-Path $PSScriptRoot 'tests/v217_probe.c') -o (Join-Path $out 'v217_probe')
if ($LASTEXITCODE -ne 0) { throw 'v217 probe compile failed' }
# Standalone differential test for the urov-y LL/SC window model.  It shares
# urov_y_window.h with the backend and needs no KPM or root to run.
& $clang @userFlags ('-I' + $repo) ('-I' + $PSScriptRoot) `
    -idirafter (Join-Path $repo 'kernel/include') `
    (Join-Path $PSScriptRoot 'tests/urov_window_test.c') -o (Join-Path $out 'urov_window_test')
if ($LASTEXITCODE -ne 0) { throw 'window model test compile failed' }
# Standalone differential test for the read-before value proof.  It shares
# urov_y_prewin.h with the backend and needs decode.c; no KPM or root.
& $clang @userFlags '-Wno-unused-function' ('-I' + $repo) ('-I' + $PSScriptRoot) `
    -idirafter (Join-Path $repo 'kernel/include') `
    (Join-Path $PSScriptRoot 'decode.c') `
    (Join-Path $PSScriptRoot 'tests/urov_prewin_test.c') -o (Join-Path $out 'urov_prewin_test')
if ($LASTEXITCODE -ne 0) { throw 'pre-window proof test compile failed' }
Get-FileHash -Algorithm SHA256 (Join-Path $out 'urov-lab-check.kpm')
Get-FileHash -Algorithm SHA256 (Join-Path $out 'urov-lab.kpm')
Get-FileHash -Algorithm SHA256 (Join-Path $out 'urov-x.kpm')
$built = @('urov-lab.kpm', 'urov-lab-check.kpm', 'urov-x.kpm', 'urov-y.kpm', 'urov_overlay_test',
    'urov_hold_test', 'urov_hold2_test', 'urov_foreign_test', 'urov_y_test', 'urov_copy_probe',
    'urov_vector_fault_probe', 'urov_emulate_test', 'urov_native_test', 'urov_kpm_check_test',
    'v217_probe', 'urov_window_test', 'urov_prewin_test')
$sums = foreach ($name in $built) {
    $hash = (Get-FileHash -Algorithm SHA256 -LiteralPath (Join-Path $out $name)).Hash.ToLowerInvariant()
    "$hash  $name"
}
[IO.File]::WriteAllLines((Join-Path $out 'SHA256SUMS'), [string[]]$sums, [Text.Encoding]::ASCII)
