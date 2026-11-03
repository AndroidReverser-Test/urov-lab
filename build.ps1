param([string]$Ndk = 'D:\androidSDK\ndk\27.0.12077973')
$ErrorActionPreference = 'Stop'
$repo = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\..'))
$bin = Join-Path $Ndk 'toolchains\llvm\prebuilt\windows-x86_64\bin'
$clang = Join-Path $bin 'clang.exe'
$linker = Join-Path $bin 'ld.lld.exe'
$readelf = Join-Path $bin 'llvm-readelf.exe'
foreach ($tool in @($clang, $linker, $readelf)) {
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
& $clang @flags @includes -c (Join-Path $PSScriptRoot 'urov_kpm.c') -o (Join-Path $out 'urov_kpm.o')
if ($LASTEXITCODE -ne 0) { throw 'Active KPM compile failed' }
& $linker -r -o (Join-Path $out 'urov-lab.kpm') (Join-Path $out 'urov_kpm.o')
if ($LASTEXITCODE -ne 0) { throw 'Active KPM link failed' }
$userFlags = @('--target=aarch64-linux-android31','-std=gnu11','-O2','-Wall','-Wextra',
    '-Werror','-Wformat=2','-Wshadow','-fPIE','-pie','-pthread')
$core = @('decode.c','emulate.c','core_selftest.c') | ForEach-Object { Join-Path $PSScriptRoot $_ }
foreach ($test in @('emulate_test','native_test','kpm_check_test','copy_probe','vector_fault_probe','urov_lab_test')) {
    $filename = if ($test -eq 'urov_lab_test') { 'urov_lab_test' } else { 'urov_' + $test }
    & $clang @userFlags ('-I' + $repo) ('-I' + (Join-Path $repo 'kernel/patch/include')) `
        -idirafter (Join-Path $repo 'kernel/include') @core `
        (Join-Path $PSScriptRoot ('tests/' + $test + '.c')) -o (Join-Path $out $filename)
    if ($LASTEXITCODE -ne 0) { throw "Android compile failed: $test" }
}
Get-FileHash -Algorithm SHA256 (Join-Path $out 'urov-lab-check.kpm')
Get-FileHash -Algorithm SHA256 (Join-Path $out 'urov-lab.kpm')
