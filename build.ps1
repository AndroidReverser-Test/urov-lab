param(
    [string]$KernelPatchRoot = (Join-Path $PSScriptRoot '..\..'),
    [string]$Ndk = $env:ANDROID_NDK_HOME
)
$ErrorActionPreference = 'Stop'
if (!$Ndk) { throw 'Pass -Ndk <Android NDK directory> or set ANDROID_NDK_HOME.' }
$KernelPatchRoot = [IO.Path]::GetFullPath($KernelPatchRoot)
$bin = Join-Path $Ndk 'toolchains\llvm\prebuilt\windows-x86_64\bin'
$clang = Join-Path $bin 'clang.exe'
$linker = Join-Path $bin 'ld.lld.exe'
$out = Join-Path $PSScriptRoot 'out'
New-Item -ItemType Directory -Force -Path $out | Out-Null
if (!(Test-Path (Join-Path $KernelPatchRoot 'kernel\include\kpmodule.h'))) {
    throw 'KernelPatchRoot must contain the KernelPatch kernel headers.'
}
$includes = @('include','patch/include','linux/include','linux/arch/arm64/include','linux/tools/arch/arm64/include') |
    ForEach-Object { '-I' + (Join-Path (Join-Path $KernelPatchRoot 'kernel') $_) }
$flags = @('--target=aarch64-none-elf','-std=gnu11','-O2','-Wall','-Wextra','-Werror',
    '-Wformat=2','-Wshadow','-ffreestanding','-fno-builtin','-nostdinc','-fno-pic',
    '-fno-pie','-fno-stack-protector','-fno-asynchronous-unwind-tables',
    '-fno-unwind-tables','-mgeneral-regs-only','-mno-outline-atomics','-ffixed-x18')
$objects = @()
foreach ($name in @('decode','emulate','core_selftest','backend','urov_z')) {
    $object = Join-Path $out ($name + '.o')
    & $clang @flags @includes -c (Join-Path $PSScriptRoot "module\$name.c") -o $object
    if ($LASTEXITCODE -ne 0) { throw "Compile failed for $name" }
    $objects += $object
}
& $linker -r -o (Join-Path $out 'urov-z.kpm') @objects
if ($LASTEXITCODE -ne 0) { throw 'KPM link failed' }
& (Join-Path $bin 'llvm-readelf.exe') -h (Join-Path $out 'urov-z.kpm')
if ($LASTEXITCODE -ne 0) { throw 'ELF validation failed' }
Get-FileHash -Algorithm SHA256 (Join-Path $out 'urov-z.kpm')
