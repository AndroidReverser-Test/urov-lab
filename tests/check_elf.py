#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Check Android ELF LOAD/RELRO coverage for both 4K and 16K runtimes.

No third-party packages. Accepts paths or glob patterns. This checks linked
artifacts, not KPM relocatable objects, and is not a substitute for device runs.
"""
import glob
from pathlib import Path
import struct
import sys

PT_LOAD, PT_GNU_RELRO = 1, 0x6474E552


def require(condition, message):
    if not condition:
        raise ValueError(message)


def check(path):
    data = path.read_bytes()
    require(len(data) >= 64 and data[:7] == b"\x7fELF\x02\x01\x01", "expected ELF64 little-endian")
    header = struct.unpack_from("<HHIQQQIHHHHHH", data, 16)
    kind, machine, _, _, phoff, _, _, _, phsize, phnum, _, _, _ = header
    require(kind in (2, 3) and machine == 183, "expected linked AArch64 ELF")
    require(phsize == 56 and phnum and phoff + phsize * phnum <= len(data), "invalid program headers")
    segments = [struct.unpack_from("<IIQQQQQQ", data, phoff + i * phsize) for i in range(phnum)]
    loads = [p for p in segments if p[0] == PT_LOAD and p[6]]
    relros = [p for p in segments if p[0] == PT_GNU_RELRO and p[6]]
    require(loads and relros, "missing LOAD or GNU_RELRO")
    for _, _, offset, address, _, filesz, memsz, align in loads:
        require(filesz <= memsz and offset + filesz <= len(data), "LOAD outside file")
        require(align >= 16384 and not align & (align - 1) and (address - offset) % align == 0,
                "LOAD lacks congruent 16K alignment")
    for page in (4096, 16384):
        floor = lambda x: x & -page
        ceil = lambda x: (x + page - 1) & -page
        ranges = sorted((floor(p[3]), ceil(p[3] + p[6])) for p in loads)
        for a, b in zip(ranges, ranges[1:]):
            require(a[1] <= b[0], f"{page}: overlapping LOAD pages")
        for relro in relros:
            raw_start, raw_end = relro[3], relro[3] + relro[6]
            start, end = floor(raw_start), ceil(raw_end)
            cursor = start
            for lo, hi in ranges:
                if lo <= cursor < hi:
                    cursor = hi
                if cursor >= end:
                    break
            require(cursor >= end, f"{page}: RELRO [{start:#x},{end:#x}) includes unmapped LOAD pages")
            for load in loads:
                lo, hi = load[3], load[3] + load[6]
                if max(lo, start) >= min(hi, end):
                    continue
                require(not load[1] & 1, f"{page}: RELRO overlaps executable bytes")
                if load[1] & 2:
                    require(lo >= raw_start and hi <= raw_end,
                            f"{page}: RELRO would protect mutable bytes outside its declared range")
    return len(loads)


def main(arguments):
    if not arguments:
        print("usage: check_elf.py <ELF path or glob> [...]", file=sys.stderr)
        return 2
    paths = []
    for pattern in arguments:
        matches = glob.glob(pattern)
        if not matches:
            print(f"FAIL {pattern}: no matching files", file=sys.stderr)
            return 1
        paths.extend(Path(p) for p in matches)
    failed = 0
    for path in dict.fromkeys(paths):
        try:
            count = check(path)
            print(f"PASS {path}: {count} LOADs, 16K alignment, 4K/16K RELRO mapped and isolated")
        except (OSError, ValueError, struct.error) as error:
            print(f"FAIL {path}: {error}", file=sys.stderr)
            failed += 1
    return bool(failed)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
