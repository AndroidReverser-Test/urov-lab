#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Check inspect mode's input failures and optional real-BTF reporting."""
from pathlib import Path
import subprocess
import sys
import tempfile


def invoke(binary, args, expected):
    result = subprocess.run([binary, "--inspect", *args], capture_output=True, text=True, timeout=30)
    if result.returncode != expected:
        raise AssertionError(f"expected exit {expected}, got {result.returncode}: {result.stderr}")
    if "runtime error:" in result.stderr or "AddressSanitizer" in result.stderr:
        raise AssertionError(result.stderr)
    return result.stdout


def main():
    binary = str(Path(sys.argv[1]).resolve())
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        invalid = root / "invalid.btf"
        invalid.write_bytes(b"not a BTF blob")
        invoke(binary, [], 2)
        invoke(binary, [str(root / "absent.btf")], 2)
        invoke(binary, [str(invalid)], 2)
        invalid.write_bytes(b"")
        invoke(binary, [str(invalid)], 2)
        invoke(binary, [str(invalid), "--kernel", "6.1.bad"], 2)
        invoke(binary, [str(invalid), "--symbols"], 2)
        if len(sys.argv) > 2:
            btf = str(Path(sys.argv[2]).resolve())
            text = invoke(binary, [btf], 0)
            assert "kernel=unknown" in text and "symbol=unknown" in text
            assert "runtime=unverified" in text and "PASS" not in text
            names = root / "symbols.txt"
            names.write_text("0000000000000000 T apply_to_existing_page_range\n__contpte_try_unfold_suffix\n")
            text = invoke(binary, [btf, "--symbols", str(names), "--kernel", "6.1.134"], 0)
            assert "apply_existing=1/present" in text
            assert "unfold=0/absent" in text or "unfold=1/absent" in text
            assert "runtime=unverified" in text and "PASS" not in text
    print("PASS inspector CLI: invalid/missing inputs, explicit runtime limits, optional real BTF and exact symbol names")


if __name__ == "__main__":
    main()
