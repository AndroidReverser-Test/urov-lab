#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-or-later
set -euo pipefail
lab_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
repo_dir="$(cd -- "$lab_dir/../.." && pwd)"
test_out="${UROV_TEST_OUT:-$lab_dir/out/host}"
host_cc="${CC:-gcc}"
if [[ ! -f "$lab_dir/out/resident_profile.h" ]]; then
    echo 'Missing resident_profile.h. Run tools/generate_test_profile.py --btf /path/to/vmlinux.btf first.' >&2
    exit 2
fi
mkdir -p -- "$test_out"
host_flags=(-std=gnu11 -O1 -g -Wall -Wextra -Werror -Wno-attributes
            -fno-strict-aliasing -fno-omit-frame-pointer -pthread)
if [[ "${UROV_TSAN:-0}" == 1 ]]; then
    host_flags+=(-fsanitize=thread)
    test_bin="$test_out/resident-protocol-tsan"
else
    host_flags+=(-fsanitize=address,undefined)
    test_bin="$test_out/resident-protocol-asan"
fi
"$host_cc" "${host_flags[@]}" -I"$lab_dir/out" -idirafter "$repo_dir/kernel/include" \
    "$lab_dir/decode.c" "$lab_dir/emulate.c" "$lab_dir/core_selftest.c" \
    "$lab_dir/tests/resident_protocol_test.c" -o "$test_bin"
"$test_bin"
