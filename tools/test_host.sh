#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-or-later
set -euo pipefail
lab_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
repo_dir="$(cd -- "$lab_dir/../.." && pwd)"
test_out="${UROV_TEST_OUT:-$lab_dir/out/host}"
mkdir -p -- "$test_out"
host_cc="${CC:-gcc}"
a64_cc="${AARCH64_CC:-aarch64-linux-gnu-gcc}"
a64_objcopy="${AARCH64_OBJCOPY:-aarch64-linux-gnu-objcopy}"
host_flags=(-std=gnu11 -O1 -g -Wall -Wextra -Werror -fno-strict-aliasing
            -fsanitize=address,undefined -fno-omit-frame-pointer)

"$a64_cc" -x assembler-with-cpp -DURO_ASM_CORPUS -c "$lab_dir/tests/decode_test.c" -o "$test_out/corpus.o"
"$a64_objcopy" -O binary -j .text "$test_out/corpus.o" "$test_out/corpus.bin"
"$host_cc" "${host_flags[@]}" "$lab_dir/decode.c" "$lab_dir/tests/decode_test.c" -o "$test_out/decode-test"
"$test_out/decode-test" "$test_out/corpus.bin"
"$host_cc" "${host_flags[@]}" -pthread "$lab_dir/decode.c" "$lab_dir/emulate.c" \
    "$lab_dir/core_selftest.c" "$lab_dir/tests/emulate_test.c" -o "$test_out/emulate-test"
"$test_out/emulate-test"
if [[ "${UROV_TEST_LEGACY_LOADER:-0}" != 1 ]]; then exit 0; fi
"$host_cc" "${host_flags[@]}" -Wno-unused-parameter -Wno-sign-compare -pthread \
    -I"$lab_dir/tests" -I"$lab_dir/tests/loader_stubs" -I"$repo_dir/kernel/patch/include" \
    "$lab_dir/tests/loader_v2_test.c" -o "$test_out/loader-v2-test"
"$test_out/loader-v2-test"
