#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-or-later
# Run from any directory. Optional BTF paths are passed to compat-check.
set -euo pipefail
cd "$(dirname "$0")/.."
out=${UROV_TEST_OUT:-out/compat-1.2.5}
mkdir -p "$out"
flags=(-std=gnu11 -O1 -g -Wall -Wextra -Werror -fsanitize=address,undefined)
cc "${flags[@]}" -pthread tests/optimization_test.c -o "$out/optimization"
"$out/optimization"
cc "${flags[@]}" tests/pt_leaf_test.c -o "$out/pt-leaf"
"$out/pt-leaf"
cc "${flags[@]}" tests/runtime_compat_test.c module/decode.c -o "$out/runtime-compat"
"$out/runtime-compat"
cc "${flags[@]}" -pthread tests/page_index_test.c -o "$out/page-index"
"$out/page-index"
cc "${flags[@]}" -Wno-unused-function app/compat_check.c -o "$out/compat-check"
"$out/compat-check" "$@"
python3 tests/inspect_cli_test.py "$out/compat-check" ${1:+"$1"}
cc "${flags[@]}" -Wno-unused-function tests/window_hint_test.c -o "$out/window-hint"
"$out/window-hint"
cc "${flags[@]}" module/kclf/tests/compat_profile_test.c -o "$out/kclf-profile"
"$out/kclf-profile"
cc "${flags[@]}" tests/insn_scan_test.c module/decode.c module/emulate.c module/core_selftest.c -o "$out/insn-scan"
"$out/insn-scan"
cc "${flags[@]}" -DKCLF_ELF_HOST -Imodule/kclf integration/relro_test.c module/kclf/kclf_elf.c -o "$out/relro"
"$out/relro"
