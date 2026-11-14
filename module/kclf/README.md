# Embedded KCLF

Source: sibling `kpms/kclf`, commit `eb30b39d6dcc7c4336a5551626e4627e4c3958d9`
(KCLF 1.5.7). The original license and source attribution are retained. This
directory contains source files only; it is not a nested Git repository.

Integration changes:

- `UROV_KCLF_EMBEDDED` suppresses standalone KPM metadata/entry sections and
  exposes `urov_kclf_init`, `urov_kclf_control`, `urov_kclf_exit`.
- `kclf_urds` uses the UROV synchronous current-task real-memory accessor.
  Nofault completion reads and writes retain their original implementations.
- GNU_RELRO has a dedicated writable-load padding check. A 16-KiB-linked
  payload on a 4-KiB kernel may extend to the LOAD's declared alignment boundary,
  but its runtime protection pages must not overlap another LOAD. `ke_contains`
  remains strict for all ELF tables, symbols and relocation accesses. The
  integration `relro-test` additionally accepts real SO paths to validate their
  load/RELRO layouts for both runtime page sizes.
- The overlay passes its validated live or exact-build detached BTF to
  `urov_kclf_set_btf` before releasing BTF storage. The loader keeps only layout
  offsets and ABI selectors, so detached BTF works for task-work ABI selection,
  exception-frame size and locked VMA traversal without a dangling BTF pointer.
- `urov_kclf_preflight` resolves loader dependencies and cross-checks the
  current task's mm before either subsystem installs hooks. Missing symbols or
  incompatible layouts therefore fail before publishing overlay callbacks.
  The later loader init only installs optional completion-watch hooks; a failed
  watch still uses the existing controller-poll path.

The outer entry owns lifecycle flags, and dispatches `ctl0 urov-z kclf,<command>`.
Build via the repository's `build.ps1`. Both manual and linker backends remain
available. See [integration analysis](../../docs/INTEGRATION.md) for limits and tests.

The portable profile regression covers the 5.4 bool, 5.8 int and 5.11+ enum
task-work notification signatures, both cancellation ABIs, `mmap_sem` /
`mmap_lock`, invalid frames/prototypes, detached-storage lifetime and truncation.
From this directory on a host with a C compiler:

```sh
cc -std=c11 -Wall -Wextra -Werror -O2 tests/compat_profile_test.c -o /tmp/kclf-profile-test
/tmp/kclf-profile-test
```

This validates profile parsing, not operation on all kernels. Host hook
trampoline retirement and vendor changes to non-BTF `TIF_*` definitions remain
outside the profile's guarantees; retain the outer module's reboot-based update
procedure.
