# Embedded KCLF

Source: sibling `kpms/kclf`, commit `eb30b39d6dcc7c4336a5551626e4627e4c3958d9`
(KCLF 1.5.7). The original license and source attribution are retained. This
directory contains source files only; it is not a nested Git repository.

Integration changes:

- `UROV_KCLF_EMBEDDED` suppresses standalone KPM metadata/entry sections and
  exposes `urov_kclf_init`, `urov_kclf_control`, `urov_kclf_exit`.
- `kclf_urds` uses the UROV synchronous current-task real-memory accessor.
  Nofault completion reads and writes retain their original implementations.
- GNU_RELRO has a dedicated writable-load page-tail bounds check; `ke_contains`
  remains strict for all ELF tables, symbols and relocation accesses.

The outer entry owns lifecycle flags, and dispatches `ctl0 urov-z kclf,<command>`.
Build via the repository's `build.ps1`. Both manual and linker backends remain
available. See [integration analysis](../../INTEGRATION.md) for limits and tests.
