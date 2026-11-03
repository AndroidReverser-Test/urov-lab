#!/usr/bin/env python3
"""Install reviewed integration points in the exact 66e758f7d0c0 kernel tree.

This prepares source only. It never configures, flashes, or boots a device.
Every replacement is checked before any file is written. Re-running is safe.
"""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess

LAB = Path(__file__).resolve().parents[1]
REV = "66e758f7d0c0"


def prepare(root):
    root = root.resolve()
    revision = subprocess.check_output(["git", "-C", str(root), "rev-parse", "HEAD"], text=True).strip()
    if not revision.startswith(REV):
        raise SystemExit("Refusing different kernel revision: " + revision)
    changes = {}

    def edit(name, before, after, count=1):
        path = root / name
        text = changes.get(path, path.read_text())
        if text.count(after) == count:
            return
        if after in text or text.count(before) != count:
            raise SystemExit("Integration anchor differs: " + name + " / " + before[:90])
        changes[path] = text.replace(before, after, count)

    for name in ("arch/arm64/mm/fault.c", "mm/mmap.c", "mm/mprotect.c", "mm/mremap.c",
                 "mm/madvise.c", "mm/mlock.c", "fs/userfaultfd.c"):
        text = (root / name).read_text()
        if "#include <linux/urov.h>" not in text:
            anchor = next(line for line in text.splitlines() if line.startswith("#include "))
            edit(name, anchor, "#include <linux/urov.h>\n" + anchor)
    edit("arch/arm64/mm/fault.c", "\tif (!inf->fn(far, esr, regs))",
         "\tif (urov_handle_abort(far, esr, regs))\n\t\treturn;\n\n\tif (!inf->fn(far, esr, regs))")
    edit("mm/mmap.c", "\t /* arch_unmap() might do unmaps itself.  */",
         "\tif (urov_range_busy(mm, start, end))\n\t\treturn -EBUSY;\n\n\t /* arch_unmap() might do unmaps itself.  */")
    edit("mm/mmap.c", "\t/* mm's last user has gone, and its about to be pulled down */",
         "\turov_mm_release(mm);\n\n\t/* mm's last user has gone, and its about to be pulled down */")
    edit("mm/mmap.c", "\tbool merge_next = false;\n\n\t/*",
         "\tbool merge_next = false;\n\n\t/* Do not merge an active code VMA through an adjacent operation. */\n"
         "\tif (urov_mm_busy(mm))\n\t\treturn NULL;\n\n\t/*")
    edit("mm/mprotect.c", "\tif (newflags == oldflags) {",
         "\tif (urov_range_busy(mm, start, end))\n\t\treturn -EBUSY;\n\n\tif (newflags == oldflags) {")
    edit("mm/mremap.c", "\tif (mmap_write_lock_killable(current->mm))\n\t\treturn -EINTR;\n\tvma = vma_lookup(mm, addr);",
         "\tif (mmap_write_lock_killable(current->mm))\n\t\treturn -EINTR;\n"
         "\tif (urov_range_busy(mm, addr, addr + (old_len ?: PAGE_SIZE)) ||\n"
         "\t    ((flags & MREMAP_FIXED) && urov_range_busy(mm, new_addr, new_addr + new_len))) {\n"
         "\t\tret = -EBUSY;\n\t\tgoto out;\n\t}\n\tvma = vma_lookup(mm, addr);")
    edit("mm/madvise.c", "\tblk_start_plug(&plug);\n\terror = madvise_walk_vmas",
         "\tif (urov_range_busy(mm, start, end)) {\n\t\terror = -EBUSY;\n\t\tgoto urov_unlock;\n\t}\n"
         "\tblk_start_plug(&plug);\n\terror = madvise_walk_vmas")
    edit("mm/madvise.c", "\tblk_finish_plug(&plug);\n\tif (write)",
         "\tblk_finish_plug(&plug);\nurov_unlock:\n\tif (write)")
    # mlock_fixup has one common exit that sets *prev for the caller.
    edit("mm/mlock.c", "\tif (newflags == oldflags || (oldflags & VM_SPECIAL) ||",
         "\tif (urov_range_busy(mm, start, end)) {\n\t\t*prev = vma;\n\t\treturn -EBUSY;\n\t}\n\n"
         "\tif (newflags == oldflags || (oldflags & VM_SPECIAL) ||")
    edit("fs/userfaultfd.c", "\tmmap_write_lock(mm);\n\tmas_set(&mas, start);",
         "\tmmap_write_lock(mm);\n\tif (urov_range_busy(mm, start, end)) {\n\t\tret = -EBUSY;\n\t\tgoto out_unlock;\n\t}\n"
         "\tmas_set(&mas, start);", count=2)
    # A Kconfig bool ensures these objects can never be unloaded separately.
    for name, line in (("mm/Kconfig", '\nsource "mm/urov_lab/Kconfig"\n'),
                       ("mm/Makefile", '\nobj-$(CONFIG_UROV_LAB) += urov_lab/\n')):
        path = root / name
        text = path.read_text()
        if line.strip() not in text:
            changes[path] = text + line
    copies = {root / "include/linux/urov.h": LAB / "native/urov.h"}
    for name in ("urov.c", "Kconfig", "Makefile"):
        copies[root / "mm/urov_lab" / name] = LAB / "native" / name
    for name in ("urov_abi.h", "decode.h", "decode.c", "emulate.h", "emulate.c", "core_selftest.c"):
        copies[root / "mm/urov_lab" / name] = LAB / name
    for dest, src in copies.items():
        expected = src.read_text()
        if dest.exists() and dest.read_text() != expected:
            raise SystemExit("Refusing to overwrite edited backend file: " + str(dest))
        changes[dest] = expected
    hashes = {}
    for path, text in changes.items():
        data = text.encode()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        hashes[str(path.relative_to(root))] = hashlib.sha256(data).hexdigest()
    print(json.dumps({"revision": revision, "files": hashes}, indent=2))


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("kernel_tree", type=Path)
    args = parser.parse_args()
    prepare(args.kernel_tree)
