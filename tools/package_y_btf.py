#!/usr/bin/env python3
"""Package exact-build ARM64 BTF for urov-y's btf= load argument."""

import argparse
from pathlib import Path
import struct


MAX_BTF = 64 * 1024 * 1024
MAX_NOTES = 64 * 1024
ELF64 = struct.Struct("<16sHHIQQQIHHHHHH")
SECTION64 = struct.Struct("<IIQQQQIIQQ")


def read_vmlinux(path, need_btf):
    """Read named sections without rewriting or copying the vmlinux."""
    limit = path.stat().st_size
    with path.open("rb") as stream:
        def read_at(offset, size):
            if offset > limit or size > limit - offset:
                raise ValueError("ELF section outside the file")
            stream.seek(offset)
            data = stream.read(size)
            if len(data) != size:
                raise ValueError("truncated ELF")
            return data

        hdr = ELF64.unpack(read_at(0, ELF64.size))
        if hdr[0][:7] != b"\x7fELF\x02\x01\x01" or hdr[2] != 183:
            raise ValueError("expected little-endian AArch64 vmlinux ELF")
        offset, stride, count, names_index = hdr[6], hdr[11], hdr[12], hdr[13]
        if not offset or stride != SECTION64.size:
            raise ValueError("vmlinux has no usable section table")
        first = SECTION64.unpack(read_at(offset, stride))
        count = count or first[5]
        if names_index == 0xffff:
            names_index = first[6]
        if not 0 < names_index < count <= 65536:
            raise ValueError("invalid section index")
        table = read_at(offset, count * stride)
        names = SECTION64.unpack_from(table, names_index * stride)
        if names[5] > MAX_BTF:
            raise ValueError("section name table is too large")
        names = read_at(names[4], names[5])
        sections = {}
        for section in SECTION64.iter_unpack(table):
            name_start = section[0]
            name_end = names.find(b"\0", name_start)
            if name_end < 0:
                raise ValueError("invalid section name")
            name = names[name_start:name_end]
            if name in (b".notes", b".note.gnu.build-id") or (need_btf and name == b".BTF"):
                if section[5] > (MAX_BTF if name == b".BTF" else MAX_NOTES):
                    raise ValueError(f"{name!r} is too large")
                sections[name] = read_at(section[4], section[5])
    return sections.get(b".note.gnu.build-id") or sections.get(b".notes"), sections.get(b".BTF")


def build_id_from_notes(notes):
    offset = 0
    while len(notes) - offset >= 12:
        namesz, descsz, kind = struct.unpack_from("<III", notes, offset)
        name_at = offset + 12
        desc_at = name_at + ((namesz + 3) & ~3)
        offset = desc_at + ((descsz + 3) & ~3)
        if offset > len(notes):
            raise ValueError("truncated ELF note")
        if kind == 3 and namesz == 4 and notes[name_at:name_at + 4] == b"GNU\0":
            if not 0 < descsz <= 64:
                raise ValueError("invalid GNU build ID size")
            return notes[desc_at:desc_at + descsz]
    raise ValueError("no GNU build ID found")


def read_limited(path, limit):
    with path.open("rb") as stream:
        data = stream.read(limit + 1)
    if len(data) > limit:
        raise ValueError(f"{path} exceeds the supported size")
    return data


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--vmlinux", type=Path, help="exact running build's unstripped ELF")
    source.add_argument("--notes", type=Path, help="binary /sys/kernel/notes from the same build as --btf")
    parser.add_argument("--btf", type=Path, help="raw BTF from the same build (e.g. pahole detached output)")
    parser.add_argument("output", type=Path)
    args = parser.parse_args()

    if args.notes and not args.btf:
        parser.error("--notes requires --btf")
    try:
        if args.vmlinux:
            notes, btf = read_vmlinux(args.vmlinux, not args.btf)
        else:
            notes, btf = read_limited(args.notes, MAX_NOTES), None
        if args.btf:
            btf = read_limited(args.btf, MAX_BTF)
        if not btf or len(btf) < 24 or btf[:4] != b"\x9f\xeb\x01\x00":
            raise ValueError("need raw little-endian BTF v1 from this exact kernel build")
        build_id = build_id_from_notes(notes or b"")
        with args.output.open("xb") as stream:
            stream.write(struct.pack("<8sII64s", b"UYBTF01", len(btf), len(build_id), build_id))
            stream.write(btf)
    except (OSError, ValueError) as exc:
        parser.error(str(exc))
    print(f"{args.output}: {len(btf)} BTF bytes, GNU build ID {build_id.hex()}")


if __name__ == "__main__":
    main()
