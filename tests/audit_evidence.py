#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Audit a saved evidence bundle without executing its tools or contacting a device.

Hashes establish consistency with a local manifest, not independent authenticity.
PASS text in a log never establishes a completed run or runtime compatibility.
"""
import argparse
import hashlib
import json
from pathlib import Path, PureWindowsPath
import re
import struct
import sys


CAPTURE_FILES = ("device.txt", "kernel.config", "vmlinux.btf", "kernel.notes")
LOG_FILES = ("models-final.txt", "profile-final.txt", "elf-final.txt")
SHA256 = re.compile(r"[0-9a-fA-F]{64}\Z")
FAILURE = re.compile(r"^\s*(?:FAIL\b|\[FAIL\])|ERROR: (?:AddressSanitizer|LeakSanitizer)|runtime error:", re.M)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def contained_file(root, name):
    if not isinstance(name, str) or not name or "\\" in name:
        raise ValueError("expected a relative path with forward slashes")
    if Path(name).is_absolute() or PureWindowsPath(name).drive or ".." in Path(name).parts:
        raise ValueError("path must stay within its declared directory")
    path = (root / name).resolve(strict=True)
    try:
        path.relative_to(root.resolve())
    except ValueError:
        raise ValueError("resolved path escapes its declared directory") from None
    if not path.is_file():
        raise ValueError("expected a regular file")
    return path


def no_duplicate_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def read_object(root, name):
    data = contained_file(root, name).read_bytes()
    if len(data) > 2 * 1024 * 1024:
        raise ValueError("JSON input exceeds 2 MiB")
    obj = json.loads(data.decode("utf-8-sig"), object_pairs_hook=no_duplicate_keys)
    if not isinstance(obj, dict):
        raise ValueError("expected a JSON object")
    return obj


def btf_header(data):
    if len(data) < 24:
        raise ValueError("truncated BTF header")
    magic, version, flags, size, toff, tlen, soff, slen = struct.unpack_from("<HBBIIIII", data)
    if magic != 0xEB9F or version != 1 or flags or size < 24 or size > len(data):
        raise ValueError("unsupported or malformed BTF header")
    if not tlen or not slen or size + toff + tlen > len(data) or size + soff + slen > len(data):
        raise ValueError("BTF sections outside file")
    if max(toff, soff) < min(toff + tlen, soff + slen) or data[size + soff] != 0:
        raise ValueError("overlapping BTF sections or missing initial empty string")
    return {"version": version, "type_bytes": tlen, "string_bytes": slen}


def build_id(data):
    pos, found = 0, []
    while pos < len(data):
        if len(data) - pos < 12:
            raise ValueError("truncated ELF note header")
        namesz, descsz, kind = struct.unpack_from("<III", data, pos)
        pos += 12
        name_end = pos + namesz
        desc_start = pos + ((namesz + 3) & ~3)
        next_pos = desc_start + ((descsz + 3) & ~3)
        if next_pos > len(data):
            raise ValueError("ELF note outside file")
        if kind == 3 and data[pos:name_end] == b"GNU\0":
            found.append(data[desc_start:desc_start + descsz].hex())
        pos = next_pos
    if len(found) != 1 or not found[0]:
        raise ValueError("expected exactly one GNU Build ID")
    return found[0]


def audit(bundle, repo, module):
    report = {
        "schema_version": 1,
        "scope": "saved_evidence_only",
        "runtime_validation": "not_established",
        "authenticity": "not_independently_attested",
        "checks": [],
        "log_observations": [],
        "limitations": [
            "No device, module, log command, or captured executable was run.",
            "Matching hashes prove consistency with the supplied manifest only.",
            "Log PASS markers do not prove process completion, current device behavior, or test provenance.",
            "BTF header validity does not establish kernel ABI compatibility.",
        ],
    }

    def record(name, ok, detail):
        report["checks"].append({"name": name, "status": "pass" if ok else "fail", "detail": detail})

    def read_json(name):
        try:
            return read_object(bundle, name)
        except (OSError, ValueError) as error:
            record(name, False, str(error))
            return None

    manifest = read_json("manifest.json")
    captured = {}
    if manifest is not None:
        for name in CAPTURE_FILES:
            try:
                spec = manifest.get(name)
                if not isinstance(spec, dict) or type(spec.get("bytes")) is not int or spec["bytes"] < 0:
                    raise ValueError("missing or invalid file length")
                expected = spec.get("sha256")
                if not isinstance(expected, str) or not SHA256.fullmatch(expected):
                    raise ValueError("missing or invalid SHA-256")
                data = contained_file(bundle, name).read_bytes()
                if len(data) != spec["bytes"] or digest(data) != expected.lower():
                    raise ValueError("content does not match recorded length/SHA-256")
                captured[name] = data
                record(name, True, "length and SHA-256 match manifest")
            except (OSError, ValueError) as error:
                record(name, False, str(error))
        try:
            expected = manifest.get("kpm_sha256")
            if not isinstance(expected, str) or not SHA256.fullmatch(expected):
                raise ValueError("missing or invalid module SHA-256")
            if digest(module.read_bytes()) != expected.lower():
                raise ValueError("current module differs from captured module hash")
            record("module_sha256", True, "current artifact matches captured hash; not executed")
        except (OSError, ValueError) as error:
            record("module_sha256", False, str(error))

    if "vmlinux.btf" in captured:
        try:
            report["btf_header"] = btf_header(captured["vmlinux.btf"])
            record("btf_header", True, "header and section bounds only")
        except ValueError as error:
            record("btf_header", False, str(error))
    if "kernel.notes" in captured:
        try:
            actual_id = build_id(captured["kernel.notes"])
            if manifest.get("kernel_build_id") != actual_id:
                raise ValueError("kernel Build ID differs from manifest")
            report["kernel_build_id"] = actual_id
            record("kernel_build_id", True, "GNU note matches manifest")
        except ValueError as error:
            record("kernel_build_id", False, str(error))

    sources = read_json("source-sha256.json")
    if sources is not None:
        if not sources:
            record("source-sha256.json", False, "source manifest is empty")
        for name, expected in sources.items():
            try:
                if not isinstance(expected, str) or not SHA256.fullmatch(expected):
                    raise ValueError("invalid source SHA-256")
                data = contained_file(repo, name).read_bytes()
                if digest(data) != expected.lower():
                    raise ValueError("source changed since evidence capture")
                record("source:" + name, True, "current source hash matches")
            except (OSError, ValueError) as error:
                record("source:" + name, False, str(error))

    for name in LOG_FILES:
        try:
            data = contained_file(bundle, name).read_bytes()
            text = data.decode("utf-8-sig")
            failures = len(FAILURE.findall(text))
            observation = {
                "file": name,
                "sha256_at_review": digest(data),
                "reported_pass_lines": sum(bool(re.search(r"\bPASS\b|checks passed\b", line)) for line in text.splitlines()),
                "failure_markers": failures,
                "process_exit_status": "not_recorded",
                "provenance": "unverified_log_text",
            }
            report["log_observations"].append(observation)
            if failures:
                record("log:" + name, False, "failure markers present; raw log content not included")
        except (OSError, ValueError) as error:
            record("log:" + name, False, str(error))

    state = read_json("final-state.json")
    if state is not None:
        fields = ("loaded_kpm_this_audit", "installed_apk_this_audit", "boot_id_unchanged")
        if any(type(state.get(field)) is not bool for field in fields):
            record("final-state.json", False, "missing or invalid observation booleans")
        else:
            report["captured_state"] = {field: state[field] for field in fields}
            report["limitations"].append("Captured device state is a historical observation, not a fresh query.")

    report["evidence_consistency"] = "issues_found" if any(c["status"] == "fail" for c in report["checks"]) else "matches_recorded_hashes"
    return report


def markdown(report):
    lines = [
        "**保存证据核验报告**", "",
        "证据一致性：`" + report["evidence_consistency"] + "`。",
        "当前设备运行兼容性：**未建立（not_established）**。", "",
        "本工具只读取本地文件。散列一致仅表示与所提供清单相符，不代表独立真实性认证；"
        "历史日志中的 PASS 不会被提升为当前设备实测结论。", "",
        "| 检查 | 结果 | 说明 |", "|---|---|---|",
    ]
    def cell(value):
        return str(value).replace("&", "&amp;").replace("<", "&lt;").replace("|", "&#124;").replace("\n", " ").replace("\r", " ")
    for check in report["checks"]:
        lines.append("| " + " | ".join(cell(check[key]) for key in ("name", "status", "detail")) + " |")
    lines.extend(["", "日志只记录当前散列及观察到的标记数量；没有记录进程退出状态，不能认证完整运行。", "",
                  "| 日志 | PASS 行数 | 失败标记 |", "|---|---|---|"])
    for log in report["log_observations"]:
        lines.append("| {} | {} | {} |".format(cell(log["file"]), log["reported_pass_lines"], log["failure_markers"]))
    return "\n".join(lines) + "\n"


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("bundle", type=Path)
    parser.add_argument("--repo", type=Path, default=Path(__file__).resolve().parent.parent)
    parser.add_argument("--module", type=Path, help="artifact to hash; default: REPO/out/urov-z.kpm")
    parser.add_argument("--output", type=Path, help="new directory for JSON and Markdown; never overwrites")
    args = parser.parse_args(argv)
    report = audit(args.bundle, args.repo, args.module or args.repo / "out/urov-z.kpm")
    encoded = json.dumps(report, ensure_ascii=False, indent=2) + "\n"
    if args.output:
        try:
            args.output.mkdir(parents=True, exist_ok=False)
            (args.output / "report.json").write_bytes(encoded.encode("utf-8"))
            (args.output / "report.zh-CN.md").write_bytes(markdown(report).encode("utf-8"))
        except OSError as error:
            parser.error("cannot create report output: " + str(error))
        print(report["evidence_consistency"] + "; runtime_validation=not_established")
    else:
        print(encoded, end="")
    return int(report["evidence_consistency"] == "issues_found")


if __name__ == "__main__":
    sys.exit(main())
