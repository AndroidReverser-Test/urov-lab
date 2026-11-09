#!/usr/bin/env python3
"""Test in-process SO patching and CRC32 views on a connected Android device."""

import argparse
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import re
import secrets
import shlex
import subprocess
import time


LAB = Path(__file__).resolve().parents[1]
PACKAGE = "com.example.urovdetect"
ACTIVITY = f"{PACKAGE}/.MainActivity"
MODULE = "urov-y"
KV = re.compile(r"(\w+)=([^\s]+)")
STAMP = re.compile(r"^\[\s*([0-9.]+)\]", re.M)


class IncompleteLog(RuntimeError):
    """The app passed but logcat lost one or more required records."""


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--serial", required=True)
    parser.add_argument("--key", required=True, help="KernelPatch superkey")
    parser.add_argument("--skip-install", action="store_true", help="use the already installed test APK")
    matrix = parser.add_mutually_exclusive_group()
    matrix.add_argument("--dobby-detection", action="store_true",
                        help="run the keyless probe against a Dobby patch masked by PAGE_AP")
    matrix.add_argument("--read-defense", action="store_true",
                        help="compare live and overlaid bytes, then test recovery and registration refusal")
    matrix.add_argument("--read-defense-v216", action="store_true",
                        help="test keyless iovec readback and LL/SC against urov-y 2.16.0")
    matrix.add_argument("--read-defense-v218", action="store_true",
                        help="test independent reads, LL/SC and protected mappings against urov-y 2.18.0")
    matrix.add_argument("--read-defense-v219", action="store_true",
                        help="test keyless detection and reference protection against urov-y 2.19.0")
    matrix.add_argument("--read-defense-v220", action="store_true",
                        help="test modeled and unmodeled LL/SC windows and keyless defense against 2.20.0")
    matrix.add_argument("--read-defense-v221", action="store_true",
                        help="test pre-load ALU and FPSIMD window modeling against 2.21.0")
    matrix.add_argument("--read-defense-v221-guarded", action="store_true",
                        help="verify the keyless guard against all six urov-y 2.21.0 modes")
    matrix.add_argument("--read-defense-v222", action="store_true",
                        help="verify the keyless guard against all six urov-y 2.22.0 modes")
    matrix.add_argument("--read-defense-v223", action="store_true",
                        help="test the keyless LDXR precheck probe and guard against urov-y 2.23.0")
    matrix.add_argument("--read-defense-v224", action="store_true",
                        help="compare the older LL/SC probes with the pair-load probe for urov-y 2.24.0")
    matrix.add_argument("--read-defense-v225", action="store_true",
                        help="verify every sampled-access shape and pre-load class against urov-y 2.25.0")
    parser.add_argument("--repeats", type=int, default=15)
    parser.add_argument("--cycles", type=int, default=3)
    args = parser.parse_args()
    if not 3 <= args.repeats <= 200 or not 1 <= args.cycles <= 10:
        parser.error("repeats 3..200, cycles 1..10")

    if args.read_defense_v221 or args.read_defense_v221_guarded:
        prefix = "read-defense-v221"
        if args.read_defense_v221_guarded:
            prefix += "-guarded"
        modes = tuple(f"{prefix}-{shape}" for shape in ("brk", "brk-all", "uxn", "uxn-all", "ap", "ap-all"))
    elif args.read_defense_v222:
        prefix = "read-defense-v222"
        modes = tuple(f"{prefix}-{shape}" for shape in ("brk", "brk-all", "uxn", "uxn-all", "ap", "ap-all"))
    elif args.read_defense_v223:
        prefix = "read-defense-v223"
        modes = tuple(f"{prefix}-{shape}" for shape in ("brk", "brk-all", "uxn", "uxn-all", "ap", "ap-all"))
    elif args.read_defense_v224:
        prefix = "read-defense-v224"
        modes = tuple(f"{prefix}-{shape}" for shape in ("brk", "brk-all", "uxn", "uxn-all", "ap", "ap-all"))
    elif args.read_defense_v225:
        prefix = "read-defense-v225"
        modes = tuple(f"{prefix}-{shape}" for shape in ("brk", "brk-all", "uxn", "uxn-all", "ap", "ap-all"))
    elif args.read_defense_v220:
        prefix = "read-defense-v220"
        modes = tuple(f"{prefix}-{shape}" for shape in ("brk", "brk-all", "uxn", "uxn-all", "ap", "ap-all"))
    elif args.read_defense_v219:
        prefix = "read-defense-v219"
        modes = tuple(f"{prefix}-{shape}" for shape in ("brk", "brk-all", "uxn", "uxn-all", "ap", "ap-all"))
    elif args.read_defense_v218:
        prefix = "read-defense-v218"
        modes = tuple(f"{prefix}-{shape}" for shape in ("brk", "brk-all", "uxn", "uxn-all", "ap", "ap-all"))
    elif args.read_defense_v216:
        prefix = "read-defense-v216"
        modes = tuple(f"{prefix}-{shape}" for shape in ("brk", "uxn", "ap", "ap-all"))
    elif args.read_defense:
        prefix = "read-defense"
        modes = ("read-defense-brk", "read-defense-uxn", "read-defense-ap-hard",
                 "read-defense-ap-all-hard")
    elif args.dobby_detection:
        prefix = "dobby-detect"
        modes = ("dobby-detect-active",)
    else:
        prefix = "crc"
        modes = ("crc-brk", "crc-uxn", "crc-ap", "crc-ap-all", "crc-ap-text", "crc-ap-libc", "crc-ap-big")
    stamp = datetime.now(timezone(timedelta(hours=8))).strftime("%Y%m%d-%H%M%S")
    output = LAB / "results" / f"{prefix}-{stamp}"
    output.mkdir(parents=True)
    module_key = secrets.token_hex(16)
    remote = f"/data/local/tmp/urov-crc-{stamp}.kpm"
    report = {"serial": args.serial, "repeats": args.repeats, "cycles": args.cycles,
              "runs": [], "passed": False}
    clean_start = loaded = staged = False
    before = None

    def redact(value):
        return value.replace(args.key, "<SUPERKEY>").replace(module_key, "<MODULE-KEY>")

    def adb(*argv, timeout=45):
        result = subprocess.run(["adb", "-s", args.serial, *argv], timeout=timeout,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                encoding="utf-8", errors="replace")
        value = redact(result.stdout).strip()
        if result.returncode:
            raise RuntimeError(f"adb exit {result.returncode} {value}")
        return value

    def shell(*argv):
        return adb("shell", shlex.join(argv))

    def kp(*argv):
        return shell("/data/local/tmp/kpatch", args.key, *argv)

    def run_once(label, mode):
        dobby = mode.startswith("dobby-detect-")
        defense = mode.startswith("read-defense-")
        v218 = mode.startswith("read-defense-v218-")
        v219 = mode.startswith("read-defense-v219-")
        v220 = mode.startswith("read-defense-v220-")
        v221 = mode.startswith("read-defense-v221-")
        v222 = mode.startswith("read-defense-v222-")
        v223 = mode.startswith("read-defense-v223-")
        v224 = mode.startswith("read-defense-v224-")
        v225 = mode.startswith("read-defense-v225-")
        window_mode = v220 or v221 or v222 or v223 or v224 or v225
        modern_defense = v218 or v219 or window_mode or mode.startswith("read-defense-v216-")
        defense_tag = "V225" if v225 else "V224" if v224 else "V223" if v223 else "V222" if v222 else "V221" if v221 else "V220" if v220 else "V219" if v219 else "V218" if v218 else "V216"
        active = mode != f"{prefix}-clean"
        shell("am", "force-stop", PACKAGE)
        argv = ["am", "start", "-W", "-n", ACTIVITY, "--es", "mode", mode,
                "--ei", "repeats", str(args.repeats)]
        if active:
            argv += ["--es", "key", module_key]
        shell(*argv)
        pid = shell("pidof", PACKAGE).split()[0]
        log_path = output / f"{label}-{pid}.log"
        deadline = time.monotonic() + 45
        while time.monotonic() < deadline:
            logs = shell("logcat", "-d", f"--pid={pid}", "-v", "threadtime", "-s",
                         "urovdetect:I", "AndroidRuntime:E", "libc:F", "DEBUG:F")
            log_path.write_text(logs + "\n", encoding="utf-8")
            result = re.search(rf"DETECT_RESULT (PASS|FAIL) mode={mode}\b[^\n]*", logs)
            if result or "Fatal signal" in logs or "FATAL EXCEPTION" in logs:
                break
            time.sleep(0.2)
        else:
            raise RuntimeError(f"{label}: timed out")
        if not result or result[1] != "PASS":
            raise RuntimeError(f"{label}: app failed, see {log_path.name}")
        uid = re.search(r"CONTEXT pid=\d+ uid=(\d+) selinux=u:r:untrusted_app:", logs)
        if not uid or int(uid[1]) < 10000 or not re.search(r"CapEff:\s*0{16}\b", logs) or not re.search(
                r"Seccomp:\s*2\b", logs):
            raise RuntimeError(f"{label}: invalid app credentials")
        if modern_defense:
            stages = [dict(KV.findall(line)) for line in re.findall(rf"READ_DEFENSE_{defense_tag} [^\n]+", logs)]
            stage_key = "stage"
        elif defense:
            stages = [dict(KV.findall(line)) for line in re.findall(r"READ_DEFENSE [^\n]+", logs)]
            stage_key = "stage"
        elif dobby:
            stages = [dict(KV.findall(line)) for line in re.findall(r"DOBBY_DETECT [^\n]+", logs)]
            stage_key = "stage"
        elif mode == "crc-ap-text":
            stages = [dict(KV.findall(line)) for line in
                      re.findall(r"CRC_PAGE name=linker_text [^\n]+", logs)]
            stage_key = "stage"
        else:
            stages = [dict(KV.findall(line)) for line in re.findall(r"CRC_STAGE [^\n]+", logs)]
            stage_key = "name"
        if modern_defense:
            expected = ["clean", "identity", "patch_only", "overlay", "deactivated"] if active else \
                       ["clean", "patch_only"]
        elif defense:
            expected = ["clean", "patch_only", "overlay", "restored"] if active else ["clean", "patch_only"]
        elif dobby:
            expected = ["clean", "patch_only", "overlay", "deactivated"] if active else ["clean", "patch_only"]
        elif mode in ("crc-ap-text", "crc-ap-libc", "crc-ap-big"):
            expected = ["clean", "overlay", "deactivated"]
        else:
            expected = ["clean", "patch_only", "overlay", "deactivated"] if active else \
                       ["clean", "patch_only"]
        names = [stage[stage_key] for stage in stages]
        if names != [name for name in expected if name in names]:
            raise RuntimeError(f"{label}: unexpected CRC stage order {names}")
        if active and "state=inactive" not in kp("kpm", "ctl0", MODULE, "status"):
            raise RuntimeError(f"{label}: fixture left an active session")
        marker = "DOBBY_HOOK address=" if dobby or defense else "CRC_FIXTURE dlopen=1"
        if names != expected or marker not in logs:
            raise IncompleteLog(f"{label}: missing CRC records in {log_path.name}")
        if modern_defense:
            if not re.search(r"READ_DEFENSE_BUSINESS ops=[1-9]\d* errors=0\b", logs):
                raise IncompleteLog(f"{label}: missing business worker result in {log_path.name}")
            callers = 0 if mode.endswith("-all") else 1
            if active and (f"READ_DEFENSE_{defense_tag}_STATUS parent_active=1 callers={callers}" not in logs or
                           "READ_DEFENSE_GUARD shape=1 errno=22 execute=1234 inactive=1" not in logs):
                raise IncompleteLog(f"{label}: missing parent-session or registration guard result")
            if (v218 or v219 or window_mode) and active and (f"READ_DEFENSE_{defense_tag}_GUARD shape=1 errno=22 "
                                                             "inactive=1 reference=1 execute=1234" not in logs):
                raise IncompleteLog(f"{label}: missing execute-only registration guard result")
            if v219 or window_mode:
                keyless = [dict(KV.findall(line)) for line in
                           re.findall(r"READ_DEFENSE_KEYLESS [^\n]+", logs)]
                if [s["stage"] for s in keyless] != expected:
                    raise IncompleteLog(f"{label}: missing keyless probe records")
                if active and "READ_DEFENSE_KEYLESS_GUARD shape=1 errno=22 inactive=1 intact=1" not in logs:
                    raise IncompleteLog(f"{label}: missing read-only reference guard result")
            if window_mode:
                window = [dict(KV.findall(line)) for line in
                          re.findall(r"READ_DEFENSE_KEYLESS2 [^\n]+", logs)]
                if [s["stage"] for s in window] != expected:
                    raise IncompleteLog(f"{label}: missing window probe records in {log_path.name}")
                if any(s["load"] != "0" or s["store"] != "0" or s["branch"] != "0" or
                       s["xload"] != "0" or s["unknown"] != "0" or
                       s["value"] != s["value_ok"] or s["clrex_bad"] != "0" or
                       s["clrex_done"] != s["n"] or s["svc_bad"] != "0" or
                       s["svc_done"] != s["n"] for s in window):
                    raise RuntimeError(f"{label}: window probes reported a residual feature")
                policy = [dict(KV.findall(line)) for line in
                          re.findall(rf"READ_DEFENSE_{defense_tag}_POLICY [^\n]+", logs)]
                if [s["stage"] for s in policy] != expected:
                    raise IncompleteLog(f"{label}: missing policy records in {log_path.name}")
                if args.read_defense_v221_guarded or v222 or v223 or v224 or v225:
                    ap_mode = mode.endswith(("-ap", "-ap-all"))
                    ap_all = mode.endswith("-ap-all")
                    for s in policy:
                        n = s["n"]
                        covered = s["stage"] in ("identity", "overlay")
                        if v223 or v224 or v225:
                            ap = "0"
                            evidence = n if covered and (
                                not ap_mode or (s["stage"] == "overlay" and not ap_all)) else "0"
                            split = n if (s["stage"] == "overlay" and not (ap_mode and ap_all)) else "0"
                            accepted = n if (covered and split == "0" and evidence == "0") or \
                                s["stage"] == "clean" else "0"
                            changed = n if s["stage"] in ("patch_only", "deactivated") else "0"
                            if (s["baseline_ok"] != n or s["pre_alu"] != "0" or s["fp"] != "0" or
                                    s["pre_gpr"] != "0" or s["simd"] != "0" or s["ap"] != ap or
                                    s["simd_value"] != n or
                                    s["ap_unknown"] != "0" or s["unknown"] != "0" or
                                    s["evidence"] != evidence or s["accepted"] != accepted or
                                    s["split"] != split or s["changed"] != changed):
                                raise RuntimeError(f"{label}: {defense_tag.lower()} policy mismatch at {s['stage']}")
                        elif v222:
                            ap = n if covered and ap_mode else "0"
                            evidence = n if covered else "0"
                            accepted = n if s["stage"] == "clean" else "0"
                            split = n if (s["stage"] == "overlay" and not (ap_mode and ap_all)) else "0"
                            changed = n if s["stage"] in ("patch_only", "deactivated") else "0"
                            if (s["baseline_ok"] != n or s["pre_alu"] != "0" or s["fp"] != "0" or
                                    s["pre_gpr"] != "0" or s["simd"] != "0" or s["ap"] != ap or
                                    s["simd_value"] != n or
                                    s["ap_unknown"] != "0" or s["unknown"] != "0" or
                                    s["evidence"] != evidence or s["accepted"] != accepted or
                                    s["split"] != split or s["changed"] != changed):
                                raise RuntimeError(f"{label}: v222 policy mismatch at {s['stage']}")
                        else:
                            ap = n if covered and ap_mode else "0"
                            if (s["baseline_ok"] != n or s["pre_gpr"] != ap or s["simd"] != ap or
                                    s["ap"] != ap or s["ap_unknown"] != "0" or s["unknown"] != "0" or
                                    s["evidence"] != (n if covered else "0") or
                                    s["accepted"] != (n if s["stage"] == "clean" else "0")):
                                raise RuntimeError(f"{label}: guarded policy mismatch at {s['stage']}")
                    if v222 and ap_all and not re.search(
                            r"READ_DEFENSE_V222_LDTR byte=([0-9a-f]{2}) want=\1", logs):
                        raise IncompleteLog(f"{label}: missing v222 unprivileged-load result")
                if v222 or v223 or v224 or v225:
                    tag = "V225" if v225 else "V224" if v224 else "V223" if v223 else "V222"
                    residual = [dict(KV.findall(line)) for line in
                                re.findall(rf"READ_DEFENSE_{tag}_RESIDUAL [^\n]+", logs)]
                    if [s["stage"] for s in residual] != expected:
                        raise IncompleteLog(f"{label}: missing {tag.lower()} residual probe records")
                    for decision, probes in zip(policy, residual):
                        ap = "0" if (v223 or v224 or v225) else decision["ap"]
                        ok = (probes["n"] == decision["n"] and probes["leaf_call"] == ap and
                              probes["permute"] == ap and
                              int(probes["trials"]) == int(probes["n"]) * 2 * 3 * 32 and
                              int(probes["target_failed"]) == int(ap) * 2 * 3 * 32)
                        if v223 or v224 or v225:
                            ok = ok and probes.get("fp_arith") == "0"
                        if v224 or v225:
                            ok = ok and probes.get("pre_mov") == "0" and \
                                probes.get("pre_long") == "0"
                            covered = probes["stage"] in ("identity", "overlay")
                            if ap_mode and covered:
                                ok = ok and probes.get("self_bad") == "0" and \
                                    probes.get("neon_bad") == "0" and \
                                    probes.get("deep_bad") == "0" and \
                                    probes.get("deep_done") == probes["n"]
                            else:
                                ok = ok and probes.get("deep_done") == "0"
                        if not ok:
                            raise RuntimeError(f"{label}: {tag.lower()} residual probes disagree at {probes['stage']}")
                if v223 or v224 or v225:
                    boundary_tag = "V225" if v225 else "V224" if v224 else "V223"
                    boundary = [dict(KV.findall(line)) for line in
                                re.findall(rf"READ_DEFENSE_{boundary_tag}_BOUNDARY [^\n]+", logs)]
                    if [s["stage"] for s in boundary] != expected:
                        raise IncompleteLog(f"{label}: missing LDXR precheck probe records")
                    for s in boundary:
                        covered = s["stage"] in ("identity", "overlay")
                        if v224 or v225:
                            ap = 0
                            evidence = args.repeats if covered and (
                                not ap_mode or (s["stage"] == "overlay" and not ap_all)) else 0
                            split = args.repeats if (
                                s["stage"] == "overlay" and not (ap_mode and ap_all)) else 0
                            accepted = args.repeats if (
                                covered and split == 0 and evidence == 0) or \
                                s["stage"] == "clean" else 0
                        else:
                            ap = args.repeats if covered and ap_mode else 0
                            evidence = args.repeats if covered else 0
                            accepted = args.repeats if s["stage"] == "clean" else 0
                        if (int(s["n"]) != args.repeats or int(s["ap"]) != ap or
                                s["ap_unknown"] != "0" or s["unknown"] != "0" or
                                int(s["triplets"]) != args.repeats * 3 * 32 or
                                int(s["target_failed"]) != ap * 3 * 32 or
                                int(s["evidence"]) != evidence or
                                int(s["changed"]) != (args.repeats if s["stage"] in
                                                      ("patch_only", "deactivated") else 0) or
                                int(s["accepted"]) != accepted):
                            raise RuntimeError(f"{label}: {boundary_tag.lower()} LDXR precheck mismatch at {s['stage']}")
                if v224:
                    pair_load = [dict(KV.findall(line)) for line in
                                 re.findall(r"READ_DEFENSE_V224_LDP [^\n]+", logs)]
                    if [s["stage"] for s in pair_load] != expected:
                        raise IncompleteLog(f"{label}: missing pair-load probe records")
                    for s in pair_load:
                        stage = s["stage"]
                        n = args.repeats
                        covered = stage in ("identity", "overlay")
                        ap = n if covered and ap_mode else 0
                        if (int(s["n"]) != n or int(s["ap"]) != ap or
                                s["ap_unknown"] != "0" or s["unknown"] != "0" or
                                int(s["triplets"]) != n * 3 * 32 or
                                int(s["target_failed"]) != ap * 3 * 32 or
                                int(s["evidence"]) != (n if covered else 0) or
                                int(s["changed"]) != (n if stage in ("patch_only", "deactivated") else 0) or
                                int(s["accepted"]) != (n if stage == "clean" else 0)):
                            raise RuntimeError(f"{label}: v224 pair-load policy mismatch at {stage}")
                if v225:
                    probes = [dict(KV.findall(line)) for line in
                              re.findall(r"READ_DEFENSE_V225_PROBE [^\n]+", logs)]
                    if [s["stage"] for s in probes] != expected:
                        raise IncompleteLog(f"{label}: missing 2.25.0 access-shape probe records")
                    for s in probes:
                        stage, n = s["stage"], args.repeats
                        if (int(s["n"]) != n or
                                any(int(s[key]) != 0 for key in (
                                    "pair", "vec", "multi", "pre_fp", "pre_load", "pre_store",
                                    "pre_lse", "pre_ext", "pair_gap", "unknown", "xldr_bad")) or
                                int(s["trials"]) != n * 9 * 3 * 32 or
                                int(s["xldr_done"]) != n):
                            raise RuntimeError(f"{label}: v225 access-shape probe mismatch at {stage}")
                if active and (f"READ_DEFENSE_{defense_tag}_FALLBACK shape=1 reference=1 "
                               "execute=1234" not in logs):
                    raise IncompleteLog(f"{label}: missing independent read and execution result")
        elif defense:
            remaps = [dict(KV.findall(line)) for line in re.findall(r"READ_DEFENSE_REMAP [^\n]+", logs)]
            if [step["stage"] for step in remaps] != (["unarmed", "outside", "overlap"] if active else ["unarmed"]):
                raise IncompleteLog(f"{label}: missing no-op remap controls in {log_path.name}")
            pairs = [dict(KV.findall(line)) for line in re.findall(r"READ_DEFENSE_PAIR [^\n]+", logs)]
            if [pair["stage"] for pair in pairs] != expected:
                raise IncompleteLog(f"{label}: missing paired exclusive records in {log_path.name}")
            if not re.search(r"READ_DEFENSE_BUSINESS ops=[1-9]\d* errors=0\b", logs):
                raise IncompleteLog(f"{label}: missing business worker result in {log_path.name}")
            if active and ("-hard" in mode and
                           ("READ_DEFENSE_STATUS active_before=1 active_after_remap=1" not in logs or
                            "READ_DEFENSE_GUARD shape=1 errno=22 execute=1234 inactive=1" not in logs) or
                           "-hard" not in mode and
                           ("READ_DEFENSE_STATUS active_before=1 inactive_after=1" not in logs or
                            "READ_DEFENSE_GUARD shape=1 errno=22 execute=1234 inactive=1" not in logs)):
                raise IncompleteLog(f"{label}: missing recovery/guard result in {log_path.name}")
        if dobby:
            live_views = [dict(KV.findall(line)) for line in
                          re.findall(r"DOBBY_DETECT_LIVE [^\n]+", logs)]
            if [view["stage"] for view in live_views] != expected:
                raise IncompleteLog(f"{label}: missing live view records in {log_path.name}")
            many_views = [dict(KV.findall(line)) for line in
                          re.findall(r"DOBBY_DETECT_MANY [^\n]+", logs)]
            if [view["stage"] for view in many_views] != expected:
                raise IncompleteLog(f"{label}: missing 1024-iovec records in {log_path.name}")
            sibling_views = [dict(KV.findall(line)) for line in
                             re.findall(r"DOBBY_DETECT_SIBLING [^\n]+", logs)]
            if [view["stage"] for view in sibling_views] != expected:
                raise IncompleteLog(f"{label}: missing sibling-tid records in {log_path.name}")
            split_views = [dict(KV.findall(line)) for line in
                           re.findall(r"DOBBY_DETECT_SPLIT [^\n]+", logs)]
            if [view["stage"] for view in split_views] != expected:
                raise IncompleteLog(f"{label}: missing split-iovec records in {log_path.name}")
            ap_views = [dict(KV.findall(line)) for line in re.findall(r"DOBBY_DETECT_AP [^\n]+", logs)]
            if [view["stage"] for view in ap_views] != expected:
                raise IncompleteLog(f"{label}: missing AP reservation records in {log_path.name}")
            recovery = [dict(KV.findall(line)) for line in
                        re.findall(r"DOBBY_DETECT_KEYLESS_RESTORE [^\n]+", logs)]
            expected_recovery = ["unarmed", "outside", "overlap"] if active else ["unarmed"]
            if [step["stage"] for step in recovery] != expected_recovery:
                raise IncompleteLog(f"{label}: missing keyless recovery controls in {log_path.name}")
            if any(step["errno"] != "22" or step["bytes_expected"] != "1" or
                   step["vma_preserved"] != "1" or step["execute"] != "1235" for step in recovery):
                raise RuntimeError(f"{label}: keyless recovery did not preserve the fixture")
        if dobby and active and ("DOBBY_DETECT_RESTORE " not in logs or
                                 "DOBBY_DETECT_LOCK " not in logs or
                                 "DOBBY_DETECT_GUARD " not in logs):
            raise IncompleteLog(f"{label}: missing recovery or guard records in {log_path.name}")
        if mode == "crc-ap-text" and not re.search(
                r"CRC_VMA name=linker_text .*shared=0 maywrite=1 dc=0 private_dirty_kb=0 "
                r"anonymous_kb=0", logs):
            raise RuntimeError(f"{label}: linker text VMA was not the normal private mapping")
        if mode == "crc-ap-libc" and not re.search(
                r"CRC_LIBC_VMA .*private_dirty_kb=0 anonymous_kb=0", logs):
            raise RuntimeError(f"{label}: libc text VMA was not the normal private mapping")
        if mode == "crc-ap-big" and not re.search(
                r"CRC_BIG_VMA .*private_dirty_kb=0 anonymous_kb=0", logs):
            raise RuntimeError(f"{label}: big-transfer VMA was not the normal private mapping")
        if mode == "crc-ap-big" and not re.search(
                r"CRC_BIG n=\d+ lengths=16,32,64,160,512,1024,4096 ", logs):
            raise RuntimeError(f"{label}: big-transfer reader matrix missing")
        report["runs"].append({"label": label, "mode": mode, "uid": int(uid[1]), "pid": pid,
                               "log": log_path.name, "result": result[0], "stages": stages,
                               "details": re.findall(r"(?:CRC_(?:REJECT|PRIVATE|REMAP|MAP|OVERLAY|SITE|"
                                                     r"CHANGED_BYTE|TEXT|VMA|PAGE|LIBC|BIG|BIG_OVERLAY|BIG_VMA|MIXED|"
                                                     r"SET|RESTORE|REREGISTER|LOCK_GUARD)"
                                                     r"|ELIM_EXEC|DOBBY_DETECT_(?:STATUS|RESTORE|LOCK|GUARD|BUSINESS|ACCESS|KMEM|FORK_KMEM|MANY|SIBLING|SPLIT)) [^\n]+", logs)})
        if modern_defense:
            report["runs"][-1]["details"] = re.findall(
                rf"READ_DEFENSE_(?:{defense_tag}_(?:STATUS|GUARD|FALLBACK)|KEYLESS_GUARD|GUARD|BUSINESS) [^\n]+", logs)
            report["runs"][-1]["ui"] = dict(KV.findall(result[0]))
            if v219 or window_mode:
                report["runs"][-1]["keyless"] = keyless
            if window_mode:
                report["runs"][-1]["window"] = window
                report["runs"][-1]["policy"] = policy
            if v222 or v223 or v224:
                report["runs"][-1]["residual"] = residual
            if v223 or v224:
                report["runs"][-1]["boundary"] = boundary
            if v224:
                report["runs"][-1]["pair_load"] = pair_load
            if v218 or v219 or window_mode:
                matches = ", ".join(f"{s['stage']}=split:{s['split']}/trap:{s['trap']}/accept:{s['accept']}"
                                    f" of {s['n']}" for s in stages)
            else:
                matches = ", ".join(f"{s['stage']}={s['split']}/{s['n']}" for s in stages)
            if v219:
                selected = keyless[3 if active else 0]
                matches += (f"; {selected['stage']} keyless csel={selected['csel']}/{selected['n']} "
                            f"site={selected['site_code']}/{selected['site_fetch']} "
                            f"guarded={selected['guarded']}/{selected['n']}")
            if window_mode:
                selected = window[3 if active else 0]
                decision = policy[3 if active else 0]
                matches += (f"; {selected['stage']} window load={selected['load']} "
                            f"store={selected['store']} branch={selected['branch']} "
                            f"xload={selected['xload']} value={selected['value_ok']}/"
                            f"{selected['value']} clrex_bad={selected['clrex_bad']} "
                            f"svc_bad={selected['svc_bad']} "
                            f"ap={decision['ap']}/{decision['n']} "
                            f"evidence={decision['evidence']}/{decision['n']} "
                            f"guarded={decision['accepted']}/{decision['n']}")
            if v223 or v224:
                decision = boundary[3 if active else 0]
                matches += (f"; LDXR precheck ap={decision['ap']}/{decision['n']} "
                            f"evidence={decision['evidence']}/{decision['n']} "
                            f"accepted={decision['accepted']}/{decision['n']}")
                if v224:
                    residual_line = residual[3 if active else 0]
                    pair_decision = pair_load[3 if active else 0]
                    matches += (f"; pre_mov={residual_line.get('pre_mov')} "
                                f"pre_long={residual_line.get('pre_long')} "
                                f"self_bad={residual_line.get('self_bad')} "
                                f"neon_bad={residual_line.get('neon_bad')} "
                                f"deep_bad={residual_line.get('deep_bad')}; "
                                f"LDP ap={pair_decision['ap']}/{pair_decision['n']} "
                                f"evidence={pair_decision['evidence']}/{pair_decision['n']} "
                                f"accepted={pair_decision['accepted']}/{pair_decision['n']}")
            print(f"{label}: {matches}", flush=True)
            return
        if defense:
            report["runs"][-1]["details"] = re.findall(r"READ_DEFENSE_(?:REMAP|STATUS|GUARD|BUSINESS) [^\n]+", logs)
            report["runs"][-1]["pairs"] = pairs
            report["runs"][-1]["ui"] = dict(KV.findall(result[0]))
            matches = ", ".join(f"{s[stage_key]}={s['match']}/{s['n']}" for s in stages)
            print(f"{label}: {matches}", flush=True)
            return
        if dobby:
            report["runs"][-1]["live_views"] = live_views
            report["runs"][-1]["many_views"] = many_views
            report["runs"][-1]["sibling_views"] = sibling_views
            report["runs"][-1]["split_views"] = split_views
            report["runs"][-1]["ap_views"] = ap_views
            report["runs"][-1]["keyless_recovery"] = recovery
            last = stages[2] if active else stages[-1]
            live = live_views[2] if active else live_views[-1]
            many = many_views[2] if active else many_views[-1]
            sibling = sibling_views[2] if active else sibling_views[-1]
            split = split_views[2] if active else split_views[-1]
            ap = ap_views[2] if active else ap_views[-1]
            print(f"{label} PASS execute={last['execute']} file={last['file']} live={last['live']} "
                  f"iov1={live['single_crc']} iov65={live['kernel_crc']} "
                  f"iov1024_match={many['match']} sibling_match={sibling['match']} "
                  f"split_match={split['match']} views={live['match']}/{live['n']} "
                  f"xzr={live['zero_match']}/{live['n']} cross_page={last['match']}/{last['n']} "
                  f"ap={ap['match']}/{ap['n']} ap_unknown={ap['unknown']} "
                  f"accepted_crc_old={last['accepted_crc']} accepted_crc_with_ap={ap['accepted_crc']}",
                  flush=True)
            return
        if mode in ("crc-ap-text", "crc-ap-libc", "crc-ap-big"):
            last = stages[1]
        elif active:
            last = stages[2]
        else:
            last = stages[-1]
        print(f"{label} PASS execute={last['execute']} file={last['file']} "
              f"direct={last['direct']} window={last['window']} bridge={last['bridge_match']}/"
              f"{last['n']}", flush=True)

    def run_app(label, mode):
        for attempt in range(3):
            try:
                return run_once(label, mode)
            except IncompleteLog as exc:
                report.setdefault("incomplete_logs", []).append(str(exc))
                if attempt == 2:
                    raise
                print(f"RETRY {exc}", flush=True)

    try:
        report["initial_modules"] = kp("kpm", "list")
        if report["initial_modules"]:
            raise RuntimeError("existing modules preserved")
        clean_start = True
        report["boot_id_before"] = shell("cat", "/proc/sys/kernel/random/boot_id")
        report["kernel"] = shell("uname", "-a")
        report["kpver"] = kp("kpver")
        report["selinux"] = shell("getenforce")
        before = kp("su", "-c", "dmesg")
        apk = LAB / "apps/urov-detect/out/urovdetect.apk"
        kpm = LAB / "out/urov-y.kpm"
        report["artifacts"] = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in (apk, kpm)}
        if not args.skip_install:
            adb("install", "--no-incremental", "-r", str(apk), timeout=120)
        clean_mode = f"{prefix}-clean"
        run_app("no-module", clean_mode)

        staged = True
        adb("push", str(kpm), remote)
        kp("kpm", "load", remote, f"key={module_key}")
        loaded = True
        report["loaded_status"] = kp("kpm", "ctl0", MODULE, "status")
        if "hooks=0xff" not in report["loaded_status"]:
            raise RuntimeError("UROV-Y hooks incomplete")
        run_app("loaded-idle", clean_mode)
        for i in range(1, args.cycles + 1):
            for mode in modes:
                run_app(f"{mode}-{i}", mode)
        if prefix != "crc":
            kp("kpm", "unload", MODULE)
            loaded = False
            run_app("post-unload", clean_mode)
        report["passed"] = True
    except Exception as exc:
        report["error"] = redact(str(exc))
        print(f"ERROR {report['error']}", flush=True)
    finally:
        if clean_start:
            try:
                shell("am", "force-stop", PACKAGE)
                if loaded:
                    kp("kpm", "unload", MODULE)
                if staged:
                    shell("rm", "-f", remote)
                report["final_modules"] = kp("kpm", "list")
                report["boot_id_after"] = shell("cat", "/proc/sys/kernel/random/boot_id")
                if report["boot_id_after"] != report.get("boot_id_before"):
                    raise RuntimeError("device rebooted during the test")
                if before is not None:
                    timestamps = STAMP.findall(before)
                    since = float(timestamps[-1]) if timestamps else 0
                    delta = []
                    for line in kp("su", "-c", "dmesg").splitlines():
                        match = STAMP.match(line)
                        if match and float(match[1]) > since:
                            delta.append(line)
                    (output / "kernel-new.log").write_text("\n".join(delta) + "\n", encoding="utf-8")
                    report["kernel_issues"] = [line for line in delta if re.search(
                        r"\bBUG:|\bWARNING:|\bOops:|\bKernel panic|rcu.*stall|hung task|\bCall trace", line)]
                if report["final_modules"] or report.get("kernel_issues"):
                    report["passed"] = False
            except Exception as exc:
                report["cleanup_error"] = redact(str(exc))
                report["passed"] = False
        (output / "summary.json").write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n",
                                             encoding="utf-8")
    print(f"RESULT {'PASS' if report['passed'] else 'FAIL'} {output}", flush=True)
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
