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
    parser.add_argument("--dobby-detection", action="store_true",
                        help="run the keyless probe against a Dobby patch masked by PAGE_AP")
    parser.add_argument("--repeats", type=int, default=15)
    parser.add_argument("--cycles", type=int, default=3)
    args = parser.parse_args()
    if not 3 <= args.repeats <= 200 or not 1 <= args.cycles <= 10:
        parser.error("repeats 3..200, cycles 1..10")

    stamp = datetime.now(timezone(timedelta(hours=8))).strftime("%Y%m%d-%H%M%S")
    prefix = "dobby-detect" if args.dobby_detection else "crc"
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
        active = mode not in ("crc-clean", "dobby-detect-clean")
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
        if dobby:
            stages = [dict(KV.findall(line)) for line in re.findall(r"DOBBY_DETECT [^\n]+", logs)]
            stage_key = "stage"
        elif mode == "crc-ap-text":
            stages = [dict(KV.findall(line)) for line in
                      re.findall(r"CRC_PAGE name=linker_text [^\n]+", logs)]
            stage_key = "stage"
        else:
            stages = [dict(KV.findall(line)) for line in re.findall(r"CRC_STAGE [^\n]+", logs)]
            stage_key = "name"
        if dobby:
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
        marker = "DOBBY_HOOK address=" if dobby else "CRC_FIXTURE dlopen=1"
        if names != expected or marker not in logs:
            raise IncompleteLog(f"{label}: missing CRC records in {log_path.name}")
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
                                                     r"CHANGED_BYTE|TEXT|VMA|PAGE|LIBC|BIG|BIG_OVERLAY|BIG_VMA|MIXED|SET)|ELIM_EXEC|DOBBY_DETECT_STATUS) [^\n]+", logs)})
        if dobby:
            last = stages[2] if active else stages[-1]
            print(f"{label} PASS execute={last['execute']} file={last['file']} live={last['live']} "
                  f"match={last['match']}/{last['n']} unknown={last['unknown']} "
                  f"accepted_crc={last['accepted_crc']}", flush=True)
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
        clean_mode = "dobby-detect-clean" if args.dobby_detection else "crc-clean"
        run_app("no-module", clean_mode)

        staged = True
        adb("push", str(kpm), remote)
        kp("kpm", "load", remote, f"key={module_key}")
        loaded = True
        report["loaded_status"] = kp("kpm", "ctl0", MODULE, "status")
        if "hooks=0x7f" not in report["loaded_status"]:
            raise RuntimeError("UROV-Y hooks incomplete")
        run_app("loaded-idle", clean_mode)
        modes = ("dobby-detect-active",) if args.dobby_detection else (
            "crc-brk", "crc-uxn", "crc-ap", "crc-ap-all", "crc-ap-text", "crc-ap-libc", "crc-ap-big")
        for i in range(1, args.cycles + 1):
            for mode in modes:
                run_app(f"{mode}-{i}", mode)
        if args.dobby_detection:
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
