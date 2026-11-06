#!/usr/bin/env python3
"""ABI v8 device matrix: multi-page ARMED set, LD1/LD2/LD3/LD4 and cross-page."""

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
MODES = ("mp-multi", "mp-ld1", "mp-cross", "mp-srcfile", "mp-audit")
STAMP = re.compile(r"^\[\s*([0-9.]+)\]", re.M)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--serial", required=True)
    parser.add_argument("--key", required=True, help="KernelPatch superkey")
    parser.add_argument("--skip-install", action="store_true")
    parser.add_argument("--kpm", type=Path, default=LAB / "out/urov-y.kpm",
                        help="urov-y build to test (defaults to the lab output)")
    parser.add_argument("--btf", type=Path, help="exact-build BTF package made by package_y_btf.py")
    parser.add_argument("--verbose", action="store_true", help="record module compatibility decisions in dmesg")
    parser.add_argument("--repeats", type=int, default=5)
    parser.add_argument("--cycles", type=int, default=1)
    args = parser.parse_args()
    if not 3 <= args.repeats <= 50 or not 1 <= args.cycles <= 10:
        parser.error("repeats 3..50, cycles 1..10")

    stamp = datetime.now(timezone(timedelta(hours=8))).strftime("%Y%m%d-%H%M%S")
    output = LAB / "results" / f"multipage-{stamp}"
    output.mkdir(parents=True)
    module_key = secrets.token_hex(16)
    remote = f"/data/local/tmp/urov-mp-{stamp}.kpm"
    remote_btf = remote + ".btf"
    report = {"serial": args.serial, "repeats": args.repeats, "cycles": args.cycles,
              "runs": [], "passed": False}
    clean_start = loaded = staged = staged_btf = False
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

    def run_app(label, mode):
        shell("am", "force-stop", PACKAGE)
        shell("am", "start", "-W", "-n", ACTIVITY, "--es", "mode", mode,
              "--ei", "repeats", str(args.repeats), "--es", "key", module_key)
        pid = shell("pidof", PACKAGE).split()[0]
        log_path = output / f"{label}-{pid}.log"
        deadline = time.monotonic() + 90
        result = None
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
        if not uid or int(uid[1]) < 10000:
            raise RuntimeError(f"{label}: invalid app credentials")
        query = re.search(r"MP_QUERY caps=(0x[0-9a-f]+) max_pages=(\d+) page_shift=(12|14) abi=8", logs)
        if not query or int(query[1], 16) & 0x47f != 0x47f or int(query[2]) < 24:
            raise RuntimeError(f"{label}: ABI v8 QUERY report missing")
        page_bytes = 1 << int(query[3])
        if page_bytes != report["page_size"]:
            raise RuntimeError(f"{label}: module page size differs from the device")
        required = {
            "mp-multi": (rf"MP_MULTI pages=24 span={24 * page_bytes} register=1",
                         r"MP_STATUS name=multi pages=24 armed=24",
                         r"MP_SET_PAGE page=7 generation=2",
                         r"MP_MULTI_DONE pages=24 restored=1"),
            "mp-ld1": (r"MP_LD register=1 page=1",
                       r"MP_LD_DONE readers=ld1x4/ld1x2/ld1x1/ld1_8b/post_imm/"
                       r"post_reg/ld2/ld3/ld4"),
            "mp-cross": (r"MP_CROSS register=1 pages=2",
                         r"MP_CROSS_DONE reads=ldp_page1_page2/ld1_page1_page2/"
                         r"ld1_tail/uncovered_page0"),
            "mp-srcfile": (r"MP_SRC_FILE register=1 page=1",
                           r"MP_SRC_FILE_DONE page=1"),
            "mp-audit": (r"MP_AUDIT invalid=5 updates=48 reads=[1-9]\d* errors=0 child_restored=1",),
        }[mode]
        for pattern in required:
            if not re.search(pattern, logs):
                raise RuntimeError(f"{label}: missing {pattern}")
        status = kp("kpm", "ctl0", MODULE, "status")
        if "state=inactive" not in status:
            raise RuntimeError(f"{label}: fixture left an active session")
        run = {"label": label, "mode": mode, "uid": int(uid[1]), "pid": pid,
               "log": log_path.name, "result": result[0],
               "status": status,
               "details": re.findall(r"MP_[^\n]+", logs)}
        report["runs"].append(run)
        print(f"{label} PASS uid={uid[1]} details={len(run['details'])}", flush=True)

    try:
        report["initial_modules"] = kp("kpm", "list")
        if report["initial_modules"]:
            raise RuntimeError("existing modules preserved")
        clean_start = True
        report["kernel"] = shell("uname", "-a")
        report["page_size"] = int(shell("getconf", "PAGE_SIZE"))
        report["kpver"] = kp("kpver")
        report["selinux"] = shell("getenforce")
        before = kp("su", "-c", "dmesg")
        apk = LAB / "apps/urov-detect/out/urovdetect.apk"
        kpm = args.kpm
        artifacts = [apk, kpm]
        if args.btf:
            artifacts.append(args.btf)
        report["artifacts"] = {p.name: hashlib.sha256(p.read_bytes()).hexdigest()
                               for p in artifacts}
        report["layout_source"] = "detached" if args.btf else "live"
        if not args.skip_install:
            adb("install", "--no-incremental", "-r", str(apk), timeout=120)

        staged = True
        adb("push", str(kpm), remote)
        load_args = [f"key={module_key}"]
        if args.btf:
            staged_btf = True
            adb("push", str(args.btf), remote_btf)
            load_args.append(f"btf={remote_btf}")
        if args.verbose:
            load_args.append("verbose")
        kp("kpm", "load", remote, " ".join(load_args))
        loaded = True
        report["loaded_status"] = kp("kpm", "ctl0", MODULE, "status")
        hooks = re.search(r"hooks=(0x[0-9a-f]+)", report["loaded_status"])
        if not hooks or int(hooks[1], 16) & 0x7e != 0x7e or "abi=8" not in report["loaded_status"]:
            raise RuntimeError("UROV-Y ABI v8 hooks incomplete")
        for cycle in range(1, args.cycles + 1):
            for mode in MODES:
                run_app(f"{mode}-{cycle}", mode)
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
                if staged_btf:
                    shell("rm", "-f", remote_btf)
                report["final_modules"] = kp("kpm", "list")
                if before is not None:
                    timestamps = STAMP.findall(before)
                    since = float(timestamps[-1]) if timestamps else 0
                    delta = []
                    for line in kp("su", "-c", "dmesg").splitlines():
                        match = STAMP.match(line)
                        if match and float(match[1]) > since:
                            delta.append(line)
                    (output / "kernel-new.log").write_text("\n".join(delta) + "\n",
                                                           encoding="utf-8")
                    report["kernel_issues"] = [line for line in delta if re.search(
                        r"\bBUG:|\bWARNING:|\bOops:|\bKernel panic|rcu.*stall|hung task|"
                        r"\bCall trace", line)]
                if report["final_modules"] or report.get("kernel_issues"):
                    report["passed"] = False
            except Exception as exc:
                report["cleanup_error"] = redact(str(exc))
                report["passed"] = False
        (output / "summary.json").write_text(
            json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"RESULT {'PASS' if report['passed'] else 'FAIL'} {output}", flush=True)
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
