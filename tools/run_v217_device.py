#!/usr/bin/env python3
"""Run the urov-y 2.17.0 residual-feature matrix on a connected Android device.

The app fixtures cover the EL0/pipe/readv/GUP/fork/atomic/CRC paths as an
untrusted_app.  The app's seccomp policy blocks remap_file_pages, so that one
syscall path is exercised by the root probe; the app still verifies that the
same call cannot end the session when seccomp rejects it.
"""

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

APP_MODES = ("v217-store", "v217-atomic", "v217-fork", "v217-gup", "v217-remap", "v217-crc")
PROBE_MODES = ("store", "atomic", "fork", "gup", "remap")


class IncompleteLog(RuntimeError):
    """The app passed but logcat lost one or more required records."""


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--serial", required=True)
    parser.add_argument("--key", required=True, help="KernelPatch superkey")
    parser.add_argument("--skip-install", action="store_true")
    parser.add_argument("--repeats", type=int, default=32, help="store/atomic iterations per run")
    parser.add_argument("--cycles", type=int, default=2)
    parser.add_argument("--skip-probe", action="store_true", help="skip the root remap probe")
    args = parser.parse_args()
    if not 3 <= args.repeats <= 2000 or not 1 <= args.cycles <= 10:
        parser.error("repeats 3..2000, cycles 1..10")

    stamp = datetime.now(timezone(timedelta(hours=8))).strftime("%Y%m%d-%H%M%S")
    output = LAB / "results" / f"v217-{stamp}"
    output.mkdir(parents=True)
    module_key = secrets.token_hex(16)
    remote = f"/data/local/tmp/urov-v217-{stamp}.kpm"
    report = {"serial": args.serial, "repeats": args.repeats, "cycles": args.cycles,
              "runs": [], "probe": [], "passed": False}
    clean_start = loaded = staged = False
    before = None

    def redact(value):
        return value.replace(args.key, "<SUPERKEY>").replace(module_key, "<MODULE-KEY>")

    def adb(*argv, timeout=60):
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

    def wait_result(mode, log_path):
        deadline = time.monotonic() + 45
        while time.monotonic() < deadline:
            logs = shell("logcat", "-d", "-v", "threadtime", "-s", "urovdetect:I",
                         "AndroidRuntime:E", "libc:F", "DEBUG:F")
            log_path.write_text(logs + "\n", encoding="utf-8")
            result = re.search(rf"DETECT_RESULT (PASS|FAIL) mode={mode}\b[^\n]*", logs)
            if result or "Fatal signal" in logs or "FATAL EXCEPTION" in logs:
                return logs, result
            time.sleep(0.25)
        raise RuntimeError(f"{mode}: timed out")

    def run_app(label, mode, active=True):
        shell("am", "force-stop", PACKAGE)
        time.sleep(0.6)
        shell("logcat", "-c")
        argv = ["am", "start", "-W", "-n", ACTIVITY, "--es", "mode", mode,
                "--ei", "repeats", str(args.repeats)]
        if active:
            argv += ["--es", "key", module_key]
        shell(*argv)
        log_path = output / f"{label}.log"
        logs, result = wait_result(mode, log_path)
        if not result or result[1] != "PASS":
            raise RuntimeError(f"{label}: app failed, see {log_path.name}")
        context = re.search(r"CONTEXT pid=\d+ uid=(\d+) selinux=u:r:untrusted_app:", logs)
        if not context or int(context[1]) < 10000 or not re.search(
                r"CapEff:\s*0{16}\b", logs) or not re.search(r"Seccomp:\s*2\b", logs):
            raise RuntimeError(f"{label}: invalid app credentials")
        if "state=inactive" not in kp("kpm", "ctl0", MODULE, "status"):
            raise RuntimeError(f"{label}: fixture left an active session")
        details = re.findall(r"V217_[A-Z]+ [^\n]+", logs)
        report["runs"].append({"label": label, "mode": mode, "uid": int(context[1]),
                               "result": result[0], "details": details,
                               "ui": dict(KV.findall(result[0]))})
        check_v217(label, mode, details, log_path)
        shell("am", "force-stop", PACKAGE)
        time.sleep(0.5)
        return details

    def check_v217(label, mode, details, log_path):
        stage = {line.split()[0]: dict(KV.findall(line)) for line in details}
        if mode == "v217-store":
            row = stage.get("V217_STORE", {})
            if not row or row.get("view") != row.get("image") or row.get("active") != "1":
                raise IncompleteLog(f"{label}: store row {row}")
            if row.get("pipe") != "0" or row.get("iov") != "0" or row.get("armed") == "0":
                raise RuntimeError(f"{label}: store readers {row}")
        elif mode == "v217-atomic":
            row = stage.get("V217_ATOMIC")
            if not row or row.get("value") != row.get("want") or row.get("active") != "1":
                raise RuntimeError(f"{label}: atomic row {row}")
        elif mode == "v217-fork":
            row = stage.get("V217_FORK")
            if not row or row.get("child") != "0" or row.get("active") != "1":
                raise RuntimeError(f"{label}: fork row {row}")
        elif mode == "v217-gup":
            if "V217_GUP" not in stage:
                raise IncompleteLog(f"{label}: gup row missing in {log_path.name}")
            row = stage["V217_GUP"]
            if "live_matches" in row and (row.get("live_matches") != "1" or row.get("active") != "1"):
                raise RuntimeError(f"{label}: gup row {row}")
        elif mode == "v217-remap":
            if "V217_REMAP" not in stage:
                raise IncompleteLog(f"{label}: remap row missing in {log_path.name}")
            row = stage["V217_REMAP"]
            raw = " ".join(details)
            if "skipped" in raw:
                if "V217_REMAP skipped seccomp" not in raw:
                    raise IncompleteLog(f"{label}: unexpected remap skip {row}")
            elif row.get("active") != "1" or row.get("errno") != "22":
                raise RuntimeError(f"{label}: remap gate result {row}")
        elif mode == "v217-crc":
            row = stage.get("V217_CRC")
            if not row or row.get("execute") != "1235" or row.get("active") != "1":
                raise RuntimeError(f"{label}: crc row {row}")
            digests = (row.get("file"), row.get("user"), row.get("pipe"), row.get("iov"))
            if "mem skipped" not in " ".join(details) and row.get("mem") not in digests:
                raise RuntimeError(f"{label}: crc digest {row}")
            if len(set(digests)) != 1 or row.get("child") != "0":
                raise RuntimeError(f"{label}: crc digest {row}")

    def run_probe(label, mode, iterations):
        argv = ["/data/local/tmp/v217_probe", module_key, mode, str(iterations)]
        text = adb("shell", shlex.join(["/data/local/tmp/kpatch", args.key, "su", "-c",
                                        " ".join(argv)]), timeout=120)
        (output / f"{label}.log").write_text(text + "\n", encoding="utf-8")
        summary = re.search(rf"PROBE {mode} checks=(\d+) failures=(\d+)", text)
        if not summary or summary.group(2) != "0":
            raise RuntimeError(f"{label}: probe failed: {text.splitlines()[-3:]}")
        if "SKIP" in text:
            raise RuntimeError(f"{label}: probe skipped")
        report["probe"].append({"label": label, "mode": mode,
                                "checks": int(summary.group(1)), "output": text.splitlines()})

    try:
        report["initial_modules"] = kp("kpm", "list")
        if report["initial_modules"]:
            raise RuntimeError("existing module present")
        clean_start = True
        report["boot_id_before"] = shell("cat", "/proc/sys/kernel/random/boot_id")
        report["kernel"] = shell("uname", "-a")
        report["kpver"] = kp("kpver")
        report["selinux"] = shell("getenforce")
        before = kp("su", "-c", "dmesg")
        apk = LAB / "apps/urov-detect/out/urovdetect.apk"
        kpm = LAB / "out/urov-y.kpm"
        probe = LAB / "out/v217_probe"
        report["artifacts"] = {p.name: hashlib.sha256(p.read_bytes()).hexdigest()
                               for p in (apk, kpm, probe)}
        if not args.skip_install:
            adb("install", "--no-incremental", "-r", str(apk), timeout=180)

        staged = True
        adb("push", str(kpm), remote)
        kp("kpm", "load", remote, f"key={module_key}")
        loaded = True
        status = kp("kpm", "ctl0", MODULE, "status")
        report["loaded_status"] = status
        if "hooks=0xff" not in status or "abi=8" not in status:
            raise RuntimeError("urov-y did not load with the full hook set")

        for cycle in range(1, args.cycles + 1):
            for mode in APP_MODES:
                run_app(f"{mode}-{cycle}", mode)

        if not args.skip_probe:
            adb("push", str(probe), "/data/local/tmp/v217_probe", timeout=60)
            shell("chmod", "755", "/data/local/tmp/v217_probe")
            for mode in PROBE_MODES:
                run_probe(f"probe-{mode}", mode, args.repeats)
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
