#!/usr/bin/env python3
"""Ordinary-app detection matrix. Root is used only for KPM lifecycle/oracles.

Build both APKs with apps/urov-detect/build.ps1 (second time with -Observer),
and build the unchanged KPM with build.ps1 before running this script.
"""
import argparse
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import re
import shlex
import subprocess
import sys
import time

LAB = Path(__file__).resolve().parents[1]
OWNER = "com.example.urovdetect"
OBSERVER = "com.example.urovobserver"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--serial", required=True)
    parser.add_argument("--key", required=True, help="Not persisted to results")
    parser.add_argument("--repeats", type=int, default=30)
    parser.add_argument("--cycles", type=int, default=3)
    parser.add_argument("--skip-live-unload", action="store_true",
                        help="test only sessions that the app deactivates before unload")
    args = parser.parse_args()
    if not 3 <= args.repeats <= 200 or not 1 <= args.cycles <= 10:
        parser.error("repeats must be 3..200; cycles must be 1..10")
    stamp = datetime.now(timezone(timedelta(hours=8))).strftime("%Y%m%d-%H%M%S")
    output = LAB / "results" / f"detection-{stamp}"
    output.mkdir(parents=True, exist_ok=False)
    remote = f"/data/local/tmp/urov-detection-{stamp}.kpm"
    report = {"host_time_utc8": stamp, "serial": args.serial, "repeats": args.repeats,
              "cycles": args.cycles, "skip_live_unload": args.skip_live_unload,
              "runs": [], "steps": [], "passed": False}
    prefix = ["adb", "-s", args.serial]
    loaded = staged = False
    dmesg_before = ""

    def adb(argv, check=True, timeout=15):
        result = subprocess.run(prefix + argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                timeout=timeout, encoding="utf-8", errors="replace")
        text = result.stdout.replace(args.key, "<KEY>").strip()
        if check and result.returncode:
            raise RuntimeError(f"adb command failed (exit={result.returncode}): {text}")
        return result.returncode, text

    def shell(argv, **kwargs):
        return adb(["shell", shlex.join([str(item) for item in argv])], **kwargs)

    def kpatch(*argv, **kwargs):
        return shell(["/data/local/tmp/kpatch", args.key, *argv], **kwargs)[1]

    def step(label, value):
        report["steps"].append({"label": label, "output": value})
        print(f"{label}: {value}", flush=True)

    def save(name, text):
        (output / name).write_text(text + "\n", encoding="utf-8")

    def app_log(pid):
        return shell(["logcat", "-d", f"--pid={pid}", "-v", "threadtime", "-s",
                      "urovdetect:I", "AndroidRuntime:E", "libc:F"])[1]

    def launch(mode, label, package=OWNER, activity="com.example.urovdetect.MainActivity"):
        shell(["am", "force-stop", package])
        shell(["am", "start", "-W", "-n", f"{package}/{activity}",
               "--es", "mode", mode, "--ei", "repeats", str(args.repeats)])
        pid = shell(["pidof", package])[1].split()[0]
        return {"mode": mode, "label": label, "pid": pid, "package": package}

    def wait_log(run, pattern, timeout=25):
        until = time.monotonic() + timeout
        last = ""
        while time.monotonic() < until:
            last = app_log(run["pid"])
            save(run["label"] + ".log", last)
            if re.search(pattern, last):
                return last
            if "Fatal signal" in last or "FATAL EXCEPTION" in last:
                raise RuntimeError(f"{run['label']}: app crashed; see its log")
            time.sleep(0.25)
        raise RuntimeError(f"{run['label']}: timeout; saved last app log")

    def finish(run):
        logs = wait_log(run, rf"DETECT_RESULT (?:PASS|FAIL) mode={run['mode']}\b")
        match = re.search(rf"DETECT_RESULT (PASS|FAIL) mode={run['mode']}\b[^\n]*", logs)
        cases = []
        for found in re.finditer(r"CASE (\S+) result=(PASS|FAIL) ([^\n]+)", logs):
            item = {"name": found[1], "result": found[2]}
            item.update({key: int(value, 0) for key, value in re.findall(
                r"([a-zA-Z_][a-zA-Z_0-9]*)=(-?(?:0x[0-9a-f]+|[0-9]+))", found[3])})
            cases.append(item)
        run["result"] = match[1]
        run["summary"] = match[0]
        run["cases"] = cases
        run["skipped"] = re.findall(r"SKIP [^\n]+", logs)
        run["business"] = re.findall(r"BUSINESS [^\n]+", logs)
        run["assertions"] = int(re.search(r"NATIVE_RESULT (?:PASS|FAIL) cases=\d+ assertions=(\d+)", logs)[1])
        run["uid"] = int(re.search(r"CONTEXT pid=\d+ uid=(\d+)", logs)[1])
        report["runs"].append(run)
        step(run["label"], match[0])
        if match[1] != "PASS" or not cases or any(c["result"] != "PASS" for c in cases):
            raise RuntimeError(f"{run['label']}: test failure")
        if not re.search(r"CapEff:\s*0{16}\b", logs) or not re.search(r"Seccomp:\s*2\b", logs):
            raise RuntimeError(f"{run['label']}: not an ordinary seccomp-confined app")
        if "selinux=u:r:untrusted_app:" not in logs:
            raise RuntimeError(f"{run['label']}: unexpected SELinux domain")
        return logs

    try:
        step("root", kpatch("su", "-c", "id"))
        initial = kpatch("kpm", "list")
        report["initial_modules"] = initial
        if re.search(r"\burov-lab\b", initial):
            raise RuntimeError("urov-lab already loaded; preserve it and stop before changing state")
        report["boot_id_before"] = shell(["cat", "/proc/sys/kernel/random/boot_id"])[1]
        report["device"] = shell(["getprop", "ro.build.fingerprint"])[1]
        report["kernel"] = shell(["uname", "-a"])[1]
        report["device_time"] = shell(["date", "+%Y-%m-%dT%H:%M:%S%z"])[1]
        report["kpver"] = kpatch("kpver")
        dmesg_before = kpatch("su", "-c", "dmesg")
        save("kernel-before.log", dmesg_before)
        artifacts = {"kpm": LAB / "out/urov-lab.kpm",
                     "detector_apk": LAB / "apps/urov-detect/out/urovdetect.apk",
                     "observer_apk": LAB / "apps/urov-detect/out/urovobserver.apk"}
        report["artifacts"] = {}
        for kind, path in artifacts.items():
            report["artifacts"][kind] = {"path": str(path), "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
        for kind in ("detector_apk", "observer_apk"):
            adb(["install", "--no-incremental", "-r", str(artifacts[kind])], timeout=30)
        finish(launch("clean", "01-clean"))
        staged = True
        adb(["push", str(artifacts["kpm"]), remote])
        kpatch("kpm", "load", remote, "active")
        loaded = True
        step("loaded", kpatch("kpm", "ctl0", "urov-lab", "status"))
        finish(launch("idle", "02-loaded-idle"))
        for cycle in range(args.cycles):
            finish(launch("active", f"03-active-{cycle + 1}"))
            state = kpatch("kpm", "ctl0", "urov-lab", "status")
            step(f"active-{cycle + 1}-cleanup", state)
            if "state=inactive" not in state or "hits=0 failures=0" not in state:
                raise RuntimeError("matrix left a session behind")
        if not args.skip_live_unload:
            owner = launch("hold", "04-owner-live")
            wait_log(owner, r"HOLD_READY\b")
            state_before = kpatch("kpm", "ctl0", "urov-lab", "status")
            step("foreign-before", state_before)
            observer = launch("observer", "05-other-uid-observer", OBSERVER,
                              "com.example.urovdetect.ObserverActivity")
            finish(observer)
            state_after = kpatch("kpm", "ctl0", "urov-lab", "status")
            step("foreign-after", state_after)
            if "state=active" not in state_before or state_before != state_after:
                raise RuntimeError("foreign observer changed owner's session/counters")
        kpatch("kpm", "unload", "urov-lab")
        loaded = False
        if not args.skip_live_unload:
            finish(owner)
            if owner["uid"] == observer["uid"]:
                raise RuntimeError("observer must have a different app UID")
        finish(launch("clean", "06-post-unload"))
        report["passed"] = True
    except Exception as exc:
        # subprocess timeout exceptions can include argv; never persist the key.
        report["error"] = str(exc).replace(args.key, "<KEY>")
        print("ERROR: " + report["error"], flush=True)
    finally:
        if loaded:
            try:
                kpatch("kpm", "unload", "urov-lab")
            except Exception:
                report["cleanup_error"] = "module unload failed"
                report["passed"] = False
        for package in (OWNER, OBSERVER):
            shell(["am", "force-stop", package], check=False)
        try:
            if staged:
                shell(["rm", "-f", remote])
            report["final_modules"] = kpatch("kpm", "list")
            report["boot_id_after"] = shell(["cat", "/proc/sys/kernel/random/boot_id"])[1]
            if "boot_id_before" in report and report["boot_id_after"] != report["boot_id_before"]:
                raise RuntimeError("device rebooted during the test")
            if "urov-lab" in report["final_modules"]:
                report["passed"] = False
            after = kpatch("su", "-c", "dmesg")
            save("kernel-after.log", after)
            # Kernel timestamps remain useful even if the ring buffer wrapped.
            times = re.findall(r"^\[\s*([0-9.]+)\]", dmesg_before, re.M)
            since = float(times[-1]) if times else 0.0
            new_lines = []
            for line in after.splitlines():
                found = re.match(r"\[\s*([0-9.]+)\]", line)
                if found and float(found[1]) > since:
                    new_lines.append(line)
            save("kernel-new.log", "\n".join(new_lines))
            report["kernel_issues"] = [line for line in new_lines if re.search(
                r"\bBUG:|\bWARNING:|\bOops:|\bKernel panic|\brcu[^\n]*stall|\bhung task|\bCall trace",
                line, re.I)]
            if report["kernel_issues"]:
                report["passed"] = False
        except Exception as exc:
            report["verification_error"] = str(exc).replace(args.key, "<KEY>")
            report["passed"] = False
        save("summary.json", json.dumps(report, ensure_ascii=False, indent=2))
        print(f"RESULT {'PASS' if report['passed'] else 'FAIL'} {output}", flush=True)
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
