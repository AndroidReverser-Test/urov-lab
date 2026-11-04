#!/usr/bin/env python3
"""Ordinary-app, keyless observation matrix; root only sets fixture truth."""
import argparse
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import re
import secrets
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
    parser.add_argument("--key", required=True, help="KernelPatch superkey, never persisted")
    parser.add_argument("--repeats", type=int, default=30)
    parser.add_argument("--cycles", type=int, default=3)
    parser.add_argument("--owner-only", action="store_true", help="Pilot without the observer APK")
    args = parser.parse_args()
    if not 3 <= args.repeats <= 200 or not 1 <= args.cycles <= 10:
        parser.error("repeats must be 3..200, cycles 1..10")
    module_key = secrets.token_hex(16)
    stamp = datetime.now(timezone(timedelta(hours=8))).strftime("%Y%m%d-%H%M%S")
    output = LAB / "results" / f"observe-{stamp}"
    output.mkdir(parents=True, exist_ok=False)
    report = {"host_time_utc8": stamp, "serial": args.serial, "repeats": args.repeats,
              "cycles": args.cycles, "runs": [], "passed": False}
    loaded = False
    safe_cleanup = False
    before = ""

    def redact(text):
        return text.replace(args.key, "<KEY>").replace(module_key, "<FIXTURE-KEY>")

    def adb(argv, check=True, timeout=30):
        result = subprocess.run(["adb", "-s", args.serial, *argv],
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                encoding="utf-8", errors="replace", timeout=timeout)
        value = redact(result.stdout).strip()
        if check and result.returncode:
            raise RuntimeError(f"adb exit {result.returncode}: {value}")
        return value

    def shell(*argv, **kwargs):
        return adb(["shell", shlex.join([str(x) for x in argv])], **kwargs)

    def kp(*argv):
        return shell("/data/local/tmp/kpatch", args.key, *argv)

    def save(name, value):
        (output / name).write_text(redact(value) + "\n", encoding="utf-8")

    def run_app(label, mode, package=OWNER, keyed=False, ready_only=False, existing_pid=None):
        if existing_pid is None:
            shell("am", "force-stop", package)
            activity = "MainActivity" if package == OWNER else "ObserverActivity"
            argv = ["am", "start", "-W", "-n", f"{package}/com.example.urovdetect.{activity}",
                    "--es", "mode", mode, "--ei", "repeats", str(args.repeats)]
            if keyed:
                argv += ["--es", "key", module_key]
            shell(*argv)
            pid = shell("pidof", package).split()[0]
        else:
            pid = existing_pid
        until = time.monotonic() + 60
        logs = ""
        while time.monotonic() < until:
            logs = shell("logcat", "-d", f"--pid={pid}", "-v", "threadtime", "-s",
                         "urovdetect:I", "AndroidRuntime:E", "libc:F", "DEBUG:F")
            save(f"{label}-{pid}.log", logs)
            if ready_only and "HOLD_READY" in logs:
                return pid
            found = re.search(rf"DETECT_RESULT (PASS|FAIL) mode={re.escape(mode)}\b[^\n]*", logs)
            if found:
                run = {"label": label, "mode": mode, "pid": pid, "package": package,
                       "result": found[1], "ui": found[0], "log": f"{label}-{pid}.log"}
                report["runs"].append(run)
                if not re.search(r"CapEff:\s*0{16}\b", logs) or not re.search(r"Seccomp:\s*2\b", logs):
                    raise RuntimeError(f"{label}: capability or seccomp context incorrect")
                if "selinux=u:r:untrusted_app:" not in logs:
                    raise RuntimeError(f"{label}: not untrusted_app")
                run["uid"] = int(re.search(r"CONTEXT pid=\d+ uid=(\d+)", logs)[1])
                cases = []
                for line in re.findall(r"OBS_CASE [^\n]+", logs):
                    pairs = dict(re.findall(r"(\w+)=([^ ]+)", line))
                    cases.append(pairs)
                run["cases"] = cases
                run["state"] = re.findall(r"OBS_STATE [^\n]+", logs)
                run["business"] = re.findall(r"OBS_BUSINESS [^\n]+", logs)
                run["cpus"] = re.findall(r"OBS_CPUS [^\n]+", logs)
                run["contracts"] = re.findall(r"OBS_CONTRACT [^\n]+", logs)
                print(f"{label}: {found[0]}", flush=True)
                for line in re.findall(r"OBS_CASE [^\n]+", logs):
                    print("  " + line, flush=True)
                if found[1] != "PASS" or any(case["result"] != "PASS" for case in cases):
                    raise RuntimeError(f"{label}: app assertions failed")
                if not cases and mode != "x-hold":
                    raise RuntimeError(f"{label}: observation did not execute")
                if mode == "x-hold" and "HOLD_UNLOADED restored=1" not in logs:
                    raise RuntimeError(f"{label}: owner did not resume original reads")
                return logs
            if "Fatal signal" in logs or "FATAL EXCEPTION" in logs:
                raise RuntimeError(f"{label}: app crashed")
            time.sleep(0.25)
        raise RuntimeError(f"{label}: timed out")

    try:
        report["initial_modules"] = kp("kpm", "list")
        if report["initial_modules"].strip():
            raise RuntimeError("existing modules preserved; no fixture changes made")
        safe_cleanup = True
        report["root"] = kp("su", "-c", "id")
        report["kernel"] = shell("uname", "-a")
        report["fingerprint"] = shell("getprop", "ro.build.fingerprint")
        report["device_time"] = shell("date", "+%Y-%m-%dT%H:%M:%S%z")
        report["kpver"] = kp("kpver")
        before = kp("su", "-c", "dmesg")
        save("kernel-before.log", before)
        artifacts = {"kpm": LAB / "out/urov-x.kpm",
                     "owner": LAB / "apps/urov-detect/out/urovdetect.apk"}
        if not args.owner_only:
            artifacts["observer"] = LAB / "apps/urov-detect/out/urovobserver.apk"
        report["artifacts"] = {}
        for name, path in artifacts.items():
            report["artifacts"][name] = {"path": str(path), "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
        adb(["push", str(artifacts["kpm"]), "/data/local/tmp/urov-observe-x.kpm"])
        for name in ("owner", "observer"):
            if name in artifacts:
                adb(["install", "--no-incremental", "-r", str(artifacts[name])], timeout=60)
        run_app("01-clean", "observe-clean")
        kp("kpm", "load", "/data/local/tmp/urov-observe-x.kpm", f"key={module_key}")
        loaded = True
        report["loaded_status"] = kp("kpm", "ctl0", "urov-x", "status")
        if "hooks=0x1f" not in report["loaded_status"]:
            raise RuntimeError("fixture hooks incomplete")
        run_app("02-loaded-idle", "observe-clean")
        for cycle in range(args.cycles):
            run_app(f"03-active-{cycle + 1}", "observe-active", keyed=True)
            if "state=inactive" not in kp("kpm", "ctl0", "urov-x", "status"):
                raise RuntimeError("fixture leaked a session")
        if not args.owner_only:
            run_app("04-independent-idle", "observe-clean", package=OBSERVER)
            owner_pid = run_app("04-owner-hold", "x-hold", keyed=True, ready_only=True)
            status_before = kp("kpm", "ctl0", "urov-x", "status")
            if "state=active" not in status_before:
                raise RuntimeError("owner hold not active")
            run_app("04-independent-foreign-active", "observe-clean", package=OBSERVER)
            status_after = kp("kpm", "ctl0", "urov-x", "status")
            report["foreign_observer"] = {"before": status_before, "after": status_after}
            if re.sub(r"hits=\d+", "hits=*", status_before) != re.sub(r"hits=\d+", "hits=*", status_after):
                raise RuntimeError("foreign observer changed owner state")
            observer_uid = report["runs"][-1]["uid"]
            kp("kpm", "unload", "urov-x")
            loaded = False
            run_app("04-owner-unload", "x-hold", existing_pid=owner_pid)
            if report["runs"][-1]["uid"] == observer_uid:
                raise RuntimeError("observer did not use a different uid")
        else:
            kp("kpm", "unload", "urov-x")
            loaded = False
        run_app("05-post-unload", "observe-clean")
        report["passed"] = True
    except Exception as exc:
        report["error"] = redact(str(exc))
        print("ERROR " + report["error"], flush=True)
    finally:
        if loaded:
            try:
                kp("kpm", "unload", "urov-x")
            except Exception as exc:
                report["cleanup_error"] = redact(str(exc))
                report["passed"] = False
        if safe_cleanup:
            for package in (OWNER, OBSERVER):
                shell("am", "force-stop", package, check=False)
            try:
                report["final_modules"] = kp("kpm", "list")
                after = kp("su", "-c", "dmesg")
                save("kernel-after.log", after)
                times = re.findall(r"^\[\s*([0-9.]+)\]", before, re.M)
                since = float(times[-1]) if times else 0
                lines = [line for line in after.splitlines()
                         if (m := re.match(r"^\[\s*([0-9.]+)\]", line)) and float(m[1]) > since]
                save("kernel-new.log", "\n".join(lines))
                report["kernel_issues"] = [line for line in lines if re.search(
                    r"BUG:|WARNING:|Oops:|Kernel panic|rcu[^\n]*stall|hung task|Call trace", line, re.I)]
                if report["final_modules"].strip() or report["kernel_issues"]:
                    report["passed"] = False
            except Exception as exc:
                report["verification_error"] = redact(str(exc))
                report["passed"] = False
        report["totals"] = {"runs": len(report["runs"]), "cases": 0, "observations": 0,
                            "reservation_matches": 0, "clean": 0, "unknown": 0,
                            "accepted_triplets": 0, "failed_target_stores": 0,
                            "discarded_controls": 0, "reader_matches": 0}
        for run in report["runs"]:
            for case in run.get("cases", []):
                report["totals"]["cases"] += 1
                for dest, source in (("observations", "n"), ("reservation_matches", "match"),
                                     ("clean", "clean"), ("unknown", "unknown"),
                                     ("accepted_triplets", "accepted"), ("failed_target_stores", "failed"),
                                     ("discarded_controls", "control_failed"), ("reader_matches", "reader_match")):
                    report["totals"][dest] += int(case[source])
        save("summary.json", json.dumps(report, ensure_ascii=False, indent=2))
        print(f"RESULT {'PASS' if report['passed'] else 'FAIL'} {output}", flush=True)
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
