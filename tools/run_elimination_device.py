#!/usr/bin/env python3
"""urov-y elimination matrix: the delivered keyless detectors must stay negative.

Runs on one device; root only loads/unloads modules and collects kernel truth:

  1. app without the module                   -> y-clean
  2. urov-x control, same app/detector core   -> observe-active must MATCH
  3. urov-y loaded, no session                -> y-clean (idle module)
  4. urov-y active cycles, BRK site mode      -> y-active: A and B must be
                                                 NO_MATCH, the registered
                                                 business call must see the fake,
                                                 and the code-page probe must
                                                 fire (differs=1, COW page)
  5. urov-y active cycles, page-trap mode     -> z-active: same detector
                                                 results, but the code-page
                                                 probe must be clean
                                                 (differs=0, private_dirty=0)
  6. unload while a BRK session is live       -> site restored in the running app
  7. unload while a page-trap session is live -> same, page stays clean
  8. final clean run                          -> y-clean

The detector core (native/urov_observe.c, native/urov_detect.c) is unmodified.
"""
import argparse
from datetime import datetime, timedelta, timezone
import hashlib
import json
import re
import secrets
import shlex
import subprocess
import sys
import time
from pathlib import Path

LAB = Path(__file__).resolve().parents[1]
PACKAGE = "com.example.urovdetect"

KV = re.compile(r"(\w+)=([^ ]+)")


def kv(line):
    return dict(KV.findall(line))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--serial", required=True)
    parser.add_argument("--key", required=True, help="KernelPatch superkey")
    parser.add_argument("--repeats", type=int, default=10)
    parser.add_argument("--cycles", type=int, default=2)
    args = parser.parse_args()
    if not 3 <= args.repeats <= 200 or not 1 <= args.cycles <= 10:
        parser.error("repeats 3..200, cycles 1..10")

    module_key = secrets.token_hex(16)
    control_key = secrets.token_hex(16)
    stamp = datetime.now(timezone(timedelta(hours=8))).strftime("%Y%m%d-%H%M%S")
    output = LAB / "results" / f"eliminate-{stamp}"
    output.mkdir(parents=True, exist_ok=False)
    report = {"host_time_utc8": stamp, "serial": args.serial, "repeats": args.repeats,
              "cycles": args.cycles, "runs": [], "passed": False}
    loaded = None
    safe_cleanup = False
    before = ""

    def redact(text):
        return (text.replace(args.key, "<KEY>").replace(module_key, "<MODULE-KEY>")
                    .replace(control_key, "<CONTROL-KEY>"))

    def adb(argv, check=True, timeout=120):
        result = subprocess.run(["adb", "-s", args.serial, *argv],
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                encoding="utf-8", errors="replace", timeout=timeout)
        value = redact(result.stdout).strip()
        if check and result.returncode:
            raise RuntimeError(f"adb exit {result.returncode}: {value}")
        return value

    def shell(*argv, **kwargs):
        return adb(["shell", shlex.join([str(x) for x in argv])], **kwargs)

    def kp(*argv, **kwargs):
        return shell("/data/local/tmp/kpatch", args.key, *argv, **kwargs)

    def save(name, value):
        (output / name).write_text(redact(value) + "\n", encoding="utf-8")

    def logcat(pid):
        return shell("logcat", "-d", f"--pid={pid}", "-v", "threadtime", "-s",
                     "urovdetect:I", "AndroidRuntime:E", "libc:F", "DEBUG:F")

    def start_app(mode, key):
        shell("am", "force-stop", PACKAGE)
        argv = ["am", "start", "-W", "-n", f"{PACKAGE}/com.example.urovdetect.MainActivity",
                "--es", "mode", mode, "--ei", "repeats", str(args.repeats)]
        if key:
            argv += ["--es", "key", key]
        shell(*argv)
        return shell("pidof", PACKAGE).split()[0]

    def collect(pid, label, mode, wait_for=None):
        until = time.monotonic() + 120
        logs = ""
        while time.monotonic() < until:
            logs = logcat(pid)
            save(f"{label}-{pid}.log", logs)
            if wait_for and wait_for in logs:
                return logs
            if re.search(rf"DETECT_RESULT (?:PASS|FAIL) mode={re.escape(mode)}\b", logs):
                return logs
            if "Fatal signal" in logs or "FATAL EXCEPTION" in logs:
                raise RuntimeError(f"{label}: app crashed")
            time.sleep(0.25)
        raise RuntimeError(f"{label}: timed out")

    def run_app(label, mode, key=None):
        pid = start_app(mode, key)
        logs = collect(pid, label, mode)
        found = re.search(rf"DETECT_RESULT (PASS|FAIL) mode={re.escape(mode)}\b[^\n]*", logs)
        if not found:
            raise RuntimeError(f"{label}: no DETECT_RESULT")
        if not re.search(r"CapEff:\s*0{16}\b", logs):
            raise RuntimeError(f"{label}: CapEff is not zero")
        if not re.search(r"Seccomp:\s*2\b", logs):
            raise RuntimeError(f"{label}: Seccomp is not 2")
        if "selinux=u:r:untrusted_app:" not in logs:
            raise RuntimeError(f"{label}: not untrusted_app")
        cases = [kv(line) for line in re.findall(r"ELIM_CASE [^\n]+", logs)]
        run = {"label": label, "mode": mode, "pid": pid, "result": found[0],
               "app_pass": found[1] == "PASS", "cases": cases,
               "features": re.findall(r"ELIM_FEATURE [^\n]+", logs),
               "business": re.findall(r"ELIM_BUSINESS [^\n]+", logs),
               "residuals": re.findall(r"ELIM_RESIDUAL [^\n]+", logs),
               "timing": re.findall(r"ELIM_TIMING [^\n]+", logs),
               "log": f"{label}-{pid}.log",
               "uid": int(re.search(r"CONTEXT pid=\d+ uid=(\d+)", logs)[1])}
        report["runs"].append(run)
        print(f"{label}: {found[0]}", flush=True)
        for line in re.findall(r"ELIM_CASE [^\n]+", logs):
            print("  " + line, flush=True)
        for line in run["features"] + run["residuals"] + run["timing"]:
            print("  " + line, flush=True)
        if found[1] != "PASS":
            raise RuntimeError(f"{label}: app assertions failed")
        return run, logs

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
        artifacts = {"y_kpm": LAB / "out/urov-y.kpm",
                     "x_kpm": LAB / "out/urov-x.kpm",
                     "apk": LAB / "apps/urov-detect/out/urovdetect.apk"}
        report["artifacts"] = {k: {"path": str(v),
                                   "sha256": hashlib.sha256(v.read_bytes()).hexdigest()}
                               for k, v in artifacts.items()}
        adb(["install", "--no-incremental", "-r", str(artifacts["apk"])], timeout=180)
        adb(["push", str(artifacts["y_kpm"]), "/data/local/tmp/urov-y.kpm"])
        adb(["push", str(artifacts["x_kpm"]), "/data/local/tmp/urov-x.kpm"])

        run_app("01-no-module", "y-clean")

        # Positive control: the same detector core and the same fixture page do
        # fire on urov-x, so a negative urov-y result cannot be blamed on a
        # broken detector.
        kp("kpm", "load", "/data/local/tmp/urov-x.kpm", f"key={control_key}")
        loaded = "urov-x"
        report["control_status"] = kp("kpm", "ctl0", "urov-x", "status")
        if "hooks=0x1f" not in report["control_status"]:
            raise RuntimeError("urov-x control hooks incomplete")
        _, control_logs = run_app("02-urov-x-control", "observe-active", key=control_key)
        control_cases = [kv(line) for line in re.findall(r"OBS_CASE [^\n]+", control_logs)]
        by_name = {c["name"]: c for c in control_cases}
        changed = by_name.get("active_changed")
        if not changed or int(changed["match"]) <= 0 or int(changed["reader_match"]) <= 0:
            raise RuntimeError("urov-x control active_changed did not reproduce the detections")
        cpus = [c for c in control_cases if c["name"].startswith("active_cpu_")]
        if not cpus or any(int(c["match"]) <= 0 or int(c["reader_match"]) <= 0 for c in cpus):
            raise RuntimeError("urov-x control per-CPU cases did not reproduce the detections")
        report["control"] = {
            "active_changed": {"match": int(changed["match"]),
                               "clean": int(changed["clean"]),
                               "reader_match": int(changed["reader_match"])},
            "cpu_cases": len(cpus),
            "cpu_exclusive_matches": sum(int(c["match"]) for c in cpus),
            "cpu_reader_matches": sum(int(c["reader_match"]) for c in cpus)}
        kp("kpm", "unload", "urov-x")
        loaded = None

        kp("kpm", "load", "/data/local/tmp/urov-y.kpm", f"key={module_key}")
        loaded = "urov-y"
        report["loaded_status"] = kp("kpm", "ctl0", "urov-y", "status")
        if "hooks=0x7f" not in report["loaded_status"]:
            raise RuntimeError("urov-y hooks incomplete")

        run_app("03-loaded-idle", "y-clean")
        for cycle in range(args.cycles):
            run, _ = run_app(f"04-active-{cycle + 1}", "y-active", key=module_key)
            if not run["cases"]:
                raise RuntimeError("y-active produced no observation cases")
            for case in run["cases"]:
                if case["name"].startswith("active") and (
                        int(case["exclusive_match"]) != 0 or int(case["reader_match"]) != 0):
                    raise RuntimeError(f"detector positive on {case['name']}")
            if "state=inactive" not in kp("kpm", "ctl0", "urov-y", "status"):
                raise RuntimeError("fixture leaked a session")
            # Positive control for the code-page probe: the BRK mode must show
            # the modified instruction and the private COW page.
            brk = [r for r in run["residuals"] if "mode=brk" in r and "site_live_word" in r]
            if not brk or any("differs=1" not in r for r in brk):
                raise RuntimeError("BRK-mode residual probe did not fire")
            if any("site_cow_private=1" not in r for r in brk):
                raise RuntimeError("BRK-mode page was not private-dirty")
        for cycle in range(args.cycles):
            run, _ = run_app(f"05-page-{cycle + 1}", "z-active", key=module_key)
            if not run["cases"]:
                raise RuntimeError("z-active produced no observation cases")
            for case in run["cases"]:
                if case["name"].startswith("active") and (
                        int(case["exclusive_match"]) != 0 or int(case["reader_match"]) != 0):
                    raise RuntimeError(f"detector positive on {case['name']}")
            if "state=inactive" not in kp("kpm", "ctl0", "urov-y", "status"):
                raise RuntimeError("page fixture leaked a session")
            # The feature this iteration removes: no code-word difference and no
            # private page in the page-trap mode.
            active = [r for r in run["residuals"] if "mode=page" in r and "site_live_word" in r]
            if not active or any("differs=0" not in r for r in active):
                raise RuntimeError("page-mode site word differs from the file")
            if any("site_cow_private=0" not in r for r in active):
                raise RuntimeError("page-mode site page is private")
            for r in active:
                fields = kv(r)
                if (fields.get("private_dirty_kb") != fields.get("base_dirty_kb") or
                        fields.get("anonymous_kb") != fields.get("base_anonymous_kb")):
                    raise RuntimeError("page-mode page accounting changed")

        # Unload while a session is live: the module must restore the site in
        # the running app, which keeps executing the same reader routine.
        for hold_mode, label in (("y-hold", "06-hold"), ("z-hold", "07-hold-page")):
            pid = start_app(hold_mode, module_key)
            hold_logs = collect(pid, label, hold_mode, wait_for="ELIM_HOLD_READY")
            if "ELIM_HOLD_READY" not in hold_logs:
                raise RuntimeError(f"{hold_mode} fixture did not arm")
            status = kp("kpm", "ctl0", "urov-y", "status")
            report[f"{label}_status"] = status
            if "state=active" not in status:
                raise RuntimeError(f"{label} session is not active")
            report[f"{label}_unload"] = kp("kpm", "unload", "urov-y", check=False)
            if kp("kpm", "list").strip():
                raise RuntimeError("unload with a live session did not remove the module")
            loaded = None
            hold_logs = collect(pid, f"{label}-after-unload", hold_mode)
            restored = re.findall(r"ELIM_HOLD_RESTORED [^\n]+", hold_logs)
            if not restored:
                raise RuntimeError("running app did not observe the restored site")
            result = re.search(rf"DETECT_RESULT (PASS|FAIL) mode={re.escape(hold_mode)}\b[^\n]*",
                               hold_logs)
            if not result or result[1] != "PASS":
                raise RuntimeError(f"{label} fixture failed after the unload")
            if not shell("pidof", PACKAGE, check=False):
                raise RuntimeError("app died during the unload")
            report["runs"].append({"label": f"{label}-after-unload", "mode": hold_mode,
                                   "pid": pid, "result": result[0], "restored": restored,
                                   "log": f"{label}-after-unload-{pid}.log"})
            print(f"{label}-after-unload: {result[0]}", flush=True)
            for line in restored:
                print("  " + line, flush=True)
            if hold_mode == "z-hold":
                fields = kv(restored[0])
                if fields.get("private_dirty_kb") != fields.get("base_dirty_kb") or \
                        fields.get("anonymous_kb") != fields.get("base_anonymous_kb"):
                    raise RuntimeError("page-mode site page changed after unload")
            kp("kpm", "load", "/data/local/tmp/urov-y.kpm", f"key={module_key}")
            loaded = "urov-y"

        run_app("08-final-clean", "y-clean")
        kp("kpm", "unload", "urov-y")
        loaded = None
        report["passed"] = True
    except Exception as exc:
        report["error"] = redact(str(exc))
        print("ERROR " + report["error"], flush=True)
    finally:
        if loaded:
            try:
                kp("kpm", "unload", loaded)
            except Exception as exc:
                report["cleanup_error"] = redact(str(exc))
                report["passed"] = False
        if safe_cleanup:
            for _ in range(5):
                shell("am", "force-stop", PACKAGE, check=False)
                time.sleep(0.2)
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
                    r"\bBUG:|\bWARNING:|\bOops:|\bKernel panic|\brcu[^\n]*stall|\bhung task|\bCall trace",
                    line)]
                if report["final_modules"].strip() or report["kernel_issues"]:
                    report["passed"] = False
            except Exception as exc:
                report["verification_error"] = redact(str(exc))
                report["passed"] = False
        totals = {"runs": len(report["runs"]), "elim_cases": 0, "observations": 0,
                  "exclusive_matches": 0, "exclusive_clean": 0, "exclusive_unknown": 0,
                  "accepted_triplets": 0, "failed_target_stores": 0,
                  "control_failed_stores": 0, "reader_matches": 0, "reader_clean": 0,
                  "reader_unknown": 0, "feature_business_reads": 0}
        for run in report["runs"]:
            for case in run.get("cases", []):
                totals["elim_cases"] += 1
                for dest, source in (("observations", "n"),
                                     ("exclusive_matches", "exclusive_match"),
                                     ("exclusive_clean", "exclusive_clean"),
                                     ("exclusive_unknown", "exclusive_unknown"),
                                     ("accepted_triplets", "accepted"),
                                     ("failed_target_stores", "failed"),
                                     ("control_failed_stores", "control_failed"),
                                     ("reader_matches", "reader_match"),
                                     ("reader_clean", "reader_clean"),
                                     ("reader_unknown", "reader_unknown")):
                    totals[dest] += int(case[source])
            totals["feature_business_reads"] += sum(
                1 for f in run.get("features", []) if "business_reader=1" in f)
        report["totals"] = totals
        save("summary.json", json.dumps(report, ensure_ascii=False, indent=2))
        print(f"RESULT {'PASS' if report['passed'] else 'FAIL'} {output}", flush=True)
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
