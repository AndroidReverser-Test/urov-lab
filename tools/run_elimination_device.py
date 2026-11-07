#!/usr/bin/env python3
"""UROV-Y device matrix with keyless instruction-fetch and store checks.

Runs on one device; root only loads/unloads modules and collects kernel truth:

  - No module, idle and post-unload: clean canary.
  - UROV-X: the older data-read detectors match on an active raw-XOM page.
  - UROV-Y BRK: the site word changes, but the canary executes natively.
  - UROV-Y PAGE_UXN: the site word is unchanged and canary fetches trap.
  - UROV-Y PAGE_AP: site word and canary are native. 2.5.0 completes an
    adjacent, execution-proven LDXR/load/STXR in the fault handler; a skipped
    LDXR must still fail natively and never lead to a store.
  - All UROV-Y modes: the business reader receives the fake value.
  - A separate UID sees no findings while the owner's PAGE_UXN or PAGE_AP is live.
  - The owner reads the original bytes after deactivation and unload.
    Live unload without deactivation is opt-in on suitable loaders.

Build the two APKs with apps/urov-detect/build.ps1 (second time with -Observer).
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
OBSERVER = "com.example.urovobserver"

KV = re.compile(r"(\w+)=([^ ]+)")


def kv(line):
    return dict(KV.findall(line))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--serial", required=True)
    parser.add_argument("--key", required=True, help="KernelPatch superkey")
    parser.add_argument("--skip-install", action="store_true", help="use the already installed test APKs")
    parser.add_argument("--skip-x-control", action="store_true",
                        help="omit the UROV-X control on kernels without its MM layout")
    parser.add_argument("--active-unload", action="store_true",
                        help="unload without DEACTIVATE; requires a sleepable loader exit")
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
              "cycles": args.cycles, "active_unload": args.active_unload,
              "runs": [], "passed": False}
    loaded = None
    safe_cleanup = False
    staged = None
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

    def start_app(mode, key, package=PACKAGE):
        activity = "MainActivity" if package == PACKAGE else "ObserverActivity"
        shell("am", "force-stop", package)
        argv = ["am", "start", "-W", "-n", f"{package}/com.example.urovdetect.{activity}",
                "--es", "mode", mode, "--ei", "repeats", str(args.repeats)]
        if key:
            argv += ["--es", "key", key]
        shell(*argv)
        return shell("pidof", package).split()[0]

    def app_uid(logs):
        if not re.search(r"CapEff:\s*0{16}\b", logs):
            raise RuntimeError("CapEff is not zero")
        if not re.search(r"Seccomp:\s*2\b", logs):
            raise RuntimeError("Seccomp is not 2")
        if "selinux=u:r:untrusted_app:" not in logs:
            raise RuntimeError("not untrusted_app")
        match = re.search(r"CONTEXT pid=\d+ uid=(\d+)", logs)
        if not match or int(match[1]) < 10000:
            raise RuntimeError("missing ordinary app UID")
        return int(match[1])

    def execution_cases(logs):
        return [kv(line) for line in re.findall(r"ELIM_EXEC [^\n]+", logs)]

    def store_cases(logs, mode):
        cases = [kv(line) for line in re.findall(r"ELIM_STORE [^\n]+", logs)]
        if not cases:
            raise RuntimeError(f"{mode}: no store observations")
        for case in cases:
            # No mode may retire a Store-Exclusive whose Load-Exclusive was
            # skipped: the native monitor is open, so every active sample must
            # be a clean native failure with zero unexpected writes.
            if int(case["expected"]) != 0 or int(case["match"]) != 0 or \
                    int(case["clean"]) == 0 or int(case["stores"]) != 0:
                raise RuntimeError(f"{mode}: unexpected store result {case}")
        return cases

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

    def run_app(label, mode, key=None, package=PACKAGE):
        pid = start_app(mode, key, package)
        logs = collect(pid, label, mode)
        found = re.search(rf"DETECT_RESULT (PASS|FAIL) mode={re.escape(mode)}\b[^\n]*", logs)
        if not found:
            raise RuntimeError(f"{label}: no DETECT_RESULT")
        cases = [kv(line) for line in re.findall(r"ELIM_CASE [^\n]+", logs)]
        run = {"label": label, "mode": mode, "pid": pid, "result": found[0],
               "app_pass": found[1] == "PASS", "cases": cases,
               "execution": execution_cases(logs),
               "store_checks": store_cases(logs, mode),
               "bridge_checks": [kv(line) for line in re.findall(r"ELIM_BRIDGE [^\n]+", logs)],
               "store_state": re.findall(r"ELIM_STORE_STATE [^\n]+", logs),
               "execution_state": re.findall(r"ELIM_EXEC_STATE [^\n]+", logs),
               "features": re.findall(r"ELIM_FEATURE [^\n]+", logs),
               "business": re.findall(r"ELIM_BUSINESS [^\n]+", logs),
               "residuals": re.findall(r"ELIM_RESIDUAL [^\n]+", logs),
               "timing": re.findall(r"ELIM_TIMING [^\n]+", logs),
               "log": f"{label}-{pid}.log",
               "uid": app_uid(logs)}
        report["runs"].append(run)
        print(f"{label}: {found[0]}", flush=True)
        for line in re.findall(r"ELIM_CASE [^\n]+", logs):
            print("  " + line, flush=True)
        for line in run["features"] + run["residuals"] + run["timing"]:
            print("  " + line, flush=True)
        if found[1] != "PASS" or (mode.startswith(("y-", "z-", "w-")) and not run["execution"]):
            raise RuntimeError(f"{label}: app assertions failed")
        return run, logs

    try:
        report["initial_modules"] = kp("kpm", "list")
        if report["initial_modules"].strip():
            raise RuntimeError("existing modules preserved; no fixture changes made")
        safe_cleanup = True
        report["root"] = kp("su", "-c", "id")
        report["kernel"] = shell("uname", "-a")
        report["initial_boot_id"] = shell("cat", "/proc/sys/kernel/random/boot_id")
        report["fingerprint"] = shell("getprop", "ro.build.fingerprint")
        report["device_time"] = shell("date", "+%Y-%m-%dT%H:%M:%S%z")
        report["kpver"] = kp("kpver")
        before = kp("su", "-c", "dmesg")
        artifacts = {"y_kpm": LAB / "out/urov-y.kpm",
                     "apk": LAB / "apps/urov-detect/out/urovdetect.apk",
                     "observer_apk": LAB / "apps/urov-detect/out/urovobserver.apk"}
        variants = ("y",) if args.skip_x_control else ("x", "y")
        if not args.skip_x_control:
            artifacts["x_kpm"] = LAB / "out/urov-x.kpm"
        report["artifacts"] = {k: {"path": str(v),
                                   "sha256": hashlib.sha256(v.read_bytes()).hexdigest()}
                               for k, v in artifacts.items()}
        if not args.skip_install:
            for kind in ("apk", "observer_apk"):
                adb(["install", "--no-incremental", "-r", str(artifacts[kind])], timeout=180)
        remote = f"/data/local/tmp/urov-eliminate-{stamp}"
        shell("mkdir", remote)
        staged = [f"{remote}/urov-{variant}.kpm" for variant in variants]
        for variant, path in zip(variants, staged):
            adb(["push", str(artifacts[f"{variant}_kpm"]), path])

        run_app("01-no-module", "y-clean")

        report["x_control_skipped"] = args.skip_x_control
        if not args.skip_x_control:
            # Positive control using the same detector and fixture page.
            kp("kpm", "load", staged[0], f"key={control_key}")
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

        kp("kpm", "load", staged[-1], f"key={module_key}")
        loaded = "urov-y"
        if args.active_unload:
            info = kp("kpm", "info", loaded)
            if not re.search(r"^callback_context=sleepable-v2$", info, re.M):
                raise RuntimeError("active unload requires a loader reporting sleepable-v2")
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

        for cycle in range(args.cycles):
            run, _ = run_app(f"06-ap-{cycle + 1}", "w-active", key=module_key)
            if not run["cases"]:
                raise RuntimeError("w-active produced no observation cases")
            store_names = {c["name"] for c in run["store_checks"]}
            # The app asserts its baseline and deactivated controls itself;
            # some logd builds drop individual records. Require evidence of
            # the active store paths in addition to the native PASS result.
            if not {"active_changed", "active_outside_window", "active_equal_value"} <= store_names or not any(
                        name.startswith("active_cpu_") for name in store_names):
                raise RuntimeError("w-active store matrix incomplete")
            for case in run["cases"]:
                if case["name"].startswith("active") and (
                        int(case["exclusive_match"]) != 0 or int(case["exclusive_clean"]) == 0 or
                        int(case["reader_match"]) != 0):
                    raise RuntimeError(f"unexpected AP reservation/read result on {case['name']}")
            if "state=inactive" not in kp("kpm", "ctl0", "urov-y", "status"):
                raise RuntimeError("AP fixture leaked a session")
            # The 2026-11-05 execution canary is the feature this mode removes:
            # the site page is not execute-never, so every canary trial must
            # execute natively and leave the exclusive monitor alone.
            if any(int(e["expected"]) != 0 or int(e["match"]) != 0
                   for e in run["execution"]):
                raise RuntimeError("AP mode still traps instruction fetch")
            active = [r for r in run["residuals"] if "mode=ap" in r and "site_live_word" in r]
            if not active or any("differs=0" not in r for r in active):
                raise RuntimeError("AP-mode site word differs from the file")
            if any("site_cow_private=0" not in r for r in active):
                raise RuntimeError("AP-mode site page is private")
            for r in active:
                fields = kv(r)
                if (fields.get("private_dirty_kb") != fields.get("base_dirty_kb") or
                        fields.get("anonymous_kb") != fields.get("base_anonymous_kb")):
                    raise RuntimeError("AP-mode page accounting changed")

        # Keep the owner running across unload. By default it restores the
        # session itself, avoiding teardown inside legacy RCU loader context.
        for prefix, label in (("y", "07-hold"), ("z", "08-hold-page"), ("w", "09-hold-ap")):
            hold_mode = prefix + ("-hold" if args.active_unload else "-quiesce")
            pid = start_app(hold_mode, module_key)
            hold_logs = collect(pid, label, hold_mode, wait_for="ELIM_HOLD_READY")
            if "ELIM_HOLD_READY" not in hold_logs:
                raise RuntimeError(f"{hold_mode} fixture did not arm")
            status = kp("kpm", "ctl0", "urov-y", "status")
            report[f"{label}_status"] = status
            if "state=active" not in status:
                raise RuntimeError(f"{label} session is not active")
            uid = app_uid(hold_logs)
            hold_stores = store_cases(hold_logs, hold_mode)
            if prefix == "w":
                stores = sum(int(c["stores"]) for c in hold_stores)
                if stores != 0:
                    raise RuntimeError("AP retired a skipped-LDXR store")
                if int(kv(status)["llsc"]) != 0:
                    raise RuntimeError("AP reported an emulated store")
            if prefix in ("z", "w"):
                is_ap = prefix == "w"
                observer_label = "09-other-uid-ap" if is_ap else "08-other-uid"
                observer, _ = run_app(observer_label, "z-observer", package=OBSERVER)
                if observer["uid"] == uid:
                    raise RuntimeError("observer has the owner's UID")
                after_observer = kp("kpm", "ctl0", "urov-y", "status")
                status_key = "other_uid_ap_owner_status" if is_ap else "other_uid_owner_status"
                report[status_key] = after_observer
                if "state=active" not in after_observer:
                    raise RuntimeError("owner session ended during observation")
                if kv(after_observer)["llsc"] != kv(status)["llsc"]:
                    raise RuntimeError("owner store counter changed during foreign observation")
            if not args.active_unload:
                quiet = collect(pid, label, hold_mode, wait_for="ELIM_HOLD_QUIESCED")
                status = kp("kpm", "ctl0", "urov-y", "status")
                if "ELIM_HOLD_QUIESCED" not in quiet or "state=inactive" not in status:
                    raise RuntimeError(f"{label} did not quiesce before unload")
                report[f"{label}_quiesced_status"] = status
            report[f"{label}_unload"] = kp("kpm", "unload", "urov-y", timeout=20)
            if kp("kpm", "list").strip():
                raise RuntimeError("unload did not remove the module")
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
                                   "pid": pid, "uid": uid, "result": result[0],
                                   "execution": execution_cases(hold_logs),
                                   "store_checks": store_cases(hold_logs, hold_mode),
                                   "restored": restored,
                                   "log": f"{label}-after-unload-{pid}.log"})
            print(f"{label}-after-unload: {result[0]}", flush=True)
            for line in restored:
                print("  " + line, flush=True)
            if prefix in ("z", "w"):
                fields = kv(restored[0])
                if fields.get("private_dirty_kb") != fields.get("base_dirty_kb") or \
                        fields.get("anonymous_kb") != fields.get("base_anonymous_kb"):
                    raise RuntimeError("page-mode site page changed after unload")
            if prefix in ("y", "z"):
                kp("kpm", "load", staged[-1], f"key={module_key}")
                loaded = "urov-y"

        run_app("10-final-clean", "y-clean")
        report["passed"] = True
    except Exception as exc:
        report["error"] = redact(str(exc))
        print("ERROR " + report["error"], flush=True)
    finally:
        if safe_cleanup:
            try:
                for package in (PACKAGE, OBSERVER):
                    shell("am", "force-stop", package)
                if loaded:
                    kp("kpm", "unload", loaded, timeout=20)
                if staged:
                    shell("rm", "-f", *staged)
                    shell("rmdir", remote)
                report["final_modules"] = kp("kpm", "list")
                report["final_boot_id"] = shell("cat", "/proc/sys/kernel/random/boot_id")
                after = kp("su", "-c", "dmesg")
                times = re.findall(r"^\[\s*([0-9.]+)\]", before, re.M)
                since = float(times[-1]) if times else 0
                lines = [line for line in after.splitlines()
                         if (m := re.match(r"^\[\s*([0-9.]+)\]", line)) and float(m[1]) > since]
                save("kernel-new.log", "\n".join(lines))
                report["kernel_issues"] = [line for line in lines if re.search(
                    r"\bBUG:|\bWARNING:|\bOops:|\bKernel panic|\brcu[^\n]*stall|\bhung task|\bCall trace",
                    line)]
                if (report["final_modules"].strip() or report["kernel_issues"] or
                        report["final_boot_id"] != report["initial_boot_id"]):
                    report["passed"] = False
            except Exception as exc:
                report["verification_error"] = redact(str(exc))
                report["passed"] = False
        totals = {"runs": len(report["runs"]), "elim_cases": 0, "observations": 0,
                  "exclusive_matches": 0, "exclusive_clean": 0, "exclusive_unknown": 0,
                  "accepted_triplets": 0, "failed_target_stores": 0,
                  "control_failed_stores": 0, "reader_matches": 0, "reader_clean": 0,
                  "reader_unknown": 0, "feature_business_reads": 0}
        execution_fields = ("n", "match", "clean", "unknown", "accepted", "failed",
                            "control_failed")
        execution = {scope: dict.fromkeys(execution_fields, 0)
                     for scope in ("active_page", "controls")}
        store_fields = ("n", "match", "clean", "unknown", "completed", "stores", "total_ns")
        stores = {scope: dict.fromkeys(store_fields, 0) for scope in ("ap_active", "controls")}
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
            for case in run.get("execution", []):
                scope = "active_page" if case["expected"] == "1" else "controls"
                for field in execution_fields:
                    execution[scope][field] += int(case[field])
            for case in run.get("store_checks", []):
                mode = run.get("mode")
                ap_active = ((mode == "w-active" and case["name"].startswith("active_")) or
                             (mode in ("w-hold", "w-quiesce") and case["name"] == "hold_active"))
                scope = "ap_active" if ap_active else "controls"
                for field in store_fields:
                    stores[scope][field] += int(case[field])
        report["totals"] = totals
        report["execution_totals"] = execution
        report["store_totals"] = stores
        save("summary.json", json.dumps(report, ensure_ascii=False, indent=2))
        print(f"RESULT {'PASS' if report['passed'] else 'FAIL'} {output}", flush=True)
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
