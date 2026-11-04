#!/usr/bin/env python3
"""UROV-X covert-overlay device matrix.

Root (kpatch) is used only for the KPM lifecycle and the kernel-side truth. The
ordinary apps run as untrusted_app with seccomp, no capabilities and no root.

Phases:
  01  no module loaded        x-clean must behave like an unprotected device
  02  urov-lab loaded         the *unchanged* detector must still catch it
  03  urov-x loaded, no key   x-clean must stay blind to the covert channel
  04  urov-x + key            x-active: overlay works at the sites, detector blind
  05  urov-x + key            x-simd: unsupported reader degrades without signal
  06  urov-x + key            x-fork: children never inherit the protected page
  07  owner hold + observer   cross-UID invisibility, unload while active
  08  post unload             x-clean again

Build first:
    .\\kpms\\urov-lab\\build.ps1
    .\\kpms\\urov-lab\\apps\\urov-detect\\build.ps1
    .\\kpms\\urov-lab\\apps\\urov-detect\\build.ps1 -Observer
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
OWNER_ACT = "com.example.urovdetect.MainActivity"
OBSERVER_ACT = "com.example.urovdetect.ObserverActivity"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--serial", required=True)
    parser.add_argument("--key", required=True, help="KernelPatch superkey; never persisted")
    parser.add_argument("--module-key", required=True, help="UROV-X control secret; never persisted")
    parser.add_argument("--repeats", type=int, default=30)
    parser.add_argument("--cycles", type=int, default=3)
    args = parser.parse_args()
    if not 3 <= args.repeats <= 200 or not 1 <= args.cycles <= 10:
        parser.error("repeats must be 3..200; cycles must be 1..10")
    if not re.fullmatch(r"[0-9a-fA-F]{32}", args.module_key):
        parser.error("module-key must be 32 hex digits")

    stamp = datetime.now(timezone(timedelta(hours=8))).strftime("%Y%m%d-%H%M%S")
    output = LAB / "results" / f"stealth-{stamp}"
    output.mkdir(parents=True, exist_ok=False)
    report = {"host_time_utc8": stamp, "serial": args.serial, "repeats": args.repeats,
              "cycles": args.cycles, "steps": [], "runs": [], "passed": False}
    prefix = ["adb", "-s", args.serial]
    loaded_module = None
    dmesg_before = ""

    def redact(text):
        return text.replace(args.key, "<KEY>").replace(args.module_key, "<MODULE-KEY>")

    def adb(argv, check=True, timeout=30):
        result = subprocess.run(prefix + argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                timeout=timeout, encoding="utf-8", errors="replace")
        text = redact(result.stdout).strip()
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
                      "urovdetect:I", "AndroidRuntime:E", "libc:F", "DEBUG:F"])[1]

    def launch(mode, package=OWNER, activity=OWNER_ACT, module_key=None):
        shell(["am", "force-stop", package])
        argv = ["am", "start", "-W", "-n", f"{package}/{activity}", "--es", "mode", mode,
                "--ei", "repeats", str(args.repeats)]
        if module_key:
            argv += ["--es", "key", module_key]
        shell(argv)
        pid = shell(["pidof", package])[1].split()[0]
        return {"mode": mode, "label": None, "pid": pid, "package": package,
                "activity": activity}

    def wait_log(run, pattern, timeout=60):
        until = time.monotonic() + timeout
        last = ""
        while time.monotonic() < until:
            last = app_log(run["pid"])
            save(f"{run['pid']}-{run['mode']}.log", last)
            if re.search(pattern, last):
                return last
            if "Fatal signal" in last or "FATAL EXCEPTION" in last or "Fatal exception" in last:
                raise RuntimeError(f"{run['mode']}: app crashed; see its log")
            time.sleep(0.25)
        raise RuntimeError(f"{run['mode']}: timeout waiting for {pattern}")

    def finish(run, label, expect_pass=True, must_be_ordinary=True):
        logs = wait_log(run, rf"(?:DETECT_RESULT|NATIVE_RESULT) (?:PASS|FAIL) mode={re.escape(run['mode'])}\b")
        native = re.search(rf"NATIVE_RESULT (PASS|FAIL)[^\n]*mode={re.escape(run['mode'])}", logs)
        detect = re.search(rf"DETECT_RESULT (PASS|FAIL) mode={re.escape(run['mode'])}\b", logs)
        run["label"] = label
        run["result"] = detect[1] if detect else native[1]
        run["log"] = f"{run['pid']}-{run['mode']}.log"
        if expect_pass and run["result"] != "PASS":
            raise RuntimeError(f"{label}: {run['result']}")
        if must_be_ordinary:
            if not re.search(r"CapEff:\s*0{16}\b", logs) or not re.search(r"Seccomp:\s*2\b", logs):
                raise RuntimeError(f"{label}: not an ordinary seccomp-confined app")
            if "selinux=u:r:untrusted_app:" not in logs:
                raise RuntimeError(f"{label}: unexpected SELinux domain")
            run["uid"] = int(re.search(r"CONTEXT pid=\d+ uid=(\d+)", logs)[1])
        report["runs"].append(run)
        step(label, f"{run['result']} uid={run.get('uid', '?')}")
        return logs

    def parse_pairs(text):
        return {key: int(value, 0) for key, value in re.findall(
            r"([a-zA-Z_][a-zA-Z_0-9]*)=(-?(?:0x[0-9a-f]+|[0-9]+))", text)}

    def check(name, condition, detail):
        entry = {"name": name, "ok": bool(condition), "detail": detail}
        report.setdefault("checks", []).append(entry)
        if not condition:
            raise RuntimeError(f"check failed: {name}: {detail}")
        print(f"  ok {name}: {detail}", flush=True)

    def load_module(path, module_args, name):
        nonlocal loaded_module
        current = kpatch("kpm", "list")
        if re.search(rf"\b{re.escape(name)}\b", current):
            raise RuntimeError(f"{name} already loaded; preserve it and stop")
        kpatch("kpm", "load", path, module_args)
        loaded_module = name
        listed = kpatch("kpm", "list")
        if name not in listed:
            raise RuntimeError(f"{name} did not appear in kpm list")
        return kpatch("kpm", "ctl0", name, "status")

    def unload_module(name):
        nonlocal loaded_module
        kpatch("kpm", "unload", name)
        loaded_module = None
        if re.search(rf"\b{re.escape(name)}\b", kpatch("kpm", "list")):
            raise RuntimeError(f"{name} still listed after unload")

    try:
        step("root", kpatch("su", "-c", "id"))
        initial = kpatch("kpm", "list")
        report["initial_modules"] = initial
        if initial.strip():
            raise RuntimeError("a KPM is already loaded; preserve it and stop")
        report["device"] = shell(["getprop", "ro.build.fingerprint"])[1]
        report["kernel"] = shell(["uname", "-a"])[1]
        report["device_time"] = shell(["date", "+%Y-%m-%dT%H:%M:%S%z"])[1]
        report["kpver"] = kpatch("kpver")
        dmesg_before = kpatch("su", "-c", "dmesg")
        save("kernel-before.log", dmesg_before)

        artifacts = {"stealth_kpm": LAB / "out/urov-x.kpm",
                     "baseline_kpm": LAB / "out/urov-lab.kpm",
                     "detector_apk": LAB / "apps/urov-detect/out/urovdetect.apk",
                     "observer_apk": LAB / "apps/urov-detect/out/urovobserver.apk"}
        report["artifacts"] = {}
        for kind, path in artifacts.items():
            if not path.is_file():
                raise RuntimeError(f"missing artifact {path}")
            report["artifacts"][kind] = {"path": str(path),
                                         "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
        for kind in ("detector_apk", "observer_apk"):
            adb(["install", "--no-incremental", "-r", str(artifacts[kind])], timeout=60)

        # 01 - no module: a clean device.
        run = launch("x-clean")
        logs = finish(run, "01-clean-no-module")
        check("clean-no-module", re.search(r"NATIVE_RESULT PASS[^\n]*mode=x-clean", logs),
              "no module, no channel, no overlay")
        if "UX_PROOF" in logs:
            raise RuntimeError("x-clean must not run the active fixture")
        run["phase"] = "no module"

        # 02 - the original urov-lab module is still detected by the same app.
        status = load_module("/data/local/tmp/urov-lab.kpm", "active", "urov-lab")
        step("urov-lab-status", status)
        run = launch("active")
        logs = finish(run, "02-original-detected")
        cases = [parse_pairs(line) for line in re.findall(r"CASE \S+ result=PASS [^\n]+", logs)]
        positive_ctl = [case for case in cases if case.get("ctl") == 1]
        positive_file = [case for case in cases if case.get("file") == 1]
        native = re.search(r"NATIVE_RESULT PASS cases=\d+[^\n]*module=(\d+)[^\n]*mode=active", logs)
        report["baseline"] = {"cases": len(cases),
                              "positive_control": len(positive_ctl),
                              "positive_file_diff": len(positive_file),
                              "module_verdict": int(native[1]) if native else None,
                              "sample": positive_file[0] if positive_file else None}
        check("original-fingerprint", report["baseline"]["module_verdict"] == 1,
              f"control verdict={report['baseline']['module_verdict']}")
        check("original-scope", any(c.get("scope") == 1 for c in positive_ctl),
              f"{len(positive_ctl)} cases saw SELF scope")
        check("original-file-diff", len(positive_file) > 0,
              f"{len(positive_file)} cases saw read/file divergence")
        unload_module("urov-lab")

        # 03 - covert channel loaded but the app has no key.
        status = load_module("/data/local/tmp/urov-x.kpm",
                             f"key={args.module_key}", "urov-x")
        step("urov-x-status", status)
        check("stealth-hooks", "hooks=0x1f" in status, status.strip())
        run = launch("x-clean")
        logs = finish(run, "03-stealth-loaded-unkeyed")
        if "UX_PROOF" in logs:
            raise RuntimeError("x-clean must not touch the keyed channel")

        # 04 - keyed activation. The detector stays blind, the overlay works.
        for cycle in range(args.cycles):
            run = launch("x-active", module_key=args.module_key)
            logs = finish(run, f"04-stealth-active-{cycle + 1}")
            proof = re.search(r"UX_PROOF ([^\n]+)", logs)
            if not proof:
                raise RuntimeError("missing UX_PROOF evidence")
            values = parse_pairs(proof[1])
            check(f"stealth-control-blind-{cycle + 1}", values["control"] == 0,
                  f"control={values['control']} scope={values['scope']}")
            check(f"stealth-file-blind-{cycle + 1}",
                  values["file_diff"] == 0 and values["rounds"] == 3,
                  f"file_diff={values['file_diff']} rounds={values['rounds']}")
            check(f"stealth-smaps-clean-{cycle + 1}",
                  values["smaps_dc"] == 0 and values["smaps_rr"] == 0,
                  f"dc={values['smaps_dc']} rr={values['smaps_rr']}")
            check(f"stealth-site-works-{cycle + 1}",
                  values["site"] != values["file_word"] and values["hits_delta"] >= 2,
                  f"site=0x{values['site']:x} file=0x{values['file_word']:x} "
                  f"hits_delta={values['hits_delta']}")
            check(f"stealth-watch-native-{cycle + 1}",
                  values["watch"] == values["file_word"] & 0xff,
                  f"watch=0x{values['watch']:02x}")
            run["proof"] = values
            state = kpatch("kpm", "ctl0", "urov-x", "status")
            if "state=inactive" not in state:
                raise RuntimeError(f"cycle {cycle + 1} left a session behind: {state}")

        # 05 - an unauthorized reader outside the decoder subset must not crash.
        run = launch("x-simd", module_key=args.module_key)
        finish(run, "05-stealth-simd-fallback")

        # 06 - fork children never inherit the protected page.
        run = launch("x-fork", module_key=args.module_key)
        finish(run, "06-stealth-fork-child")

        # 07 - another UID cannot see or disturb the owner's session.
        owner = launch("x-hold", module_key=args.module_key)
        wait_log(owner, r"HOLD_READY\b")
        state_before = kpatch("kpm", "ctl0", "urov-x", "status")
        step("owner-hold-status", state_before)
        check("owner-active", "state=active" in state_before and "sites=2" in state_before,
              state_before.strip())
        observer = launch("x-observer", package=OBSERVER, activity=OBSERVER_ACT)
        finish(observer, "07-observer-other-uid")
        state_after = kpatch("kpm", "ctl0", "urov-x", "status")
        # The owner keeps reading its authorized site, so its own hit counter
        # advances; everything else must be untouched by the foreign process.
        def stable_status(text):
            return re.sub(r"hits=\d+", "hits=*", text)
        check("observer-invisible", stable_status(state_before) == stable_status(state_after),
              f"{state_before.strip()} -> {state_after.strip()}")
        if observer.get("uid") == owner.get("uid"):
            raise RuntimeError("observer must have a different app UID")
        unload_module("urov-x")
        owner_logs = wait_log(owner, r"HOLD_UNLOADED\b")
        finish(owner, "07-owner-unload-restored")
        if "restored=1" not in owner_logs:
            raise RuntimeError("owner did not observe restoration")

        # 08 - back to a clean device.
        run = launch("x-clean")
        finish(run, "08-post-unload-clean")

        report["passed"] = True
    except Exception as exc:
        report["error"] = redact(str(exc))
        print("ERROR: " + report["error"], flush=True)
    finally:
        if loaded_module:
            try:
                unload_module(loaded_module)
            except Exception:
                report["cleanup_error"] = "module unload failed"
                report["passed"] = False
        for package in (OWNER, OBSERVER):
            shell(["am", "force-stop", package], check=False)
        try:
            report["final_modules"] = kpatch("kpm", "list")
            if report["final_modules"].strip():
                report["passed"] = False
            after = kpatch("su", "-c", "dmesg")
            save("kernel-after.log", after)
            times = re.findall(r"^\[\s*([0-9.]+)\]", dmesg_before, re.M)
            since = float(times[-1]) if times else 0.0
            new_lines = []
            for line in after.splitlines():
                found = re.match(r"\[\s*([0-9.]+)\]", line)
                if found and float(found[1]) > since:
                    new_lines.append(line)
            save("kernel-new.log", "\n".join(new_lines))
            report["kernel_issues"] = [line for line in new_lines if re.search(
                r"BUG:|WARNING:|Oops:|Kernel panic|rcu[^\n]*stall|hung task|Call trace",
                line, re.I)]
            if report["kernel_issues"]:
                report["passed"] = False
        except Exception as exc:
            report["verification_error"] = redact(str(exc))
            report["passed"] = False
        save("summary.json", json.dumps(report, ensure_ascii=False, indent=2))
        print(f"RESULT {'PASS' if report['passed'] else 'FAIL'} {output}", flush=True)
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
