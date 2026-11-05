#!/usr/bin/env python3
"""Single-variable A/B for the LL/SC bridge: same (new) APK, two KPM builds.

Baseline KPM: urov-y-baseline.kpm (sha256 fbe8dc84...), the build measured in
PAGE_AP_KEYLESS_RESULTS.md: the adjacent bridge retires the store even when a
branch skipped the LDXR.

Verified KPM: urov-y.kpm built from the working tree: the bridge is armed only
when the LDXR result is still in Rt.

Both runs use mode=w-active (PAGE_AP) with the same APK, repeats and fixture.
The APK now expects NO_MATCH for ud_observe_unreserved_store(), so the baseline
run fails those assertions and the verified run passes them; the ELIM_STORE
lines are the actual evidence.
"""
import re
import secrets
import subprocess
import sys
import time
from pathlib import Path

SERIAL = "25091FDF60063J"
SUPERKEY = "Test6666"
LAB = Path(__file__).resolve().parents[2]
OUT = Path(__file__).resolve().parent
APK = LAB / "apps/urov-detect/out/urovdetect.apk"
KPATCH = "/data/local/tmp/kpatch"
VARIANTS = [
    ("baseline", LAB / "out/urov-y-baseline.kpm"),
    ("verified", LAB / "out/urov-y.kpm"),
]


def adb(args, timeout=120):
    r = subprocess.run(["adb", "-s", SERIAL, *args], stdout=subprocess.PIPE,
                       stderr=subprocess.STDOUT, encoding="utf-8",
                       errors="replace", timeout=timeout)
    return r.returncode, r.stdout


def shell(cmd, timeout=120):
    return adb(["shell", cmd], timeout)


def main():
    rc, out = adb(["install", "--no-incremental", "-r", str(APK)], timeout=180)
    print(out.strip())
    if rc:
        return 1
    for name, path in VARIANTS:
        remote = f"/data/local/tmp/ab-{name}.kpm"
        rc, out = adb(["push", str(path), remote])
        if rc:
            print(out)
            return 1
    results = {}
    for name, path in VARIANTS:
        key = secrets.token_hex(16)
        shell(f"am force-stop com.example.urovdetect")
        remote = f"/data/local/tmp/ab-{name}.kpm"
        rc, out = shell(f"{KPATCH} {SUPERKEY} kpm load {remote} key={key}")
        print(f"load {name}: rc={rc} {out.strip()}")
        if rc:
            return 1
        rc, out = shell(f"{KPATCH} {SUPERKEY} kpm ctl0 urov-y status")
        print(f"status {name}: {out.strip()}")
        rc, out = shell(
            "am start -W -n com.example.urovdetect/com.example.urovdetect.MainActivity "
            f"--es mode w-active --ei repeats 6 --es key {key}")
        print(out.strip().splitlines()[-1] if out.strip() else "am start failed")
        pid = ""
        for _ in range(20):
            rc, out = shell("pidof com.example.urovdetect")
            pid = out.strip().split()[0] if out.strip() else ""
            if pid:
                break
            time.sleep(0.2)
        logs = ""
        deadline = time.monotonic() + 90
        while time.monotonic() < deadline:
            rc, logs = shell(f"logcat -d --pid={pid} -v threadtime -s urovdetect:I "
                             "AndroidRuntime:E libc:F DEBUG:F")
            if "DETECT_RESULT" in logs or "Fatal signal" in logs:
                break
            time.sleep(0.25)
        (OUT / f"{name}.log").write_text(logs, encoding="utf-8")
        rc, out = shell(f"{KPATCH} {SUPERKEY} kpm ctl0 urov-y status")
        (OUT / f"{name}-status.txt").write_text(out, encoding="utf-8")
        print(f"app {name}:")
        for line in logs.splitlines():
            if "ELIM_STORE " in line or "DETECT_RESULT" in line:
                print("  " + line.split("urovdetect: ")[-1])
        shell(f"{KPATCH} {SUPERKEY} kpm unload urov-y")
        results[name] = logs
    # compact comparisons
    print("\nsummary")
    for name, logs in results.items():
        stores = re.findall(r"ELIM_STORE ([^\n]+)", logs)
        active = [s for s in stores if "name=active" in s]
        total_match = sum(int(re.search(r"match=(\d+)", s).group(1)) for s in active)
        total_stores = sum(int(re.search(r"stores=(\d+)", s).group(1)) for s in active)
        verdict = re.search(r"DETECT_RESULT (PASS|FAIL)", logs)
        print(f"  {name}: active_store_match={total_match} active_stores={total_stores} "
              f"app={verdict.group(1) if verdict else 'NO-RESULT'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
