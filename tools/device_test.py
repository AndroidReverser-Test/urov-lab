#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Run baselines, then optionally exercise UROV on an already prepared kernel.

No boot image preparation, flashing, reboot, or automatic module cleanup.
Credentials come from getpass or --key-fd; they are never written to the report.
The installed kpatch CLI necessarily receives its key in device-side argv.
"""
import argparse
from datetime import datetime, timezone
import getpass
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import uuid

LAB = Path(__file__).resolve().parents[1]
TEST_PROGRAMS = ("urov_lab_test", "urov_copy_probe", "urov_vector_fault_probe")


def credential(fd):
    if fd is None:
        key = getpass.getpass("KernelPatch key: ").encode("utf-8")
    else:
        data = bytearray()
        while len(data) < 65:
            char = os.read(fd, 1)
            if not char or char == b"\n":
                break
            data.extend(char)
        key = bytes(data).rstrip(b"\r")
    if not 1 <= len(key) <= 63 or any(c in key for c in (b"\0", b"\r", b"\n")):
        raise ValueError("Key must contain 1..63 bytes without NUL or newlines")
    key.decode("utf-8")
    return key


class Device:
    def __init__(self, adb, serial, key):
        self.adb = [adb, "-s", serial]
        self.key = key
        self.runs = []

    def run(self, label, args, data=None):
        try:
            proc = subprocess.run(self.adb + args, input=data, stdout=subprocess.PIPE,
                                  stderr=subprocess.STDOUT, timeout=75, check=False)
            output, rc = proc.stdout, proc.returncode
        except subprocess.TimeoutExpired as exc:
            output, rc = exc.stdout or b"", 124
        # No commands/argv or input are recorded. Redact even unexpected CLI output.
        output = output.decode("utf-8", errors="replace").replace(self.key.decode("utf-8"), "<redacted>")
        record = {"name": label, "returncode": rc, "output": output[:20000]}
        self.runs.append(record)
        print("{}: rc={}".format(label, rc), flush=True)
        return record

    def shell(self, label, command):
        return self.run(label, ["shell", "exec timeout 60 sh -c " + shlex.quote(command)])

    def kpatch(self, label, args, key_input=False):
        command = ('IFS= read -r UROV_KEY && exec timeout 60 /data/local/tmp/kpatch '
                   '"$UROV_KEY" ' + " ".join(shlex.quote(x) for x in args))
        data = self.key + b"\n"
        if key_input:
            data += self.key + b"\n"
        return self.run(label, ["shell", command], data)

    def root(self, label, command, key_input=False):
        return self.kpatch(label, ["su", "-c", "exec " + command], key_input)

    @staticmethod
    def checked(record):
        if record["returncode"]:
            raise RuntimeError("Command failed: " + record["name"])
        return record["output"].strip()

    def snapshot(self, suffix):
        boot = self.checked(self.shell("boot_" + suffix, "cat /proc/sys/kernel/random/boot_id"))
        if not re.fullmatch(r"[0-9a-f-]{36}", boot):
            raise RuntimeError("Invalid boot_id")
        kp = self.checked(self.kpatch("kp_version_" + suffix, ["kpver"]))
        if not re.fullmatch(r"(?:0x)?[0-9a-fA-F]{1,8}", kp) or int(kp, 16) in (0, 0xffffffff):
            raise RuntimeError("Invalid KP version or authorization")
        count = self.checked(self.kpatch("module_count_" + suffix, ["kpm", "num"]))
        if not re.fullmatch(r"[0-9]+", count):
            raise RuntimeError("Invalid module count")
        names = self.checked(self.kpatch("module_list_" + suffix, ["kpm", "list"]))
        modules = sorted(x for x in names.splitlines() if x)
        if len(modules) != int(count):
            raise RuntimeError("Module list/count mismatch")
        return {"boot_id": boot, "kp": kp, "modules": modules}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--adb", default="adb")
    parser.add_argument("--serial", required=True)
    parser.add_argument("--out", type=Path, default=LAB / "out")
    parser.add_argument("--report", type=Path)
    parser.add_argument("--key-fd", type=int)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--activate", action="store_true", help="requires all baselines to pass")
    mode.add_argument("--inspect", action="store_true", help="load, query and unload the KPM in read-only mode")
    parser.add_argument("--allow-raw-xom", action="store_true")
    parser.add_argument("--iterations", type=int, default=100)
    args = parser.parse_args()
    if args.allow_raw_xom and not args.activate:
        parser.error("--allow-raw-xom requires --activate")
    if not 1 <= args.iterations <= 10000:
        parser.error("--iterations must be 1..10000")
    # Validate local inputs before requesting a credential or changing the device.
    module = "urov-lab-native.kpm" if args.activate else "urov-lab.kpm"
    hashes = {name: hashlib.sha256((args.out / name).read_bytes()).hexdigest()
              for name in (module, *TEST_PROGRAMS)}
    try:
        key = credential(args.key_fd)
    except (OSError, ValueError, UnicodeError) as exc:
        parser.error(str(exc))
    device = Device(args.adb, args.serial, key)
    remote = "/data/local/tmp/urov-" + uuid.uuid4().hex
    report_path = args.report or args.out / ("device-report-" + uuid.uuid4().hex + ".json")
    report = {"schema": 1, "utc": datetime.now(timezone.utc).isoformat(), "serial": args.serial,
              "remote_directory": remote, "artifacts_sha256": hashes, "runs": device.runs,
              "activate_requested": args.activate, "inspect_requested": args.inspect,
              "raw_xom_requested": args.allow_raw_xom,
              "outcome": "ERROR", "overlay_test": "NOT_RUN"}
    exit_code = 1
    try:
        report["before"] = device.snapshot("before")
        report["kernel"] = device.checked(device.shell("kernel", "uname -r"))
        uid = device.checked(device.root("root_identity", "id -u"))
        if uid != "0":
            raise RuntimeError("Root identity check failed")
        if "urov-lab" in report["before"]["modules"]:
            raise RuntimeError("urov-lab is already loaded; existing instance left for its owner")
        device.checked(device.shell("mkdir", "mkdir -m 700 " + shlex.quote(remote)))
        for name, expected in hashes.items():
            target = remote + "/" + name
            device.checked(device.run("push_" + name, ["push", str(args.out / name), target]))
            actual = device.checked(device.shell("hash_" + name, "sha256sum " + shlex.quote(target)))
            if actual.split()[0].lower() != expected:
                raise RuntimeError("Device SHA256 mismatch: " + name)
            mode = "644" if name.endswith(".kpm") else "755"
            device.checked(device.shell("chmod_" + name, "chmod " + mode + " " + shlex.quote(target)))
        baselines = []
        for name in ("urov_copy_probe", "urov_vector_fault_probe"):
            for root in (False, True):
                label = ("root_" if root else "shell_") + name
                run = device.root if root else device.shell
                result = run(label, shlex.quote(remote + "/" + name))
                baselines.append(result["returncode"] == 0 and "failures=0" in result["output"])
        result = device.root("root_self_text", shlex.quote(remote + "/urov_lab_test") + " --text-only")
        baselines.append(result["returncode"] == 0 and
                         "PASS scope=self_text_baseline overlay=NOT_ENABLED" in result["output"])
        report["baselines_passed"] = all(baselines)
        if args.inspect:
            command = (shlex.quote(remote + "/urov_lab_test") + " --inspect-only --key-fd 0 --module " +
                       shlex.quote(remote + "/" + module))
            result = device.root("standalone_inspection", command, key_input=True)
            passed = (result["returncode"] == 0 and
                      "PASS scope=standalone_inspection protocol=verified unloaded=1" in result["output"])
            report["inspection_test"] = "PASS" if passed else "FAIL"
            report["outcome"] = "INSPECTION_FAIL"
            if passed:
                report["outcome"] = "INSPECTION_PASS" if all(baselines) else "INSPECTION_PASS_BASELINE_BLOCKED"
            exit_code = 0 if passed else 1
        elif not all(baselines):
            report["outcome"], exit_code = "BLOCKED_BASELINE", 3
        elif not args.activate:
            report["outcome"], exit_code = "BASELINE_PASS", 0
        else:
            command = (shlex.quote(remote + "/urov_lab_test") + " --key-fd 0 --module " +
                       shlex.quote(remote + "/" + module) + " --iterations " + str(args.iterations))
            if args.allow_raw_xom:
                command += " --allow-raw-xom"
            result = device.root("active_overlay", command, key_input=True)
            report["overlay_test"] = "FAIL"
            if result["returncode"] == 0 and "scope=active_overlay" in result["output"]:
                report["outcome"], report["overlay_test"], exit_code = "ACTIVE_PASS", "PASS", 0
            elif result["returncode"] == 2:
                report["outcome"], report["overlay_test"], exit_code = "BLOCKED_CAPABILITY", "NOT_RUN", 2
            else:
                report["outcome"], exit_code = "ACTIVE_FAIL", 1
    except (OSError, RuntimeError) as exc:
        report["error"] = str(exc).replace(key.decode("utf-8"), "<redacted>")
    finally:
        if "before" in report:
            try:
                report["after"] = device.snapshot("after")
                report["boot_unchanged"] = report["before"]["boot_id"] == report["after"]["boot_id"]
                report["modules_unchanged"] = report["before"]["modules"] == report["after"]["modules"]
                if not report["boot_unchanged"] or not report["modules_unchanged"]:
                    report["outcome"], exit_code = "ERROR_STATE_CHANGED", 1
            except (OSError, RuntimeError) as exc:
                report["state_error"] = str(exc).replace(key.decode("utf-8"), "<redacted>")
                report["outcome"], exit_code = "ERROR_STATE_UNKNOWN", 1
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_bytes((json.dumps(report, ensure_ascii=False, indent=2) + "\n").encode("utf-8"))
        print("outcome={} overlay_test={} report={}".format(report["outcome"], report["overlay_test"], report_path))
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
