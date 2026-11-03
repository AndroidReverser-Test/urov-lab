#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
"""Generate verified structure offsets for the host regression model."""
import argparse
import json
from pathlib import Path
import subprocess

LAB = Path(__file__).resolve().parents[1]


def run(*args):
    return subprocess.check_output([str(x) for x in args], text=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--btf', type=Path, required=True)
    args = parser.parse_args()
    out = LAB / 'out'
    out.mkdir(exist_ok=True)
    profile = json.loads(run('node', LAB / 'tools/inspect_btf.js', args.btf))
    expected = 'ef6ffa2e5d2f10ad1438a89a77d42747e80c7b78367c1d191140c5e623ff4970'
    if profile['sha256'] != expected:
        raise SystemExit('Unsupported kernel BTF: this port is only for 66e758f7d0c0 / Pixel 6')
    lines = ['/* Host test layout from BTF SHA256 ' + expected + '. */',
             '#ifndef UROV_PROFILE_H', '#define UROV_PROFILE_H']
    for name, candidates in profile['structs'].items():
        if len(candidates) != 1:
            raise SystemExit('Ambiguous structure: ' + name)
        for field, matches in candidates[0]['fields'].items():
            if len(matches) != 1 or matches[0]['bitfieldSize'] or matches[0]['bitOffset'] % 8:
                raise SystemExit('Ambiguous field: ' + name + '.' + field)
            lines.append('#define O_%s_%s %d' % (name, field, matches[0]['byteOffset']))
    lines.append('#endif')
    (out / 'resident_profile.h').write_text('\n'.join(lines) + '\n')
    print('Generated test profile:', out / 'resident_profile.h')


if __name__ == '__main__':
    main()
