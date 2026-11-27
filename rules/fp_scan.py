"""
False-positive scan for the YARA rule set (M11).

Compiles rules/yara/*.yar and scans one or more directory trees of KNOWN-GOOD files (goodware),
reporting any match as a false positive. A clean supplementary rule should produce zero FPs on
system binaries while still firing on the measured gap samples (see tests/test_rules.py).

Usage:
    python rules/fp_scan.py                      # default goodware dirs (Windows system + .NET)
    python rules/fp_scan.py <dir> [<dir> ...]    # custom dirs
"""
from __future__ import annotations
import glob
import os
import sys
import time

import yara  # yara-python

EXTS = {".exe", ".dll", ".sys", ".ocx", ".cpl", ".bin", ".scr"}
DEFAULT_DIRS = [
    r"C:\Windows\System32",
    r"C:\Windows\SysWOW64",
    r"C:\Windows\Microsoft.NET\Framework64",
    r"C:\Windows\Microsoft.NET\Framework",
]


def compile_rules(rule_glob="rules/yara/*.yar"):
    files = glob.glob(rule_glob)
    if not files:
        raise SystemExit(f"no YARA rules at {rule_glob}")
    return yara.compile(filepaths={os.path.basename(f): f for f in files}), files


def scan_dirs(dirs):
    rules, rule_files = compile_rules()
    scanned = errors = 0
    fps = []
    t0 = time.time()
    for d in dirs:
        if not os.path.isdir(d):
            print(f"  (skip, not found: {d})")
            continue
        for root, _, names in os.walk(d):
            for n in names:
                if os.path.splitext(n)[1].lower() not in EXTS:
                    continue
                p = os.path.join(root, n)
                try:
                    m = rules.match(p, timeout=20)
                    scanned += 1
                    if m:
                        fps.append((p, [r.rule for r in m]))
                except Exception:
                    errors += 1
    return rule_files, scanned, errors, fps, time.time() - t0


def main(argv):
    dirs = argv[1:] or DEFAULT_DIRS
    print("YARA false-positive scan over goodware")
    print("Dirs:", ", ".join(dirs))
    rule_files, scanned, errors, fps, dt = scan_dirs(dirs)
    print(f"Rules: {len(rule_files)} ({', '.join(os.path.basename(f) for f in rule_files)})")
    print(f"Scanned: {scanned} files  |  skipped/locked: {errors}  |  {dt:.1f}s")
    if fps:
        print(f"FALSE POSITIVES: {len(fps)}")
        for p, rs in fps:
            print(f"  [FP] {p} -> {rs}")
        return 1
    print("FALSE POSITIVES: 0  (clean)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
