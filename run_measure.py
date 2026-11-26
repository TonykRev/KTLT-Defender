"""
M10 — Main orchestration loop (Owner: Opus). Assembles all blocks into one atomic measurement.

Each measurement runs exactly this sequence:
  clean reset -> load/activate sample -> static scan (MpCmdRun) ->
  collect logs (Defender + Sysmon) -> compute fidelity -> score 1 of 4 states -> write to SQLite.

SAFETY (see docs/SAFETY.md):
  - DEFAULT is --dry-run: only lists measurements, activates NOTHING. --yes is required to run for real.
  - Invasive techniques (axis B) are blocked by `atomic_runner` when machine_label != 'cloud-vm'.
  - Axis A v0/v2 drop a benign EICAR sample -> Defender reacts; runs only when you explicitly pass --yes.

Examples:
  python run_measure.py --plan scenarios/g5_discovery_lolbin.yaml        # dry-run (safe)
  python run_measure.py --plan scenarios/g5_discovery_lolbin.yaml --yes  # live run
  python run_measure.py --static --variants v1,v3 --yes                  # axis A only, variants v1/v3
  python run_measure.py --all-behavior --dry-run                         # view the full axis B matrix
"""
from __future__ import annotations
import argparse
import glob as _glob
import json
import os
import re
import subprocess
import sys
import time

import common
from collect import log_collector
from engine import atomic_runner
from db import db_writer
from score import scorer, fidelity


# =====================================================================
#  Atomic steps (split into functions for testing & for patching during mocks)
# =====================================================================

def run_reset(cfg: dict) -> dict:
    """Run vm/reset.ps1 according to machine_label. Returns {reset_ok, took_ms, reset_done_at, actions}."""
    label = (cfg.get("environment") or {}).get("machine_label", "dev-win11")
    out_dir = (cfg.get("payloads") or {}).get("out_dir", "payloads/out")
    timeout = int((cfg.get("timing") or {}).get("reset_timeout_s", 60))
    script = (
        f"& '{_ps_quote('vm/reset.ps1')}' "
        f"-MachineLabel '{_ps_quote(label)}' -OutDir '{_ps_quote(out_dir)}'"
    )
    done_at = common.utcnow_iso()
    try:
        data = common.ps_json(script, timeout=timeout)
    except (subprocess.TimeoutExpired, OSError, ValueError, json.JSONDecodeError):
        return {"reset_ok": False, "took_ms": None, "reset_done_at": done_at, "actions": []}
    data = data or {}
    data.setdefault("reset_ok", False)
    data["reset_done_at"] = common.utcnow_iso()
    return data


def build_payloads(cfg: dict) -> dict:
    """Compile the 4 variants via payloads/build.ps1. Returns {variant: {variant,path,sha256,size}}."""
    out_dir = (cfg.get("payloads") or {}).get("out_dir", "payloads/out")
    csc = (cfg.get("tools") or {}).get("csc_exe")
    script = (
        f"& '{_ps_quote('payloads/build.ps1')}' -OutDir '{_ps_quote(out_dir)}'"
        + (f" -Csc '{_ps_quote(csc)}'" if csc else "")
    )
    data = common.ps_json(script, timeout=180)
    if isinstance(data, dict):
        data = [data]
    result = {}
    for row in (data or []):
        v = row.get("variant")
        if v:
            result[v] = row
    return result


def detonate_payload(variant: str, cfg: dict) -> dict:
    """Run payloads/out/<variant>.exe (drop the sample). Returns timestamps + dropped_path + ran."""
    out_dir = (cfg.get("payloads") or {}).get("out_dir", "payloads/out")
    exe = os.path.join(out_dir, f"{variant}.exe")
    started = common.utcnow_iso()
    ran = False
    stdout = ""
    stderr = ""
    try:
        cp = subprocess.run([exe], capture_output=True, text=True, timeout=60)
        stdout = cp.stdout or ""
        stderr = cp.stderr or ""
        ran = bool(stdout.strip()) or cp.returncode == 0
    except (subprocess.TimeoutExpired, OSError) as e:
        stderr = f"{type(e).__name__}: {e}"
    ended = common.utcnow_iso()
    dropped = os.path.join(out_dir, f"sample_{variant}.bin")
    return {
        "trigger_started_at": started,
        "trigger_ended_at": ended,
        "ran": ran,
        "dropped_path": dropped if os.path.exists(dropped) else None,
        "exe_path": exe if os.path.exists(exe) else None,
        "stdout": stdout,
        "stderr": stderr,
    }


def static_scan(file_path: str, cfg: dict) -> dict:
    """
    Static scan of 1 file with MpCmdRun (-DisableRemediation so NOTHING is quarantined; the sample is kept for traceability).
    MpCmdRun exit codes: 0 = clean, 2 = threat found. Returns {result, threat_name, scan_at}.
    """
    scan_at = common.utcnow_iso()
    if not file_path or not os.path.exists(file_path):
        return {"result": None, "threat_name": None, "scan_at": scan_at}
    pattern = (cfg.get("tools") or {}).get("mpcmdrun_glob", "")
    mp = common.find_mpcmdrun(pattern) if pattern else None
    if not mp:
        return {"result": "error", "threat_name": None, "scan_at": scan_at}
    script = (
        f"& '{_ps_quote(mp)}' -Scan -ScanType 3 -File '{_ps_quote(os.path.abspath(file_path))}' "
        f"-DisableRemediation; exit $LASTEXITCODE"
    )
    try:
        cp = common.run_powershell(script, timeout=120)
    except (subprocess.TimeoutExpired, OSError):
        return {"result": "error", "threat_name": None, "scan_at": scan_at}
    rc = cp.returncode
    out = (cp.stdout or "")
    if rc == 2:
        result = "threat_found"
    elif rc == 0:
        result = "clean"
    else:
        result = "error"
    threat = None
    m = re.search(r"Threat\s*:\s*(.+)", out) or re.search(r"was detected.*?:\s*(.+)", out)
    if m:
        threat = m.group(1).strip()
    return {"result": result, "threat_name": threat, "scan_at": scan_at}


def collect_evidence(start_iso: str, end_iso: str, cfg: dict) -> list:
    """Collect all evidence (Defender + Sysmon) within the window [start, end]."""
    return log_collector.collect_all(start_iso, end_iso, cfg)


def wait_collect_window(cfg: dict) -> bool:
    """Wait for the log collection window to finish. Returns True if the wait completed fully (not interrupted)."""
    secs = int((cfg.get("timing") or {}).get("collect_window_s", 20))
    try:
        time.sleep(secs)
        return True
    except KeyboardInterrupt:
        return False


# =====================================================================
#  Atomic measurement
# =====================================================================

def _split_evidence(evidence):
    """Split evidence into 2 JSON-serializable lists by source (for DB writes)."""
    defender, sysmon = [], []
    for e in evidence:
        row = {
            "event_id": getattr(e, "event_id", None),
            "time_created": getattr(e, "time_created", None),
            "message": getattr(e, "message", None),
        }
        if getattr(e, "source", None) == "defender":
            defender.append(row)
        elif getattr(e, "source", None) == "sysmon":
            sysmon.append(row)
    return defender, sysmon


def measure_one(conn, run_id, item: dict, cfg: dict) -> dict:
    """
    Perform 1 atomic measurement for 1 (technique/variant) and write 1 row to measurements.
    `item` describes the measurement:
      - axis B: {axis:'behavior', technique_id, scenario_group, test_number, invasive}
      - axis A: {axis:'static',   variant, sample:{sha256,path,size,...}}
    Returns the written `record` (for testing/inspection).
    """
    axis = item.get("axis", "behavior")
    cwin = int((cfg.get("timing") or {}).get("collect_window_s", 20))

    # 1) Reset environment
    rs = run_reset(cfg)
    reset_ok = bool(rs.get("reset_ok"))
    reset_done_at = rs.get("reset_done_at")
    clean_before = reset_ok  # reset clears samples/noise from the previous run

    had_error = not reset_ok
    technique_ran = False
    static = {"result": None, "threat_name": None, "scan_at": None}
    sample_id = None
    sample_loaded_at = None
    trigger_started_at = trigger_ended_at = None
    err_parts = []
    if not reset_ok:
        err_parts.append("reset failed")

    # 2) Trigger according to axis
    if axis == "static":
        variant = item.get("variant")
        sample = item.get("sample") or {}
        if sample.get("sha256"):
            sample_id = db_writer.write_sample(conn, {
                "variant": variant,
                "sample_sha256": sample.get("sha256"),
                "file_path": sample.get("path"),
                "size_bytes": sample.get("size"),
                "built_at": common.utcnow_iso(),
                "csc_version": "v4.0.30319",
                "description": f"payload {variant}",
            })
        deto = detonate_payload(variant, cfg)
        trigger_started_at = deto["trigger_started_at"]
        trigger_ended_at = deto["trigger_ended_at"]
        sample_loaded_at = trigger_ended_at
        technique_ran = deto["ran"]
        if not deto["ran"]:
            err_parts.append(f"payload {variant} did not run: {deto.get('stderr','')[:120]}")
        # Static scan of the dropped sample (if still present) to measure the signature layer
        scan_target = deto.get("dropped_path") or deto.get("exe_path")
        static = static_scan(scan_target, cfg)
    else:  # behavior
        tid = item.get("technique_id")
        res = atomic_runner.invoke_atomic(
            tid, test_number=item.get("test_number"), cfg=cfg,
        )
        trigger_started_at = res.started_iso
        trigger_ended_at = res.ended_iso
        technique_ran = res.ran
        if not res.ran and not res.exit_ok:
            had_error = True
            err_parts.append((res.stderr or "technique did not run")[:160])

    # 3) Log collection window
    collect_complete = wait_collect_window(cfg)
    collect_until_at = common.utcnow_iso()
    evidence = []
    if trigger_started_at:
        try:
            evidence = collect_evidence(trigger_started_at, collect_until_at, cfg)
        except Exception as e:  # log collection must not crash the measurement
            err_parts.append(f"log collection error: {type(e).__name__}")

    # 4) Fidelity
    fid = fidelity.compute_fidelity(
        reset_ok=reset_ok,
        technique_ran=technique_ran,
        collect_window_complete=collect_complete,
        clean_before=clean_before,
        cfg=cfg,
    )

    # 5) Score 1 of 4 states
    sc = scorer.score(
        evidence,
        trigger_started_iso=trigger_started_at,
        fidelity_valid=fid.valid,
        had_error=had_error,
        static_result=static["result"],
        cfg=cfg,
        axis=axis,
    )

    # 6) Write measurements
    defender_json, sysmon_json = _split_evidence(evidence)
    record = {
        "axis": axis,
        "technique_id": item.get("technique_id"),
        "scenario_group": item.get("scenario_group"),
        "variant": item.get("variant"),
        "sample_id": sample_id,
        "reset_done_at": reset_done_at,
        "sample_loaded_at": sample_loaded_at,
        "static_scan_at": static["scan_at"],
        "trigger_started_at": trigger_started_at,
        "trigger_ended_at": trigger_ended_at,
        "collect_until_at": collect_until_at,
        "static_scan_result": static["result"],
        "static_threat_name": static["threat_name"],
        "state": sc.state,
        "detection_layer": sc.detection_layer,
        "detect_latency_ms": sc.detect_latency_ms,
        "fidelity_score": fid.score,
        "fidelity_valid": 1 if fid.valid else 0,
        "evidence_source": sc.evidence_source,
        "defender_events_json": defender_json,
        "sysmon_events_json": sysmon_json,
        "error_message": "; ".join(err_parts) or None,
    }
    record["measurement_id"] = db_writer.write_measurement(conn, run_id, record)
    record["_reason"] = sc.reason
    return record


# =====================================================================
#  Load measurement matrix
# =====================================================================

def load_plan(path: str) -> list:
    """Read 1 scenarios/*.yaml file -> list of axis B items."""
    import yaml
    with open(path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}
    group = data.get("group")
    items = []
    for t in (data.get("techniques") or []):
        nums = t.get("test_numbers") or [None]
        for n in nums:
            items.append({
                "axis": "behavior",
                "technique_id": t.get("id"),
                "scenario_group": group,
                "test_number": n,
                "invasive": bool(t.get("invasive")),
                "expectation": t.get("expectation"),
            })
    return items


def build_matrix(args, cfg: dict) -> list:
    """Build the list of measurements from CLI arguments."""
    items = []
    if not args.static_only:
        if args.plan:
            items += load_plan(args.plan)
        if args.all_behavior:
            for p in sorted(_glob.glob("scenarios/*.yaml")):
                items += load_plan(p)
    if args.static or args.static_only:
        want = None
        if args.variants:
            want = {v.strip() for v in args.variants.split(",") if v.strip()}
        for v in (cfg.get("payloads") or {}).get("variants", []):
            if want is None or v in want:
                items.append({"axis": "static", "variant": v})
    return items


def _gather_env(cfg: dict) -> dict:
    envc = cfg.get("environment") or {}
    sysmon = _sysmon_present(cfg)
    return {
        "machine_label": envc.get("machine_label"),
        "defender": common.get_defender_status(),
        "os_caption": _os_caption(),
        "os_version": _os_version(),
        "cloud_protection_enabled": 1 if envc.get("cloud_protection_enabled") else 0,
        "auto_submit_enabled": 1 if envc.get("auto_submit_enabled") else 0,
        "sysmon_present": 1 if sysmon else 0,
        "tool_git_commit": _git_commit(),
        "started_at": common.utcnow_iso(),
    }


# ----- small helpers (best-effort, never raise) -----

def _ps_quote(s: str) -> str:
    return str(s).replace("'", "''")


def _os_caption():
    try:
        return common.ps_json("(Get-CimInstance Win32_OperatingSystem).Caption | ConvertTo-Json")
    except Exception:
        return None


def _os_version():
    try:
        import platform
        return platform.version()
    except Exception:
        return None


def _sysmon_present(cfg: dict) -> bool:
    log = (cfg.get("evidence") or {}).get("sysmon_log")
    if not log:
        return False
    try:
        cp = common.run_powershell(
            f"if (Get-WinEvent -ListLog '{_ps_quote(log)}' -ErrorAction SilentlyContinue) "
            "{ 'yes' } else { 'no' }", timeout=30)
        return "yes" in (cp.stdout or "")
    except Exception:
        return False


def _git_commit():
    try:
        cp = subprocess.run(["git", "rev-parse", "--short", "HEAD"],
                            capture_output=True, text=True, timeout=15)
        return (cp.stdout or "").strip() or None
    except Exception:
        return None


# =====================================================================
#  CLI
# =====================================================================

def main():
    # Windows consoles often default to cp1252 -> force UTF-8 so Vietnamese text can be printed.
    for _s in (sys.stdout, sys.stderr):
        try:
            _s.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass

    ap = argparse.ArgumentParser(description="M10 — Defender measurement orchestration loop")
    ap.add_argument("--plan", help="1 scenario YAML file (scenarios/*.yaml)")
    ap.add_argument("--all-behavior", action="store_true", help="run all scenarios/*.yaml")
    ap.add_argument("--static", action="store_true", help="include axis A (payload v0-v3)")
    ap.add_argument("--static-only", action="store_true", help="axis A ONLY (payload)")
    ap.add_argument("--variants", help="filter axis A variants, e.g. 'v1,v3'")
    ap.add_argument("--config", default="config.yaml")
    ap.add_argument("--db", help="override the DB path (default taken from config)")
    g = ap.add_mutually_exclusive_group()
    g.add_argument("--yes", action="store_true", help="RUN FOR REAL (activates samples/techniques)")
    g.add_argument("--dry-run", action="store_true", help="list only, do not activate (default)")
    args = ap.parse_args()

    cfg = common.load_config(args.config)
    label = (cfg.get("environment") or {}).get("machine_label")
    matrix = build_matrix(args, cfg)

    if not matrix:
        print("[run_measure] Matrix is empty. Use --plan/--all-behavior/--static. "
              "See: python run_measure.py -h")
        return

    # Safe default: without --yes -> dry-run
    dry = args.dry_run or not args.yes
    print(f"[run_measure] machine_label={label}  measurements={len(matrix)}  "
          f"mode={'DRY-RUN (safe)' if dry else 'LIVE RUN'}")
    for it in matrix:
        tag = it.get("variant") or it.get("technique_id")
        inv = " [invasive]" if it.get("invasive") else ""
        warn = ""
        if it["axis"] == "static" and it.get("variant") in ("v0", "v2"):
            warn = " [drops benign EICAR -> Defender reacts]"
        if it.get("invasive") and label != "cloud-vm":
            warn = " [WILL BE BLOCKED on dev machine]"
        print(f"   - {it['axis']:8s} {tag}{inv}{warn}")

    if dry:
        print("[run_measure] DRY-RUN: nothing activated. Add --yes to run for real.")
        return

    # Live run
    db_path = args.db or (cfg.get("database") or {}).get("path", "db/results.sqlite")
    schema = (cfg.get("database") or {}).get("schema", "db/schema.sql")
    os.makedirs(os.path.dirname(db_path) or ".", exist_ok=True)
    conn = db_writer.init_db(db_path, schema)
    env = _gather_env(cfg)
    run_id = db_writer.start_run(conn, env)
    print(f"[run_measure] run_id={run_id}  defender_sig={env['defender'].get('AntivirusSignatureVersion')}")

    # Axis A: build payloads once, attach samples to items
    static_items = [it for it in matrix if it["axis"] == "static"]
    if static_items:
        samples = build_payloads(cfg)
        for it in static_items:
            it["sample"] = samples.get(it.get("variant"), {})

    counts = {}
    for i, it in enumerate(matrix, 1):
        tag = it.get("variant") or it.get("technique_id")
        rec = measure_one(conn, run_id, it, cfg)
        counts[rec["state"]] = counts.get(rec["state"], 0) + 1
        print(f"   [{i:>2}/{len(matrix)}] {it['axis']:8s} {tag:14s} -> "
              f"{rec['state']:13s} (fid={rec['fidelity_score']}) {rec.get('_reason','')}")

    db_writer.end_run(conn, run_id)
    conn.close()
    print(f"[run_measure] DONE. Summary: {counts}")
    print(f"[run_measure] DB: {db_path}  (run_id={run_id})")


if __name__ == "__main__":
    main()
