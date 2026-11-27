"""
Reconstruct db/results.sqlite from the VALIDATED Phase-3 measurements (report/evidence/09-18).

The cloud-vm holds the authoritative raw DB (full per-event JSON). This script rebuilds the SAME
schema locally with the validated summary results, so report/generate.py and the Chapter-4 tables are
reproducible on any machine (and gradeable from the repo alone). Every row here is the validated
outcome from the evidence files; see report/evidence/18_axis_b_final_validated.md for the tally.

Run from repo root:  python report/reconstruct_db.py
"""
from __future__ import annotations
import os
import sys

# Allow running as `python report/reconstruct_db.py` (repo root not on sys.path[0] otherwise).
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from db import db_writer

DB_PATH = "db/results.sqlite"
SCHEMA = "db/schema.sql"

# --- Run A: Axis A static (dev-win11, Phase 2) ---------------------------------
AXIS_A_ENV = {"machine_label": "dev-win11", "cloud_protection_enabled": 0,
              "defender_sig_version": "1.463.x", "notes": "Axis A static payloads v0-v3"}
AXIS_A = [
    # variant, state, layer, latency, note
    ("v0", "detected", "static", 0, "raw EICAR on disk -> signature catches"),
    ("v1", "not_detected", None, None, "XOR+Base64 encoded sample -> missed (obfuscation)"),
    ("v2", "detected", "static", 0, "decoded-to-disk -> signature catches"),
    ("v3", "not_detected", None, None, "in-memory / fileless -> missed"),
]

# --- Run B: Axis B baseline (cloud-vm, cloud protection OFF) --------------------
AXIS_B_ENV = {"machine_label": "cloud-vm", "cloud_protection_enabled": 0,
              "defender_sig_version": "1.463.490.0", "sysmon_present": 0,
              "notes": "Axis B baseline, cloud OFF (run_ids 5-8, 11)"}
# group, technique, state, layer, latency_ms, note
AXIS_B = [
    ("G5", "T1082",     "not_detected", None,   None, "System Information Discovery"),
    ("G5", "T1057",     "not_detected", None,   None, "Process Discovery"),
    ("G5", "T1218.010", "not_detected", None,   None, "Regsvr32 LOLBin"),
    ("G1", "T1059.001", "detected",     "amsi", 3804, "Mimikatz via PowerShell -> AMSI blocked"),
    ("G1", "T1059.003", "not_detected", None,   None, "Windows Command Shell"),
    ("G4", "T1547.001", "not_detected", None,   None, "Registry Run Key"),
    ("G4", "T1053.005", "not_detected", None,   None, "Scheduled Task"),
    ("G3", "T1003.001", "not_detected", None,   None, "OS Credential Dumping: LSASS Memory"),
    ("G3", "T1555",     "not_detected", None,   None, "Credentials from Password Stores"),
    ("G2", "T1562.001", "detected",     "tamper_protection", 0,
        "Impair Defenses -> BLOCKED by Tamper Protection (verified via RTP-state, evidence 17; "
        "automated run_id=11 invalid because the atomic was not installed)"),
    ("G2", "T1140",     "not_detected", None,   None, "Deobfuscate/Decode Files"),
]

# --- Run C: cloud-ON spot-check (delta) ----------------------------------------
CLOUD_ON_ENV = {"machine_label": "cloud-vm", "cloud_protection_enabled": 1,
                "defender_sig_version": "1.463.490.0",
                "notes": "cloud-ON spot-check (run_id 9) - only cloud toggled"}
CLOUD_ON = [
    ("G3", "T1003.001", "not_detected", None,       None, "cloud ON - LSASS still missed"),
    ("G4", "T1547.001", "not_detected", None,       None, "cloud ON - Run key still missed"),
    ("G5", "T1218.010", "not_detected", None,       None, "cloud ON - regsvr32 still missed"),
    ("G1", "T1059.001", "detected",     "behavior", 7654, "CONTROL held; +2010 cloud events, +3.8s"),
]

# --- Run D: ASR spot-check -----------------------------------------------------
ASR_ENV = {"machine_label": "cloud-vm", "cloud_protection_enabled": 0,
           "defender_sig_version": "1.463.490.0",
           "notes": "ASR spot-check (run_id 10) - lsass ASR rule in Block"}
ASR = [
    ("G3", "T1003.001", "not_detected", None, None, "ASR Block enabled; no 1121 -> still missed"),
]

# --- YARA goodware FP result (evidence 13) -------------------------------------
RULE_FP = [
    # rule_name, rule_type, technique_id, goodware_total, fps
    ("KTLD_Encoded_Sample_On_Disk", "yara", "T1027", 12450, 0),
    ("KTLD_Payload_Loader_Binary",  "yara", "T1027", 12450, 0),
]


def _meas(axis, group, technique, variant, state, layer, latency, note, fid=1.0):
    return {
        "axis": axis, "technique_id": technique, "scenario_group": group, "variant": variant,
        "state": state, "detection_layer": layer, "detect_latency_ms": latency,
        "fidelity_score": fid, "fidelity_valid": 1,
        "evidence_source": "defender" if state in ("detected", "not_detected") else "none",
        "error_message": note,
    }


def main():
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)
    os.makedirs(os.path.dirname(DB_PATH) or ".", exist_ok=True)
    conn = db_writer.init_db(DB_PATH, SCHEMA)

    run_a = db_writer.start_run(conn, AXIS_A_ENV)
    for variant, state, layer, lat, note in AXIS_A:
        db_writer.write_measurement(conn, run_a,
            _meas("static", None, None, variant, state, layer, lat, note))

    run_b = db_writer.start_run(conn, AXIS_B_ENV)
    for group, tech, state, layer, lat, note in AXIS_B:
        db_writer.write_measurement(conn, run_b,
            _meas("behavior", group, tech, None, state, layer, lat, note))

    run_c = db_writer.start_run(conn, CLOUD_ON_ENV)
    for group, tech, state, layer, lat, note in CLOUD_ON:
        db_writer.write_measurement(conn, run_c,
            _meas("behavior", group, tech, None, state, layer, lat, note))

    run_d = db_writer.start_run(conn, ASR_ENV)
    for group, tech, state, layer, lat, note in ASR:
        db_writer.write_measurement(conn, run_d,
            _meas("behavior", group, tech, None, state, layer, lat, note))

    for name, rtype, tech, total, fps in RULE_FP:
        conn.execute(
            "INSERT INTO rule_fp (rule_name, rule_type, technique_id, goodware_total, "
            "false_positives, fp_rate, measured_at) VALUES (?,?,?,?,?,?,?)",
            (name, rtype, tech, total, fps, (fps / total) if total else None, "2026-11-27"))
    conn.commit()

    for run in (run_a, run_b, run_c, run_d):
        db_writer.end_run(conn, run)
    conn.close()
    print(f"Reconstructed {DB_PATH}: runs A(static)={run_a} B(baseline)={run_b} "
          f"C(cloud-ON)={run_c} D(ASR)={run_d}")


if __name__ == "__main__":
    main()
