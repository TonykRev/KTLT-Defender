# Evidence 13 — YARA rule set false-positive test on goodware

**Date:** 2026-11-27
**Machine:** dev-win11 (local; no detonation — pure static scan of known-good files)
**Rules:** rules/yara/ktld_encoded_sample.yar, rules/yara/ktld_payload_loader.yar
**Tool:** rules/fp_scan.py (yara-python 4.5.4)

## Corpus (known-good system binaries)
- C:\Windows\System32
- C:\Windows\SysWOW64
- C:\Windows\Microsoft.NET\Framework64
- C:\Windows\Microsoft.NET\Framework
Extensions scanned: .exe .dll .sys .ocx .cpl .bin .scr

## Result

| Metric | Value |
|---|---|
| Files scanned | **12,450** |
| Skipped / locked | 0 |
| Scan time | 67.2 s |
| **False positives** | **0** |

The .NET Framework assemblies are a deliberate stress test: many legitimately call
`FromBase64String` (one of the loader rule's strings), yet none matched, because the rule also
requires the project's unique encoded blob constant. Specificity holds.

## Precision summary (with the true-positive check from tests/test_rules.py)

| | Fires | Notes |
|---|---|---|
| True positives | 5 / 5 | `sample_v1.bin` + the four built loaders v0–v3 (incl. fileless v3) |
| False positives | 0 / 12,450 | clean on OS + .NET goodware |

→ YARA supplementary rules: **precision = 1.0** on this corpus, recall = 1.0 on the measured gap
samples. Repeatable via `python rules/fp_scan.py`.

## Scope / next
- Sigma FP testing is NOT covered here — it needs a benign process/registry/Sysmon telemetry corpus,
  which is a behavioural dataset (VM / log sample), not static files. Deferred to the telemetry-FP
  step (M12 report).
- Optional extension: add C:\Program Files (third-party goodware) to widen the YARA corpus.
