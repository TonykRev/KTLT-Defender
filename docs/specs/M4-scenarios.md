# Work Packet M4 — 5 Scenario Groups (G1–G5)

**Worker:** Haiku. **Review:** Opus. **Files:** `scenarios/g1_execution.yaml` ... `g5_discovery.yaml`.

## Goal
Declare 5 scenario groups mapped to MITRE ATT&CK, so that `run_measure.py` can read and loop over them.

## YAML schema per file
```yaml
group: G1
tactic: TA0002
name: Execution
techniques:
  - id: T1059.001
    name: PowerShell
    test_numbers: [1]        # Atomic test number
    invasive: false          # true = run only on cloud-vm
    axis: behavior
    notes: ""
```

## Contents of the 5 groups (from PLAN.md)
- **G1 Execution** (TA0002): T1059.001 PowerShell, T1059.003 cmd, T1204 User Execution. invasive=false.
- **G2 Defense Evasion** (TA0005): T1562.001 disable tools (invasive=true), T1027 obfuscation, T1140 decoding, AMSI bypass (invasive=true).
- **G3 Credential Access** (TA0006): T1003.001 LSASS (invasive=true), T1555 (invasive=true).
- **G4 Persistence** (TA0003): T1547.001 Run key (invasive=true), T1053.005 scheduled task (invasive=true).
- **G5 Discovery/LOLBin** (TA0007): T1082 (false), T1057 (false), certutil/mshta/regsvr32 LOLBins.

## Acceptance
- 5 valid YAML files (`yaml.safe_load` raises no errors).
- Each technique has all of: id, name, test_numbers, invasive, axis.
- `invasive` is flagged CORRECTLY per SAFETY.md (invasive techniques = true).
- `tests/test_scenarios.py` loads all 5 files and checks the required fields.
