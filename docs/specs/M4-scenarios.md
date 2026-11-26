# Work-packet M4 — 5 nhóm kịch bản (G1–G5)

**Worker:** Haiku. **Review:** Opus. **File:** `scenarios/g1_execution.yaml` ... `g5_discovery.yaml`.

## Mục tiêu
Khai báo 5 nhóm kịch bản ánh xạ MITRE ATT&CK, để `run_measure.py` đọc và lặp.

## Schema mỗi file YAML
```yaml
group: G1
tactic: TA0002
name: Execution
techniques:
  - id: T1059.001
    name: PowerShell
    test_numbers: [1]        # Atomic test number
    invasive: false          # true nếu chỉ chạy trên cloud-vm
    axis: behavior
    notes: ""
```

## Nội dung 5 nhóm (từ PLAN.md)
- **G1 Execution** (TA0002): T1059.001 PowerShell, T1059.003 cmd, T1204 User Execution. invasive=false.
- **G2 Defense Evasion** (TA0005): T1562.001 tắt tool (invasive=true), T1027 obfuscation, T1140 giải mã, AMSI bypass (invasive=true).
- **G3 Credential Access** (TA0006): T1003.001 LSASS (invasive=true), T1555 (invasive=true).
- **G4 Persistence** (TA0003): T1547.001 Run key (invasive=true), T1053.005 scheduled task (invasive=true).
- **G5 Discovery/LOLBin** (TA0007): T1082 (false), T1057 (false), certutil/mshta/regsvr32 LOLBin.

## Acceptance
- 5 file YAML hợp lệ (`yaml.safe_load` không lỗi).
- Mỗi technique có đủ: id, name, test_numbers, invasive, axis.
- Đánh dấu `invasive` ĐÚNG theo SAFETY.md (kỹ thuật xâm lấn = true).
- `tests/test_scenarios.py` load cả 5 file, kiểm field bắt buộc.
