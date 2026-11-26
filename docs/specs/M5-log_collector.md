# Work Packet M5 — Log Collector

**Worker:** Sonnet. **Review:** Opus. **File:** `collect/log_collector.py` (stub + dataclass already exist).

## Goal
Given the time window `[start_iso, end_iso]`, return a list of `EvidenceEvent` from Defender + Sysmon.
This is an INDEPENDENT source of EVIDENCE, separate from whether the payload "reports success" — an objective strength.

## Approach
- Use `common.run_powershell` to call `Get-WinEvent -FilterHashtable @{LogName=...; StartTime=...; EndTime=...}`.
  Retrieve `Id, TimeCreated, Message`; export with `ConvertTo-Json`. Parse into `EvidenceEvent`.
- LogName comes from `cfg['evidence']['defender_log']` / `['sysmon_log']`.
- Convert ISO <-> `[datetime]` for PowerShell with the correct timezone (compare in UTC in code).
- Sysmon may NOT be installed → `collect_sysmon_events` returns `[]` (catch "No events" / missing-log errors); it must NOT raise.

## Acceptance
- `collect_defender_events(start,end,cfg)` runs for real on the dev machine and returns a list (possibly empty) without error.
- Filters the time window correctly (no events outside the range).
- Has `tests/test_log_collector.py`: creates 1 fake event via `eventcreate`/test write, or mocks subprocess,
  and asserts Id/Time/Message are parsed correctly.
- No dependency on pywin32 — only PowerShell via subprocess.

## Edge cases
Empty log; JSON returning a single object (not a list) when there is only 1 event; Unicode characters in Message; timeout.
