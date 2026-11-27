# Phase 3 — T1562.001 verification runbook (did Defender actually get disabled?)

**Why.** In G2 (run_id 11) T1562.001 scored `not_detected` with **zero** Defender events — not even a
5013 — while Tamper Protection is ON. That is ambiguous: the disable attempt was most likely **blocked
by Tamper Protection** (a Defender *win*) rather than a real miss. The measurement log alone can't
tell, because `run_measure` records detection *events*, not the resulting **protection state**. This
runbook resolves it by directly observing whether real-time protection ever turns off.

**Design.** Run the technique **outside `run_measure`** so that `reset.ps1` (which itself attempts a
RTP toggle and is the usual source of the 5013 noise) does not muddy the signal. Observe RTP live with
the read-only monitor `vm/watch_rtp.ps1`.

**Run on:** cloud-vm only, snapshot current. This is **user-driven** (the on-prem session is blocked
by its safety classifier from relaying a disable-Defender instruction).

---

## Steps

1. Confirm the starting state:
   ```powershell
   Get-MpComputerStatus | Select-Object RealTimeProtectionEnabled, IsTamperProtected
   ```
   Expect `True, True`.

2. **Window A — start the read-only monitor** (changes nothing):
   ```powershell
   powershell -ExecutionPolicy Bypass -File vm\watch_rtp.ps1 -Seconds 60
   ```

3. **Window B — trigger the technique directly** (the same Atomic test #1 used in G2, without
   run_measure/reset), then clean it up:
   ```powershell
   Invoke-AtomicTest T1562.001 -TestNumbers 1
   # ...watch Window A for ~10s...
   Invoke-AtomicTest T1562.001 -TestNumbers 1 -Cleanup
   ```

4. **Cross-check the Defender log** in a wide window around the trigger (not the narrow collect window):
   ```powershell
   Get-WinEvent -LogName "Microsoft-Windows-Windows Defender/Operational" -MaxEvents 40 |
     Where-Object { $_.Id -in 5007,5013,5001,5000 } |
     Select-Object TimeCreated, Id, @{n='Msg';e={$_.Message.Split("`n")[0]}} | Format-Table -Auto
   ```
   - **5013** = Tamper Protection blocked a change (a block/defence).
   - **5007** = a Defender setting actually changed (would indicate RTP really toggled).
   - **5001** = real-time protection disabled.

5. **Restore** (safety — strengthening only), then confirm:
   ```powershell
   Set-MpPreference -DisableRealtimeMonitoring $false
   Get-MpComputerStatus | Select-Object RealTimeProtectionEnabled, IsTamperProtected
   ```
   Expect `True, True`. If anything looks off, revert to the snapshot.

---

## How to read it (send me these)

| Observation | Meaning | How to score T1562.001 |
|---|---|---|
| RTP **never** went False; 5013 present (or Tamper rejected it) | Tamper Protection **blocked** the disable | **Defender WIN** — re-label as detected/blocked, drop from the "miss" count |
| RTP went **True→False** (even briefly); 5007/5001 present | disable **succeeded** | real evasion gap — `not_detected` stands, and it's a serious finding |

Send: the monitor's RESULT line, the Window-B output, and the step-4 event table (with timestamps).
That settles whether T1562.001 belongs in the gap list or the Defender-win list for Chapter 4.
