# Evidence 17 — T1562.001 verified (Defender win) + atomic_runner validity fix

**Date:** 2026-11-27 · **Environment:** cloud-vm · User-driven verification (on-prem session is
classifier-blocked for the disable-Defender technique).

## Part A — T1562.001 is a Defender WIN (not a gap)
Direct, instrumented verification (runbook `docs/PHASE3_T1562_VERIFY.md`, read-only monitor
`vm/watch_rtp.ps1`):

- Trigger: `Set-MpPreference -DisableRealtimeMonitoring 1` at 23:15:17.
- Monitor result: **RTP never left True** for the whole window.
- Defender log: **5013 (Tamper Protection blocked a change) at 23:15:17** — exactly the trigger time.
  **No 5007** (config changed), **no 5001** (RTP disabled).
- Final state: RTP=True, TamperProtected=True (restored).

**Verdict:** Tamper Protection blocked the disable attempt → **Defender successfully defended**.
T1562.001 is **re-labelled detected/blocked (Defender win)** and removed from the "miss" list. This is
Defender's clearest win in the study and should be highlighted, not buried.

## Part B — tool bug this exposed (and the fix) — affects measurement validity
The VM also found that the **Atomic test for T1562.001 was not installed** on this host
(`C:\AtomicRedTeam\atomics\T1562.001\` absent). `Invoke-AtomicTest T1562.001` then **exited 0 while
printing an error to stdout**, and the old `atomic_runner` computed
`ran = exit_ok and bool(out.strip())` → **ran=True by mistake**. So run_id=11's T1562.001 measurement
**never actually executed the technique** — its `not_detected` was a false result produced by a
non-run.

**Fix (`engine/atomic_runner.py`):** `ran` now requires the positive **"Executing test"** marker that
Invoke-AtomicTest prints when a test really runs, and rejects not-installed phrases ("does not exist",
"unable to find", "no atomics", ...). A missing/failed atomic is now `ran=False` → the scorer returns
**inconclusive/error**, never a false `not_detected`. +2 tests (missing-atomic, exit-0-without-marker);
**59 tests pass**.

## Part C — re-validation required (in progress)
Because this bug would silently invalidate ANY not_detected whose atomic wasn't installed, the full
Axis-B set must be re-checked. Requested from the VM (read-only):
1. `Test-Path` for all 11 technique IDs' atomic files → which are actually installed.
2. Exact stdout of a known-good run (T1059.001) and the missing one (T1562.001) to confirm the
   detection strings.
3. Any ID that is not installed → that measurement is invalid and must be re-run (after
   `Install-AtomicRedTeam` / updating the atomics repo).

**Confidence so far:**
- **T1059.001 (detected)** — produced real Defender detection events (1116/1117, +2010 cloud in the
  spot-check) → definitely executed. Valid.
- **T1003.001 (not_detected)** — ran consistently across 3 configs (3.3–6.8 s) with post-run lsass
  stability checks → very likely executed, pending the Test-Path confirmation.
- **The rest** — pending step 1. Any that are not installed will be re-run before the tally is final.

## Net effect on the headline
- T1562.001 moves to **Defender win** (verified).
- The "1 detected / 9 not_detected" tally is **provisional** until the install-check confirms the other
  atomics ran. The fix guarantees future runs can't repeat this error.
