# Work Packet M1+M2 — 4 C# Payload Variants + build.ps1

**Worker:** v0,v1 → Haiku · v2,v3 → Sonnet (in-memory is harder). **Review:** Opus.
**Files:** `payloads/src/v0.cs..v3.cs`, `payloads/build.ps1`.

## Scientific goal
Each variant differs from the previous one by EXACTLY 1 factor, so the effect on static/AMSI scanning can be isolated:
| Variant | Difference | What it measures |
|---|---|---|
| v0 | Bare sample: "malware-signature" strings simulated, clearly visible | Baseline — does Defender catch it by signature? |
| v1 | v0 + string encoding (XOR + Base64), decoded at runtime | Does string encoding get past static scanning? |
| v2 | v1 + writes the payload to DISK, then runs it | Does writing to disk trigger static/RTP scanning? |
| v3 | v1 + executes in MEMORY (never touches disk) | Does in-memory execution evade static scanning? Does AMSI catch it? |

## SAFETY CONSTRAINTS (mandatory)
- Payload is **HARMLESS**: do NOT download or run real malware, NO outbound network, do NOT modify the system.
- "Simulated behavior" = only write 1 line to stdout or write 1 marker text file, e.g. using an EICAR-style signature string
  OR a self-defined marker (state it in a comment). The goal is to create a signal for the scanning layer without causing harm.
- v3 "memory execution": load a harmless .NET assembly from a byte[] and call a method that prints a marker — NO shellcode, NO VirtualAlloc/CreateThread toward unknown code.

## Interface / Acceptance
- Compiles with `csc.exe v4.0.30319` (verified on the dev machine).
- `build.ps1 -OutDir payloads/out` → outputs `v0.exe..v3.exe` and prints JSON: `[{variant, sha256, size}]`.
- Each exe runs (or is quarantined by Defender — that is a valid measurement result for v0/v1).
- Code has comments explaining "which point differs from the previous variant".

## Note
Move the string-encoding logic (v1) into a shared helper so v1/v2/v3 can reuse it (only the execution method differs).
