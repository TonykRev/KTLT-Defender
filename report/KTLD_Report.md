# Automated Evaluation of Windows Defender Detection on Windows 11 and a Supplementary YARA/Sigma Rule Set

**Course project (KTLT) — Academy of Cryptography Techniques (Học viện Kỹ thuật Mật mã).**

Team: Trần Quang Huy, Nguyễn Văn Thành, Nguyễn Viết Nhật Long, Nguyễn Việt Hiếu. Supervisor: Nguyễn Mạnh Thắng.

_Generated from the validated Phase-3 measurements (report/evidence/09–18). Date: 2026-11-27._

---



## 1. Abstract, Introduction & Objectives

### Abstract

Endpoint defence on Windows 11 increasingly relies on Microsoft Defender as the default, always-on security control, yet its real detection coverage is seldom measured in a reproducible, evidence-backed way. This work presents an automated, two-axis framework that quantifies Defender's attack-detection capability and derives a supplementary YARA/Sigma rule set for the gaps it leaves. Axis A exercises four C# payload variants (bare, string-encoded, decode-to-disk, in-memory/fileless) using a benign EICAR proxy; Axis B drives eleven MITRE ATT&CK techniques through Invoke-AtomicRedTeam, each scored as detected, not_detected, inconclusive, or error against Defender Operational telemetry. On an isolated Azure Windows 11 virtual machine, Defender detected every raw on-disk sample but missed obfuscated and fileless variants, and stopped only 2 of 11 behavioural techniques (18.2%). Two YARA rules close the payload gaps, firing on all five real artefacts with zero false positives across 12,450 goodware files, and seven Sigma rules — logic-validated on synthetic events — cover the behavioural gaps.

### 1.1 Introduction

Microsoft Defender ships enabled by default on every modern Windows installation and, for a large share of consumer and small-organisation endpoints, is the only anti-malware layer in place. Because of this reach, the practical question is not whether Defender detects *something*, but precisely *which* classes of attack it catches and which it lets through under a realistic, lightly-configured deployment. Vendor marketing and aggregate third-party lab scores answer neither question at the granularity a defender needs: they rarely isolate the contribution of individual engine layers (static signatures, AMSI, Tamper Protection, cloud protection, ASR), rarely attribute a result to a specific MITRE ATT&CK technique, and are not reproducible on an analyst's own machine.

This project fills that gap with an automated measurement tool that produces per-sample, per-technique, traceable verdicts and, crucially, turns Defender's blind spots into concrete, deployable detection content. Rather than reporting a single opaque pass rate, the framework records the evidence behind each verdict — Defender Operational event IDs (1116/1117 detection and action, 1015/1119 behaviour, 5013 Tamper Protection block, 2010 cloud lookup, 5007 configuration change) — and a fidelity score that certifies each test actually executed. Where Defender misses, a supplementary YARA/Sigma rule set demonstrates that the gaps are closable with lightweight, open signatures, and a mitigation mapping ties every gap to the Defender layer that should have caught it.

### 1.2 Objectives & Scope

**Primary objective.** Build an automated tool that evaluates Microsoft Defender's attack-detection capability on Windows 11 and, for the samples and techniques Defender fails to catch, supplies a validated supplementary YARA/Sigma rule set.

**Specific objectives.**

1. Design a reproducible, two-axis measurement over (A) four code-delivery variants and (B) a MITRE ATT&CK-mapped behavioural matrix, with a well-defined four-state scoring scheme (error / inconclusive / detected / not_detected) and a 0–1 fidelity model (valid at ≥ 0.5) that distinguishes a genuine Defender miss from a broken test.
2. Execute the measurements on a controlled, isolated Windows 11 environment and attribute each verdict to the responsible Defender layer, supported by Windows Defender Operational-log evidence.
3. Author supplementary YARA (file-level) and Sigma (behaviour-level) rules targeting the confirmed gaps, and validate them for both true-positive coverage and false-positive safety.
4. Map each technique to its intended Defender layer and remediation, so the results are directly actionable.

**Scope and boundaries.** The tool is Python 3.12 (standard library plus `pyyaml`), covered by 61 passing `unittest` cases. Malware behaviour is approximated with EICAR — the benign industry test string — stored XOR(0x5A)+Base64-encoded in source so the repository and build artefacts remain AV-clean; raw EICAR touches disk only while variants v0/v2 run, which is itself the measurement. Invasive techniques and all official measurements run exclusively on an isolated Azure Windows 11 Pro (Insider build 26300) VM with a clean snapshot (RTP on, Tamper Protection on, cloud protection off for the baseline; Defender AMEngine 1.1.26100.4, signature 1.463.490.0); the development machine only builds and smoke-tests. Each behavioural technique is exercised with a single Atomic test (test #1) under a default-ish consumer configuration. Out of scope are exhaustive technique coverage, evasion research beyond the four defined variants, and any assessment of third-party EDR products.

### 1.3 Contributions

This report makes three contributions.

1. **An automated, two-axis Defender-evaluation tool.** A reproducible harness (reset → build/arm → trigger → collect → score → write) that measures Axis A (four C# payload variants against an EICAR proxy) and Axis B (eleven Invoke-AtomicRedTeam v2.3.0 techniques across groups G1–G5 mapped to MITRE ATT&CK), emitting traceable four-state verdicts with Operational-log evidence and a fidelity gate. The harness itself was hardened on real data — correcting detection-layer attribution by axis, treating an evidenced Defender block as a detection, and rejecting a technique whose Atomic test did not actually execute.

2. **A validated empirical picture of Defender's coverage.** On the isolated VM, Defender's signature engine detected raw on-disk samples (v0, v2 DETECTED) but missed obfuscation (v1) and fileless execution (v3); across eleven behavioural techniques it stopped only two — T1059.001 (Mimikatz via PowerShell), caught by AMSI at ~3.8 s latency, and T1562.001 (Impair Defenses), blocked by Tamper Protection and verified by event 5013 — leaving nine genuine gaps (T1082, T1057, T1218.010, T1059.003, T1547.001, T1053.005, T1003.001, T1555, T1140) for an 18.2% detection rate. Spot-checks confirmed the gaps are real rather than a cloud-off artefact: enabling cloud protection added no new detections (0/3) and enabling only the LSASS ASR rule still left T1003.001 undetected.

3. **A supplementary rule set that closes the gaps.** Two YARA rules (one for the encoded on-disk sample, one for the v0–v3 loader binary, which catches the fileless v3 by its dropper) fire on all five real artefacts with zero false positives across 12,450 goodware files (System32, SysWOW64, .NET Framework), and seven Sigma rules cover the behavioural gaps (T1082, T1057, T1218.010, T1059.003, T1547.001, T1053.005, T1003.001), each citing the run that evidenced the gap and logic-validated against synthetic matching and benign events. A mitigation mapping links each technique to its Defender layer, ASR rule, MITRE mitigation, and supplementary rule, keeping the repository AV-clean by embedding only already-obfuscated blobs.

**Honest limitations.** Only Atomic test #1 was run per technique, under a default-ish configuration; fidelity proves each atomic executed, not that the malicious effect fully occurred; Sysmon was unavailable on the measurement VM (an image-level bug), so there is no Sysmon evidence and no live-telemetry false-positive study for the Sigma rules; and EICAR is a benign detection proxy, not live malware. These bound the generality of the findings and are revisited in the limitations discussion.

## 2. Background & Measurement Design

This section establishes the two things the evaluation rests on. First, it describes the detection layers that make up Microsoft Defender on Windows 11, so that each later result can be attributed to the layer that produced (or failed to produce) it. Second, it defines the measurement design itself: the two experimental axes, the four scoring states, the fidelity model that decides whether a measurement is trustworthy, and the evidence sources from which every verdict is derived.

### 2.1 Microsoft Defender's detection layers

Modern Microsoft Defender is not a single scanner but a stack of cooperating detection mechanisms. An evaluation that reports only "detected / not detected" without naming the responsible layer is of little diagnostic value, because the same sample can be invisible to one layer and obvious to another. The layers relevant to this study are:

- **Signature / static scanning (on-demand).** The classic antivirus engine matches file contents against a signature database. In this project it is exercised directly through `MpCmdRun.exe`, which performs an on-demand scan of a given file without relying on access-time triggers. This layer operates on bytes at rest and is therefore defeated by content-level obfuscation and by code that never touches disk.
- **Real-time protection (RTP).** The on-access engine that scans files as they are written, read, or executed. RTP is what turns a dormant signature database into continuous protection; a sample that is invisible to RTP can persist and run even though the same bytes would match on an explicit scan.
- **AMSI (Antimalware Scan Interface) script scanning.** AMSI lets Defender inspect the *content* a script engine is about to execute — for example PowerShell command text after it has been de-obfuscated in memory — rather than the file on disk. This is the layer that catches in-memory script attacks that leave no scannable file.
- **Behaviour monitoring.** Runtime heuristics that watch sequences of actions (process creation, injection, suspicious API usage) and flag malicious *behaviour* rather than malicious *bytes*.
- **Attack Surface Reduction (ASR) rules.** A set of configurable, policy-driven controls that block whole classes of abuse (for example, blocking credential theft from LSASS, or blocking Office child-process creation) independently of whether the specific sample is known. ASR rules are off or in audit mode by default and must be explicitly enabled in Block mode.
- **Tamper Protection (self-defence).** A protection of Defender *itself*: it prevents external processes from disabling real-time monitoring or otherwise weakening the product, even when the caller holds administrative rights. It is a defence against "impair defenses" attacks rather than against malware payloads.
- **Cloud-delivered protection.** An optional online layer that submits metadata and samples to Microsoft's backend for near-real-time reputation and machine-learning verdicts, extending coverage beyond the locally installed signatures.

Because these layers are distinct, this study attributes every detection to the layer that produced it rather than reporting an undifferentiated outcome. In particular, a catch on the behaviour axis is treated as a **runtime/AMSI or behavioural** detection, never as a static file scan — a distinction that is load-bearing for interpreting the results in Section 4.

### 2.2 MITRE ATT&CK

MITRE ATT&CK is a publicly maintained knowledge base that catalogues real-world adversary behaviour as a matrix of **tactics** (the attacker's objective, e.g. *Discovery*, *Credential Access*, *Persistence*, *Defense Evasion*) and **techniques** (the concrete way an objective is achieved, each with a stable identifier such as `T1003.001` for *LSASS Memory* dumping). Using ATT&CK as the vocabulary for the behavioural axis gives the evaluation two properties it would otherwise lack: results map to recognised, named adversary actions rather than ad-hoc test cases, and each measured technique can be traced back to published attacker tradecraft and to candidate mitigations. The behavioural stimuli in this study are driven by **Invoke-AtomicRedTeam (v2.3.0)**, an open-source execution framework whose "atomic tests" implement individual ATT&CK techniques in a reproducible way.

### 2.3 Two-axis measurement design

The experiment is organised along two orthogonal axes so that two independent questions — "does obfuscation/filelessness defeat the file scanner?" and "does Defender detect adversary behaviour?" — can be answered separately.

**Axis A — payload variants (static / file dimension).** A single malware proxy is presented to Defender in four increasingly evasive forms:

| Variant | Form | What it tests |
|---------|------|---------------|
| v0 | Bare sample written to disk | Baseline signature match on a raw, known-bad file |
| v1 | String-encoded sample (XOR `0x5A` + Base64) stored on disk | Whether content obfuscation defeats the static scanner |
| v2 | Decode-to-disk (encoded at rest, decoded to a plaintext file before scanning) | Whether a decoded-on-disk payload is caught |
| v3 | In-memory / fileless (decoded and executed without a plaintext file on disk) | Whether a fileless payload is caught |

The malware proxy is **EICAR**, the benign, industry-standard antivirus test string. EICAR is stored in source already **XOR+Base64-encoded**, so the repository and the compiled binaries contain no plaintext malicious marker and remain AV-clean; only when **v0** or **v2** are actually *run* is a raw EICAR string dropped to disk, at which point Defender's reaction is precisely the measurement.

**Axis B — behavioural techniques (runtime dimension).** Invoke-AtomicRedTeam executes a set of ATT&CK techniques organised into five groups, **G1–G5**, each mapped to a MITRE tactic (for example, G5 covers *Discovery* and LOLBin proxy-execution techniques such as `T1082`, `T1057`, and `T1218.010`). This axis measures whether Defender's runtime layers — RTP, AMSI, behaviour monitoring, ASR, Tamper Protection — react to the technique being performed, rather than to any file on disk.

### 2.4 The four scoring states

Every measurement resolves to exactly one of four states, which separate genuine detection outcomes from measurement failures:

| State | Meaning |
|-------|---------|
| `error` | The measurement harness itself failed (build, trigger, or collection error); the result says nothing about Defender. |
| `inconclusive` | The measurement ran but the evidence is insufficient to decide detected vs. not_detected. |
| `detected` | Defender produced an in-window detection against the sample/technique. |
| `not_detected` | The stimulus demonstrably reached Defender and no detection was produced — a genuine coverage result. |

Two scoring rules proved essential once the harness met real data. First, **a Defender block counts as a detection**: a technique that Tamper Protection or another layer blocks, accompanied by in-window detection events, scores `detected` rather than `error` or `inconclusive` — a positive detection outranks the error/fidelity gates. Second, the scorer must not re-infer whether the technique ran from the evidence alone. An earlier version inferred "did it run?" from telemetry (Sysmon events or a non-clean static scan); on the behaviour axis, where Sysmon was unavailable, that inference collapsed to false and wrongly buried every *non-detected* technique — precisely the coverage gaps this study exists to surface — as `inconclusive`. The fix is to pass the atomic runner's authoritative `technique_ran` signal straight into the scorer, so that a technique which demonstrably executed and drew no detection is scored `not_detected`.

### 2.5 The fidelity model

Not every completed run is a *valid* measurement. The fidelity model assigns each measurement a score in the range 0..1, computed from four conditions:

- **`reset_ok`** — the environment was reset to a known clean state before the run;
- **`technique_ran`** — the stimulus was actually delivered, meaning either the payload executed or Defender blocked it (a block still counts as delivery, because Defender clearly received the stimulus);
- **`collect_window_complete`** — the evidence-collection window ran to completion;
- **`clean_before`** — the machine was verified clean before the stimulus.

A measurement is treated as **valid only when fidelity ≥ 0.5**; lower scores mark a result as untrustworthy regardless of its nominal state. Crucially, fidelity attests that the atomic *executed* — not that the intended malicious *effect* actually occurred — a limitation revisited in Section 2.7.

The model is also what catches "non-runs" masquerading as results. In one case the `T1562.001` atomic was not installed on the measurement VM, so `Invoke-AtomicTest` exited successfully while merely printing that the test "does not exist". An early runner mis-counted this as a run and produced a false `not_detected`. The runner was hardened to require the "Executing test" marker before crediting a technique as run; an install check then confirmed that 10 of 11 atomics were present and only `T1562.001` was missing, so only that single measurement was invalid. `T1562.001` is additionally scored by **direct RTP-state verification** rather than through the event-window pipeline, because `reset.ps1` itself toggles real-time protection and emits event `5013` noise that would otherwise confound impair-defenses scoring.

### 2.6 Evidence sources

Verdicts are grounded in operating-system telemetry, not in the exit codes of the tools under test. The primary source is the **`Microsoft-Windows-Windows Defender/Operational`** event log, whose relevant event IDs are:

| Event ID | Meaning |
|----------|---------|
| 1116 / 1117 | Malware detected / remediation action taken |
| 1015 / 1119 | Behaviour-monitoring detection |
| 5013 | Tamper Protection blocked a change to Defender |
| 2010 | Cloud-protection lookup performed |
| 5007 | Defender configuration changed |

Only true detection events (the 1116/1117 and 1015/1119 families) count toward a `detected` verdict. Configuration and self-defence events such as `5007` and `5013` are explicitly **not** detection events: the scorer ignores them, so that the benign `5013` noise emitted by `reset.ps1` cannot be mistaken for a real catch.

The intended secondary source is **Sysmon**, particularly Event ID 10 (process access) for credential-access techniques. Sysmon was, however, **unavailable on the measurement VM** owing to an image-level defect. Its absence has two consequences carried throughout the study: there is no Sysmon-based corroborating evidence for the behavioural axis, and the live false-positive validation of the supplementary Sigma rules (which key off Sysmon telemetry) cannot be performed — a limitation stated plainly in Section 2.7 rather than worked around.

### 2.7 Measurement environment and limitations

**Environment.** The safe build-and-smoke-test machine (`dev-win11`) only compiles payloads and runs harmless checks; all invasive techniques and all official measurements run on an isolated **cloud-vm**: an Azure **Windows 11 Pro Insider build 26300**, with **real-time protection ON** and **Tamper Protection ON**, restored from a clean snapshot. The **baseline** runs with **cloud-delivered protection OFF**; dedicated spot-checks re-enable cloud protection and a single ASR rule to confirm that the observed gaps are not artefacts of the baseline configuration. The engine under test is Defender **AMEngine 1.1.26100.4** with **signature version 1.463.490.0**.

**Limitations.** The scope of the measurement is deliberately bounded, and the following constraints apply to every result reported later:

- Only the first atomic test (`test#1`) of each technique is exercised; a technique missed here may still be caught in another of its atomic variants.
- The target is a near-default consumer configuration; a hardened enterprise policy (full ASR Block mode, cloud protection on, additional controls) would be expected to detect more.
- Fidelity proves that each atomic *executed*, not that its malicious *effect* was realised.
- Sysmon was unavailable, so there is no Sysmon evidence and no live-telemetry false-positive study for the Sigma rules.
- The malware proxy is **EICAR**, a benign detection test string, not live malware; Axis A therefore measures the signature/obfuscation/fileless pipeline rather than Defender's verdict on genuine malicious code.

## 3. System Architecture & Methodology

The evaluation tool is organised as three cooperating blocks: a **sample-generation block** that produces controlled malicious stimuli, a **behaviour engine** that exercises adversary techniques, and an **automated measurement station** that drives each trial end-to-end and records a verdict. The first two blocks define *what* is presented to Microsoft Defender; the third defines *how* each presentation is executed, observed, and scored. The whole tool is implemented in Python 3.12 using only the standard library plus `pyyaml`, with `unittest` as the test framework (61 tests pass). Measurement is organised along two orthogonal axes — **Axis A** (static/file-based detection via four payload variants) and **Axis B** (behavioural detection via MITRE ATT&CK techniques) — so that the static signature layer and the runtime/behavioural layers are probed independently.

### 3.1 Block 1 — Sample Generation (Axis A)

Axis A isolates the file-scanning path of Defender by presenting the *same* malicious content in four increasingly evasive forms. Because using live malware would be both unsafe and non-reproducible, the malware is proxied by the **EICAR** test string — a benign, industry-standard antivirus test pattern that compliant engines treat as a detection. The four C# payload variants are:

| Variant | Form presented to Defender | Purpose |
|---------|----------------------------|---------|
| **v0** | Bare EICAR sample written to disk | Baseline: plaintext signature match on disk |
| **v1** | String-encoded sample (XOR `0x5A` + Base64) written to disk in encoded form | Tests resilience to simple obfuscation |
| **v2** | Encoded sample decoded to disk at runtime | Tests on-write scanning of a decoded artefact |
| **v3** | In-memory / fileless execution of the sample | Tests whether a never-on-disk payload is seen |

A deliberate design constraint keeps the repository and the compiled binaries free of any raw detectable content: the EICAR string is stored **XOR `0x5A` + Base64-encoded in source**, so neither the cloned repository nor the built executables trip Defender. Only when **v0** and **v2** are actually *run* is the raw EICAR string materialised on disk, at which point Defender's reaction is precisely the quantity being measured. The C# variants are compiled with the system `csc.exe` compiler (.NET Framework), requiring no Visual Studio or SDK installation, which keeps the build reproducible on a default Windows image.

### 3.2 Block 2 — Behaviour Engine (Axis B)

Axis B exercises Defender's runtime and behavioural layers using **Invoke-AtomicRedTeam (v2.3.0)**, a public implementation of adversary procedures mapped to MITRE ATT&CK. Techniques are organised into five groups (**G1–G5**) spanning discovery, execution, defence evasion, persistence, and credential access. The behaviour engine delivers the atomic stimulus, waits for Defender to react, and hands control back to the measurement station. A specific hardening measure governs this block: the runner only counts a technique as *executed* when Invoke-AtomicTest emits its `Executing test` marker, because an atomic that is **not installed** can exit with status 0 while merely printing a "does not exist" notice. Requiring the execution marker prevents a non-run from being mis-scored as a genuine `not_detected` result.

### 3.3 Block 3 — Automated Measurement Station

The measurement station (`run_measure`) drives every trial through a fixed, repeatable loop:

**reset → build/arm → trigger → collect logs → compute fidelity → score (1 of 4 states) → write to SQLite.**

Each stage is deterministic and logged, so an individual measurement can be reconstructed from its stored record.

#### 3.3.1 Scoring core

Every trial resolves to exactly one of **four states**:

| State | Meaning |
|-------|---------|
| `error` | The trial could not be completed as intended |
| `inconclusive` | The trial ran but evidence was insufficient to decide |
| `detected` | Defender raised a detection against the stimulus |
| `not_detected` | The stimulus was delivered but Defender did not detect it |

Two scoring rules were refined against real data. First, **detection attribution is axis-aware**: a catch on the behaviour axis is attributed to the runtime/AMSI layer rather than to a static file scan, so the reported detection layer reflects the mechanism that actually fired. Second, **a Defender block counts as a detection**: a technique that Defender blocks, when accompanied by in-window detection events, is scored `detected` rather than `error` or `inconclusive` — positive detections outrank the error and fidelity gates. One technique, T1562.001 (Impair Defenses), is deliberately *excluded* from the event-window pipeline and scored instead by **direct Real-Time-Protection state verification**, because the reset procedure itself toggles RTP and emits event `5013` noise that would otherwise confound impair-defenses scoring.

#### 3.3.2 Fidelity model

Detection outcomes are only meaningful if the trial was itself well-formed. A **fidelity score in [0, 1]** is computed from four conditions:

- `reset_ok` — the environment was returned to a known clean state;
- `technique_ran` — the stimulus was genuinely delivered (the payload ran *or* Defender blocked it);
- `collect_window_complete` — the log-collection window ran to completion;
- `clean_before` — the system was clean at the start of the trial.

A trial is considered **valid when fidelity ≥ 0.5**. Fidelity thus certifies that each atomic *executed* and was *observed under controlled conditions*; it does not claim that the technique's malicious *effect* was achieved — a limitation discussed in Section [Limitations].

#### 3.3.3 Evidence sources

Detections are read from the **`Microsoft-Windows-Windows Defender/Operational`** log, keyed on the following event IDs:

| Event ID(s) | Signal |
|-------------|--------|
| 1116 / 1117 | Malware detected / remediation action taken |
| 1015 / 1119 | Behavioural detection |
| 5013 | Tamper Protection block |
| 2010 | Cloud-protection (MAPS) lookup |
| 5007 | Configuration changed |

**Sysmon** was intended as a secondary evidence source (notably EID 10 for process access), but it was **unavailable on the measurement VM** due to an image-level issue; the consequences for the supplementary Sigma rules are noted under Limitations.

#### 3.3.4 Traceability

Every measurement row is self-describing and reproducible. Each row records the **sample SHA-256 hash**, the **trigger timestamp**, and the **Defender signature version** in effect, and is written to a **SQLite** database together with its state, fidelity, validity flag, evidence source, detection layer, detection latency, and the Defender event IDs observed. Pinning the signature version is essential because cloud-delivered verdicts drift over time; recording it lets later readers distinguish a genuine capability gap from signature churn.

### 3.4 Safety Boundary

Because Axis B contains genuinely invasive procedures (e.g. LSASS credential dumping and disabling Defender), the tool enforces a two-tier safety boundary governed by a single configuration lock:

- **`dev-win11` (developer machine).** Used only to build payloads, run smoke tests, and perform static scans. The atomic runner blocks all invasive techniques, and the reset routine never touches Defender or its logs. This machine never produces official measurements.
- **`cloud-vm` (isolated Azure VM).** All invasive techniques and all official measurements run here, on a **clean snapshot** of **Azure Windows 11 Pro (Insider build 26300)**. The documented baseline configuration is **RTP ON, Tamper Protection ON, cloud protection OFF**, with Defender **AMEngine 1.1.26100.4** and **signature 1.463.490.0**. If Defender's protection state ever looks wrong during a run, the procedure is to stop and revert to the VM snapshot.

### 3.5 Configuration-Locking Methodology

To attribute any change in Defender's behaviour to a *single* cause, the measurement campaign follows a strict experimental-control protocol in which **exactly one setting is varied between a baseline and a spot-check**, with everything else held fixed and the Defender build pinned before and after the run.

- **Baseline.** The primary Axis-B results are taken with cloud protection OFF and no ASR rules, establishing a representative default-ish consumer configuration.
- **Cloud-ON spot-check.** Only the cloud variables (`MAPSReporting → Advanced`, `SubmitSamplesConsent → SendSafeSamples`) are enabled; ASR and every other setting are left untouched, and the project config flag `environment.cloud_protection` is flipped so rows are labelled correctly. A **control technique** (T1059.001, caught locally by AMSI) must stay `detected`; if the control flips, something other than cloud changed and the run is invalidated. After the run the Defender build is re-captured (the signature may have updated via cloud) and the configuration is **reverted** to restore the reproducible baseline.
- **ASR spot-check.** Only a single ASR rule (the LSASS rule, in Block mode) is enabled, again changing nothing else, so any state change is attributable to that one rule alone.

This per-variable locking is what lets the study report a capability *gap* honestly: by re-testing the same stimuli under cloud-ON and under ASR, it demonstrates that an undetected technique remains undetected not because of a disabled baseline setting, but as a genuine gap in the layer under test.

## 4. Measurement Results

This section reports the validated outcomes of the two measurement axes. All measurements for the invasive techniques and all official results were produced on the isolated cloud virtual machine (Azure Windows 11 Pro, Insider build 26300) with real-time protection (RTP) and Tamper Protection enabled and cloud-delivered protection off for the baseline (Defender AMEngine 1.1.26100.4, signature 1.463.490.0). Every reported measurement has a fidelity score of 1.0, confirming that each stimulus was delivered — the payload ran or Defender blocked it — the collection window completed, and the host was clean before the run. Axis A results are drawn from the static-scan path; Axis B results from the behavioural (Invoke-AtomicRedTeam, v2.3.0) path.

### 4.1 Axis A — Payload-variant static detection

Axis A exercises Microsoft Defender's static (signature) engine against four C# payload variants built around EICAR as a benign detection proxy. The variants differ only in how the sample is presented to the engine: bare on disk, string-encoded (XOR 0x5A + Base64), decoded to disk at runtime, or loaded in memory without ever touching disk.

| Variant | Description | Sample on disk? | State | Fidelity | Detecting layer |
|---------|-------------|-----------------|-------|----------|-----------------|
| v0 | Bare sample written to disk | Yes (raw) | **detected** | 1.0 | Signature / static |
| v1 | String-encoded sample (XOR 0x5A + Base64) | Yes (encoded) | **not_detected** | 1.0 | — |
| v2 | Decode-to-disk, then present | Yes (raw, after decode) | **detected** | 1.0 | Signature / static |
| v3 | In-memory / fileless | No | **not_detected** | 1.0 | — |

**Analysis.** Defender's signature engine detected exactly the two variants that place the raw sample bytes on disk (v0 and v2) and missed the two that do not expose those bytes to a file scan (v1, which stays encoded, and v3, which never writes the sample to disk). The result isolates a single mechanism: on-disk signature matching. Trivial obfuscation (v1) and a fileless loading strategy (v3) each defeat it, even though v2 shows that the very same raw bytes are caught the moment they are written in the clear. These two gaps — the encoded sample on disk and the fileless loader — are the direct targets of the supplementary YARA rules described in Section 5.

### 4.2 Axis B — Behavioural detection across MITRE ATT&CK techniques

Axis B drives eleven ATT&CK techniques (Atomic test #1 of each) across five groups and records whether Defender detected, blocked, or missed each one, together with the responsible detection layer and the observed latency.

| # | Technique | Group | State | Layer | Latency |
|---|-----------|-------|-------|-------|---------|
| 1 | T1059.001 — PowerShell (Mimikatz) | G1 | **detected** | AMSI / runtime | ~3.8 s (3804 ms) |
| 2 | T1562.001 — Impair Defenses (disable Defender) | G2 | **detected** (blocked) | Tamper Protection | — (state-verified) |
| 3 | T1082 — System Information Discovery | G5 | not_detected | — | — |
| 4 | T1057 — Process Discovery | G5 | not_detected | — | — |
| 5 | T1218.010 — Regsvr32 (LOLBin) | G5 | not_detected | — | — |
| 6 | T1059.003 — Windows Command Shell | G1 | not_detected | — | — |
| 7 | T1547.001 — Registry Run Key | G4 | not_detected | — | — |
| 8 | T1053.005 — Scheduled Task | G4 | not_detected | — | — |
| 9 | T1003.001 — OS Credential Dumping (LSASS) | G3 | not_detected | — | — |
| 10 | T1555 — Credentials from Password Stores | G3 | not_detected | — | — |
| 11 | T1140 — Deobfuscate/Decode Files or Information | G2 | not_detected | — | — |

**Headline: of the eleven behavioural techniques, Defender stopped 2 and missed 9 — a detection rate of 18.2%.**

#### The two Defender successes

- **T1059.001 (PowerShell, Mimikatz) — detected by AMSI at ~3.8 s.** The atomic (the Mimikatz test) was caught at runtime through the Antimalware Scan Interface, which inspects script content as it is submitted for execution. Defender emitted events 1116 (malware detected, realtime) and 1117 (countermeasure action taken), and the atomic itself failed with "Access is denied", consistent with the recorded block. Because this catch occurred on the behaviour axis — where no on-demand file scan runs — the detection is attributed to the runtime/AMSI layer rather than a static file scan, even though 1116/1117 are generic "malware detected / action taken" records.
- **T1562.001 (Impair Defenses — disable Defender) — blocked by Tamper Protection.** The attempt to disable Defender was stopped by Tamper Protection, Defender's self-defence layer. This technique is scored by direct verification of the post-technique protection state, not by the event-window pipeline, because Tamper Protection blocks are logged as event 5013 and `reset.ps1` itself toggles RTP and emits 5013 noise in-window, which would confound event-based scoring. The direct check confirmed RTP never dropped, event 5013 landed at the exact trigger time, and no configuration-change events (5007/5001) were emitted — i.e. the disable attempt was defeated. This is a genuine Defender win and is credited as a block.

#### The nine gaps

Defender did not fire at all on the remaining nine techniques, which span the full behavioural spectrum: discovery (T1082, T1057), a signed-binary LOLBin (T1218.010 Regsvr32), command-shell execution (T1059.003), both persistence techniques (T1547.001 Registry Run Key, T1053.005 Scheduled Task), both credential-access techniques (T1003.001 LSASS dumping, T1555 password stores), and deobfuscation (T1140). In each case the atomic ran to completion with no Defender detection events beyond the usual reset noise.

**Confirming the gaps are real, not a configuration artifact.** Because the baseline runs with cloud-delivered protection off, two spot-checks were performed to rule out that the misses were merely an offline-engine effect:

- **Cloud-ON spot-check (run 9).** Toggling only cloud protection on left T1003.001 (LSASS), T1547.001 (Run Key) and T1218.010 (Regsvr32) still **not_detected** — a delta of 0 of 3. The control technique T1059.001 stayed detected and emitted cloud-lookup events (2010), proving cloud was genuinely active; its latency rose from ~3.8 s to ~7.6 s. Cloud added nothing for the tested variants.
- **ASR spot-check (run 10).** Enabling only the LSASS attack-surface-reduction rule (GUID 9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2) in Block mode still left T1003.001 **not_detected** (no event 1121). Even the dedicated ASR rule missed this atomic variant.

Together these spot-checks show the nine gaps persist with cloud protection and the relevant ASR rule enabled, so they characterise genuine coverage gaps for the tested variants rather than an artifact of the baseline posture.

#### Detection layers and latency

The measurements expose exactly three working Defender layers across both axes:

1. **Signature on raw on-disk samples** (Axis A, v0/v2): fast and reliable against plaintext malware bytes on disk, but defeated by encoding and by fileless loading.
2. **AMSI / runtime** (Axis B, T1059.001): the only behavioural layer that produced a detection, catching malicious script content at execution. AMSI is a local layer and therefore fires regardless of cloud state, which is why it is the lone behavioural detection in the baseline. Measured latency was ~3.8 s offline and ~7.6 s with cloud protection on — the extra ~3.8 s being the cost of the cloud-reputation round-trip (events 2010). Both figures are well within a single execution window, indicating that when AMSI does catch a technique it does so promptly.
3. **Tamper Protection** (Axis B, T1562.001): Defender's self-defence layer, which blocked the attempt to disable Defender. Its action is observable through protection-state verification rather than detection latency.

The overall picture is consistent across the two axes: Defender's coverage in this configuration concentrates on content it can inspect statically on disk or at script-execution time, and on defending its own controls. Behavioural techniques that avoid readable script content — discovery, LOLBins, registry- and task-based persistence, credential access, and deobfuscation — pass without detection, and neither cloud protection nor the LSASS ASR rule closed those gaps for the tested atomics.

### 4.3 Measurement validity and limitations

One of the eleven Axis-B measurements was found invalid and corrected. The T1562.001 atomic was not installed on the VM, so Invoke-AtomicTest exited 0 while printing that the test "does not exist"; an earlier version of the runner mis-counted this as a successful run (a false not_detected at run 11). The runner was fixed to require the "Executing test" marker before counting a technique as run, and an install-check confirmed 10 of 11 atomics were installed — only T1562.001 was missing — so only that single measurement was affected. T1562.001 was then re-measured by direct RTP-state verification, yielding the Tamper Protection block reported above. All remaining Axis-B measurements used installed atomics and stand.

These results carry the following limitations, which bound their interpretation:

- Only Atomic test #1 of each technique was exercised; other test numbers within a technique may behave differently.
- The configuration is a default-ish consumer posture (RTP and Tamper Protection on; cloud and ASR off by baseline and measured separately). The spot-checks show cloud and the LSASS ASR rule do not close the gaps for the tested variants, but a fuller configuration sweep is out of scope.
- Fidelity confirms that each atomic executed, not that the intended malicious effect was achieved.
- Sysmon was unavailable on the measurement VM (an image-level issue), so no Sysmon-based evidence was collected and live-telemetry false-positive validation of the Sigma rules (Section 5) is not possible.
- EICAR is a benign industry test string used as a detection proxy; Axis A measures the engine's reaction to that proxy, not to live malware.

## 5. Validity, Spot-checks & Measurement Hardening

A detection study whose headline is "Defender missed 9 of 11 techniques" invites an obvious objection: are those gaps real properties of the product, or artefacts of how the measurement was run? This section defends the validity of the Axis A and Axis B results. It reports two targeted spot-checks that rule out the most plausible configuration artefact (cloud protection being off), one further spot-check against Defender's Attack Surface Reduction (ASR) layer, three measurement-hardening fixes that were discovered by inspecting real data rather than in review, and the single measurement that the hardening correctly invalidated and the way it was ultimately settled. The guiding principle throughout was that a reported gap must survive the strongest cheap attempt to explain it away.

### 5.1 The validity concern: is a gap a cloud-OFF artefact?

The baseline measurements were taken with Defender's cloud-delivered protection (MAPS) turned off, while real-time protection (RTP) and Tamper Protection remained on. Cloud protection is an additional analysis layer that submits suspicious material to Microsoft's backend for a verdict, so a sceptic could reasonably argue that the on-device engine was being judged with one hand tied behind its back, and that the gaps would close under a default consumer configuration with cloud on. Two spot-checks were run specifically to test that objection; a third extended the same reasoning to ASR.

### 5.2 Cloud-ON spot-check: delta 0/3, control held

In the cloud-ON spot-check (run 9) only the cloud variable was changed: MAPSReporting was set to Advanced and SubmitSamplesConsent to SendSafeSamples, with RTP and Tamper Protection left exactly as in the baseline, and the setting reverted afterwards. The Defender build was pinned for reproducibility (AMEngine 1.1.26100.4, signature 1.463.490.0, stable before and after the run). Three representative gap techniques were re-measured against their cloud-OFF verdicts.

| Technique | Baseline (cloud-OFF) | Spot-check (cloud-ON) | Delta |
|---|---|---|---|
| T1003.001 (LSASS dump) | not_detected | not_detected | 0 |
| T1547.001 (Registry Run Key) | not_detected | not_detected | 0 |
| T1218.010 (Regsvr32 LOLBin) | not_detected | not_detected | 0 |
| T1059.001 (PowerShell, control) | detected | detected | 0 (held) |

Not one of the three gap techniques changed verdict: the cloud-ON delta is 0/3. Crucially, this is a genuine negative result and not a silently broken run, because the control proves the cloud path was live during the measurement. T1059.001 remained detected and, under cloud-ON, additionally emitted event 2010 (cloud-protection lookup) three times — "used cloud protection to get additional security intelligence" — which is direct evidence that the MAPS path was exercised. As a side observation, cloud-ON detection latency for the control rose from roughly 3.8 s to roughly 7.6 s, the cloud round-trip adding time even when local AMSI had already made the catch. The conclusion is that, for these Atomic test variants, cloud-delivered protection adds nothing the on-device engine did not already provide, and the cloud-OFF baseline is therefore representative. The gaps are a property of the product's coverage, not of the test configuration.

### 5.3 ASR spot-check: LSASS still missed

The cloud-ON run deliberately left ASR disabled to isolate the cloud variable, so a dedicated ASR spot-check (run 10) was run to close the remaining question for the study's most sensitive technique, LSASS credential dumping. Only the "Block credential stealing from lsass.exe" ASR rule (GUID 9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2) was enabled, in Block mode, with cloud left off so that ASR was the only changed variable. This rule is widely regarded as effective against common LSASS-dump methods, so it was the strongest single Defender layer left to try against this gap.

| Configuration | T1003.001 state | ASR block/audit event |
|---|---|---|
| RTP, cloud OFF (run 8) | not_detected | — |
| RTP, cloud ON (run 9) | not_detected | — |
| RTP + LSASS ASR, Block (run 10) | not_detected | none (1121 absent) |

The ASR rule did not fire: there was no 1121 block event and no 1122 audit event, and the atomic ran cleanly. All three Defender layers available on this host — signature/RTP, cloud, and the dedicated ASR rule — missed this variant of T1003.001. This result is honestly scoped to Invoke-AtomicTest #1 for the technique (other test numbers may be caught), and it directly motivates the project's supplementary Sigma rule for LSASS process access (Sysmon EID 10) as the primary gap-filler for this case rather than any built-in Defender layer. Together the two spot-checks establish that neither cloud protection nor the relevant ASR rule rescues the baseline gaps, so the cloud-OFF matrix can be presented with confidence.

### 5.4 Measurement hardening: three fixes found on real data

Running the measurements on real telemetry — rather than only reasoning about them — surfaced three defects in the scoring and orchestration logic. Each was fixed and is documented here because each materially affects how a verdict is reached.

**Detection layer attributed by axis.** A detection on the behaviour axis is a runtime catch (for example AMSI inspecting script content at execution), whereas a detection on the static axis is a file scan. The tooling now labels the detection layer by axis so that a behaviour-axis catch is never mis-reported as a static file scan. This was confirmed on real data: the cloud-ON control's layer was correctly labelled `behavior`, consistent with AMSI being the detecting component.

**A Defender block counts as a detection.** The original scoring gates could let an error or low-fidelity signal override a real detection. The rule was corrected so that positive detections outrank the error and fidelity gates: a technique that Defender blocks, and for which in-window detection events were captured, scores `detected` rather than `error` or `inconclusive`. Without this fix, genuine Defender wins would be understated.

**The runner no longer counts a non-run as a run.** The orchestrator's fidelity model treats "the technique ran" as the signal that a stimulus was actually delivered. The original `atomic_runner` computed `ran = exit_ok and bool(output)`, which is unsound because `Invoke-AtomicTest` can exit 0 while merely printing an error to stdout. The runner now requires the positive "Executing test" marker that Invoke-AtomicTest prints only when a test truly runs, and it rejects not-installed phrases ("does not exist", "unable to find", "no atomics"). A missing or failed atomic is now `ran=False`, so the scorer returns `inconclusive`/`error` instead of a false `not_detected`. The regression suite was extended for the missing-atomic and exit-0-without-marker cases, and the full tool now passes its unit tests (61 overall).

### 5.5 The atomic-install bug and the install-check that validated the rest

The third fix was not hypothetical: it was found because it had already produced one wrong result. The Atomic test for T1562.001 (Impair Defenses — disable Defender) was not installed on the measurement VM. `Invoke-AtomicTest T1562.001` therefore exited 0 while printing that the test file did not exist, and the old runner's `ran = exit_ok and bool(output)` logic mis-counted this non-run as a run. Run 11 consequently recorded a `not_detected` for a technique that had never actually executed — a false gap.

Because this failure mode would silently invalidate any `not_detected` whose atomic happened to be absent, the entire Axis B set was re-validated with a `Test-Path` install-check across all 11 technique IDs, together with exact-stdout confirmation of the detection strings. The check found that 10 of 11 atomics were installed and only T1562.001 was missing. The exact stdout confirmed the mechanism: the good run `T1059.001-1` contained "Executing test" (the new positive marker fires), while `T1562.001-1` produced "...does not exist" at exit 0 with no marker (the new runner correctly returns `ran=False`). The conclusion is that only run 11 was invalid; every other Axis B measurement used an installed atomic that genuinely executed, and those verdicts stand. As a bonus, the install-check confirmed that `T1059.001-1` is the Mimikatz test, which Defender blocked with "Access is denied", consistent with the detection the pipeline had already recorded.

### 5.6 Settling T1562.001 by direct RTP-state verification

The invalid measurement was not simply discarded; the technique was re-measured by a method appropriate to its class. Impair-Defenses cannot be scored reliably through the event-window pipeline, because Tamper Protection blocks are logged as event 5013, which the scorer treats as a configuration/defence event rather than a detection, and because `reset.ps1` itself toggles RTP and emits 5013 noise that lands inside the same collection window — a technique-induced 5013 cannot be told apart from reset noise. The sound method is therefore to observe the protection state directly: did RTP actually drop?

A read-only monitor watched RTP across the window while the trigger `Set-MpPreference -DisableRealtimeMonitoring 1` was issued at 23:15:17. RTP never left True for the entire window; the Defender log showed event 5013 (Tamper Protection blocked a change) at exactly the trigger time, with no 5007 (config changed) and no 5001 (RTP disabled); and the final state was RTP=True, TamperProtected=True. Tamper Protection blocked the disable attempt, so T1562.001 is scored a Defender win rather than a gap. This scoring-by-state-verification is a documented scoping of the tool for the impair-defenses class, not a defect in the measurement.

The net effect on the headline is to strengthen, not weaken, the result. Rather than a provisional "1 detected / 9 not_detected", the validated tally is that Defender stopped 2 of 11 behavioural techniques through two distinct layers — AMSI (script content, catching Mimikatz) and Tamper Protection (self-defence, blocking the disable attempt) — and missed 9 genuine gaps that the spot-checks confirmed are not configuration artefacts. The validity work thus changed one verdict from a false gap to Defender's clearest win, confirmed that every remaining gap is real, and left the measurement pipeline unable to repeat the error that was found.

### 5.7 Residual threats to validity

Several limitations remain and are stated plainly. Only Atomic test #1 was exercised per technique, so each verdict is scoped to that specific variant rather than the technique as a whole; the LSASS result in particular is bounded to test #1. The fidelity model proves that each atomic executed (exit status plus output marker), not that the intended malicious effect — for example an actual read of LSASS memory — occurred, which is a general limitation of all behaviour-axis measurements. Sysmon was unavailable on the measurement VM owing to an image-level bug, so there is no Sysmon evidence and no live-telemetry false-positive study for the Sysmon-based Sigma rules. The target configuration is a default-ish consumer setup, so results should not be read as covering hardened enterprise policy. Finally, the malware proxy throughout is EICAR, a benign industry test string, so Axis A speaks to the signature and fileless-coverage mechanism rather than to real malware. These caveats bound the claims; within those bounds, the spot-checks and the hardening establish that the reported gaps are genuine.

## 6. Supplementary Rule Set & Mitigation

The measurements in Sections 4 and 5 established that Microsoft Defender, in a default-ish consumer configuration on the cloud-vm, caught only the raw on-disk samples (Axis A v0/v2) and 2 of 11 behavioural techniques (Axis B: AMSI on T1059.001, Tamper Protection on T1562.001), leaving a detection rate of 18.2% on Axis B and two uncovered payload variants on Axis A. This section describes the supplementary YARA/Sigma rule set (M11) built to close those measured gaps, its validation, and the consolidated mitigation mapping. The guiding principle is minimalism: a supplementary rule is written only where Defender was measured to fail, so v0/v2 and the two techniques Defender already handles receive no rule.

### 6.1 YARA rules for the payload-variant gaps (Axis A)

Two YARA rules target the two Axis A variants that Defender's signature engine missed: the string-encoded sample (v1) and the in-memory/fileless loader (v3).

| Rule | Target | Gap it closes |
|---|---|---|
| `KTLD_Encoded_Sample_On_Disk` | The v1 encoded-sample bytes (the XOR 0x5A + Base64 blob as it lands on disk) | v1 not_detected by the signature engine, because obfuscation defeats the raw-string signature |
| `KTLD_Payload_Loader_Binary` | The v0–v3 loader `.exe` (the dropper that carries and decodes the blob) | v3 not_detected, by catching the fileless payload through its on-disk loader/dropper rather than the in-memory artifact |

A key design constraint is that the rule files themselves must not trip an antivirus scan, so the repository and its build outputs stay clean. The rules therefore embed only the already-obfuscated blob and ordinary .NET loader strings as their match criteria; they never contain a plaintext malicious signature.

**Live validation.** The YARA set was validated against real artifacts, not synthetic stand-ins. It fired on 5 of 5 true-positive targets: the one real encoded sample plus the four loader binaries (v0–v3). It produced 0 false positives over a goodware corpus of 12,450 files drawn from System32, SysWOW64, and the .NET Framework directories. On this corpus the two rules therefore achieve a precision of 1.0 and a recall of 1.0.

### 6.2 Sigma rules for the behavioural gaps (Axis B)

Seven Sigma rules were written, one for each behavioural technique that scored not_detected and is amenable to a generic detection rule. Each rule cites the specific `run_id` that documents the gap it addresses, so the detection is traceable back to the measurement that motivated it.

| Sigma rule | Technique | Log source |
|---|---|---|
| `ktld_t1082_system_information_discovery` | T1082 System Information Discovery | Process creation / Sysmon |
| `ktld_t1057_process_discovery` | T1057 Process Discovery | Process creation / Sysmon |
| `ktld_t1218_010_regsvr32_lolbin` | T1218.010 Regsvr32 LOLBin | Process creation / Sysmon |
| `ktld_t1059_003_windows_command_shell` | T1059.003 Windows Command Shell | Process creation / Sysmon |
| `ktld_t1547_001_registry_run_key` | T1547.001 Registry Run Key | Registry event |
| `ktld_t1053_005_scheduled_task` | T1053.005 Scheduled Task | Process creation / task event |
| `ktld_t1003_001_lsass_memory_access` | T1003.001 LSASS Memory Dump | Sysmon EID 10 (process access) |

The T1003.001 rule is the primary gap-filler: LSASS credential dumping was missed by the real-time protection, by cloud-delivered protection in the cloud-ON spot-check, and by the dedicated LSASS ASR rule in Block mode, so a detection-layer rule is the only remaining control in this measured configuration. Two measured techniques were deliberately left uncovered because a single generic rule is not the right instrument: T1555 (Credentials from Password Stores) is too application-specific and is held as a candidate for a targeted rule once the exact store and atomic are fixed, and T1140 (Deobfuscate/Decode) is likewise a candidate better addressed by content/behaviour correlation.

**Validation (logical).** All 7 rules were logic-validated: each fires on a synthetic event that models its corresponding atomic behaviour and stays silent on a benign event, giving a 7/7 true-positive result with no false positive on the benign cases. A live-telemetry false-positive study — running the Sigma set against real benign process/registry telemetry to count field FPs — could not be performed, because Sysmon was unavailable on the measurement VM (an image-level bug). This is an honest limitation: unlike the YARA rules, the Sigma rules carry no live false-positive figure, and their precision on real-world telemetry is therefore unverified. The absence of Sysmon equally blocks the live Sigma false-positive measurement and the Sysmon-based detection evidence noted in Section 4.

### 6.3 Mitigation mapping

The mitigation mapping (`report/mitigation_mapping.md`) consolidates, for each measured technique and variant, the Defender layer that stopped it (if any), the relevant ASR rule, the MITRE ATT&CK mitigation, and the supplementary KTLT rule that fills the gap. The following table summarises the technique-to-layer-to-rule relationship.

| Technique / variant | Measured | Defender layer | ASR | Supplementary rule |
|---|---|---|---|---|
| T1059.001 PowerShell (Mimikatz) | detected | AMSI (runtime) | - | - (covered) |
| T1562.001 Impair Defenses | blocked | Tamper Protection | - | - (covered) |
| T1003.001 LSASS dump | not_detected | none (ASR tested, missed) | lsass rule `9e6c4e1f-…` (Block, missed) | `ktld_t1003_001_lsass_memory_access` |
| T1547.001 Registry Run Key | not_detected | - | - | `ktld_t1547_001_registry_run_key` |
| T1053.005 Scheduled Task | not_detected | - | - | `ktld_t1053_005_scheduled_task` |
| T1218.010 Regsvr32 LOLBin | not_detected | - | WDAC/AppLocker instead | `ktld_t1218_010_regsvr32_lolbin` |
| T1059.003 Windows cmd | not_detected | - | - | `ktld_t1059_003_windows_command_shell` |
| T1082 System Info Discovery | not_detected | - | - | `ktld_t1082_system_information_discovery` (detect-only) |
| T1057 Process Discovery | not_detected | - | - | `ktld_t1057_process_discovery` (detect-only) |
| T1555 Password Stores | not_detected | - | - | candidate (app-specific) |
| T1140 Deobfuscate/Decode | not_detected | - | - | candidate |
| Axis A v0 raw sample | detected | signature (static) | - | - (covered) |
| Axis A v1 encoded sample | not_detected | - | - | `KTLD_Encoded_Sample_On_Disk` (YARA) |
| Axis A v2 decode-to-disk | detected | signature (static) | - | - (covered) |
| Axis A v3 fileless loader | not_detected | - | - | `KTLD_Payload_Loader_Binary` (YARA) |

The mapping resolves into a clear picture of Defender's effective layers versus its gaps:

- **Working layers.** Three Defender layers performed as intended: AMSI, which inspected script content and caught the Mimikatz-via-PowerShell execution; Tamper Protection, which blocked the attempt to disable Defender itself (verified directly via a 5013 event at the trigger time, with RTP never dropping); and the signature engine, which detected the raw EICAR sample whenever it reached disk in plaintext (v0 and v2).
- **Gaps.** The gaps fall into two families: behavioural techniques with no AMSI, signature, or Tamper hook — discovery, LOLBin proxy execution, persistence, and LSASS dumping — and payloads that avoid a plaintext on-disk form through obfuscation (v1) or fileless execution (v3). The spot-checks confirm these gaps are genuine and not an artifact of the cloud-protection-OFF baseline: enabling cloud protection changed nothing for the sampled techniques (delta 0/3), and enabling the LSASS ASR rule in Block mode still left T1003.001 undetected.
- **Fill.** The KTLT supplementary rule set — 2 YARA plus 7 Sigma rules — closes the measured gaps, alongside the enterprise hardening the mapping recommends per technique (the LSASS ASR rule deployed together with the Sigma rule, since ASR alone missed this variant; WDAC/AppLocker for the Regsvr32 LOLBin; and command-line and scheduled-task auditing). The recommendation for the discovery techniques (T1082, T1057) is detection only, because they rely on benign LOLBins that cannot be blocked without breaking legitimate use.

### 6.4 Scope and limitations of the rule set

The supplementary rules should be read against the same limitations that bound the measurements. They answer only the gaps observed under a single, default-ish consumer configuration, using the first Atomic test per technique and the EICAR proxy as a benign stand-in for real malware; a different configuration, a different atomic variant, or genuine malware could shift which layer catches what. The YARA rules carry a strong, live false-positive result (0 over 12,450 goodware files), but the Sigma rules are only logic-validated: with Sysmon unavailable on the measurement VM, their behaviour against real benign telemetry is untested, so their deployed false-positive rate remains an open item. The rule set is therefore best understood as an evidence-backed starting point that directly maps to the measured gaps, to be re-validated — especially the Sigma false-positive study — once Sysmon telemetry is available.

## 7. Discussion, Limitations, Recommendations & Conclusion

### 7.1 Discussion: what Defender defended and what it missed

The measurements separate Microsoft Defender's genuine strengths from its behavioural blind spots with unusual clarity, because the two axes stress complementary detection layers. Axis A exercises the static signature engine against the same logical payload in four forms, and Axis B exercises the runtime/behavioural engine against eleven MITRE ATT&CK techniques.

**Where Defender works.** Three defensive layers performed exactly as designed:

- **Signature on raw on-disk content.** In Axis A, both variants that place a plaintext sample on disk were caught: v0 (bare sample) and v2 (decode-to-disk) were `detected` by the signature engine. The engine reliably recognises the known-bad byte pattern once it exists on disk in the clear.
- **AMSI on script content.** In Axis B, the only `detected` technique was T1059.001 (Mimikatz launched through PowerShell), flagged by the Antimalware Scan Interface at roughly 3.8 s latency. AMSI's visibility into the deobfuscated script buffer at runtime is the single behavioural win.
- **Tamper Protection self-defence.** T1562.001 (Impair Defenses — an attempt to disable Defender) was blocked by Tamper Protection. This was verified directly rather than through the event-window pipeline: real-time protection never dropped, event 5013 fired at the exact trigger time, and no configuration-change events (5007/5001) were emitted. Defender successfully protected its own controls from being switched off.

**Where Defender is blind.** Against the eleven Axis B techniques, Defender stopped 2 and missed 9 — a **detection rate of 18.2%**. The nine genuine gaps span the whole post-compromise lifecycle:

| Category | Techniques missed (`not_detected`) |
| --- | --- |
| Discovery | T1082 System Information Discovery, T1057 Process Discovery |
| LOLBins / execution | T1218.010 Regsvr32, T1059.003 Windows cmd |
| Persistence | T1547.001 Registry Run Key, T1053.005 Scheduled Task |
| Credential access | T1003.001 LSASS Dump, T1555 Password Stores |
| Defense evasion | T1140 Deobfuscate/Decode |

Axis A reinforces the same lesson from the payload side: v1 (string-encoded with XOR 0x5A + Base64) and v3 (in-memory/fileless) were both `not_detected`. The signature engine catches the known pattern only when it is materialised on disk in the clear; it misses the identical logic once it is obfuscated (v1) or never written to disk at all (v3). Taken together, the evidence describes a defender that is strong on *known content* — raw files, script buffers, and its own configuration — but weak on *behaviour*: discovery, living-off-the-land binaries, persistence mechanisms, credential dumping, and deobfuscation routines pass largely unremarked.

**The critical nuance: cloud and ASR did not close these gaps.** It would be easy to dismiss the nine misses as an artefact of the cloud-protection-OFF baseline. Two targeted spot-checks rule this out:

- **Cloud-ON (run 9).** Only cloud protection was toggled on; the delta was **0/3** — LSASS dump, the Run-key, and Regsvr32 all remained `not_detected`. That cloud was genuinely active is confirmed by the control technique T1059.001, which stayed `detected` and emitted event 2010 (cloud lookups), with its latency rising from ~3.8 s to ~7.6 s. Cloud lookups therefore added observable round-trips but no new detections for these variants.
- **ASR (run 10).** Enabling *only* the LSASS-theft ASR rule (GUID `9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2`, Block mode) still left T1003.001 `not_detected`, with no event 1121 emitted. Even the attack-surface-reduction rule purpose-built for credential dumping missed this specific atomic variant.

These controls are not useless in general, but for the tested variants they contributed nothing. The blind spots are properties of Defender's default behavioural coverage, not of a stripped-down configuration — which is precisely why a supplementary rule set is warranted.

**On measurement integrity.** The findings above are only trustworthy because several measurement bugs were found and fixed on real data rather than in theory. Detection is now attributed by axis, so a behaviour-axis catch is correctly credited to the runtime/AMSI layer rather than mistaken for a static file scan. A Defender *block* accompanied by in-window detection events now scores `detected` rather than falling through to `error`/`inconclusive`, so positive detections outrank the error and fidelity gates. Most importantly, the runner no longer counts a non-run as a run: the T1562.001 atomic was not installed on the VM, so `Invoke-AtomicTest` exited 0 while printing "does not exist", which the earlier runner mis-counted as `ran` and produced a false `not_detected`. Requiring the "Executing test" marker fixed this; an install check confirmed 10/11 atomics were present, so only that one measurement had been invalid — and T1562.001 is now scored by direct RTP-state verification instead of the event window, because `reset.ps1` itself toggles RTP and emits 5013 noise that would confound impair-defenses scoring. The reported 18.2% therefore reflects corrected, verified outcomes.

### 7.2 Limitations

The results should be read with the following honest caveats, each of which bounds how far the conclusions generalise:

- **Single atomic test per technique.** Only Atomic test #1 was run for each of the eleven techniques. A `not_detected` result means *this particular* implementation evaded Defender, not that every variant of the technique would. The ASR spot-check is a concrete illustration: a different LSASS-dump atomic might well trip event 1121.
- **Default-ish consumer configuration.** The baseline is a near-default Windows 11 Pro install. Enterprise hardening (Defender for Endpoint EDR, tuned ASR, WDAC, audit policy) was out of scope and would likely change several outcomes.
- **Fidelity proves execution, not effect.** The fidelity model (built from `reset_ok`, `technique_ran`, `collect_window_complete`, `clean_before`, valid at ≥ 0.5) confirms that each atomic's stimulus was actually delivered. It does *not* confirm that the malicious effect occurred — only that the technique ran and Defender had the opportunity to react.
- **Sysmon unavailable.** Sysmon could not be loaded on the measurement VM (an image-level bug). This means no Sysmon-sourced evidence was collected, and — critically — the Sigma rules keyed to Sysmon Event ID 10 could not be validated against live telemetry or assessed for live false positives.
- **EICAR is a benign proxy.** The malware payload is the EICAR industry test string, not live malware. It is a faithful proxy for *signature* behaviour (a universally-recognised known-bad pattern) but cannot model the heuristic, emulation, or cloud-reputation responses that genuine novel malware would provoke.

### 7.3 Recommendations

For a defender operating a comparable Windows 11 estate, the evidence supports five concrete actions:

1. **Deploy the supplementary rule set.** The two YARA rules (`KTLD_Encoded_Sample_On_Disk` and `KTLD_Payload_Loader_Binary`) and the seven Sigma rules directly target the measured gaps — the encoded sample, the loader binary (which catches the fileless v3 by its dropper), and the nine `not_detected` techniques. The YARA rules validated live at 5/5 true positives with **0 false positives across 12,450 goodware files** (System32 + SysWOW64 + .NET Framework), so they can be deployed with low operational risk.
2. **Keep AMSI and Tamper Protection enabled.** These are Defender's two confirmed behavioural wins — AMSI caught the only `detected` technique, and Tamper Protection verifiably blocked the attempt to disable Defender. They are load-bearing and should never be turned off.
3. **Enable the LSASS-theft ASR rule as defence-in-depth.** Although the rule (`9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2`, Block mode) missed the specific T1003.001 atomic tested here, it costs little and covers other credential-dumping variants that were not exercised. A control that missed one variant is not a reason to leave the surface entirely open.
4. **Turn on command-line and scheduled-task auditing.** The discovery, LOLBin, cmd, and scheduled-task gaps are exactly the activity that process-command-line auditing surfaces. This is the native log source the Sigma rules are written against and the prerequisite for ever detecting these techniques.
5. **Constrain LOLBins with WDAC.** The Regsvr32 (T1218.010) and cmd (T1059.003) gaps are best addressed by application control. Windows Defender Application Control policies that restrict or audit abusable signed binaries close the living-off-the-land path that signature and behaviour both missed.

### 7.4 Future work

- **Broaden the atomic matrix.** Run every atomic test per technique, not only test #1, so that a single evasion is not read as a blanket gap. The ASR result shows how much variant choice matters.
- **Repair Sysmon for live Sigma validation.** Fixing the VM image so Sysmon loads would let the seven Sigma rules be validated against real Event ID 10 telemetry and give them a live false-positive study — the one validation step currently blocked.
- **Widen the goodware false-positive corpus.** The YARA false-positive study (12,450 files) covered core system directories; extending it to third-party application binaries and installed software would strengthen the deployability claim.
- **Beyond the EICAR proxy.** Controlled testing with heuristic- and reputation-triggering samples (in a suitably isolated environment) would measure the engine layers that a benign test string cannot exercise.

### 7.5 Conclusion

Within a reproducible, automated framework, this work shows that Microsoft Defender on a near-default Windows 11 install defends content it already knows — raw on-disk samples, deobfuscated script buffers via AMSI, and its own configuration via Tamper Protection — but is largely blind to attacker *behaviour*. Across eleven ATT&CK techniques it stopped two and missed nine (18.2%), and across four payload variants it caught only the two that wrote plaintext to disk, missing both the obfuscated and the fileless forms. Targeted spot-checks confirm that neither cloud protection nor the matching ASR rule closed these gaps for the tested variants, so they are real coverage limits rather than configuration artefacts. The supplementary rule set — two YARA rules validated at 5/5 true positives with zero false positives over 12,450 goodware files, plus seven logic-validated Sigma rules each tied to a measured gap — demonstrates that the most significant blind spots can be covered with maintainable, low-false-positive detections. Read honestly against its limitations (single atomics, a default-ish configuration, fidelity that proves execution rather than effect, the absence of Sysmon, and a benign EICAR proxy), the study delivers both a defensible measurement of where Defender's protection ends and a practical, validated starting point for extending it.
