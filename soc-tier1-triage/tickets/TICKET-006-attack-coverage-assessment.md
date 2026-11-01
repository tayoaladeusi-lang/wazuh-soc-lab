# TICKET-006 — Detection Coverage Assessment (Atomic Red Team)

| Field | Value |
|---|---|
| Assessment date | 2026-11-01 (UTC-6, permanent) |
| Analyst | Olutayo Aladeusi |
| Method | Atomic Red Team (redcanaryco), 5 techniques against MyAgentCIA (001) |
| Scope | Windows endpoint detection (Sysmon → Wazuh) |
| Type | Coverage assessment (not an incident) |

## Purpose
Measure which ATT&CK techniques the current detection stack actually catches, using a
standardized adversary-emulation framework rather than hand-crafted tests. The gaps are the
deliverable: each becomes a detection to build or tune.

## Method
- Scoped a Microsoft Defender exclusion to `C:\AtomicRedTeam` so test behaviours could execute
  (documented, lab-only — a deliberate testing decision, not disabled security).
- Ran one atomic per technique with `-GetPrereqs`, cleaned up persistence tests afterward.
- Measured results in Wazuh Threat Hunting filtered to agent 001.

## Results

| # | Technique | ATT&CK | Detected | Rule(s) | Level | Verdict |
|---|-----------|--------|----------|---------|-------|---------|
| 1 | PowerShell (encoded) | T1059.001 | Yes | 92057 + 100600 | 12 | **False gap** — ART's T1059.001-15 harness (AtomicTestHarnesses) failed to load (Defender blocked it as PUA), so no encoded command ran; validated directly, both rules fire (100600 also catches the short `-E` form) |
| 2 | Run key persistence | T1547.001 | Yes | 92302 (built-in) | 6 | Covered by built-in; custom 100603 was redundant and did not fire |
| 3 | Scheduled task | T1053.005 | Yes | 60642 | 3 | Covered |
| 4 | System owner/user discovery | T1033 | Yes | 92022 | 3 | Covered |
| 5 | System information discovery | T1082 | Generic only | 92032 | 3 | **Gap** — no systeminfo-specific detection |

Incidental high-value detections during the run: 92058 (level 12, AppCompat database),
92217 (level 6, executable dropped in Windows root).

## Coverage summary
- **Detected:** 4 / 5 (encoded PowerShell, Run-key persistence, scheduled task, user discovery)
- **Generic only:** 1 / 5 (systeminfo) — closed with custom rule 100604 (validated)

Execution and persistence are well covered by the built-in 92xxx ruleset. The remaining weakness
is technique-specific detection of obfuscated PowerShell and discovery commands.

## Key finding — a custom rule that never worked
Custom rule 100603 (Run-key persistence) was added in TICKET-005 but **never validated**. ART
proved it does not fire: the built-in rule 92302 already covers Run-key writes, and 100603's
`targetObject` match was incorrect. Lesson: check built-in coverage before writing custom rules,
and validate every custom rule against a real technique. 100603 was removed as redundant.

## Gaps & remediation
1. **Encoded PowerShell (T1059.001) — FALSE GAP, now closed.** The original miss was caused by the
   ART test harness (AtomicTestHarnesses) failing to load, not by a detection gap. Validated directly:
   `powershell -E/-en/-enc/-EncodedCommand <base64>` all fire rule 92057 (built-in) and 100600 (custom),
   level 12. Lesson: confirm a test actually executed before recording a gap.
2. **System information discovery (T1082) — closed.** Added custom rule 100604 on `systeminfo`
   execution (level 6); validated by re-running the atomic.

## Value
This assessment turns "detections exist" into "measured coverage against ATT&CK, with named gaps,
a redundant/broken rule caught, and a remediation plan." The misses drive the next cycle.

## Evidence
- Coverage overview (211 events) — `evidence/ticket-006/01-coverage-211-events-overview.png`
- Sysmon detections (132 hits) — `evidence/ticket-006/02-sysmon-coverage-132-hits.png`
- Encoded-command gap (100600 no results) — `evidence/ticket-006/03-encoded-command-gap-100600-no-results.png`
- systeminfo generic-only — `evidence/ticket-006/04-systeminfo-generic-detection-only.png`
