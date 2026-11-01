# Methodology 06 — Detection Coverage Assessment (Atomic Red Team)

A repeatable process for measuring detection coverage against MITRE ATT&CK, rather than
assuming rules work. Produces a coverage matrix and a prioritized gap list. Pairs with
TICKET-006 (the first run's results).

**Framework:** Atomic Red Team (redcanaryco) · **Telemetry:** Sysmon → Wazuh · **Scope:** endpoint

## Principle
"The rule loaded" and "the rule works" are different claims. A rule only counts as coverage once
a real technique has fired it. This process exists to find the difference — including rules that
were added but never validated.

## 1. Prepare (safely)
- [ ] Use an isolated lab host, never production
- [ ] Scope an AV/EDR exclusion to the test folder only, and **document it** as a deliberate
      testing decision (e.g. `Add-MpPreference -ExclusionPath "C:\AtomicRedTeam"`). Note which
      techniques the control *prevented* vs. what executed — prevention is a valid result.
- [ ] Confirm the telemetry pipeline is healthy before testing: sensor logging the right events,
      agent connected, channel subscribed, decoder not dropping events. (A green service is not
      proof it is working — verify with a known test event.)

## 2. Select techniques
- [ ] Pick a small set mapped to ATT&CK, biased toward what you claim to detect and what matters
      for the environment (execution, persistence, discovery, credential access, lateral movement)
- [ ] Record the technique ID and the specific atomic test number for reproducibility

## 3. Execute
- [ ] Run one atomic at a time with prerequisites resolved (`-GetPrereqs`)
- [ ] Note the timestamp of each test
- [ ] Clean up persistence/artifact tests afterward (`-Cleanup`)

## 4. Measure
For each technique, search the SIEM (filter to the test host and time window) and record:
- [ ] Did an alert fire? (not just an event — an alert at a usable level)
- [ ] Which rule ID and level
- [ ] Built-in rule, custom rule, or generic-only (the wrapping process flagged but not the technique)

Enter results in a coverage matrix:

| # | Technique | ATT&CK | Detected | Rule | Level | Verdict |
|---|-----------|--------|----------|------|-------|---------|

Verdicts: **Detected** (specific rule fired) · **Generic only** (execution flagged, technique not
identified) · **Miss** (nothing) · **Prevented** (blocked by the endpoint control before execution).

## 5. Classify the gaps
- **Miss / generic-only** → a detection to build or tune
- **A custom rule that didn't fire** → validate and fix, or remove if a built-in already covers it
  (avoid redundant rules)
- **Prevented but not detected** → acceptable if prevention is reliable, but note the detection
  blind spot in case prevention is bypassed

## 6. Remediate and re-test (the loop)
- [ ] Write or fix one rule per gap
- [ ] Validate the rule loaded cleanly (no duplicate/parse warnings in the analysis engine)
- [ ] Re-run the same atomic and confirm the rule now fires — capture the before/after
- [ ] Only then record the gap as closed

## 7. Report
- [ ] Coverage matrix (detected / generic / miss / prevented)
- [ ] Gap list with remediation status
- [ ] Any pipeline issues found while testing (these are findings in their own right)
- [ ] Note the AV/EDR exclusion used, for transparency

## Common pitfalls (observed in this lab)
- Sensor not capturing the expected event type (e.g. no process-create) → no rule can fire
- Decoder silently dropping field-rich events → events arrive but never reach rules
- Default rules at level 0 (logged, not alerted) → nothing in the SIEM despite events arriving
- A bulk edit (e.g. `sed` on `</group>`) duplicating rules across every group → validate rule
  counts after any ruleset edit
- A custom rule's field match wrong (e.g. matching `originalFileName` when the technique ran via
  `cmd /c`) → match `commandLine` or the field the telemetry actually populates
- A test that errors or whose prerequisites did not load produces a FALSE miss — the technique
  never executed, so nothing could fire. Always confirm the atomic actually ran (check its output
  and for the expected telemetry) before recording a gap. (In this lab, T1059.001-15 silently
  failed because its harness module was blocked by AV, making encoded-PowerShell look like a gap
  when the detection was fine.)
