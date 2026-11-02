# SOC Tier 1 Triage & Detection Engineering

A hands-on Security Operations workflow built on the [Wazuh Home SOC Lab](../README.md):
seven end-to-end scenarios across Linux, web, network, Windows endpoint, adversary emulation,
and OT/ICS — each taken from **alert → triage → evidence → ticket → playbook**, and each
validated by firing a real attack, not assumed from "the rule loaded."

> **Theme:** *"the rule loaded" and "the rule works" are different claims.* Every detection here
> was proven by a live technique — and that discipline repeatedly exposed silent failures a
> config review would have missed.

## Scenarios

| # | Scenario | Detection | Outcome | MITRE |
|---|----------|-----------|---------|-------|
| [001](tickets/TICKET-001-ssh-brute.md) | SSH user enumeration / brute force | Rules 5710, 100022 | TP — no compromise | T1110.001/.003 |
| [002](tickets/TICKET-002-webshell-fim.md) | Webshell dropped in web root | 100030 + YARA 108001 + VT 87105 | TP — auto-quarantined | T1505.003 |
| [003](tickets/TICKET-003-sqli-web-attack.md) | SQL injection (attempt + success) | 100040, 100045 (level 14) | TP — successful exploitation | T1190 |
| [004](tickets/TICKET-004-port-scan-suricata.md) | Network port scan | Suricata sid 100200 → 86601 | TP — recon detected | T1046, T1595.001 |
| [005](tickets/TICKET-005-malicious-powershell-sysmon.md) | Malicious PowerShell (Windows) | Sysmon → 92057 (level 12) | TP — detected; Defender prevented downloads | T1059.001 |
| [006](tickets/TICKET-006-attack-coverage-assessment.md) | ATT&CK coverage assessment (Atomic Red Team) | 5 techniques measured | 5/5 covered; dead rule + false gap found | multiple |
| [007](tickets/TICKET-007-ics-modbus-unauthorized-write.md) | **OT/ICS** — unauthorized Modbus write to PLC | Suricata Modbus sids 100300-100302 → 86601 | TP — manipulation of control detected | T0855, T0831, T0836 |

Each scenario has a **ticket** (`tickets/`), a **playbook** or methodology (`playbooks/`), and
**evidence** (`evidence/`). Custom detections live in `../rules/local_rules.xml`,
`../suricata/` and `ics/`.

## What this demonstrates
- **Triage discipline** across IT and OT — classify TP/FP, rule out benign activity, scope impact, decide escalation.
- **Detection validation** — confirm a rule fires against a real attack, with dashboard + notification evidence.
- **Detection engineering** — custom rules where built-ins were silent (port scan, Modbus, systeminfo), and fixes where custom rules were wrong.
- **Coverage measurement** — Atomic Red Team mapped to ATT&CK, with a documented gap/remediation loop.
- **OT/ICS capability** — Modbus protocol detection distinguishing a control WRITE from benign polling.
- **Honest failure analysis** — see [`../docs/findings.md`](../docs/findings.md).

## Silent failures found (and fixed)
The value of this lab — each was invisible until a real attack exposed it:

- **Successful-exploitation rule never fired** — wrong decoder field; proven only by a live authenticated exploit returning HTTP 200 (003 / Finding 1).
- **YARA enrichment skipped on webshells** — a custom rule overrode the vendor rule the YARA response was bound to, then a quarantine race moved the file before scanning (002 / Finding 11).
- **Endpoint sensor blind to process creation** — Sysmon logged no Event 1; then a decoder field-cap silently dropped rich events; then default rules were level 0 (005).
- **A custom rule that never worked** — a Run-key rule shipped unvalidated; Atomic Red Team proved it never fired (006).
- **A false coverage gap** — an atomic test's harness failed to load, making encoded-PowerShell look undetected when it wasn't (006).
- **Suricata silently dead for ~8 weeks** — service "active" while every log output failed on permission denied (004).
- **NIDS blind to local traffic** — bound to eth0; shared-namespace traffic crosses loopback only (004).
- **OT/ICS capture pitfalls** — Modbus parser off by default; loopback MTU dropping 96% of packets; invalid loopback checksums dropping ICS traffic; and a `modbus:` keyword-syntax trap (007).

## Environment
Manager (Wazuh 4.12, Ubuntu/WSL2) · Target (OracleLinux 9.5/WSL2 — DVWA, Suricata, Modbus PLC sim) ·
Attacker (Kali/WSL2) · Windows endpoint (Sysmon). See [`../docs/architecture.md`](../docs/architecture.md).

> All testing was on self-hosted, deliberately vulnerable lab systems on an isolated network.
> A recurring limitation (documented per ticket): the WSL2 shared network namespace masks source
> IPs and complicates loopback capture — which is itself a realistic OT-monitoring lesson.

## Analyst
Olutayo Aladeusi — [LinkedIn](https://www.linkedin.com/in/olutayo-aladeusi/)
