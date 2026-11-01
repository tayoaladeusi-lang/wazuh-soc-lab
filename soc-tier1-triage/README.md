# SOC Tier 1 Triage — Detection, Response & Analyst Workflow

A hands-on Tier 1 analyst workflow built on the [Wazuh Home SOC Lab](../README.md).
Four end-to-end scenarios, each taken from **alert → triage → evidence → ticket → playbook**,
with every detection proven by firing a real attack — not assumed from "the rule loaded."

> **Theme:** *"the rule loaded" and "the rule works" are different claims.* Every ticket here
> was validated by a live attack, and several uncovered silent failures that a config review
> would have missed.

## Scenarios

| # | Scenario | Detection | Outcome | MITRE |
|---|----------|-----------|---------|-------|
| [001](tickets/TICKET-001-ssh-brute.md) | SSH user enumeration / brute force | Rules 5710, 100022 | TP — no compromise | T1110.001/.003 |
| [002](tickets/TICKET-002-webshell-fim.md) | Webshell dropped in web root | Rule 100030 + YARA 108001 + VT 87105 | TP — auto-quarantined | T1505.003 |
| [003](tickets/TICKET-003-sqli-web-attack.md) | SQL injection (attempt + success) | Rules 100040, 100045 (level 14) | TP — successful exploitation | T1190 |
| [004](tickets/TICKET-004-port-scan-suricata.md) | Network port scan | Suricata sid 100200 → Wazuh 86601 | TP — recon detected | T1046, T1595.001 |

Each scenario has a **ticket** (`tickets/`), a reusable **playbook** (`playbooks/`),
and **evidence** (`evidence/`).

## What this demonstrates

- **Triage discipline** — classify TP/FP, rule out benign activity (e.g. local sudo sessions
  mistaken for remote logins in TICKET-001), scope impact, and decide escalation.
- **Detection validation** — confirm a rule fires against a real attack, with dashboard and
  notification evidence, not just a loaded ruleset.
- **Detection engineering** — a custom port-scan rule (sid 100200) where stock ET rules were
  silent; a YARA-before-quarantine fix where a race was skipping enrichment.
- **Honest documentation of failure** — see `../docs/findings.md`.

## Silent failures found (and fixed) during this work

These are the value of the lab — each was invisible until a real attack exposed it:

- **Successful-exploitation rule never fired** — checked the wrong decoder field; only a live
  authenticated exploit returning HTTP 200 proved the fix (TICKET-003 / Finding 1).
- **YARA enrichment skipped on webshells** — a custom rule overrode the vendor rule the YARA
  response was bound to, then a quarantine race moved the file before scanning (TICKET-002 / Finding 11).
- **Suricata silently dead for ~8 weeks** — service showed `active` while every log output
  failed on `Permission denied` (TICKET-004 / NIDS findings).
- **NIDS blind to local traffic** — bound to `eth0`; in the shared WSL2 namespace, host-to-host
  traffic crosses loopback only.
- **Agent silently disconnected** after a routine upgrade pushed it past the manager version.

## Environment

See [`../docs/architecture.md`](../docs/architecture.md). Manager (Wazuh 4.12, Ubuntu/WSL2),
target (OracleLinux 9.5/WSL2, DVWA + agent + Suricata), attacker (Kali/WSL2), Windows endpoint (Sysmon).

> All testing was performed on self-hosted, deliberately vulnerable lab systems on an isolated
> network. A recurring limitation across tickets: the WSL2 shared network namespace masks the
> true source IP (attacker traffic appears to originate from the target) — documented per ticket.

## Analyst

Olutayo Aladeusi — [LinkedIn](https://www.linkedin.com/in/olutayo-aladeusi/)
