# Playbook 05 — Malicious PowerShell / Endpoint Execution (Tier 1)

**MITRE ATT&CK:** T1059.001 (PowerShell), T1105 (Ingress Tool Transfer), T1547.001 (Run key)
**Source:** Sysmon Event ID 1 → Wazuh rules 92052/92057/92213 (built-in) + custom 100600–100603
**Default severity:** High (encoded/obfuscated execution)

## 1. Trigger
Wazuh rule 92057 (encoded command), 92213 (exe in malware-common path), or a custom 1006xx rule.

## 2. Validate (≤10 min)
- [ ] Confirm in Threat Hunting (`rule.id:92057` etc.), note host, user, and full command line
- [ ] Decode the Base64 to see the real command:
```bash
# From the EncodedCommand value
echo '<base64>' | base64 -d | iconv -f UTF-16LE -t UTF-8
```
- [ ] Identify the parent process (Office app or browser spawning PowerShell = high suspicion)

## 3. Scope
- [ ] Did it download anything? (DownloadString/DownloadFile, certutil, bitsadmin)
- [ ] Persistence created? (Run key, scheduled task, service)
- [ ] Network connections from the PowerShell process (Sysmon Event 3)?
- [ ] Was it blocked by Defender/AV, or did it run?

## 4. Classification
| Outcome | Criteria | Action |
|---|---|---|
| TP — Executed | Obfuscated/suspicious command ran | Escalate to L2, isolate host if needed |
| TP — Prevented | Defender/ASR blocked it | Document, monitor for retries |
| Benign | Known admin/software script | Document, tune |
| False positive | Legit encoded command (rare) | Close FP, note source |

## 5. Containment (Tier 1 allowed)
- Isolate the host if a download or persistence succeeded
- Capture the command line, hashes, and parent chain before anything is cleaned up

## 6. Escalation criteria
- Download cradle that completed, or outbound C2-like connection
- Persistence created, credential-access tooling, or lateral movement
- Office/browser parent spawning PowerShell (initial-access pattern)

## 7. Documentation
Ticket with host, user, decoded command, parent process, hashes, whether prevented or executed,
and any persistence/network artifacts.

## 8. Lab notes
- Endpoint telemetry depends on a real Sysmon config (SwiftOnSecurity) — a bare config logs no process creation.
- Rich Sysmon events need `analysisd.decoder_order_size` raised or they are silently dropped.
- Default process-create rules are level 0; suspicious behaviour needs a detection rule (built-in 92xxx or custom).
