# TICKET-005 — Malicious PowerShell on Windows Endpoint (Sysmon)

| Field | Value |
|---|---|
| Alert time | 2026-10-31 20:31:36 MDT (2026-11-01 02:31:36 UTC) |
| Analyst | Olutayo Aladeusi |
| Alert source | Sysmon Event ID 1 → Wazuh rule 92057 (built-in) |
| Severity | High (rule level 12) |
| Agent | MyAgentCIA (001), Windows, 172.19.32.1 |
| Technique | Base64-encoded PowerShell command |
| MITRE ATT&CK | T1059.001 Command and Scripting Interpreter: PowerShell |
| Status | Closed |

## Alert Summary
- Rule **92057** (level 12): *"Powershell.exe spawned a powershell process which executed a base64 encoded command"* — fired 6× during testing
- Related built-in detections on the same host:
  - 92213 (level 15) — executable dropped in a malware-common folder
  - 92058 (level 12) — Application Compatibility Database launched
  - 92052 / 92005 (level 4) — command shell started by abnormal process / `/c` modifier
- Command line: `powershell.exe -NoProfile -EncodedCommand <base64>` (benign payload for the test)

## Prevention vs. detection
- **Prevented by Microsoft Defender ASR:** the download cradle
  (`IEX (New-Object Net.WebClient).DownloadString(...)`) and `certutil -urlcache`
  both failed to launch with "Access is denied" — behavioural prevention working.
- **Detected by Sysmon/Wazuh:** the encoded command executed (local, benign) and was
  caught at level 12. This shows the prevention and detection layers are complementary:
  what the endpoint control blocks, and what the SIEM catches when it doesn't.

## Analysis
Base64 encoding is the most common PowerShell obfuscation technique; attackers use it to
hide the real command from casual inspection and simple string matching. Sysmon Event ID 1
captured the full command line, and Wazuh's built-in Sysmon ruleset decoded and flagged it.

## Pipeline failures found and fixed (the real story)
Detection initially produced **nothing**, through three stacked silent failures — each
invisible in the UI while every service showed healthy:
1. **Sysmon wasn't capturing process creation.** The running config logged only file/registry/network
   events (IDs 11/12/13/3), no Event ID 1. Fixed by applying the SwiftOnSecurity Sysmon config.
2. **The decoder silently dropped rich events.** `wazuh-analysisd` logged
   "Too many fields for JSON decoder" and discarded the Sysmon events before any rule saw them.
   Fixed with `analysisd.decoder_order_size=1024` in local_internal_options.conf.
3. **Default process-create rules are level 0** (no alert / not indexed), so generic process
   events never surface. The suspicious command line needed a detection rule — which the built-in
   92057 provided once the events actually reached it.

Only after all three were fixed did rule 92057 fire. See docs/findings.md.

## Disposition
- [x] True Positive — High (authorised test)
- [ ] False Positive
- [ ] Escalate to L2
- [ ] Monitor only

**Reason:** Authorised endpoint test. Encoded PowerShell detected at level 12; download techniques
prevented by Defender. No malicious payload executed.

## Actions Taken
1. Ran encoded-command and download-cradle / LOLBin tests
2. Fixed the Sysmon config, decoder field cap, and confirmed detection
3. Verified rule 92057 (×6) in Wazuh for agent 001

## Recommendations
1. Enable **PowerShell Script Block Logging** (Event 4104) for full script content, not just the command line
2. Keep Defender ASR rules enabled (they blocked the download techniques)
3. Add custom rules for techniques without a strong built-in (Run-key persistence, LOLBin downloads) — see rules/local_rules.xml (sid 100600–100603)
4. Constrained Language Mode / application control to limit what PowerShell can run

## Evidence
- Threat Hunting: rule 92057, 6 hits — `evidence/ticket-005/01-threat-hunting-92057-encoded-powershell-6hits.png`
- Windows Sysmon detections overview — `evidence/ticket-005/02-windows-sysmon-detections-overview.png`
- Full Windows event list (2,181 events) — `evidence/ticket-005/03-windows-events-full-list.png`
