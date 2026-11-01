# TICKET-004 — Network Port Scan (Suricata NIDS)

| Field | Value |
|---|---|
| Alert time | 2026-10-31 17:57:46 MDT (23:57:46 UTC) |
| Analyst | Olutayo Aladeusi |
| Alert source | Suricata sid 100200 (custom) → Wazuh rule 86601 |
| Severity | Low (rule level 3) — recon |
| Agent | ol-dvwa-01 (003) |
| Signature | LOCAL Portscan detected - 20+ SYN from single source in 10s |
| Source IP | 172.19.38.57 (Kali; masked by WSL2 shared namespace) |
| MITRE ATT&CK | T1046 Network Service Discovery · T1595.001 Active Scanning: Scanning IP Blocks |
| Status | Closed |

## Alert Summary
- A SYN (stealth) scan with `nmap -sS --top-ports 50` was run against the target
- Custom Suricata rule sid 100200 fired on 20+ SYNs from one source in 10s
- 76 alerts reached Wazuh as rule 86601 (one scan retransmits SYNs to filtered ports, multiplying hits)
- Scan result: ports 22, 80, 443, 3306 open; 46 ports filtered (no response)

## Analysis
A classic reconnaissance scan: many SYN packets to many ports from a single source in a short window, no completed sessions on filtered ports. This is pre-attack enumeration (T1046). The open ports (SSH, HTTP, HTTPS, MySQL) match the lab's exposed services.

### Detection engineering note
Stock ET rules did **not** fire on this quiet SYN scan. Detection required a custom threshold rule:
`alert tcp any any -> any any (flags:S; detection_filter: track by_src, count 20, seconds 10; sid:100200)`
This is deterministic and maps cleanly to Wazuh rule 86601, rather than relying on ET's scan signatures.

### Visibility limitation
Source IP equals the target's own IP (WSL2 shared namespace, as in TICKET-001/002/003). Suricata also had to be bound to the loopback interface to see the scan, because intra-host traffic never crosses eth0 — see the ops notes in findings.md.

## Disposition
- [x] True Positive — Low (authorised test)
- [ ] False Positive
- [ ] Escalate to L2
- [ ] Monitor only

**Reason:** Authorised lab scan. Reconnaissance detected by the custom NIDS rule and confirmed in Wazuh. No exploitation followed in this window.

## Actions Taken
1. Ran `nmap -sS -T4 --top-ports 50 -Pn`
2. Confirmed sid 100200 fired in Suricata eve.json (76 alerts)
3. Confirmed rule 86601 in Wazuh Threat Hunting

## Recommendations
1. Treat repeated scans from one source as a precursor; correlate with later exploit alerts from the same source
2. Consider raising rule 86601 severity if scans are high-signal in production
3. Host firewall: the 46 filtered ports show the default-deny posture is working
4. In production (non-WSL), bind Suricata to the real ingress interface to preserve true source IPs

## Evidence
- Threat Hunting: 86601 portscan, 76 hits — `evidence/ticket-004/01-threat-hunting-86601-portscan-76hits.png`
- Security events overview (ids/suricata top group) — `evidence/ticket-004/02-security-events-overview-ids-suricata-top.png`
- Custom rule: `suricata/local.rules` (sid 100200)
