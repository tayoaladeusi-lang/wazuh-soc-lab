# Playbook 04 — Network Port Scan / Recon (Tier 1)

**MITRE ATT&CK:** T1046 (Network Service Discovery), T1595.001 (Active Scanning)
**Source:** Suricata sid 100200 (custom portscan) → Wazuh rule 86601; also ET SCAN signatures
**Default severity:** Low (recon) — escalate on follow-on activity

## 1. Trigger
Wazuh rule 86601 with a portscan signature, or a burst of Suricata alerts from one source IP.

## 2. Validate (≤10 min)
- [ ] Confirm in Threat Hunting (`rule.id:86601` or search `Portscan`)
- [ ] Record source IP, destination, ports touched, and time window
- [ ] On the sensor, check the raw Suricata record:
```bash
grep -a '"signature":"LOCAL Portscan' /var/log/suricata/eve.json | tail -1 | python3 -m json.tool
```

## 3. Scope
- [ ] How many ports / how fast? (scan speed and breadth)
- [ ] Which ports came back open vs filtered?
- [ ] Same source later hitting an open service (SSH brute force, web attack)? → that's the real incident

## 4. Classification
| Outcome | Criteria | Action |
|---|---|---|
| TP — Recon only | Scan, no follow-on | Note source, monitor, close Low |
| TP — Precursor | Scan then exploit/login attempts from same IP | Escalate to L2, link the tickets |
| Benign | Authorised vuln scan / asset discovery | Document, suppress the scanner IP |
| False positive | Health check / monitoring tripping the threshold | Tune sid 100200 count/window |

## 5. Containment (Tier 1 allowed)
- Block the source IP at the host/perimeter firewall if external and unexpected
- Raise monitoring on the services whose ports were found open

## 6. Escalation criteria
- Scan followed by exploitation or auth attempts from the same source
- External source mapping internal services
- Scan of sensitive ports (DB, RDP, management) from an unexpected host

## 7. Documentation
Ticket with source IP, ports open/filtered, the rule that fired, and whether any follow-on activity was seen.

## 8. Notes for this lab
- Stock ET rules do not reliably fire on a quiet SYN scan; detection uses custom sid 100200.
- WSL2 shared namespace masks the true source IP and requires Suricata on the loopback interface — local/east-west traffic never crosses eth0.
