# TICKET-001 — SSH User Enumeration / Brute-Force Attempt

| Field | Value |
|---|---|
| Alert time | 2026-10-29 23:33 MDT (2026-10-30 05:33 UTC) |
| Activity window | 2026-10-29 22:58:08 – 23:34:44 MDT (04:58:08 – 05:34:44 UTC) |
| Analyst | Olutayo Aladeusi |
| Alert source | Wazuh rule 100022 (custom) + rule 5710 (built-in) |
| Alert severity | Medium (rule level 10) |
| Impact | Low (unsuccessful) |
| Agent | ol-dvwa-01 (OracleLinux 9.5, WSL2) |
| Source IP | 172.19.38.57 |
| MITRE ATT&CK | T1110.001 Password Guessing · T1110.003 Password Spraying |
| Status | Closed |

## Alert Summary
- Custom rule **100022** fired: *"User enumeration: 6+ logins for non-existent users from 172.19.38.57"*
- Preceded by multiple rule **5710** events (*sshd: Attempt to login using a non-existent user*)
- Rule 100022 fired at the end of a ~36-minute activity window, confirming the enumeration threshold works as designed

## Log Evidence (`/var/log/secure` on ol-dvwa-01)
| Metric | Count |
|---|---|
| Invalid-user connections | 25 |
| — `invaliduser` | 15 |
| — `baduser` | 10 |
| Failed password attempts | 7 |
| Successful logins (`Accepted`) from source | **0** |

18 of the 25 connections disconnected before any password was attempted. Many connections with few password attempts, spread across multiple usernames, is consistent with username probing or spraying rather than guessing against a single account.

## Enrichment
- **Reputation lookup:** N/A. 172.19.38.57 is an RFC1918 private address (lab/WSL2). A VirusTotal check returned 0/92, which is expected for a private IP and not meaningful.
- **Successful sessions in window:** rule 5501 (PAM session opened) events are local `sudo` sessions by the lab user (for example, `dnf upgrade wazuh-agent`), not remote SSH from 172.19.38.57.
- **Remote authentication from source:** none.

## Analysis
Repeated SSH authentication attempts against two non-existent accounts. The pattern matches user enumeration or password spraying. There is no evidence of successful remote access, and the concurrent successful sessions are legitimate local administrative activity.

### Visibility limitation (key finding)
The source IP (172.19.38.57) is **the agent's own IP**. All WSL2 distros share one network namespace, so traffic from the attacker distro appears to come from the target itself, and the true origin is masked. In production, a source matching the target would point to a local or loopback origin and would need its own investigation. Mitigation for the lab: run attacker and target in separate VMs or network namespaces.

## Disposition
- [x] True Positive — Low (close)
- [ ] False Positive
- [ ] Escalate to L2
- [ ] Contained

**Reason:** Authorised adversary simulation in the lab. Failed authentication attempts against non-existent accounts were confirmed, with no successful remote login from the source. Detected but unsuccessful; no containment required.

## Recommended Actions
1. Disable SSH password authentication (`PasswordAuthentication no`, keys only)
2. Disable root login (`PermitRootLogin no`)
3. Attach Wazuh active response `firewall-drop` to rule 100022
4. Separate the lab hosts into distinct VMs or namespaces to restore source-IP visibility
5. Continue monitoring 172.19.38.57 for follow-on activity

## Evidence
- Raw log: [`secure-log.txt`](../evidence/ticket-001/secure-log.txt)
- Wazuh alerts: [`wazuh-alerts.json`](../evidence/ticket-001/wazuh-alerts.json)
- Screenshots (`../evidence/ticket-001/`): rule 5710 event list, rule 100022 alert, VirusTotal result, expanded 5501 events showing local sudo activity

## Resolution
Closed 2026-10-30. True positive (authorised test), no compromise. Custom rule 100022 validated. Hardening recommendations logged for follow-up.
