# TICKET-001 — SSH User Enumeration / Brute-Force Attempt

**Date/Time (UTC):** 2026-10-29 ~23:33–23:34  
**Analyst:** Olutayo Aladeusi  
**Alert Source:** Wazuh Rule 100022 (custom) + Rule 5710 (built-in)  
**Severity:** Medium (Level 10)  
**MITRE ATT&CK:** T1110.001 (Password Guessing) / T1589.001 (Credentials)  

## Alert Summary
- Custom rule 100022 fired: “User enumeration: 6+ logins for non-existent users from 172.19.38.57”
- Preceded by multiple rule 5710 events (“sshd: Attempt to login using a non-existent user”)
- Agent: ol-dvwa-01
- Source IP: 172.19.38.57
- Activity window: approximately 23:33–23:34 local time

## Enrichment
- VirusTotal: 0/92 vendors flagged the IP; marked private (lab/WSL2 address)
- Related events: Multiple failed non-existent-user attempts
- Successful logins checked: Rule 5501 events present in the same window are local sudo sessions (dnf upgrade wazuh-agent, etc.) by the lab user — not remote SSH from 172.19.38.57
- No successful remote authentication from the attacking IP

## Analysis
Repeated authentication attempts against non-existent users on the SSH service. Pattern matches classic user-enumeration / password-guessing behavior. No evidence of successful remote access. Source is internal to the lab network (WSL2). Concurrent successful sessions are legitimate local administrative activity.

## Disposition
- [x] True Positive – Low (monitor / close)
- [ ] False Positive
- [ ] Escalate to L2
- [ ] Contained

**Reason:** Confirmed failed authentication attempts against non-existent accounts from a lab-internal IP. No successful remote login from the source. Suitable for closure as a detected but unsuccessful attack.

## Recommended Actions
1. No containment required (lab environment, unsuccessful).
2. Continue normal monitoring for any follow-on activity.
3. Note for future reference: rule 100022 correctly detected the enumeration threshold.

## Evidence
- Screenshots: Wazuh rule 5710 list, Wazuh rule 100022 alert, VirusTotal result for 172.19.38.57, expanded 5501 events showing local sudo activity
- Key rules: 5710 (individual failures), 100022 (enumeration threshold)
