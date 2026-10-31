# Playbook 03 — Web SQL Injection: Attempt + Success (Tier 1)

**MITRE ATT&CK:** T1190 (Exploit Public-Facing Application)
**Wazuh rules:** 100040 (SQLi attempt), 100045 (attack returned HTTP 200 — possible success), 31122 (web server 500)
**Default severity:** High → Critical when 100045 fires (level 14)

## 1. Trigger
Rule 100040 on a SQLi payload in a request parameter, and/or rule 100045 when that attack returned HTTP 200.

## 2. Validate (≤10 min)
- [ ] Note source IP, target URL, and the payload fragment (e.g. `UNION SELECT`, `' OR '1'='1`)
- [ ] Confirm the alert in Threat Hunting (filter `rule.id:100040 or rule.id:100045`)
- [ ] Record the HTTP status the server returned (302/500 = not served, 200 = served)

```bash
# On the target
grep -aiE "union|select|' or '|sqli" /var/log/httpd/access_log | tail -20
```

## 3. Did it succeed?
- [ ] **Rule 100045 fired** → the attack returned HTTP 200, so the injection reached the app. Treat as possible data exposure.
- [ ] **Only 100040 fired** → attempt reached the server but was redirected/errored (302/500). No success evidence.
- [ ] Note that a boolean payload (`' OR '1'='1`) may NOT trip the signature (documented gap, Finding 2) — absence of 100040 is not absence of attack.

## 4. Scope
- [ ] Same source IP hitting other endpoints or parameters?
- [ ] Repeated 500s (rule 31122) around the same time? (May be the app/DB, not the attack — check before blaming the attack)
- [ ] Which table/columns were targeted (e.g. `users`, `password`)?

## 5. Classification
| Outcome | Criteria | Action |
|---|---|---|
| TP — Lab | Internal/lab IP, known vulnerable app | Close as True Positive – Lab |
| TP — Success | 100045 fired (attack→200) | **Escalate to L2 (P1)** |
| TP — Attempt only | 100040 only, external IP | Contain source IP, monitor |
| False positive | Legitimate query flagged by signature | Close FP, tune rule |

## 6. Containment (Tier 1 allowed)
- Block the source IP (Wazuh active response `firewall-drop`, or `firewall-cmd`)
- If success is confirmed, flag the affected app/DB for credential rotation

## 7. Escalation criteria
- Rule 100045 fired (possible successful exploitation)
- External source IP, or an unexpected internal host
- Sensitive table targeted (users, credentials, payment data)
- Sustained or multi-endpoint activity

## 8. Documentation
Open a ticket using `tickets/TICKET-XXX-*.md` with source IP, full URL, payload, HTTP status, the rules that fired, and your classification.

## 9. Recommendations
- Parameterised queries / prepared statements (root cause)
- WAF rule set (e.g. ModSecurity CRS) in front of the app
- Least-privilege DB accounts so one injection can't read everything
- Keep the attack→200 correlation (rule 100045) as the "did it work" signal
