# TICKET-003 — SQL Injection: Attempt and Successful Exploitation (Web Attack)

| Field | Value |
|---|---|
| Alert time | 2026-10-31 14:49:05 MDT (20:49:05 UTC) |
| Analyst | Olutayo Aladeusi |
| Alert source | Wazuh rule 100040 (SQLi attempt) + rule 100045 (successful exploitation) |
| Severity | Critical (rule 100045 level 14) |
| Agent | ol-dvwa-01 (003) |
| Endpoint | /dvwa/vulnerabilities/sqli/ |
| MITRE ATT&CK | T1190 Exploit Public-Facing Application |
| Status | Closed |

## Alert Summary
- Rule **100040** fired on a UNION-based SQLi payload in the `id` parameter
- Rule **100045** (level 14) fired: *"Web attack returned HTTP 200 — possible successful exploitation"*
- Payload: `id=1' UNION SELECT user,password FROM users-- -`
- The authenticated request returned HTTP 200, so the injection reached the database and returned data

## Detection surfaces exercised
| Payload | Auth | HTTP | Rules fired |
|---|---|---|---|
| `1' UNION SELECT 1,2-- -` (unauthenticated) | no | 302 | 100040 (attempt only) |
| `1' OR '1'='1` | n/a | n/a | none — known signature gap (Finding 2) |
| `1' UNION SELECT user,password FROM users-- -` | yes | 200 | 100040 + **100045** |

## Analysis
A UNION-based SQL injection was sent to the DVWA SQLi endpoint. Unauthenticated, the request was redirected (302) and only the attempt rule fired. With a valid session and DVWA security set to low, the same class of payload returned HTTP 200, and rule 100045 correctly identified the attack→200 sequence as possible successful exploitation.

This validates the Finding 1 fix: the "successful exploitation" rule previously never fired because it checked the wrong decoder field. It now fires on a real authenticated exploit.

### Visibility limitation
Source IP (172.19.38.57) equals the agent's own IP — the WSL2 shared-namespace limitation documented in TICKET-001 and TICKET-002.

## Disposition
- [x] True Positive — Critical (authorised test)
- [ ] False Positive
- [ ] Escalate to L2
- [ ] Monitor only

**Reason:** Authorised lab test. SQLi attempt and successful-exploitation detection both confirmed against a deliberately vulnerable app. No production systems involved.

## Actions Taken
1. Ran attempt (302) and authenticated exploit (200) variants
2. Confirmed 100040 and 100045 fired, with 100045 at level 14
3. Received Telegram notification for the level-14 incident

## Recommendations
1. Use parameterised queries / prepared statements (root cause of SQLi)
2. Deploy a WAF rule set (e.g. ModSecurity CRS) in front of the app
3. Enforce least-privilege DB accounts so a successful injection cannot read the full users table
4. Keep the attack→200 correlation (rule 100045) as the key "did it work" signal

## Evidence
- Telegram alert: rule 100045, level 14, 14:49:05 (screenshot)
- Threat Hunting: 100040 and 100045 for the endpoint (screenshot)
- Web access log excerpt for the UNION request
