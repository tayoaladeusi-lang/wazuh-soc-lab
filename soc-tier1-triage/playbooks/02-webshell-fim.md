# Playbook 02 — Webshell / Suspicious File in Web Root (Tier 1)

**MITRE ATT&CK:** T1505.003 (Web Shell)
**Wazuh rules:** 100030 (webshell in web root), 554 (file added), 553 (file deleted), 108001 (YARA match), 87105 (VirusTotal hit)
**Default severity:** High

## 1. Trigger
Rule 100030, or a syscheck "added" event on a web directory path ending in `.php`, `.asp`, `.aspx`, `.jsp` and so on.

## 2. Validate (≤10 min)
- [ ] Confirm the full file path and that the event is "added"
- [ ] Check for a follow-up rule 553 (deleted) on the same path, which may mean automatic quarantine
- [ ] Confirm the quarantine in the active-response log:
```bash
grep "<filename>" /var/ossec/logs/active-responses.log
```

## 3. Enrich
- [ ] YARA result (rule 108001) for the same path
- [ ] VirusTotal result (rule 87105) for the same path
- [ ] SHA256 of the quarantined file:
```bash
sha256sum /var/ossec/quarantine/<timestamp>_<file>.quarantined
```

## 4. Scope
- [ ] Was the file requested over HTTP before it was quarantined? (Check the web access log for the filename and look for a 200 status)
- [ ] Any other new files in the web root around the same time?
- [ ] How did it get there (upload form, vulnerability, compromised account)?

## 5. Classification
| Outcome | Criteria | Action |
|---|---|---|
| TP — Contained | Quarantined, no HTTP access to the file | Close |
| TP — Executed | Access log shows a request with 200 for the file | **Escalate to L2 (P1)** |
| TP — Not contained | File still in place | Escalate to L2 and quarantine manually |
| False positive | Legitimate deployment by an authorised admin | Close, tune the rule |

## 6. Escalation criteria
- File still on disk, or the quarantine failed
- Any HTTP request to the file returned 200
- Multiple webshells, or follow-on activity (outbound connections, new users, cron jobs)

## 7. Documentation
Open a ticket using `tickets/TICKET-XXX-*.md` with the file path, hash, YARA/VirusTotal results, the quarantine log line and your classification.
