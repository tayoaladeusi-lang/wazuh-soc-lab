# TICKET-002 — Webshell Dropped in Web Root (FIM Detection)

| Field | Value |
|---|---|
| Alert time | 2026-10-31 00:32:59 MDT (06:32:59 UTC) |
| Analyst | Olutayo Aladeusi |
| Alert source | Wazuh rule 100030 (custom) + rule 553 (built-in FIM, file deleted) |
| Severity | High (rule level 12) |
| Agent | ol-dvwa-01 (003) |
| File | /var/www/html/dvwa/shell.php |
| MITRE ATT&CK | T1505.003 Server Software Component: Web Shell |
| Status | Closed |

## Alert Summary
- Custom rule **100030** fired: *"Possible webshell dropped in web root: /var/www/html/dvwa/shell.php"*
- Followed immediately by rule **553** (file deleted) on the same path
- Sequence: file added → detected (realtime FIM) → removed, within the same second

## Enrichment
- **Containment confirmed** in `/var/ossec/logs/active-responses.log`:
  `2026/10/31 00:32:59 quarantine-webshell: MOVED /var/www/html/dvwa/shell.php -> /var/ossec/quarantine/20261031-003259_shell.php.quarantined`
- Rule 553 is the FIM record of the quarantine move, not an attacker cleaning up
- **SHA256 (quarantined copy):** `d4577e5afd2bcc503a611bbea2f532263d749b0f4cf4a8d9bf5c2cf06623e4c8`
- **YARA:** not run for this alert (see Detection gap below)
- **VirusTotal:** not captured for this alert

## Analysis
A PHP file with webshell characteristics was written into the DVWA web root. Realtime FIM detected it and custom rule 100030 raised a high-severity alert. The quarantine active response moved the file out of the web root in the same second and set it to mode 000. No execution was observed in the window.

### Detection gap found (Finding 11)
YARA enrichment did **not** run for this file. The YARA active response was bound only to vendor rule 554, which custom rule 100030 overrides for web-root files. When YARA was also bound to 100030, the quarantine won the race and moved the file before it could be scanned, and `yara-scan.sh` exited silently.
**Fixed:** the quarantine script now scans with YARA before moving the file and logs a SHA256. Revalidated with `tg-live.php` at 01:39: 100030 → YARA 108001 → VirusTotal 87105 → quarantine → Telegram, in about 4 seconds.

## Disposition
- [x] True Positive — Contained
- [ ] False Positive
- [ ] Escalate to L2
- [ ] Monitor only

**Reason:** Authorised lab test. An unauthorised PHP file in a web-accessible directory was detected in realtime and automatically quarantined. Containment achieved with no evidence of execution.

## Actions Taken
1. Confirmed the file no longer exists at its original path
2. Confirmed the quarantine in the active-response log
3. Identified and fixed the YARA enrichment gap (Finding 11)

## Recommendations
1. Make the web root read-only for the web server user, except for upload directories
2. Disable PHP execution in upload directories
3. Keep YARA scanning inside the quarantine step (now implemented)

## Evidence
- Screenshot: rule 100030 alert (00:32:59)
- Screenshot: syscheck events for shell.php (added → deleted)
- Active-response log excerpt (above)
- Quarantined file: `/var/ossec/quarantine/20261031-003259_shell.php.quarantined`
- Revalidation: Telegram alerts for `tg-live.php` (01:39)
