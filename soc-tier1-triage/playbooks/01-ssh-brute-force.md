# Playbook: SSH Brute-Force / User Enumeration

**Trigger:** Rule 100022 or repeated 5710/5712 events from the same source IP.

**L1 Steps:**
1. Confirm source IP and count of failures.
2. Check VirusTotal / AbuseIPDB (note if private/lab IP).
3. Search for any successful SSH login (rules 5501, 5715) from the same IP in the same window.
4. If only failures + private/lab IP → close as True Positive – Low.
5. If public IP with reputation or successful login → escalate to L2 with evidence.
