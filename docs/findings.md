# Detection Engineering Session — Custom Rule Development & Validation

**Analyst:** Olutayo Aladeusi
**Date:** 29 August 2026
**Platform:** Wazuh 4.12.0 (manager on Linux VM)
**Agents:** 1 Windows endpoint (Sysmon, agent 001)
**Objective:** Author custom detection rules ahead of a vulnerability assessment exercise, and validate that they actually fire.

---

## Summary

48 custom rules were authored and deployed to `local_rules.xml`. Validation against real and synthetic events found **four distinct failure modes**, three of which produce no error and no visible symptom on the dashboard.

The headline finding is that **"the rule loaded" and "the rule works" are unrelated statements**, and that a SIEM gives you no signal to distinguish them. Every rule below passed XML validation and appeared in the loaded ruleset. Several detected nothing.

---

## Finding 1 — Syntax error takes the entire manager offline

**Severity:** High (availability)

Rule 100014 used `<field name="url">`. In Wazuh, `url` is a *reserved static rule option*, not a dynamic decoder field, so `<field name=...>` is invalid for it.

Result: `wazuh-analysisd` refused to start. Not a degraded rule — the **whole manager failed**, taking every existing detection with it.

```
wazuh-analysisd: ERROR: Failure to read rule 100014. Field 'url' i...
wazuh-analysisd: CRITICAL: (1220): Error loading the rules
wazuh-analysisd: Configuration error. Exiting
```

**Root cause:** confusion between static rule options and dynamic decoder fields.

**Fix:** removed the offending line.

**Operational implication:** a single malformed custom rule is a total outage of detection capability, not a partial one. Rule changes should be validated with `wazuh-analysisd -t` *before* restart, and ideally staged on a non-production manager first.

---

## Finding 2 — Semantically wrong rules load silently and correlate nothing

**Severity:** High (detection gap)

Rules using `<same_field>srcip</same_field>` loaded without error and never fired. `srcip` is a **static** field; `<same_field>` operates only on **dynamic** fields extracted by decoders. Static fields have dedicated options (`<same_source_ip />`).

**Evidence — before fix:** 10 SSH failures from one source produced only built-in rules 5710 and 5712. Custom rules 100020, 100022, 100023 silent throughout.

**Evidence — after fix:** rule 100022 fired at event 6, level 10, correctly tagged T1110.001 / T1589.001.

**Detection method:** feeding representative events through `wazuh-logtest` and comparing which rule ID actually fired against which rule ID *should* have fired. Nothing else surfaces this — there is no error, no warning, and no dashboard indication.

**Also corrected:** `<different_field>dstuser</different_field>` → `<different_user />`. The sshd decoder populates `srcuser`, not `dstuser`, which was confirmed by reading live decoder output in `wazuh-logtest` Phase 2 rather than assuming the field name.

**Still suspect (same class, not yet verified):** `different_field` on `url` (100015), `dstport` (100051), `dstip` (100052).

---

## Finding 3 — Test methodology can invalidate results without failing

**Severity:** Medium (process)

Windows/Sysmon rules could not be tested with `wazuh-logtest`. Synthetic Sysmon JSON decoded correctly — all `win.eventdata.*` fields populated — but matched **no rule at all**, including a rule known to be correctly formed.

**Root cause:** Wazuh's entire Windows rule tree descends from rule 60000, which requires `<decoded_as>windows_eventchannel</decoded_as>`. That decoder is **compiled into analysisd**, not defined in the XML ruleset (confirmed: `grep` for it across `/var/ossec/ruleset/decoders/` returns nothing). It cannot be selected from logtest, including via `-l EventChannel`.

The event decoded as the generic `json` decoder and fell outside the Windows tree before any Sysmon rule was evaluated.

**Implication:** a negative test result was produced by a broken harness, not a broken rule. Had this not been investigated, five correct rules would have been recorded as non-functional.

**Correct method for Windows rules:** generate the real behaviour on the endpoint and verify against `alerts.json`. Synthetic events are not viable for eventchannel sources.

---

## Finding 4 — Custom and vendor rules shadow each other, in both directions

**Severity:** High (silent coverage change)

Wazuh fires **one rule per event**. When multiple rules match, ordering decides the winner, and the loser is invisible.

Observed in both directions:

| Direction | Evidence |
|---|---|
| **Custom displaces vendor** | Before fixing 100022, built-in 5712 fired at event 8. After the fix, 100022 fired at event 6, resetting the correlation window — 5712 no longer fires at all. |
| **Vendor displaces custom** | Rule 100500 (PowerShell EncodedCommand, pre-existing) has fired **zero** times. A live test confirmed the event arrives and matches the rule's criteria exactly — but built-in **92057** fires first and 100500 is unreachable. |

**Critical operational point:** adding custom rules *silently reduced* existing detection coverage. No error, no warning — the built-in rule simply stopped firing.

**Nuance:** shadowing is per-event, not per-rule. A broader custom rule still fires for events the vendor rules do not match. "Redundant" is therefore a spectrum, not a binary.

---

## Finding 5 — A low-threshold composite starves a higher-threshold sibling

**Severity:** Medium (detection gap)

Discovered 30 Aug while validating the web-scan chain against DVWA on the OracleLinux target.

Rules 100013 (fires at 10 matches) and 100015 (fires at 15 matches) both chain off the same base rule 100012 (`<if_matched_sid>100012</if_matched_sid>`). When 100013 fires, Wazuh drains the accumulated match pool to prevent immediate re-firing — so the shared counter never reaches the 15 that 100015 needs. The lower-threshold rule starves the higher.

**Evidence:** across 65 distinct 404 probe paths from one source, 100013 fired **6 times**, 100015 fired **0**. 100015 validated correctly in isolation via `wazuh-logtest`, confirming the rule itself is sound — it is unreachable only because of the pool contention.

**Root cause:** two frequency rules on the same base SID, where one threshold is a subset of the other. The general rule always wins; the specific refinement (100015 wanted *distinct* paths = true directory enumeration, vs. 100013's raw 4xx volume) can never trigger.

**Resolution:** 100015 left in place but documented as inert — 100013 already detects the scan. Proper fix (follow-up) is to re-scope 100015 to chain off 100013 rather than compete with it on the base rule.

**Pattern:** this is the third rule-interaction finding, all with the same signature — the rule loads, validates, reads as correct, and silently never fires. Finding 4 was vendor-vs-custom (both directions); this is custom-vs-custom. The lesson generalises: **a ruleset cannot be validated by inspection or by clean startup — only by firing representative events through it and confirming which rule ID actually wins.**

---

## Web-Scan Chain — Validation Status (30 Aug)

Target: DVWA on OracleLinux WSL, agent `ol-dvwa-01` (ID 003), Apache access log + web-root FIM wired.

| Rule | Detection | Status |
|---|---|---|
| 100012 | Web 4xx probe candidate | **Verified firing** — 23/25 probes, `web-accesslog` decoded, `url` confirmed a valid dynamic field |
| 100013 | Scanner behaviour (10+ 4xx/30s) | **Verified firing** — fired 6× across bursts |
| 100015 | Directory enumeration (15+ distinct) | **Verified non-firing** — starved by 100013 (Finding 5) |

The `different_field url` concern carried over from 29 Aug is **resolved**: `url` decodes as a proper dynamic field (visible in logtest Phase 2), so `different_field` operates on it correctly. The 100015 failure is the starvation above, not a field-type defect.

---

## Finding 6 — The payoff rule was broken by a wrong field name (`status` vs `id`)

**Severity:** High (the single most valuable rule, silently inert)

Rule 100045 — "web attack returned HTTP 200 → possible successful exploitation" — is the point of the whole web ruleset: it separates an attack *attempted* (noise) from an attack that *worked* (the alert that matters). It never fired.

**Root cause:** I wrote the response-code check as `<status>^200$</status>`. But the `web-accesslog` decoder stores the HTTP status code in the **`id`** field, not `status` (confirmed in logtest Phase 2: `id: '404'`, `id: '302'`, `id: '200'`). The rule checked a field that does not exist for web logs, so it could never match. Same class as the 29 Aug `same_field srcip` error: correct intent, wrong field name, loads clean, detects nothing.

**How it surfaced — this is the important part.** It could not be found by inspection or by a syntax check. It was found only by:
1. Authenticating a real DVWA session (so a payload could reach the vulnerable page and return 200 instead of a 302 redirect)
2. Firing a real union-based SQLi that returned `200 5424`
3. Observing that 100040 (attempt) incremented but 100045 (success) did not — meaning 100045's condition failed on a genuine 200

**Same defect in two sibling rules:** 100024 (web login brute) and 100046 (attack → 5xx) used `<status>` too. All three corrected to `<id>` by line-targeted sed, validated with `wazuh-analysisd -t`, manager restarted.

**Verification:** after the fix, the authenticated union SQLi returning 200 fired 100045 (level 14). Confirmed.

**Lesson:** the rules most worth having are the ones hardest to test, because they require the target to be in a specific state (here: authenticated, vulnerable, returning success). A ruleset that has never had a *successful* attack run through it has never tested its most important rules. Attempt-detection is easy to validate accidentally; success-detection has to be validated deliberately.

---

## Web Attack Chain — Validation Status (30 Aug, updated)

| Rule | Detection | Status |
|---|---|---|
| 100040 | SQL injection | **Verified firing** — `UNION SELECT` fires; `' OR '1'='1` (boolean) evades the signature. Gap characterised. |
| 100042 | XSS | **Verified firing** |
| 100043 | Path traversal | **Verified firing** |
| 100044 | Command injection | **Verified firing** |
| 100045 | Attack returned HTTP 200 (success) | **Verified firing** — after `status`→`id` fix (Finding 6), on a real authenticated SQLi returning 200 |
| 100024 / 100046 | Web login brute / attack→5xx | Corrected `status`→`id`, not yet exercised |

**Signature-evasion note:** boolean SQLi (`' OR '1'='1`) is not detected by the built-in SQLi signature; union-based SQLi is. URL-encoding (`+` for space) is faithfully logged and does not itself defeat detection — the miss is the signature's token set, not the encoding.

---

## Finding 7 — "Config didn't load" masquerades as "feature doesn't work"

**Severity:** Medium (process / diagnostic discipline)

Validating the webshell rule 100030 produced two false conclusions before the real one:

1. First webshell write (`sudo tee`) didn't trigger FIM. Initial hypothesis: realtime FIM doesn't work on WSL.
2. Checking the config showed the DVWA directory wasn't registered at all, and `grep -ic realtime` returned 0. Second hypothesis: multiple `<syscheck>` blocks across separate `<ossec_config>` sections don't merge.

**Both hypotheses were wrong.** After an actual agent restart, the log showed `Directory set for real time monitoring: '/var/www/html/dvwa'` and a fresh webshell (`shell2.php`) fired 100030 in `mode: realtime` within seconds, MITRE T1505.003, full SHA256 captured.

**Root cause:** the agent had not been restarted after the FIM config was appended (or the earlier restart didn't apply). The config was correct the whole time. Realtime FIM works on WSL; multi-block syscheck merges correctly; `<field name="file">` is valid for 4.12.

**Lesson:** when a feature appears broken, confirm the config actually loaded before theorising about the platform. "It doesn't work on WSL" is a satisfying explanation that closes investigation prematurely; "I never restarted the service" is the boring truth. Verify the boring truth first. (Also observed: `sudo tee` to create the first webshell was itself caught by sudo command logging as rule 5402 — a file-creation detected by a *different* sensor than the one intended. Defense-in-depth, by accident.)

---

## FIM / Webshell — Validation Status (30 Aug)

| Rule | Detection | Status |
|---|---|---|
| 100030 | Webshell dropped in web root | **Verified firing** — realtime, on `shell2.php` written to DVWA uploads dir; T1505.003, full hashes |

Realtime FIM confirmed working on WSL2 once config loaded — corrects the earlier assumption that WSL inotify would force scheduled-only.

---

## Overall: Four Detection Surfaces Validated Live

1. **Web-log scanning** — 100012, 100013 (100015 starved, Finding 5)
2. **Web-attack payloads** — 100040 (SQLi, gap characterised), 100042, 100043, 100044, 100045 (success detection, after Finding 6 fix)
3. **File integrity / webshell** — 100030 (realtime)
4. **SSH authentication** — 100022 (logtest, 29 Aug)

Seven documented findings, each a distinct failure mode, all sharing one signature: a rule that loads, validates, and reads as correct while detecting nothing — surfaced only by firing representative events and checking which rule ID actually won.

---

## Finding 10 — A real adversary-emulation tool proves the command-execution blind spot

**Severity:** High (detection gap, remediable)

MITRE Caldera 5.3.0 (server on Ubuntu, Sandcat agent on the OracleLinux target) ran a full **Discovery** adversary profile — ATT&CK techniques T1082 (system info), T1057 (process discovery), T1016 (network config), T1033 (owner/user), and related. The operation executed successfully and collected facts from the host.

**Wazuh detected none of it.** Custom post-exploitation rules 100060–100067 fired 0 times.

**Root cause:** those rules depend on auditd `execve` command logging, which WSL2 cannot provide (no audit kernel subsystem). Without command-execution telemetry, an entire ATT&CK tactic (Discovery) — and by extension Execution, much of Privilege Escalation, and Defense Evasion — is invisible to host-based detection, no matter how well-written the rules are.

**Why this matters more than a passing test:** it was proven with a real adversary-emulation tool running real techniques, not asserted. It quantifies exactly what the platform limitation costs in ATT&CK coverage terms.

**Remediation (production):** deploy auditd (real Linux hosts) or **Sysmon for Linux** (eBPF-based, no auditd dependency) to obtain `execve` telemetry, then 100060–100067 become live. On WSL specifically, Sysmon-for-Linux is the viable path since auditd's kernel backend is absent.

**Contrast:** the same lab's file-based and network-based detection (FIM/YARA on file drops, Suricata on the wire, web-log rules) all fire correctly — the blind spot is specifically command execution, and it is total until execve telemetry exists.

---

## Finding 8 — Signature scanner-detection (UA) fails; behavioural detection carries it

**Severity:** Informational (design validation)

An OWASP ZAP full active scan was run against DVWA (unauthenticated) from the Kali/Docker attacker. Rule 100014 detects scanners by User-Agent (regex includes `zap|zaproxy|nikto|sqlmap|nessus|...`). It fired **0 times**.

**Root cause:** ZAP does not announce itself by default — it uses a browser-like User-Agent. Signature detection keyed on the UA string is trivially defeated by any scanner that masks or omits its identity, which is the default for ZAP and a one-line config for the others.

**The contrast is the point:** the same scan that evaded UA detection fired the *behavioural* scan rule 100013 **117 times** (off 1,090 base 100012 events). Behaviour — bursts of 4xx from one source — cannot be masked the way a UA string can. This is direct, at-scale evidence for preferring behavioural detection over signature detection where both are options.

---

## ZAP Full Scan — Results (30 Aug)

Attacker: OWASP ZAP `zap-full-scan.py` (Docker, `--network host`) → DVWA, unauthenticated. Baseline alerts.json = 12,532 lines pre-scan.

| Rule | Detection | Fired | Note |
|---|---|---|---|
| 100012 | 4xx probe candidate | **1090** | scanner request volume |
| 100013 | Scanner behaviour (burst) | **117** | behavioural detection, worked |
| 100016 | Sensitive-path probe | **24** | ZAP hit `/.git`, `/etc/...`, `/var/www/...` |
| 100043 | Path traversal | **31** | traversal payloads in scan |
| 100045 | Attack → HTTP 200 (success) | **5** | successful-attack detections during scan |
| 100040 | SQL injection | 2 | union-form payloads |
| 100042 | XSS | 1 | |
| 100044 | Command injection | 1 | |
| 100014 | Scanner User-Agent | **0** | ZAP masks its UA (Finding 8) |
| 100015 | Directory enumeration | **0** | starved by 100013 (Finding 5), confirmed at volume |

**Scan coverage caveat:** unauthenticated, ZAP spidered only ~20 URLs (blocked at login), so the active scanner mostly exercised recon/scan rules rather than the deep payload rules. An authenticated ZAP context would drive far more traffic into the vulnerable modules — a documented next step. The payload rules were instead validated directly via authenticated curl (see Web Attack Chain above).

**Tuning material:** the scan generated ~1,300 alerts in minutes, dominated by 100012 (1090) and 100013 (117). This is the raw alert flood a real scan produces; see the tuning demo below.

---

## Finding 9 — Headless authenticated DAST is not a one-liner

**Severity:** Informational (tooling reality)

Goal: drive the deep payload rules the unauthenticated spider couldn't reach. An authenticated ZAP scan was attempted via `zap-full-scan.py` with a cookie-replacer injecting a valid DVWA `PHPSESSID` + `security=low` into every request.

**Result:** ZAP still reported "Total of 20 URLs" — identical to the unauthenticated run. The cookie injection did not authenticate the scan; ZAP stayed locked at login.php.

**Why:** headless authenticated DAST needs a real ZAP *context* with configured session management, login/logout URLs, a logged-in indicator, and logout exclusion — not a static cookie header. A one-shot container with a replacer rule doesn't establish the session state ZAP needs, and ZAP will also spider `logout.php` and destroy the session mid-scan. This is a well-known operational reality, not a Wazuh issue.

**Resolution:** the goal (exercise the payload rules with authenticated 200 responses) was achieved directly with authenticated curl against each vulnerable module — reliable, and sufficient to validate the detections. Full authenticated ZAP is a documented follow-up requiring a ZAP context file.

---

## Authenticated Payload Run — Results (30 Aug)

6 rounds of authenticated payloads (curl with a valid session) against DVWA's sqli / xss_r / fi / exec modules.

| Rule | Before | After | Delta | Note |
|---|---|---|---|---|
| 100045 (attack → HTTP 200, success) | 5 | 33 | **+28** | successful authenticated attacks detected |
| 100043 (path traversal) | 31 | 61 | +30 | `fi` payloads + `exec` payload (contains `/etc/passwd`) |
| 100040 (SQLi) | 2 | 2 | 0 | flat *because* the 200 responses promote to 100045 |
| 100042 (XSS) | 1 | 1 | 0 | same — child 100045 wins |
| 100044 (cmd injection) | 1 | 1 | 0 | same |

**Key insight:** the flat parent counts are the child-replaces-parent rule again, working as designed. An authenticated attack that returns 200 matches the attack rule (100040/42/44) then the success child (100045) wins the event. Parents stay flat *because* success detection is firing — the +28 on 100045 is those promotions. This is the whole "attempted vs succeeded" distinction, demonstrated on real authenticated exploits.

---

## Tuning Demo — Results (30 Aug)

Rule 100110 re-scoped from its placeholder (`<if_group>web_scan,recon</if_group>`, IP `192.168.56.101`, level 3) to suppress the noisy custom scan rules from the authorised source:

```xml
<rule id="100110" level="0">
  <if_sid>100012,100013,100016</if_sid>
  <srcip>127.0.0.1</srcip>
  ...
</rule>
```

Level 0 = matched but not written to alerts.json.

**Test:** 40 identical `tuningtest_*.php` 404 probes from 127.0.0.1 (the authorised source).

| Signal | Result |
|---|---|
| Probes logged by Apache | **40** (traffic confirmed) |
| 100012 alerts generated | **0** |
| 100013 alerts generated | **0** |
| Only alerts mentioning "tuningtest" | rule 5402 — the analyst's own `sudo grep` commands |

Before tuning, an identical 40-probe burst produced ~40 × 100012 plus composite 100013 fires. After, zero from the custom scan rules. Suppression confirmed and scoped: only the authorised source (127.0.0.1) and only the custom scan rules are silenced — Wazuh's built-in web rules and all other sources still alert normally.

**Honesty note:** a raw total-count comparison (1998 → 0) was discarded as evidence — `alerts.json` had rotated between the two reads (it reset to 319 lines), so the total drop was a rotation artifact, not tuning. The valid proof is per-probe: 40 requests in the access log, 0 corresponding custom alerts.

---

## Vendor Baseline Audit

Custom Windows rules were audited against the shipped ruleset before being retained. Method: dump vendor rule descriptions for the relevant Sysmon event ID and search for the intended detection.

```bash
sudo grep -c "<rule id=" /var/ossec/ruleset/rules/0800-sysmon_id_1.xml    # 82 rules
sudo grep -c "<rule id=" /var/ossec/ruleset/rules/0945-sysmon_id_10.xml   # 3 rules
sudo grep -oiP '<description>\K[^<]*(certutil|lsass|vssadmin|office)[^<]*' \
  /var/ossec/ruleset/rules/0800-sysmon_id_1.xml
```

| Rule | Intended detection | Vendor coverage | Verdict |
|---|---|---|---|
| 100090 | Office/browser spawns shell | `mshta` and `verclsid` only | **Retain** — Office→powershell/cmd uncovered |
| 100091 | LOLBin remote download | 5 certutil rules, all targeting `-decode` | **Retain** — `-urlcache` download uncovered |
| 100092 | LSASS credential dumping | Direct equivalent exists | **Shadowed** — retained, annotated, non-firing |
| 100093 | Shadow copy deletion (ransomware) | **None found** | **Retain** — unique coverage |
| 100094 | Endpoint security disabled | 8 Defender-tampering rules | **Shadowed** — retained, annotated |
| 100500 | PowerShell EncodedCommand | Rule 92057, more specific | **Shadowed** — superseded |

**Highest-value custom rule: 100093.** Volume shadow copy deletion is a top-tier ransomware precursor with no vendor coverage in this ruleset.

---

## Verification Status

Honest status of all custom rules. A rule that has not fired is *unverified*, not *working*.

| Status | Rules | Note |
|---|---|---|
| **Verified firing** | 100022 | Confirmed via logtest against representative events |
| **Verified non-firing (shadowed)** | 100500, 100092, 100094 | Confirmed by absence in `alerts.json` + vendor equivalent identified |
| **Unverified — logic sound, untested** | 100090, 100091, 100093 | 100093 deliberately untested: `vssadmin delete shadows` is destructive |
| **Unverified — suspected field defect** | 100015, 100051, 100052 | Same `different_field` static/dynamic issue as Finding 2 |
| **Unverified — no log source** | 100060–100067 (Linux post-exploitation) | Require auditd command logging, not yet configured |
| **Unverified — no log source** | 100050–100052 (port scan) | Require firewall log collection, not yet configured |
| **Untested** | Remainder | Await tomorrow's scanning exercise |

---

## Method Established

The validation loop that surfaced all four findings:

1. `wazuh-analysisd -t` — syntax validation, **before** restart, never after
2. `wazuh-logtest` — feed representative events; read **Phase 2** for actual decoder field names rather than assuming them
3. Compare the rule ID that *fired* against the rule ID that *should have* — this is the only step that catches semantic failures
4. For sources logtest cannot reach (Windows eventchannel), generate real behaviour and verify against `alerts.json`
5. Audit against the vendor baseline **before** writing a custom rule, not after

Step 5 should have come first. Rule 100500 duplicated existing vendor coverage and was unreachable from the day it was written.

---

## Next Steps

- [ ] Verify or correct `different_field` usage on 100015, 100051, 100052
- [ ] Enable auditd command logging to activate the Linux post-exploitation block
- [ ] Enable firewall log collection to activate port-scan detection
- [ ] Confirm Sysmon config logs Event 10, or record 100092 as a log-source gap rather than a rule defect
- [ ] Run the vulnerability assessment exercise and record which rules fire against real scan traffic
- [ ] For every rule that stays silent, determine whether the behaviour did not occur or the detection is broken — these are different findings

---

## Note on Test Environment

The endpoint carries employee-monitoring software and enforces application control (`certutil.exe` was blocked with "Access is denied" — a legitimate defensive control observed working). If this is a managed corporate device, vulnerability scanning activity should be moved to personal hardware before the exercise proceeds. Scan traffic and security tooling on a monitored endpoint is indistinguishable from insider activity to whoever is watching it.

---

## Finding 11 — Response outran enrichment (YARA silently skipped)

**Symptom:** Webshells dropped in the web root were detected (rule 100030) and quarantined, but no YARA result (rule 108001) was ever produced.

**Root cause (two layers):**
1. Custom rule 100030 overrides vendor rule 554 for web-root files. The YARA active response was bound only to 554, so it never ran for webshells.
2. Binding YARA to 100030 as well created a race. The quarantine script moved the file before YARA could scan it, and `yara-scan.sh` exited **silently** on the missing file. No error was logged.

**Evidence:**
- `race-test.php` (01:09): `MOVED` logged, no YARA line at all
- `shell.php` (00:32): rule 100030 + quarantine, no 108001

**Fix:**
- The quarantine script now runs YARA **before** moving the file, then logs a SHA256 of the file for evidence
- `yara-scan.sh` now logs a WARN when the target file is missing instead of exiting silently
- The YARA active response is kept on rule 554 only, so webshells aren't scanned twice

**Validation:** `fix-test.php` (01:20:47): YARA `php_webshell_generic` → `MOVED` → `SHA256`, in that order. Full pipeline confirmed live at 12:56: 100030 → 108001 → 87105 → quarantine → Telegram in about 3 seconds.

**Lesson:** Adding a more specific custom rule can silently remove coverage that was attached to the vendor rule it overrides. Every response action bound to a parent rule must be re-checked when a child rule is added.

---

## Tuning — Duplicate VirusTotal lookups

**Symptom:** A single webshell drop produced two VirusTotal lookups (2× rule 87105) and two Telegram alerts.

**Root cause:** The VirusTotal integration was scoped to `<group>syscheck</group>`, so it ran on more than one FIM event for the same file.

**Fix:**
```xml
<integration>
  <name>virustotal</name>
  <rule_id>554,100030</rule_id>
  <alert_format>json</alert_format>
</integration>
```
(The API key is omitted here; it's kept only in the manager config, never in the repo.)

**Validation:**
| Run | Time | 87105 alerts |
|---|---|---|
| Before | 12:46 | 2 |
| After | 12:56 | 1 |

**Impact:** Halves VirusTotal API usage and keeps the free-tier limit (4 requests per minute) from silently dropping enrichment, a likely cause of an earlier `exit status 4` integration error.

---

## Operational note — Agent silently disconnected after upgrade

**Symptom:** Agent ol-dvwa-01 showed **disconnected**. No alert was raised for a dead agent.

**Root cause:** A routine `dnf upgrade` moved the agent to 4.14.9 while the manager was on 4.12.0. The manager rejects agents newer than itself (`Agent version must be lower or equal to manager version`).

**Fix:** Downgraded the agent to 4.12.0 and disabled the Wazuh repo on the agent to stop it auto-upgrading.

**Lesson:** Upgrade the manager first, then the agents. Also consider alerting on agent disconnection, since loss of telemetry is itself a detection failure.

---

## Finding 1 — Validated live: successful-exploitation rule now fires

**Context:** Finding 1 originally documented that rule 100045 ("web attack returned HTTP 200") never fired, because it checked the `<status>` field while the web decoder stores the HTTP code in `<id>`. The fix changed the field reference.

**Live validation (2026-10-31):** A real authenticated UNION-based SQLi against DVWA returned HTTP 200, and rule 100045 fired at **level 14** at 14:49:05:
`Web attack returned HTTP 200 from 172.19.38.57 — possible successful exploitation of /dvwa/vulnerabilities/sqli/?id=1' UNION SELECT user,password FROM users-- -`

Unauthenticated, the same payload was redirected (302) and only rule 100040 fired — confirming the attempt/success distinction works as intended.

**Lesson:** "the rule loaded" and "the rule works" are different claims. Only a real attack that returned 200 proved the success rule fires; a config review would not have caught the original field-name bug.

---

## Operational note — Cross-distro port conflict masked as DB corruption

**Symptom:** DVWA login returned HTTP 500; `systemctl start mariadb` on the Oracle Linux target failed with `Can't start server: Bind on TCP/IP port. Got error: 98: Address already in use`.

**False lead:** The error points at the local host, and `ss -ltnp` on Oracle Linux showed 3306 LISTENING but with no owning process — because the process was in another distro's PID namespace.

**Root cause:** A MySQL instance running in the **Ubuntu** distro (pid 430, ports 3306 + 33060) had bound `127.0.0.1:3306`. Because all WSL2 distros share one network namespace, it blocked Oracle Linux's MariaDB — which holds the DVWA database — from binding the same port. With MariaDB down, DVWA threw 500s, which surfaced in Wazuh as rule 31122 bursts (14:20–14:27).

**Fix:** Stopped and disabled MySQL in Ubuntu; started MariaDB in Oracle Linux. DVWA recovered and the SQLi exploit then returned 200.

**Lesson:** Same shared-namespace root cause as the masked source-IP finding. In WSL2, a port conflict or a connection can originate in a different distro than the one reporting the error; `ss` with an empty process field is the tell. Separate VMs or network namespaces would remove this class of false lead.

---

## Network IDS findings (port-scan scenario)

Four distinct failures surfaced while getting Suricata to detect a simple port scan — each another case of "running" not meaning "working".

**1. Suricata was silently dead for ~8 weeks.** The service showed `active (running)`, but every log output (`eve.json`, `fast.log`, `stats.log`) failed with `Permission denied` because the files were root-owned while the service runs as the `suricata` user. It had written nothing since Sep 3. A green systemd status told us nothing about whether detection worked.
**Fix:** `chown -R suricata:suricata /var/log/suricata`.

**2. NIDS had no local/east-west visibility.** Suricata was bound to `eth0`, so every historical alert was *outbound* traffic (Telegram, apt). In the WSL2 shared namespace, host-to-host traffic to a local IP is delivered over loopback and never crosses eth0, so no scan of the target was ever visible.
**Fix:** bind Suricata to `lo` (`OPTIONS="-i lo"` in /etc/sysconfig/suricata).

**3. `-i any` is unsupported under AF_PACKET.** The obvious "watch everything" fix failed with `af-packet: any: failed to find interface: No such device` — the capture thread never started and eve.json stayed empty while the service still showed active. AF_PACKET needs a real interface; `any` is a libpcap feature.
**Fix:** use `lo` explicitly.

**4. Stock ET rules don't catch a quiet SYN scan.** With capture finally working, `nmap -sS --top-ports 50` produced packets but zero alerts. Detection required a custom threshold rule:
`alert tcp any any -> any any (flags:S; detection_filter:track by_src, count 20, seconds 10; sid:100200)`
This fired 76 times for one scan (retransmits to filtered ports) and mapped to Wazuh rule 86601.

**Lesson:** The network-detection path had three independent silent failures (permissions, interface binding, capture mode) before rule logic even mattered — and then the rule logic also needed custom work. Only firing a real scan and checking what reached Wazuh proved the chain end to end.

---

## Endpoint detection findings (Windows / Sysmon / PowerShell)

Getting a single malicious-PowerShell alert to fire exposed three stacked silent failures in
the endpoint pipeline — each invisible while Sysmon, the Wazuh agent, and the manager all
showed healthy, and the agent was connected with the Sysmon channel subscribed.

**1. Sysmon was not capturing process creation.** The running config logged only file, registry,
and network events (IDs 11/12/13/3) — no Event ID 1. An encoded-command execution produced no
telemetry at all. A green Sysmon service said nothing about what it was actually recording.
**Fix:** applied the SwiftOnSecurity Sysmon config (`sysmon64 -c sysmonconfig.xml`).

**2. The decoder silently dropped rich events.** With Event 1 flowing, still no alert.
`wazuh-analysisd` was logging `ERROR: Too many fields for JSON decoder` and discarding the
field-rich Sysmon events before any rule evaluated them. Confirmed by enabling `logall_json`
and finding the raw event in the archives while no alert existed.
**Fix:** `analysisd.decoder_order_size=1024` in `/var/ossec/etc/local_internal_options.conf`.

**3. Default process-create rules are level 0.** Generic Sysmon process events never become
alerts and are not indexed, so Threat Hunting shows nothing even when events arrive. Detection
of the *suspicious* command line came from built-in rule 92057 (level 12) once the event reached it.

**Payoff:** after all three fixes, Wazuh's built-in ruleset caught the encoded command at level 12
(rule 92057, ×6) with no custom rule required — plus 92213 (level 15), 92058, 92052. Custom rules
100600–100603 remain for techniques with weaker built-in coverage (Run-key persistence, LOLBin downloads).

**Also observed — prevention vs. detection:** Microsoft Defender ASR *prevented* the download
cradle and `certutil -urlcache` (both failed to launch with "Access is denied"), while the local
encoded command ran and was *detected*. A complete endpoint story needs both layers, and a SOC
analyst should distinguish "blocked" from "detected" in triage.

**Lesson:** the endpoint path had three independent silent failures before any detection logic
mattered. Every layer — sensor config, decoder limits, rule severity — can drop telemetry quietly.
Only firing a real technique and tracing it end to end (eventvwr → agent → archives → alert) proved
where it broke.

---

## OT/ICS findings (Modbus detection)

Building Modbus intrusion detection surfaced five issues specific to monitoring ICS traffic -
useful because OT monitoring differs markedly from IT:

1. **Modbus parser off by default.** Suricata ships with `app-layer.protocols.modbus: no`; it
   must be enabled (with detection-ports dp:502) before any Modbus rule can match.
2. **Loopback MTU dropped ~96% of packets.** WSL's `lo` uses 65536-byte frames that overflow
   Suricata's AF_PACKET buffers. Lowering `lo` MTU to 1500 took drops to ~0.
3. **Loopback checksums are invalid, so ICS packets were silently dropped.** Local traffic skips
   checksum computation; Suricata validates and drops by default. Fixed with `-k none` /
   `checksum-validation: no`.
4. **Rule keyword syntax mattered.** `modbus:function 5` never matched; `modbus: access write`
   (space after the colon) did. Found by testing variants against a captured pcap.
5. **Live loopback capture would not engage the parser** even after 1-4. Resolution: **offline
   pcap analysis** (`suricata -r modbus.pcap -k none`), then feed the alerts into Wazuh. This is
   not a workaround to apologise for - passive OT monitoring from a TAP/SPAN capture is standard
   practice, since you cannot run intrusive tooling on a live control network.

**Lesson:** ICS detection is not "IT detection on port 502." The protocol parser, the capture
path, and the operational model (passive, read-mostly, change-controlled) all differ. The
detection that matters is distinguishing a WRITE (manipulation of control) from the constant
benign READ polling.
