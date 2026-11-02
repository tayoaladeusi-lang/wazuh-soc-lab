# TICKET-007 — Unauthorized Modbus Write to PLC (OT/ICS)

| Field | Value |
|---|---|
| Date | 2026-11-01 (UTC-6) |
| Analyst | Olutayo Aladeusi |
| Alert source | Suricata Modbus rules (sids 100300-100302) -> Wazuh rule 86601 |
| Severity | Medium (recon/manipulation precursor; raise to High in production) |
| Agent | ol-dvwa-01 (003) |
| Target | Simulated PLC, Modbus TCP, port 502 |
| MITRE ATT&CK (ICS) | T0855 Unauthorized Command Message, T0831 Manipulation of Control, T0836 Modify Parameter |
| Status | Closed |

## Alert Summary
An attacker host issued unauthorized Modbus write commands to a PLC:
- **Write Single Coil (FC5)** - forcing a control bit ON (e.g. starting a pump / opening a valve)
- **Write Single/Holding Register (FC6)** - overwriting a setpoint
Suricata detected the writes and Wazuh surfaced them as rule 86601:
- "ICS Modbus - Write to Coils (FC5/FC15)" (sid 100300)
- "ICS Modbus - Write to Holding Registers (FC6/FC16)" (sid 100301)
- "ICS Modbus - Any Write Operation to PLC" (sid 100302)

## Why this matters (OT context)
In OT, read operations (polling sensor values) are normal HMI behaviour. **Write** operations
change physical state - a coil write can start a motor, a register write can change a setpoint
or safety limit. An unexpected write from a non-engineering host is a high-signal indicator of
an attacker manipulating the process (cf. the TRITON / Industroyer playbooks).

## Analysis
A client issued FC5/FC6 writes to the PLC. Reads alone would be benign; the writes are the
indicator. Detection keys on the Modbus function class (write to coils / holding registers).

## Detection engineering - what it took (findings)
Getting this working surfaced several real OT-monitoring gotchas, each documented below and in
docs/findings.md:
1. **Modbus parser disabled by default** - had to enable `app-layer.protocols.modbus` (dp:502).
2. **Loopback MTU 65536 caused ~96% packet loss** - Suricata's AF_PACKET buffers can't hold 64KB
   frames. Fixed by lowering `lo` MTU to 1500.
3. **Loopback packets carry invalid checksums** - Suricata drops them by default, so ICS packets
   never reached the parser. Fixed with `-k none` (offline) / `checksum-validation: no`.
4. **Rule keyword syntax** - `modbus:function 5` silently never matched; the space matters
   (`modbus: access write`). Validated by testing variants against a pcap.
5. **Live AF_PACKET capture on WSL loopback would not engage the Modbus parser** even after the
   above. **Resolution: offline pcap analysis** - capture the Modbus traffic to a pcap and run
   `suricata -r ... -k none`, then feed the alerts into Wazuh. This mirrors real OT monitoring,
   which is frequently passive from a TAP/SPAN capture rather than inline.

## Disposition
- [x] True Positive - Medium (authorised lab test)
- [ ] False Positive
- [ ] Escalate to L2
- [ ] Monitor only

**Reason:** Authorised OT lab test. Unauthorised Modbus writes to a PLC detected end-to-end.

## Recommendations
1. Baseline which hosts are permitted to WRITE to each PLC; alert on writes from any other source
2. Segment OT from IT (Purdue model); monitor the IT/OT boundary (passive TAP/SPAN)
3. Alert on writes to safety-critical coils/registers and on out-of-range setpoints
4. Enforce read-only access for HMIs/historians that only need to poll

## Evidence
- Wazuh rule 86601 ICS Modbus alerts (agent 003) - `evidence/ticket-007/01-wazuh-86601-ics-modbus-detected.png`, `02-wazuh-86601-ics-modbus-signatures.png`
- Packet capture of the attack - `evidence/ticket-007/modbus-attack.pcap`
- Rules: `suricata/modbus.rules` (sids 100300-100302)
- Simulator & attack: `ics/`
