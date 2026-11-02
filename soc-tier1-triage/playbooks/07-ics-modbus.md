# Playbook 07 — Unauthorized Modbus / ICS Write (Tier 1, OT)

**MITRE ATT&CK (ICS):** T0855 (Unauthorized Command Message), T0831 (Manipulation of Control), T0836 (Modify Parameter)
**Source:** Suricata Modbus rules (sids 100300-100302) -> Wazuh rule 86601

## 1. Trigger
Wazuh rule 86601 with an "ICS Modbus - Write ..." signature, i.e. a Modbus WRITE (FC5/6/15/16).

## 2. Validate (OT-aware)
- [ ] Identify source IP and destination PLC/unit
- [ ] Is the source an authorised engineering workstation, or an HMI/historian that should be read-only?
- [ ] Which coil/register was written, and to what value? (safety-critical?)
- [ ] Reads (FC1-4) are normal; the WRITE is the indicator

## 3. Scope
- [ ] Multiple PLCs targeted, or repeated writes?
- [ ] Setpoint pushed out of a safe range?
- [ ] Any prior recon (port scan on 502, Modbus device enumeration) from the same source?

## 4. Classification
| Outcome | Criteria | Action |
|---|---|---|
| TP - Unauthorised write | Write from a non-engineering host | **Escalate to OT/L2 immediately** |
| TP - Authorised change | Known engineering host, change window | Document, close |
| Benign | HMI/historian misconfigured to write | Fix config, make read-only |
| FP | Non-Modbus traffic on 502 | Tune parser/ports |

## 5. Containment (coordinate with OT - never act unilaterally on a live process)
- Do NOT block traffic inline on a live OT network without OT engineering sign-off
- Isolate the offending source host from the OT segment if safe to do so
- Preserve the pcap

## 6. Escalation
- Any unauthorised WRITE to a production PLC
- Setpoint/safety-limit changes
- Writes correlated with other intrusion activity

## 7. Notes (lab / WSL)
- Modbus must be enabled in Suricata (`app-layer.protocols.modbus`, dp:502)
- Loopback capture on WSL needs MTU 1500 + checksum validation off; low-volume ICS traffic is
  most reliably analysed from a pcap (`suricata -r ... -k none`), then alerts fed to the SIEM -
  which mirrors passive OT monitoring from a TAP/SPAN
