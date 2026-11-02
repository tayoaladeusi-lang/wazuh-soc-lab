# ICS / Modbus detection lab (TICKET-007)

Simulated PLC (pymodbus) + Suricata Modbus detection, feeding Wazuh.

## Components
- `plc_sim.py` - Modbus TCP PLC simulator (port 502): coils = pumps/valves, holding registers = setpoints
- `plc_read.py` - benign HMI read
- `plc_attack.py` - unauthorized writes (FC5 coil, FC6 register) = manipulation of control / setpoint tampering
- Suricata rules: `../suricata/modbus.rules` (sids 100300-100302) -> Wazuh rule 86601

## Run
1. PLC:    `sudo python3 plc_sim.py`
2. Attack: `python3 plc_attack.py`
3. Detect: Suricata -> Wazuh (see TICKET-007 for the WSL loopback caveats and pcap-replay method)

## Requirements
`pip install pymodbus==3.6.9`  ·  Suricata with `app-layer.protocols.modbus.enabled: yes`, detection-ports dp:502
