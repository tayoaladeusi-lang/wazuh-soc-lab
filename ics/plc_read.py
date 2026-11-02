#!/usr/bin/env python3
# Benign HMI poll
from pymodbus.client import ModbusTcpClient
c = ModbusTcpClient("127.0.0.1", port=502); c.connect()
rr = c.read_coils(0, count=5)
print("coils 0-4:", rr.bits[:5] if not rr.isError() else rr); c.close()
