#!/usr/bin/env python3
# Modbus TCP PLC simulator (lab) - coils=pumps/valves, holding regs=setpoints
from pymodbus.server import StartTcpServer
from pymodbus.datastore import ModbusSlaveContext, ModbusServerContext, ModbusSequentialDataBlock
store = ModbusSlaveContext(
    di=ModbusSequentialDataBlock(0, [0]*100),
    co=ModbusSequentialDataBlock(0, [0]*100),
    hr=ModbusSequentialDataBlock(0, [0]*100),
    ir=ModbusSequentialDataBlock(0, [0]*100))
context = ModbusServerContext(slaves=store, single=True)
print("PLC simulator up on 0.0.0.0:502")
StartTcpServer(context=context, address=("0.0.0.0", 502))
