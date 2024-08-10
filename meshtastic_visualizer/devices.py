#!/usr/bin.env python3

from typing import List
import serial.tools.list_ports


def list_serial_ports() -> List[str]:
    """
    Return a list of all available serial devices
    """
    ports = serial.tools.list_ports.comports()
    return [port.device for port in ports]