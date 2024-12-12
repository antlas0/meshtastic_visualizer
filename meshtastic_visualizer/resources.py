#!/usr/bin/env python3

import enum
import datetime
from dataclasses import dataclass, field
from typing import List, Optional


TEXT_MESSAGE_MAX_CHARS = 237


class MessageLevel(enum.Enum):
    """
    Message criticality level
    displayed in the window
    """
    ERROR = 2
    INFO = 1
    UNKNOWN = 0


class PacketInfoType(enum.Enum):
    """
    Meshtastic packet type
    """
    PCK_NEIGHBORINFO_APP = "NEIGHBORINFO_APP"
    PCK_TELEMETRY_APP = "TELEMETRY_APP"
    PCK_POSITION_APP = "POSITION_APP"
    PCK_TEXT_MESSAGE_APP = "TEXT_MESSAGE_APP"
    PCK_ROUTING_APP = "ROUTING_APP"
    PCK_TRACEROUTE_APP = "TRACEROUTE_APP"
    PCK_STORE_FORWARD_APP = "STORE_FORWARD_APP"
    PCK_NODEINFO_APP = "NODEINFO_APP"
    PCK_UNKNOWN = ""


def create_getter(field_name):
    def getter(self):
        with self._lock:
            return getattr(self, f"{field_name}")
    getter.__name__ = f"get_{field_name}"
    return getter

# Function to create a setter method


def create_setter(field_name):
    def setter(self, value):
        with self._lock:
            setattr(self, f"{field_name}", value)
    setter.__name__ = f"set_{field_name}"
    return setter


def run_in_thread(method):
    def wrapper(self, *args, **kwargs):
        self.enqueue_task(method, self, *args, **kwargs)

    wrapper.__name__ = method.__name__
    wrapper.__doc__ = method.__doc__
    wrapper.__module__ = method.__module__

    return wrapper


@dataclass
class MeshtasticMessage:
    mid: int
    date: Optional[datetime.datetime] = None
    from_id: Optional[str] = None
    to_id: Optional[str] = None
    content: Optional[str] = None
    rx_snr: Optional[float] = None
    hop_limit: Optional[int] = None
    want_ack: Optional[bool] = None
    rx_rssi: Optional[int] = None
    hop_start: Optional[int] = None
    channel_index: Optional[int] = None
    ack: Optional[bool] = None
    public_key: str = ""
    pki_encrypted: bool = False


@dataclass
class MeshtasticNode:
    long_name: Optional[str] = None
    short_name: Optional[str] = None
    id: Optional[str] = None
    role: Optional[str] = None
    hardware: Optional[str] = None
    lat: Optional[str] = None
    lon: Optional[str] = None
    alt: Optional[str] = None
    battery_level: Optional[int] = None
    voltage: Optional[float] = None
    chutil: Optional[str] = None
    txairutil: Optional[str] = None
    rssi: Optional[str] = None
    snr: Optional[str] = None
    neighbors: List[str] = field(default_factory=list)
    hopsaway: Optional[str] = None
    firstseen: Optional[str] = None
    lastseen: Optional[str] = None
    uptime: Optional[int] = None
    is_local: Optional[bool] = None
    public_key: str = ""
    rx_counter: int = 0  # number of packets received from this node

    def has_location(self) -> bool:
        return (self.lat is not None and self.lon is not None)


@dataclass
class Channel:
    index: Optional[int] = None
    name: Optional[str] = None
    role: Optional[str] = None
    psk: Optional[str] = None


@dataclass
class NodeMetrics:
    node_id: str
    timestamp: int
    snr: Optional[float] = None
    rssi: Optional[float] = None
    uptime: Optional[int] = None
    hopsaway: Optional[int] = None
    voltage: Optional[int] = None
    air_util_tx: Optional[float] = None
    channel_utilization: Optional[float] = None
    battery_level: Optional[float] = None
    latitude: Optional[str] = None
    longitude: Optional[str] = None
    altitude: Optional[str] = None
    speed: Optional[str] = None


@dataclass
class MeshtasticMQTTClientSettings:
    host: Optional[str] = None
    port: Optional[int] = None
    username: Optional[str] = None
    password: Optional[str] = None
    topic: Optional[str] = None
    channel: Optional[str] = None
    key: Optional[str] = None
    tls: bool = True
    max_msg_len: int = 255


@dataclass
class MQTTPacket:
    date: str  # datetime.datetime.strftime("%Y-%m-%d %H:%M:%S")
    pid: str
    from_id: str
    to_id: str
    channel_id: str
    is_encrypted: bool
    payload: bytes
    port_num: str
    gateway_id: str = ""
    is_decrypted: bool = False
    source: str = "mqtt"


@dataclass
class RadioPacket:
    date: str  # datetime.datetime.strftime("%Y-%m-%d %H:%M:%S")
    pid: str
    from_id: str
    to_id: str
    channel_id: str
    is_encrypted: bool
    payload: bytes
    port_num: str
    decoded: Optional[dict] = None
    snr: Optional[float] = None
    rssi: Optional[float] = None
    hop_limit: Optional[int] = None
    source: str = "radio"


MAINWINDOW_STYLESHEET = """

"""
