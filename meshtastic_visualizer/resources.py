#!/usr/bin/env python3

import enum
import meshtastic
import datetime
from dataclasses import dataclass, fields, field
from typing import List, Optional, Any, Dict
from threading import Lock


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
    date: datetime.datetime
    content: str
    from_id: str
    to_id: str
    rx_snr: Optional[float] = None
    hop_limit: Optional[int] = None
    want_ack: Optional[bool] = None
    rx_rssi: Optional[int] = None
    hop_start: Optional[int] = None
    channel_index: Optional[int] = None
    ack: str = ""


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
    batterylevel: Optional[int] = None
    chutil: Optional[str] = None
    txairutil: Optional[str] = None
    rssi: Optional[str] = None
    snr: Optional[str] = None
    last_recipient_id: Optional[str] = None
    neighbors: Optional[List[str]] = None
    hopsaway: Optional[str] = None
    firstseen: Optional[str] = None
    lastseen: Optional[str] = None
    uptime: Optional[int] = None

    def __post_init__(self):
        self._lock = Lock()
        for f in fields(self):
            field_name = f.name
            if field_name.startswith('_'):
                continue
            getter = create_getter(field_name)
            setattr(self.__class__, getter.__name__, getter)
            setter = create_setter(field_name)
            setattr(self.__class__, setter.__name__, setter)


@dataclass
class Channel:
    index: Optional[int] = None
    name: Optional[str] = None
    role: Optional[str] = None
    psk: Optional[str] = None

    def __post_init__(self):
        self._lock = Lock()
        for f in fields(self):
            field_name = f.name
            if field_name.startswith('_'):
                continue
            getter = create_getter(field_name)
            setattr(self.__class__, getter.__name__, getter)
            setter = create_setter(field_name)
            setattr(self.__class__, setter.__name__, setter)


@dataclass
class MeshtasticConfigStore:
    device_path: Optional[str] = None
    destination_id: Optional[str] = None
    timeout: Optional[int] = None
    retransmission_limit: Optional[str] = None
    interface: Optional[meshtastic.serial_interface.SerialInterface] = None
    tunnel: Optional[Any] = None
    channels: Optional[List[Channel]] = None
    local_node_config: Optional[MeshtasticNode] = None

    def __post_init__(self):
        self._lock = Lock()
        for f in fields(self):
            field_name = f.name
            if field_name.startswith('_'):
                continue
            getter = create_getter(field_name)
            setattr(self.__class__, getter.__name__, getter)
            setter = create_setter(field_name)
            setattr(self.__class__, setter.__name__, setter)


@dataclass
class MeshtasticDataStore:
    received_packets: List[str] = field(default_factory=list)
    received_chunks: Optional[dict] = None
    expected_chunks: Optional[dict] = None
    acknowledged_chunks: Optional[set] = None
    acknowledgment: Optional[Any] = None
    last_status: Optional[str] = None
    is_connected: bool = False
    nodes: Dict[str, MeshtasticNode] = field(
        default_factory=dict)  # Dict[node_id, Node object]
    messages: Dict[str, MeshtasticMessage] = field(
        default_factory=dict)  # Dict[message_id, Message object]

    def __post_init__(self):
        self._lock = Lock()
        for f in fields(self):
            field_name = f.name
            if field_name.startswith('_'):
                continue
            getter = create_getter(field_name)
            setattr(self.__class__, getter.__name__, getter)
            setter = create_setter(field_name)
            setattr(self.__class__, setter.__name__, setter)
