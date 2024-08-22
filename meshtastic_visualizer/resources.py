#!/usr/bin/env python3

import enum
import meshtastic
import copy
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
    battery_level: Optional[int] = None
    voltage: Optional[float] = None
    chutil: Optional[str] = None
    txairutil: Optional[str] = None
    rssi: Optional[str] = None
    snr: Optional[str] = None
    neighbors: Optional[List[str]] = None
    hopsaway: Optional[str] = None
    firstseen: Optional[str] = None
    lastseen: Optional[str] = None
    uptime: Optional[int] = None
    is_local: Optional[bool] = None


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


@dataclass
class MeshtasticDataStore:
    device_path: Optional[str] = None
    channels: Optional[List[Channel]] = None
    local_node_config: Optional[MeshtasticNode] = None
    connected: bool = False
    nodes: Dict[str, MeshtasticNode] = field(
        default_factory=dict)  # Dict[node_id, Node object]
    messages: Dict[str, MeshtasticMessage] = field(
        default_factory=dict)  # Dict[message_id, Message object]
    metrics: Dict[str, List[NodeMetrics]] = field(
        default_factory=dict)  # Dict[node_id, Dict[metric_name, List[value]]]

    def __post_init__(self) -> None:
        self._lock = Lock()
        self._metrics_maxlength = 120

    def is_connected(self) -> bool:
        return self.connected

    def get_local_node_config(self) -> MeshtasticNode:
        self._lock.acquire()
        res = copy.deepcopy(self.local_node_config)
        self._lock.release()
        return res

    def set_local_node_config(self, config: MeshtasticNode) -> None:
        self._lock.acquire()
        self.local_node_config = config
        self._lock.release()

    def set_local_node_config_field(self, field: str, value: Any) -> None:
        self._lock.acquire()
        setattr(self.local_node_config, field, value)
        self._lock.release()

    def get_messages(self) -> Dict[str, MeshtasticMessage]:
        self._lock.acquire()
        res = copy.deepcopy(self.messages)
        self._lock.release()
        return res

    def get_channels(self) -> Optional[List[Channel]]:
        self._lock.acquire()
        res = copy.deepcopy(self.channels)
        self._lock.release()
        return res

    def set_message(self, message: MeshtasticMessage) -> None:
        self._lock.acquire()
        self.messages[str(message.mid)] = message
        self._lock.release()

    def get_nodes(self) -> None:
        self._lock.acquire()
        res = copy.deepcopy(self.nodes)
        self._lock.release()
        return res

    def set_device_path(self, path: str) -> None:
        self._lock.acquire()
        self.device_path = path
        self._lock.release()

    def get_channel_index_from_name(self, name: str) -> int:
        self._lock.acquire()
        res: int = ""
        if self.channels is None:
            res = -1
        else:
            channel = list(filter(lambda x: x.name == name, self.channels))
            if len(channel) != 1:
                res = -1
            else:
                res = channel[0].index
        self._lock.release()
        return res

    def get_id_from_long_name(self, long_name: str) -> str:
        self._lock.acquire()
        res: str = ""
        nodes = self.nodes.values()
        if nodes is None:
            res = ""
        elif long_name == "Me":
            node = list(filter(lambda x: x.is_local, nodes))
            if len(node) != 1:
                res = ""
            else:
                res = node[0].id
        elif long_name == "All":
            res = "^all"
        else:
            node = list(filter(lambda x: x.long_name == long_name, nodes))
            if len(node) != 1:
                res = ""
            else:
                res = node[0].id
        self._lock.release()
        return res

    def get_long_name_from_id(self, id: str) -> str:
        self._lock.acquire()
        res: str = ""
        nodes = self.nodes.values()
        if not nodes:
            res = ""
        node = list(filter(lambda x: x.id == id, nodes))
        if len(node) != 1:
            res = ""
        else:
            res = node[0].long_name if node[0].long_name else node[0].id
        self._lock.release()
        return res

    def get_node_from_id(self, node_id: str) -> Optional[MeshtasticNode]:
        self._lock.acquire()
        res = None
        nodes = list(
            filter(
                lambda x: x["user"]["id"] == node_id,
                self.nodes.values()))
        if len(nodes) != 1:
            res = None
        else:
            res = nodes[0]
        self._lock.release()
        return res

    def store_or_update_node(self, node: MeshtasticNode) -> None:
        self._lock.acquire()
        if not str(node.id) in self.nodes.keys():
            self.nodes[str(node.id)] = node
            if node.lastseen:
                node.firstseen = node.lastseen
            else:
                node.firstseen = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        else:
            # update
            def __get_nodes_fields():
                return [field for field in fields(
                    MeshtasticNode) if not field.name.startswith('_')]

            for f in __get_nodes_fields():
                if getattr(self.nodes[str(node.id)],
                           f.name) != getattr(node, f.name):
                    if getattr(
                            node,
                            f.name) is not None and getattr(
                            node,
                            f.name):
                        setattr(self.nodes[str(node.id)], f.name,
                                getattr(node, f.name))
        self._lock.release()

    def store_or_update_messages(self, message: MeshtasticMessage) -> None:
        self._lock.acquire()
        key = list(
            filter(
                lambda x: self.messages[x].mid == message.mid,
                self.messages.keys()))
        if len(key) == 0:
            self.messages[message.mid] = message
        else:
            key = key[0]
            self.messages[key].date = message.date if message.date is not None else self.messages[key].date
            self.messages[key].rx_rssi = message.rx_rssi if message.rx_rssi is not None else self.messages[key].rx_rssi
            self.messages[key].rx_snr = message.rx_snr if message.rx_snr is not None else self.messages[key].rx_snr
            self.messages[key].from_id = message.from_id if message.from_id is not None else self.messages[key].from_id
            self.messages[key].to_id = message.to_id if message.to_id is not None else self.messages[key].to_id
            self.messages[key].hop_limit = message.hop_limit if message.hop_limit is not None else self.messages[key].hop_limit
            self.messages[key].hop_start = message.hop_start if message.hop_start is not None else self.messages[key].hop_start
            self.messages[key].want_ack = message.want_ack if message.want_ack is not None else self.messages[key].want_ack
            self.messages[key].ack = message.ack if message.ack is not None else self.messages[key].ack
        self._lock.release()

    def get_node_metrics_fields(self) -> list:
        return [
            "rssi",
            "snr",
            "hopsaway",
            "uptime",
            "voltage",
            "air_util_tx",
            "channel_utilization",
            "battery_level"
        ]

    def store_or_update_metrics(self, new_metric: NodeMetrics) -> None:
        self._lock.acquire()
        if new_metric.node_id not in self.metrics.keys():
            self.metrics[new_metric.node_id] = []
        self.metrics[new_metric.node_id].append(new_metric)
        self.metrics[new_metric.node_id].append(new_metric)
        if len(self.metrics[new_metric.node_id]) > self._metrics_maxlength:
            self.metrics[new_metric.node_id][0]
        self._lock.release()

    def get_node_metrics(self, node_id: str, metric: str) -> Dict:
        self._lock.acquire()
        res: Dict[str, List[Any]] = {}
        if node_id not in self.metrics.keys():
            res = {}
        else:
            if metric not in self.get_node_metrics_fields():
                res = {}
            else:
                timestamp = [x.timestamp for x in self.metrics[node_id]]
                values = [getattr(x, metric) for x in self.metrics[node_id]]
                res["timestamp"] = timestamp
                res[metric] = values
        self._lock.release()
        return res.copy()
