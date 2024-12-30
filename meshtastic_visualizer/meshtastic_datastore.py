#!/usr/bin/env python3

import queue
import copy
import datetime
from dataclasses import dataclass, fields, field
from typing import List, Optional, Any, Dict
from threading import Lock, Thread

from .resources import run_in_thread, \
    Channel, \
    MeshtasticNode, \
    MeshtasticMessage, \
    NodeMetrics, \
    MQTTPacket, \
    RadioPacket


@dataclass
class MeshtasticDataStore(Thread):
    device_path: Optional[str] = None
    channels: Optional[List[Channel]] = None
    local_node_config: Optional[MeshtasticNode] = None
    nodes: Dict[str, MeshtasticNode] = field(
        default_factory=dict)  # Dict[node_id, Node object]
    messages: Dict[str, MeshtasticMessage] = field(
        default_factory=dict)  # Dict[message_id, Message object]
    metrics: Dict[str, List[NodeMetrics]] = field(
        default_factory=dict)  # Dict[node_id, Dict[metric_name, List[value]]]
    mqttpackets: Dict[str, MQTTPacket] = field(
        default_factory=dict)
    radiopackets: Dict[str, MQTTPacket] = field(
        default_factory=dict)

    def __post_init__(self) -> None:
        self._lock = Lock()
        self._metrics_maxlength = 120
        self.task_queue = queue.Queue()

    def get_local_node_config(self) -> MeshtasticNode:
        self._lock.acquire()
        res = copy.copy(self.local_node_config)
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

    def get_channels(self) -> Optional[List[Channel]]:
        self._lock.acquire()
        res = copy.copy(self.channels)
        self._lock.release()
        return res

    def store_mqtt_packet(self, packet: MQTTPacket) -> None:
        self._lock.acquire()
        self.mqttpackets[str(packet.date)] = packet
        self._lock.release()

    def get_mqtt_packets(self) -> List:
        self._lock.acquire()
        packets = list(self.mqttpackets.values())
        self._lock.release()
        return packets

    def store_radiopacket(self, packet: RadioPacket) -> None:
        self._lock.acquire()
        self.radiopackets[str(packet.date)] = packet
        self._lock.release()

    def get_radio_packets(self) -> List:
        self._lock.acquire()
        packets = list(self.radiopackets.values())
        self._lock.release()
        return packets

    def clear_radio_packets(self) -> None:
        self._lock.acquire()
        del self.radiopackets
        self.radiopackets = {}
        self._lock.release()

    def clear_mqtt_packets(self) -> None:
        self._lock.acquire()
        del self.mqttpackets
        self.mqttpackets = {}
        self._lock.release()

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

    def get_id_from_long_name(self, long_name_or_id: str) -> str:
        self._lock.acquire()
        res: str = ""
        nodes = self.nodes.values()
        if nodes is None:
            res = ""
        elif long_name_or_id == "Me":
            node = list(filter(lambda x: x.is_local, nodes))
            if len(node) != 1:
                res = ""
            else:
                res = node[0].id
        elif long_name_or_id == "All":
            res = "^all"
        else:
            node = list(
                filter(
                    lambda x: x.long_name == long_name_or_id,
                    nodes))
            if len(node) != 1:
                res = long_name_or_id
            else:
                res = node[0].id
        self._lock.release()
        return res

    def get_long_name_from_id(self, id: str) -> str:
        self._lock.acquire()
        res: str = id
        nodes = self.nodes.values()
        if not nodes:
            res = id
        node = list(filter(lambda x: x.id == id, nodes))
        if len(node) != 1:
            res = id
        else:
            res = node[0].long_name if node[0].long_name else node[0].id

        if id == "!ffffffff":
            res = "All"

        self._lock.release()
        return res

    def get_node_from_id(self, node_id: str) -> Optional[MeshtasticNode]:
        self._lock.acquire()
        res = None
        nodes = list(
            filter(
                lambda x: x.id == node_id,
                self.nodes.values()))
        if len(nodes) != 1:
            res = None
        else:
            res = nodes[0]
        self._lock.release()
        return res

    def get_nodes(self) -> dict:
        self._lock.acquire()
        res = copy.copy(self.nodes)
        self._lock.release()
        return res

    def clear_nodes(self) -> None:
        self._lock.acquire()
        del self.nodes
        self.nodes = {}
        self._lock.release()

    def get_messages(self) -> List:
        self._lock.acquire()
        messages = list(self.messages.values())
        self._lock.release()
        return messages

    def clear_messages(self) -> None:
        self._lock.acquire()
        del self.messages
        self.messages = {}
        self._lock.release()

    def clear_nodes_metrics(self) -> None:
        self._lock.acquire()
        del self.metrics
        self.metrics = {}
        self._lock.release()

    def store_or_update_node(
            self,
            node: MeshtasticNode,
            init: bool = False) -> None:
        self._lock.acquire()
        if init:
            self.nodes[str(node.id)] = node
            self._lock.release()
            return

        if not str(node.id) in self.nodes.keys():
            # not previously in nodedb and discovering at runtime
            # meaning we got a packet from this node
            self.nodes[str(node.id)] = node
            node.firstseen = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            node.lastseen = node.firstseen
            node.rx_counter = 1
        else:
            # update already known node
            # either it was in nodedb and it is the first packet we get
            # either this is not the first packet we get
            def __get_nodes_fields():
                return [field for field in fields(
                    MeshtasticNode) if not field.name.startswith('_')]

            # if in nodedb previously but unseen so far (rx_counter == 0)
            if getattr(self.nodes[str(node.id)], "rx_counter") == 0:
                node.firstseen = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                node.lastseen = node.firstseen

            rx_counter = getattr(self.nodes[str(node.id)], "rx_counter") + 1
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
            # update the received packet conuter
            setattr(self.nodes[str(node.id)], "rx_counter", rx_counter)
        self._lock.release()

    def store_or_update_messages(
            self,
            message: MeshtasticMessage,
            only_update: bool = False) -> None:
        self._lock.acquire()
        key = list(
            filter(
                lambda x: self.messages[x].mid == message.mid,
                self.messages.keys()))
        if len(key) == 0:
            if not only_update:
                self.messages[message.mid] = message
        else:
            key = key[0]
            for field in fields(MeshtasticMessage):
                if getattr(message, field.name)is not None:
                    setattr(self.messages[key], field.name, getattr(message, field.name))
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
            "battery_level",
            "latitude",
            "longitude",
            "altitude",
            "speed",
        ]

    def store_or_update_metrics(self, new_metric: NodeMetrics) -> None:
        self._lock.acquire()
        if new_metric.node_id not in self.metrics.keys():
            self.metrics[new_metric.node_id] = []
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

    def enqueue_task(self, task, *args, **kwargs):
        self.task_queue.put((task, args, kwargs))

    def quit(self):
        # Signal the thread to exit
        self.task_queue.put((None, [], {}))

    def run(self):
        while True:
            task, args, kwargs = self.task_queue.get()
            if task is None:
                break
            task(*args, **kwargs)
            self.task_queue.task_done()
