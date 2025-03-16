#!/usr/bin/env python3

import queue
import copy
import datetime
from dataclasses import dataclass, fields, field
from typing import List, Optional, Any, Dict
from threading import Lock, Thread

from .resources import Channel, \
    MeshtasticNode, \
    MeshtasticMessage, \
    NodeMetrics, \
    MQTTPacket, \
    RadioPacket


@dataclass
class MeshtasticDataStore(Thread):
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
    radiopackets: Dict[str, RadioPacket] = field(
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
        key = str(packet.date)
        self.mqttpackets[key] = packet
        self._lock.release()

    def get_mqtt_packets(self) -> List:
        self._lock.acquire()
        packets = copy.deepcopy(list(self.mqttpackets.values()))
        self._lock.release()
        return packets

    def store_radiopacket(self, packet: RadioPacket) -> None:
        self._lock.acquire()
        key = str(packet.date)
        self.radiopackets[key] = packet
        self._lock.release()

    def get_radio_packets(self) -> List:
        self._lock.acquire()
        packets = copy.deepcopy(list(self.radiopackets.values()))
        self._lock.release()
        return packets

    def get_radio_packet(self, pid: int) -> Optional[RadioPacket]:
        self._lock.acquire()
        packet = list(
            filter(
                lambda x: x.pid == pid,
                self.radiopackets.values()))
        if len(packet) == 1:
            packet = copy.deepcopy(packet[0])
        else:
            packet = None
        self._lock.release()
        return packet

    def get_mqtt_packet(self, pid: int) -> Optional[MQTTPacket]:
        self._lock.acquire()
        packet = None
        if pid in self.mqttpackets:
            packet = copy.deepcopy(self.mqttpackets[pid])
        self._lock.release()
        return packet

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

    def get_channel_index_from_name(self, name: str) -> int:
        self._lock.acquire()
        res: int = -1
        if self.channels is None:
            pass
        else:
            channel = list(filter(lambda x: x.name == name, self.channels))
            if len(channel) != 1:
                pass
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
        try:
            res = copy.deepcopy(self.nodes[node_id])
        except Exception:
            pass
        self._lock.release()
        return res

    def add_neighbor(self, me: str, my_neighbor: str) -> None:
        if me == my_neighbor:
            return
        self._lock.acquire()
        for k, v in {me: my_neighbor, my_neighbor: me}.items():
            if k in self.nodes.keys() and self.nodes[k].neighbors is None:
                self.nodes[k].neighbors = []

            if k in self.nodes.keys() and v not in self.nodes[k].neighbors:
                self.nodes[k].neighbors.append(v)
        self._lock.release()

    def get_nodes(self) -> dict:
        self._lock.acquire()
        res = copy.deepcopy(self.nodes)
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

    def update_node_rx_counter(self, node: MeshtasticNode) -> None:
        rx_counter = getattr(self.nodes[str(node.id)], "rx_counter") + 1
        # update the received packet counter
        setattr(self.nodes[str(node.id)], "rx_counter", rx_counter)

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
            node.firstseen = datetime.datetime.now()
            node.lastseen = node.firstseen
            node.rx_counter = 0
        else:
            # update already known node
            # either it was in nodedb and it is the first packet we get
            # either this is not the first packet we get
            def __get_nodes_fields():
                return [field for field in fields(
                    MeshtasticNode) if not field.name.startswith('_')]

            # if in nodedb previously but unseen so far (rx_counter == 0)
            if getattr(self.nodes[str(node.id)], "rx_counter") == 0:
                node.firstseen = datetime.datetime.now()
                node.lastseen = node.firstseen

            for f in __get_nodes_fields():
                if getattr(self.nodes[str(node.id)],
                           f.name) != getattr(node, f.name):
                    if getattr(
                            node,
                            f.name) is not None:
                        setattr(self.nodes[str(node.id)], f.name,
                                getattr(node, f.name))
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
                if getattr(message, field.name) is not None:
                    setattr(
                        self.messages[key],
                        field.name,
                        getattr(
                            message,
                            field.name))
        self._lock.release()

    def get_node_metrics_fields(self) -> list:
        return [
            "uptime",
            "voltage",
            "air_util_tx",
            "num_packets_tx",
            "num_tx_relay",
            "num_tx_relay_canceled",
            "channel_utilization",
            "battery_level",
        ]

    def get_packet_metrics_fields(self) -> list:
        return [
            "snr",
            "rssi",
        ]

    def store_or_update_node_metrics(self, new_metric: NodeMetrics) -> None:
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

    def get_packet_metrics(self, node_id: str, metric: str) -> Dict:
        self._lock.acquire()
        res: Dict[str, List[Any]] = {}

        packets: list = list(copy.deepcopy(self.radiopackets).values(
        )) + list(copy.deepcopy(self.mqttpackets).values())
        filtered = list(
            filter(
                lambda x: x.from_id == node_id,
                packets))

        if len(filtered) == 0:
            res = {}
        else:
            if metric not in self.get_packet_metrics_fields():
                res = {}
            else:
                timestamp = [x.date.timestamp() for x in filtered]
                values = [getattr(x, metric) for x in filtered]
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
