#!/usr/bin/env python3

import os
import json
import copy
import queue
import base64
import logging
import datetime
from pubsub import pub
from colorama import Fore, init
from dataclasses import fields, asdict
from typing import Union, Optional, Dict
import google.protobuf.json_format
from typing import List, Optional
import threading
from threading import Lock
import meshtastic
import meshtastic.serial_interface
from meshtastic import channel_pb2, portnums_pb2, mesh_pb2
from PyQt6.QtCore import pyqtSignal, QObject
from dataclasses import fields

from .devices import list_serial_ports
from .resources import run_in_thread, \
    MessageLevel, \
    MeshtasticConfigStore, \
    MeshtasticDataStore, \
    Channel, \
    MeshtasticNode, \
    MeshtasticMessage, \
    PacketInfoType

# Initialize colorama
init(autoreset=True)


# Enable logging but set to ERROR level to suppress debug/info messages
logging.basicConfig(level=logging.ERROR)

FILE_IDENTIFIER = b'FILEDATA:'
ANNOUNCE_IDENTIFIER = b'FILEINFO:'
CHUNK_SIZE = 100  # Chunk size in bytes
BROADCAST_ADDR = "^all"


class MeshtasticManager(QObject, threading.Thread):

    notify_frontend_signal = pyqtSignal(MessageLevel, str)
    notify_data_signal = pyqtSignal(str, str)
    notify_message_signal = pyqtSignal()
    notify_traceroute_signal = pyqtSignal(list)
    notify_channels_signal = pyqtSignal()
    notify_nodes_signal = pyqtSignal()

    def __init__(self, dev_path=None):
        super().__init__()
        self._config = MeshtasticConfigStore()
        self._data = MeshtasticDataStore()
        self._config.device_path = dev_path
        self._config.destination_id = BROADCAST_ADDR
        self._config.interface = None
        self._data.received_chunks = {}
        self._data.acknowledged_chunks = set()
        self._data.expected_chunks = {}
        self._local_board_id: str = ""
        self._config.tunnel = None  # Initialize the tunnel attribute
        # Create an empty object to hold acknowledgment flags
        self._data.acknowledgment = type('', (), {})()
        self._data.acknowledgment.receivedTraceRoute = False
        self.task_queue = queue.Queue()
        self.daemon = True
        self._store_lock = Lock()


    def notify_frontend(self, level: MessageLevel, text: str):
        self.notify_frontend_signal.emit(level, text)

    def notify_channels(self):
        self.notify_channels_signal.emit()

    def notify_nodes(self):
        self.notify_nodes_signal.emit()

    def notify_data(self, message: str, message_type: str):
        self.notify_data_signal.emit(message, message_type)

    def notify_message(self):
        self.notify_message_signal.emit()

    def notify_traceroute(self, route: list):
        self.notify_traceroute_signal.emit(route)

    def get_config(self) -> MeshtasticConfigStore:
        return self._config

    def get_data(self) -> MeshtasticDataStore:
        return self._data

    def acquire_store_lock(self) -> None:
        self._store_lock.acquire()

    def release_store_lock(self) -> None:
        self._store_lock.release()

    def get_meshtastic_devices(self) -> List[str]:
        return list_serial_ports()

    def set_meshtastic_device(self, device: str) -> None:
        self._config.device_path = device

    def get_channel_index_from_name(self, name: str) -> int:
        channels = self._config.get_channels()
        if channels is None:
            return -1
        channel = list(filter(lambda x: x.name == name, channels))
        if len(channel) != 1:
            return -1
        return channel[0].index

    def get_id_from_long_name(self, long_name: str) -> int:
        self._store_lock.acquire()
        nodes = self._data.get_nodes().values()
        if nodes is None:
            self._store_lock.release()
            return ""
        if long_name == "Me":
            self._store_lock.release()
            return self._local_board_id
        if long_name == "All":
            self._store_lock.release()
            return "^all"

        node = list(filter(lambda x: x.long_name == long_name, nodes))
        if len(node) != 1:
            self._store_lock.release()
            return ""

        self._store_lock.release()
        return node[0].id

    def get_long_name_from_id(self, id: str) -> int:
        self._store_lock.acquire()
        nodes = self._data.get_nodes()
        if not nodes:
            self._store_lock.release()
            return ""
        node = list(filter(lambda x: x.id == id, nodes.values()))
        if len(node) != 1:
            self._store_lock.release()
            return ""
        res = node[0].long_name if node[0].long_name else node[0].id
        self._store_lock.release()
        return res

    def store_or_update_node(self, node: MeshtasticNode) -> None:
        self._store_lock.acquire()
        nodes = self._data.get_nodes()
        if not str(node.id) in nodes.keys():
            nodes[str(node.id)] = node
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
                if getattr(nodes[str(node.id)],
                           f.name) != getattr(node, f.name):
                    if getattr(node, f.name) is not None and getattr(node, f.name):
                        setattr(nodes[str(node.id)], f.name,
                                getattr(node, f.name))
        self._store_lock.release()

    @run_in_thread
    def connect_device(self, resetDB:bool=False) -> bool:
        if self._config.interface is not None:
            return False
        try:
            self._config.interface = meshtastic.serial_interface.SerialInterface(
                devPath=self._config.device_path)
        except Exception as e:
            trace = f"Failed to connect to Meshtastic device {self._config.device_path}: {str(e)}"
            self._data.set_is_connected(False)
            self.notify_frontend(MessageLevel.ERROR, trace)
            return False
        else:
            # Subscribe to received message events
            pub.subscribe(self.on_receive, "meshtastic.receive")
            trace = f"Successfully connected to Meshtastic device {self._config.device_path}"
            self._data.set_is_connected(True)
            self.retrieve_channels()

            node = self._config.interface.getMyNodeInfo()
            self._local_board_id = node["user"]["id"]
            if resetDB: self.reset_local_node_db()
            self.load_local_nodedb()
            self.load_local_node_configuration()
            self.notify_frontend(MessageLevel.INFO, trace)
            return True

    @run_in_thread
    def disconnect_device(self) -> bool:
        if self._config.interface is None:
            return False

        try:
            self._config.interface.close()
            del self._config.interface
            self._config.interface = None
        except Exception as e:
            trace = f"Failed to disconnect from Meshtastic device: {str(e)}"
            self.notify_frontend(MessageLevel.ERROR, trace)
            return False
        else:
            trace = f"Meshtastic device disconnected."
            self._data.set_is_connected(False)
            self.notify_frontend(MessageLevel.INFO, trace)
            return True

    def set_destination_id(self, destination_id) -> None:
        self._config.destination_id = destination_id

    def get_destination_id(self) -> str:
        return self._config.destination_id

    @run_in_thread
    def reset_local_node_db(self) -> None:
        if self._config.interface is None:
            return
        node = self._config.interface.getNode(self._local_board_id, False).resetNodeDb()

        self.notify_frontend(
            MessageLevel.INFO,
            "Local node configuration retrieved.")

    @run_in_thread
    def load_local_node_configuration(self) -> None:
        if self._config.interface is None:
            return

        node = self._config.interface.getMyNodeInfo()
        batlevel = node["deviceMetrics"]["batteryLevel"] if "deviceMetrics" in node else 0
        if batlevel > 100:
            batlevel = 100

        n = MeshtasticNode(
                id=node["user"]["id"],
                long_name=node["user"]["longName"],
                short_name=node["user"]["shortName"],
                hardware=node["user"]["hwModel"],
                role=node["user"]["role"] if "role" in node["user"] else None,
                lat=str(node["position"]["latitude"]) if "position" in node and "latitude" in node["position"] else None,
                lon=str(node["position"]["longitude"] if "position" in node and "longitude" in node["position"] else None),
                lastseen=datetime.datetime.fromtimestamp(node["lastHeard"]).strftime('%Y-%m-%d %H:%M:%S') if "lastHeard" in node and node["lastHeard"] is not None else None,
                batterylevel=batlevel,
                hopsaway=str(node["hopsAway"]) if "hopsAway" in node else None,
                snr=str(round(node["snr"], 2)) if "snr" in node else None,
                txairutil=str(round(node["deviceMetrics"]["airUtilTx"], 2)) if "deviceMetrics" in node and "airUtilTx" in node["deviceMetrics"] else None,
                chutil=str(round(node["deviceMetrics"]["channelUtilization"], 2)) if "deviceMetrics" in node and "channelUtilization" in node["deviceMetrics"] else None,
                uptime=node["deviceMetrics"]["uptimeSeconds"] if "deviceMetrics" in node and "uptimeSeconds" in node["deviceMetrics"] else None,
            )

        self._local_board_id = node["user"]["id"]

        self._config.set_local_node_config(n)

        self.notify_frontend(
            MessageLevel.INFO,
            "Local node configuration retrieved.")

    @run_in_thread
    def on_receive(self, packet:dict, interface:Optional[meshtastic.serial_interface.SerialInterface]=None):
        if "decoded" not in packet:
            return
        if "portnum" not in packet["decoded"]:
            return

        self.notify_data("---------------", message_type="INFO")
        print(Fore.LIGHTBLACK_EX + "---------------")
        if 'fromId' in packet:
            message = f"From ID: {packet['fromId']}"
            print(Fore.LIGHTBLACK_EX + message)
            self.notify_data(message, message_type="INFO")
        if 'toId' in packet:
            message = f"To ID: {packet['toId']}"
            print(Fore.LIGHTBLACK_EX + message)
            self.notify_data(message, message_type="INFO")
        if 'id' in packet:
            message = f"Packet ID: {packet['id']}"
            print(Fore.LIGHTBLACK_EX + message)
            self.notify_data(message, message_type="INFO")
            message = f"Packet type: {packet['decoded']['portnum'].lower()}"
            print(Fore.LIGHTBLACK_EX + message)
            self.notify_data(message, message_type="INFO")
        if 'rxSnr' in packet:
            message = f"SNR: {packet['rxSnr']}"
            print(Fore.LIGHTBLACK_EX + message)
            self.notify_data(message, message_type="SNR")
        if 'rxRssi' in packet:
            message = f"RSSI: {packet['rxRssi']}"
            print(Fore.LIGHTBLACK_EX + message)
            self.notify_data(message, message_type="RSSI")
        if 'hopLimit' in packet:
            message = f"Hop Limit: {packet['hopLimit']}"
            print(Fore.LIGHTBLACK_EX + message)
            self.notify_data(message, message_type="INFO")
        if 'encrypted' in packet:
            message = f"Encrypted: {packet['encrypted']}"
            print(Fore.LIGHTBLACK_EX + message)
            self.notify_data(message, message_type="INFO")

        self.update_node_info(packet)

        if packet["decoded"]["portnum"] == PacketInfoType.PCK_ROUTING_APP.value:
            ack_status = packet["decoded"]["routing"]["errorReason"] == "NONE"
            trace = f"Ack packet from {packet['fromId']} for packet id {packet['decoded']['requestId']}: {ack_status}"
            print(trace)
            self.notify_data(trace, "INFO")
            if packet["decoded"]["routing"]["errorReason"] != "NONE":
                print(
                    f'Received a NAK, error reason: {packet["decoded"]["routing"]["errorReason"]}'
                )
            else:
                if str(packet["fromId"]) == str(self._local_board_id):
                    print(
                        f"Received an implicit ACK. Packet will likely arrive, but cannot be guaranteed."
                    )

                messages_list = self._data.get_messages()
                key = list(
                    filter(
                        lambda x: messages_list[x].mid == packet["decoded"]["requestId"],
                        messages_list.keys()))
                if len(key) == 0:
                    return
                key = key[0]

                messages_list[key].date = datetime.datetime.now().strftime(
                    "%Y-%m-%d %H:%M:%S")
                if "rxRssi" in packet:
                    messages_list[key].rx_rssi = packet['rxRssi']
                if "rxSnr" in packet:
                    messages_list[key].rx_snr = packet['rxSnr']
                if "hopLimit" in packet:
                    messages_list[key].hop_limit = packet['hopLimit']
                if "hopStart" in packet:
                    messages_list[key].hop_start = packet['hopStart']
                if "wantAck" in packet:
                    messages_list[key].want_ack = packet['wantAck']
                messages_list[key].ack = "✅"
                self.notify_message()

        if packet["decoded"]["portnum"] == PacketInfoType.PCK_TRACEROUTE_APP.value:
            self.notify_frontend(MessageLevel.INFO, f"Traceoute completed.")
            routeDiscovery = mesh_pb2.RouteDiscovery()
            routeDiscovery.ParseFromString(packet["decoded"]["payload"])
            asDict = google.protobuf.json_format.MessageToDict(routeDiscovery)

            route: list = [self._node_id_from_num(packet["to"])]
            if "route" in asDict:
                for nodeNum in asDict["route"]:
                    route.append(self._node_id_from_num(nodeNum))
            route.append(self._node_id_from_num(packet["from"]))
            self._data.acknowledgment.receivedTraceRoute = True
            self.notify_traceroute(route)

        decoded = packet['decoded']
        if 'payload' in decoded and isinstance(
                decoded['payload'],
                bytes) and decoded["portnum"] == PacketInfoType.PCK_TEXT_MESSAGE_APP.value:
            data = decoded['payload']
            try:
                current_message = data.decode('utf-8').strip()
            except UnicodeDecodeError:
                print(
                    Fore.LIGHTBLACK_EX +
                    f"Received non-text payload: {decoded['payload']}")
                self.notify_data(
                    f"Received non-text payload: {decoded['payload']}",
                    message_type="INFO")
                return
            else:
                if len(current_message) == 0:
                    return

                messages_list = self._data.get_messages()
                key = list(
                    filter(
                        lambda x: messages_list[x].mid == packet["id"],
                        messages_list.keys()))
                if len(key) == 0:
                    # message not found, create
                    m = MeshtasticMessage(
                        mid=packet["id"],
                        date=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        content=current_message,
                        rx_rssi=packet['rxRssi'] if 'rxRssi' in packet else None,
                        rx_snr=packet['rxSnr'] if 'rxSnr' in packet else None,
                        from_id=self._node_id_from_num(packet['from']) if "from" in packet else None,
                        to_id=self._node_id_from_num(packet['to']),
                        channel_index=packet["channel"] if "channel" in packet else None,
                        hop_limit=packet['hopLimit'] if 'hopLimit' in packet else None,
                        hop_start=packet['hopStart'] if 'hopStart' in packet else None,
                        want_ack=packet['wantAck'] if 'wantAck' in packet else None,
                        ack="",
                    )
                    print(
                        Fore.GREEN + f"Received message: {m}")
                    self._data.get_messages()[str(m.mid)] = m
                    self.notify_frontend(
                        MessageLevel.INFO,
                        f"New message received from {packet['fromId']}")
                    self.notify_message()
                else:
                    key = key[0]
                    messages_list[key].date = datetime.datetime.now().strftime(
                        "%Y-%m-%d %H:%M:%S")
                    messages_list[key].rx_rssi = packet['rxRssi']
                    messages_list[key].rx_snr = packet['rxSnr']
                    messages_list[key].from_id = self._node_id_from_num(packet['from'])
                    messages_list[key].to_id = self._node_id_from_num(packet['to'])
                    messages_list[key].hop_limit = packet['hopLimit']
                    messages_list[key].hop_start = packet['hopStart']
                    messages_list[key].want_ack = packet['wantAck']
                    messages_list[key].ack = ""
                    self.notify_frontend(
                        MessageLevel.INFO,
                        f"Updating message info from {packet['fromId']}")
                    self.notify_message()
        if "payload" in packet["decoded"]:
            packet["decoded"].pop("payload")
        self.notify_data(str(packet["decoded"]), "INFO")

    @run_in_thread
    def send_text_message(self, message: MeshtasticMessage):
        if self._config.interface is None:
            return

        message.ack = "❌"
        sent_packet = self._config.interface.sendData(
            data=message.content.encode("utf8"),
            destinationId=message.to_id,
            portNum=portnums_pb2.PortNum.TEXT_MESSAGE_APP,
            wantAck=message.want_ack,
            wantResponse=True,
            channelIndex=message.channel_index,
            onResponseAckPermitted=False,
        )
        self.notify_data("---------------", "INFO")
        trace = f"Message sent to {message.to_id}."
        self.notify_frontend(MessageLevel.INFO, trace)
        trace = f"Message sent with ID: {message.to_id} with details {sent_packet}"
        self.notify_data(trace, "INFO")
        print(Fore.LIGHTBLACK_EX + f"{trace}")
        if message.want_ack:
            print(Fore.LIGHTBLACK_EX + "Waiting ack")

        message.mid = sent_packet.id
        self._data.get_messages()[str(message.mid)] = message
        self.notify_message()

    @run_in_thread
    def update_node_info(self, packet) -> None:

        n = MeshtasticNode(
            id=self._node_id_from_num(
                packet["from"])
        )

        if packet["decoded"]["portnum"] == PacketInfoType.PCK_POSITION_APP.value:
            n.lat = packet["decoded"]["position"]["latitude"] if "latitude" in packet["decoded"]["position"] else None
            n.lon = packet["decoded"]["position"]["longitude"] if "longitude" in packet["decoded"]["position"] else None
            n.alt = packet["decoded"]["position"]["altitude"] if "altitude" in packet["decoded"]["position"] else None

        if packet["decoded"]["portnum"] == PacketInfoType.PCK_TELEMETRY_APP.value:
            n.batterylevel = packet["decoded"]["telemetry"]["deviceMetrics"]["batteryLevel"] if "deviceMetrics" in packet[
                "decoded"]["telemetry"] and "batteryLevel" in packet["decoded"]["telemetry"]["deviceMetrics"] else None
            n.txairutil = str(
                round(
                    packet["decoded"]["telemetry"]["deviceMetrics"]["airUtilTx"],
                    2)) if "deviceMetrics" in packet["decoded"]["telemetry"] and "airUtilTx" in packet["decoded"]["telemetry"]["deviceMetrics"] else None
            n.chutil = str(
                round(
                    packet["decoded"]["telemetry"]["deviceMetrics"]["channelUtilization"],
                    2)) if "deviceMetrics" in packet["decoded"]["telemetry"] and "channelUtilization" in packet["decoded"]["telemetry"]["deviceMetrics"] else None
            n.uptime = packet["decoded"]["telemetry"]["deviceMetrics"]["uptimeSeconds"] if "deviceMetrics" in packet[
                "decoded"]["telemetry"] and "uptimeSeconds" in packet["decoded"]["telemetry"]["deviceMetrics"] else None

        if packet["decoded"]["portnum"] == PacketInfoType.PCK_NEIGHBORINFO_APP.value:
            if "neighbors" in packet["decoded"]["neighborinfo"]:
                n.neighbors = [
                    self._node_id_from_num(
                        x["nodeId"]) for x in packet["decoded"]["neighborinfo"]["neighbors"]]

        n.rssi = str(
            round(
                packet["rxRssi"],
                2)) if "rxRssi" in packet else None
        n.snr = str(
            round(
                packet["rxSnr"],
                2)) if "rxSnr" in packet else None
        n.hopsaway=str(packet["hopsAway"]) if "hopsAway" in packet else None

        n.lastseen = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        self.store_or_update_node(n)
        if n.id == self._local_board_id:
            local_node_config = self._config.local_node_config
            local_node_config.set_batterylevel(n.batterylevel if n.batterylevel is not None else local_node_config.batterylevel)
            local_node_config.set_chutil(n.chutil if n.chutil is not None else local_node_config.chutil)
            local_node_config.set_txairutil(n.txairutil if n.txairutil is not None else local_node_config.txairutil)
            local_node_config.set_role(n.role if n.role is not None else local_node_config.role)
            local_node_config.set_rssi(n.rssi if n.rssi is not None else local_node_config.rssi)

        self.notify_frontend(MessageLevel.INFO, f"Updated node {n.id}.")

    @run_in_thread
    def load_local_nodedb(self, include_self: bool = True) -> list:
        """Return a list of nodes in the mesh"""
        if self._config.interface is None:
            return []

        if self._config.interface.nodesByNum:
            logging.debug(
                f"self._config.interface.nodes:{self._config.interface.nodes}")
            for node in self._config.interface.nodesByNum.values():
                if not include_self and node["num"] == self._config.interface.localNode.nodeNum:
                    continue

                batlevel = node["deviceMetrics"]["batteryLevel"] if "deviceMetrics" in node else 0
                if batlevel > 100:
                    batlevel = 100

                n = MeshtasticNode(
                    long_name=node["user"]["longName"],
                    short_name=node["user"]["shortName"],
                    hardware=node["user"]["hwModel"],
                    role=node["user"]["role"] if "role" in node["user"] else None,
                    lat=str(
                        node["position"]["latitude"]) if "position" in node and "latitude" in node["position"] else None,
                    lon=str(
                        node["position"]["longitude"] if "position" in node and "longitude" in node["position"] else None),
                    lastseen=datetime.datetime.fromtimestamp(
                        node["lastHeard"]).strftime('%Y-%m-%d %H:%M:%S') if "lastHeard" in node and node["lastHeard"] is not None else None,
                    id=node["user"]["id"],
                    batterylevel=batlevel,
                    hopsaway=str(
                        node["hopsAway"]) if "hopsAway" in node else None,
                    snr=str(
                        round(
                            node["snr"],
                            2)) if "snr" in node else None,
                    txairutil=str(
                        round(
                            node["deviceMetrics"]["airUtilTx"],
                            2)) if "deviceMetrics" in node and "airUtilTx" in node["deviceMetrics"] else None,
                    chutil=str(
                        round(
                            node["deviceMetrics"]["channelUtilization"],
                            2)) if "deviceMetrics" in node and "channelUtilization" in node["deviceMetrics"] else None,
                    uptime=node["deviceMetrics"]["uptimeSeconds"] if "deviceMetrics" in node and "uptimeSeconds" in node["deviceMetrics"] else None,
                )

                self.store_or_update_node(n)
            self.notify_frontend(MessageLevel.INFO, "Updated nodes list.")
            self.notify_nodes()

    @run_in_thread
    def retrieve_channels(self) -> list:
        """Get the current channel settings from the node."""
        if self._config.interface is None:
            return []

        self._config.channels = []
        try:
            for channel in self._config.interface.localNode.channels:
                if channel.role != channel_pb2.Channel.Role.DISABLED:
                    self._config.channels.append(
                        Channel(
                            index=channel.index,
                            role=channel_pb2.Channel.Role.Name(channel.role),
                            name=channel.settings.name,
                            psk=base64.b64encode(
                                channel.settings.psk).decode('utf-8'),  # Encode to base64
                        )
                    )
        except Exception as e:
            trace = f"Failed to get channels: {str(e)}"
            self.notify_frontend(MessageLevel.ERROR, trace)
            self.notify_channels()
        else:
            self.notify_frontend(MessageLevel.INFO, "Channels retrieved.")
            self.notify_channels()

    @run_in_thread
    def export_chat(self) -> None:
        messages = [ asdict(x) for x in self._data.get_messages().values() ]
        data_json = json.dumps(messages, indent=4)
        nnow = datetime.datetime.now().strftime("%Y-%m-%d__%H_%M_%S")
        fpath = f"messages_{nnow}.json"
        with open(fpath, "w") as json_file:
            json_file.write(data_json)
            trace = f"Exported chat to file: {fpath}"
            self.notify_frontend(MessageLevel.INFO, trace)

    @run_in_thread
    def send_traceroute(self,
                       dest: Union[int,
                                   str],
                       hopLimit: int,
                       channelIndex: int = 0):
        """Send the trace route"""
        if self._config.interface is None:
            return

        r = mesh_pb2.RouteDiscovery()
        self._config.interface.sendData(
            r.SerializeToString(),
            destinationId=dest,
            portNum=portnums_pb2.PortNum.TRACEROUTE_APP,
            wantResponse=True,
            channelIndex=channelIndex,
        )
        self.notify_frontend(
            MessageLevel.INFO,
            f"Traceoute started to {dest}.")

    def get_node_from_id(self, node_id:str) -> Optional[meshtastic.Node]:
        if self._config.interface is None:
            return
        nodes = list(filter(lambda x:x["user"]["id"] == node_id, self._config.interface.nodes.values()))
        if len(nodes) != 1:
            return None
        return nodes[0]

    def _node_id_from_num(self, nodeNum):
        """Convert node number to node ID"""
        if self._config.interface is None:
            return ""

        for node in self._config.interface.nodesByNum.values():
            if node["num"] == nodeNum:
                return node["user"]["id"]
        return f"!{nodeNum:08x}"

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
