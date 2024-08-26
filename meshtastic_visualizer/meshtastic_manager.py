#!/usr/bin/env python3

import json
import queue
import base64
import logging
import datetime
from pubsub import pub
from colorama import Fore, init
from dataclasses import asdict
from typing import Union, Optional
import google.protobuf.json_format
from typing import List, Optional
import threading
from threading import Lock
import meshtastic
import meshtastic.serial_interface
from meshtastic import channel_pb2, portnums_pb2, mesh_pb2
from PyQt6.QtCore import pyqtSignal, QObject


from .devices import list_serial_ports
from .resources import run_in_thread, \
    MessageLevel, \
    Channel, \
    MeshtasticNode, \
    MeshtasticMessage, \
    PacketInfoType, \
    NodeMetrics

from .meshtastic_datastore import MeshtasticDataStore


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
    notify_nodes_map_signal = pyqtSignal()
    notify_nodes_table_signal = pyqtSignal()
    notify_nodes_metrics_signal = pyqtSignal()

    def __init__(self):
        super().__init__()
        self._data = None
        self._interface = None
        self._local_board_id: str = ""
        self.task_queue = queue.Queue()
        self.daemon = True
        self._store_lock = Lock()
        self._interface: Optional[meshtastic.serial_interface.SerialInterface] = None

    def set_store(self, store: MeshtasticDataStore) -> None:
        self._data = store

    def notify_frontend(self, level: MessageLevel, text: str):
        self.notify_frontend_signal.emit(level, text)

    def notify_channels(self):
        self.notify_channels_signal.emit()

    def notify_nodes_map(self):
        self.notify_nodes_map_signal.emit()

    def notify_nodes_table(self):
        self.notify_nodes_table_signal.emit()

    def notify_nodes_metrics(self):
        self.notify_nodes_metrics_signal.emit()

    def notify_data(self, message: str, message_type: str):
        self.notify_data_signal.emit(message, message_type)

    def notify_message(self):
        self.notify_message_signal.emit()

    def notify_traceroute(self, route: list):
        self.notify_traceroute_signal.emit(route)

    def get_data_store(self) -> MeshtasticDataStore:
        return self._data

    def get_meshtastic_devices(self) -> List[str]:
        return list_serial_ports()

    def set_meshtastic_device(self, device: str) -> None:
        self._data.set_device_path(device)

    @run_in_thread
    def connect_device(self, resetDB: bool = False) -> bool:
        if self._interface is not None:
            return False
        try:
            self._interface = meshtastic.serial_interface.SerialInterface(
                devPath=self._data.device_path)
        except Exception as e:
            trace = f"Failed to connect to Meshtastic device {self._data.device_path}: {str(e)}"
            self._data.set_is_connected(False)
            self.notify_frontend(MessageLevel.ERROR, trace)
            return False
        else:
            # Subscribe to received message events
            pub.subscribe(self.on_receive, "meshtastic.receive")
            trace = f"Successfully connected to Meshtastic device {self._data.device_path}"
            self._data.connected = True
            self.retrieve_channels()

            node = self._interface.getMyNodeInfo()
            self._local_board_id = node["user"]["id"]
            if resetDB:
                self.reset_local_node_db()
            self.load_local_nodedb()
            self.load_local_node_configuration()
            self.notify_frontend(MessageLevel.INFO, trace)
            return True

    @run_in_thread
    def disconnect_device(self) -> bool:
        if self._interface is None:
            return False

        try:
            self._interface.close()
            del self._interface
            self._interface = None
        except Exception as e:
            trace = f"Failed to disconnect from Meshtastic device: {str(e)}"
            self.notify_frontend(MessageLevel.ERROR, trace)
            return False
        else:
            trace = f"Meshtastic device disconnected."
            self._data.connected = False
            self.notify_frontend(MessageLevel.INFO, trace)
            return True

    @run_in_thread
    def reset_local_node_db(self) -> None:
        if self._interface is None:
            return
        node = self._interface.getNode(
            self._local_board_id, False).resetNodeDb()

        self.notify_frontend(
            MessageLevel.INFO,
            "Local node configuration retrieved.")

    @run_in_thread
    def load_local_node_configuration(self) -> None:
        if self._interface is None:
            return

        node = self._interface.getMyNodeInfo()
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
            battery_level=batlevel,
            hopsaway=str(node["hopsAway"]) if "hopsAway" in node else None,
            snr=str(round(node["snr"], 2)) if "snr" in node else None,
            txairutil=str(round(node["deviceMetrics"]["airUtilTx"], 2)) if "deviceMetrics" in node and "airUtilTx" in node["deviceMetrics"] else None,
            chutil=str(round(node["deviceMetrics"]["channelUtilization"], 2)) if "deviceMetrics" in node and "channelUtilization" in node["deviceMetrics"] else None,
            uptime=node["deviceMetrics"]["uptimeSeconds"] if "deviceMetrics" in node and "uptimeSeconds" in node["deviceMetrics"] else None,
            is_local=True,
        )

        self._local_board_id = node["user"]["id"]

        self._data.set_local_node_config(n)

        self.notify_frontend(
            MessageLevel.INFO,
            "Local node configuration retrieved.")

    @run_in_thread
    def on_receive(self, packet: dict,
                   interface: Optional[meshtastic.serial_interface.SerialInterface] = None):
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

                acked_message_id = packet["decoded"]["requestId"]

                m = MeshtasticMessage(
                    mid=acked_message_id,
                    rx_rssi=packet['rxRssi'] if 'rxRssi' in packet else None,
                    rx_snr=packet['rxSnr'] if 'rxSnr' in packet else None,
                    channel_index=packet["channel"] if "channel" in packet else None,
                    hop_limit=packet['hopLimit'] if 'hopLimit' in packet else None,
                    hop_start=packet['hopStart'] if 'hopStart' in packet else None,
                    want_ack=False,
                    ack="✅",
                )
                self._data.store_or_update_messages(m)
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

                m = MeshtasticMessage(
                    mid=packet["id"],
                    date=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    content=current_message,
                    rx_rssi=packet['rxRssi'] if 'rxRssi' in packet else None,
                    rx_snr=packet['rxSnr'] if 'rxSnr' in packet else None,
                    from_id=self._node_id_from_num(
                        packet['from']) if "from" in packet else None,
                    to_id=self._node_id_from_num(
                        packet['to']),
                    channel_index=packet["channel"] if "channel" in packet else None,
                    hop_limit=packet['hopLimit'] if 'hopLimit' in packet else None,
                    hop_start=packet['hopStart'] if 'hopStart' in packet else None,
                    want_ack=packet['wantAck'] if 'wantAck' in packet else None,
                    ack="",
                )

                self._data.store_or_update_messages(m)
                print(
                    Fore.GREEN + f"Received message: {m}")
                self._data.get_messages()[str(m.mid)] = m
                self.notify_frontend(
                    MessageLevel.INFO,
                    f"New message received from {packet['fromId']}")

                self.notify_message()
        if "payload" in packet["decoded"]:
            packet["decoded"].pop("payload")
        self.notify_data(str(packet["decoded"]), "INFO")

    @run_in_thread
    def send_text_message(self, message: MeshtasticMessage):
        if self._interface is None:
            return

        message.ack = "❌"
        sent_packet = self._interface.sendData(
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
        self._data.set_message(message)
        self.notify_message()

    @run_in_thread
    def update_node_info(self, packet) -> None:
        n = MeshtasticNode(
            id=self._node_id_from_num(
                packet["from"])
        )
        n.is_local = n.id == self._local_board_id

        if packet["decoded"]["portnum"] == PacketInfoType.PCK_POSITION_APP.value:
            n.lat = packet["decoded"]["position"]["latitude"] if "latitude" in packet["decoded"]["position"] else None
            n.lon = packet["decoded"]["position"]["longitude"] if "longitude" in packet["decoded"]["position"] else None
            n.alt = packet["decoded"]["position"]["altitude"] if "altitude" in packet["decoded"]["position"] else None

        if packet["decoded"]["portnum"] == PacketInfoType.PCK_TELEMETRY_APP.value:
            n.battery_level = packet["decoded"]["telemetry"]["deviceMetrics"]["batteryLevel"] if "deviceMetrics" in packet[
                "decoded"]["telemetry"] and "batteryLevel" in packet["decoded"]["telemetry"]["deviceMetrics"] else None
            n.txairutil = str(
                round(
                    packet["decoded"]["telemetry"]["deviceMetrics"]["airUtilTx"],
                    2)) if "deviceMetrics" in packet["decoded"]["telemetry"] and "airUtilTx" in packet["decoded"]["telemetry"]["deviceMetrics"] else None
            n.chutil = str(
                round(
                    packet["decoded"]["telemetry"]["deviceMetrics"]["channelUtilization"],
                    2)) if "deviceMetrics" in packet["decoded"]["telemetry"] and "channelUtilization" in packet["decoded"]["telemetry"]["deviceMetrics"] else None
            n.voltage = str(
                round(
                    packet["decoded"]["telemetry"]["deviceMetrics"]["voltage"],
                    2)) if "deviceMetrics" in packet["decoded"]["telemetry"] and "voltage" in packet["decoded"]["telemetry"]["deviceMetrics"] else None
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
        n.hopsaway = str(packet["hopsAway"]) if "hopsAway" in packet else None
        n.lastseen = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        self._data.store_or_update_node(n)

        nm = NodeMetrics(
            node_id=n.id,
            timestamp=int(round(datetime.datetime.now().timestamp())),
            rssi=float(n.rssi) if n.rssi is not None else None,
            snr=float(n.snr) if n.snr is not None else None,
            hopsaway=int(n.hopsaway) if n.hopsaway is not None else None,
            uptime=int(n.uptime) if n.uptime is not None else None,
            air_util_tx=float(n.txairutil) if n.txairutil is not None else None,
            channel_utilization=float(n.chutil) if n.chutil is not None else None,
            battery_level=float(n.battery_level) if n.battery_level is not None else None,
            voltage=float(n.voltage) if n.voltage is not None else None,
        )
        self._data.store_or_update_metrics(nm)
        self.notify_nodes_metrics()

        self.notify_frontend(MessageLevel.INFO, f"Updated node {n.id}.")
        self.notify_nodes_table()  # only notify table as map needs recreation

    @run_in_thread
    def load_local_nodedb(self, include_self: bool = True) -> list:
        """Return a list of nodes in the mesh"""
        if self._interface is None:
            return []

        if self._interface.nodesByNum:
            logging.debug(
                f"self._interface.nodes:{self._interface.nodes}")
            for node in self._interface.nodesByNum.values():
                if not include_self and node["num"] == self._interface.localNode.nodeNum:
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
                    battery_level=batlevel,
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

                self._data.store_or_update_node(n)
            self.notify_frontend(MessageLevel.INFO, "Updated nodes list.")
            self.notify_nodes_map()
            self.notify_nodes_table()

    @run_in_thread
    def retrieve_channels(self) -> list:
        """Get the current channel settings from the node."""
        if self._interface is None:
            return []

        self._data.channels = []
        try:
            for channel in self._interface.localNode.channels:
                if channel.role != channel_pb2.Channel.Role.DISABLED:
                    self._data.channels.append(
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
        messages = [asdict(x) for x in self._data.get_messages().values()]
        data_json = json.dumps(messages, indent=4)
        nnow = datetime.datetime.now().strftime("%Y-%m-%d__%H_%M_%S")
        fpath = f"messages_{nnow}.json"
        with open(fpath, "w") as json_file:
            json_file.write(data_json)
            trace = f"Exported chat to file: {fpath}"
            self.notify_frontend(MessageLevel.INFO, trace)

    @run_in_thread
    def export_nodes(self) -> None:
        messages = [asdict(x) for x in self._data.get_nodes().values()]
        data_json = json.dumps(messages, indent=4)
        nnow = datetime.datetime.now().strftime("%Y-%m-%d__%H_%M_%S")
        fpath = f"nodes_{nnow}.json"
        with open(fpath, "w") as json_file:
            json_file.write(data_json)
            trace = f"Exported nodes to file: {fpath}"
            self.notify_frontend(MessageLevel.INFO, trace)

    @run_in_thread
    def send_traceroute(self,
                        dest: Union[int,
                                    str],
                        hopLimit: int,
                        channelIndex: int = 0):
        """Send the trace route"""
        if self._interface is None:
            return

        r = mesh_pb2.RouteDiscovery()
        self._interface.sendData(
            r.SerializeToString(),
            destinationId=dest,
            portNum=portnums_pb2.PortNum.TRACEROUTE_APP,
            wantResponse=True,
            channelIndex=channelIndex,
        )
        self.notify_frontend(
            MessageLevel.INFO,
            f"Traceoute started to {dest}.")

    def _node_id_from_num(self, nodeNum):
        """Convert node number to node ID"""
        if self._interface is None:
            return ""

        for node in self._interface.nodesByNum.values():
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
