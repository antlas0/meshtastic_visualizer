#!/usr/bin/env python3

import os
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
    NodeMetrics, \
    RadioPacket


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
    notify_traceroute_signal = pyqtSignal(list, list, list)
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

    def notify_traceroute(
            self,
            route: list,
            snr_towards: list,
            snr_back: list):
        self.notify_traceroute_signal.emit(route, snr_towards, snr_back)

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
            self._data.connected = False
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
            public_key=node["user"]["publicKey"]
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

        decoded = packet['decoded']
        if 'payload' not in decoded or not isinstance(
                decoded['payload'], bytes):
            return

        nodes_to_update: list = []

        node_from = MeshtasticNode(
            id=self._node_id_from_num(
                packet["from"])
        )
        node_from.is_local = node_from.id == self._local_board_id

        message_to_store = None

        self._data.store_radiopacket(
            RadioPacket(
                date=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f"),
                pid=packet["id"],
                from_id=packet['fromId'],
                to_id=packet['toId'],
                channel_id=packet["channel"] if "channel" in packet else None,
                is_encrypted=packet["pkiEncrypted"] if "pkiEncrypted" in packet else False,
                payload=decoded['payload'],
                port_num=decoded["portnum"],
                snr=packet["rxSnr"] if "rxSnr" in packet else 0,
                rssi=packet["rxRssi"] if "rxRssi" in packet else 0,
            ))

        self.notify_data("---------------", message_type="INFO")
        if 'fromId' in packet:
            message = f"From ID: {packet['fromId']}"
            self.notify_data(message, message_type="INFO")
        if 'toId' in packet:
            message = f"To ID: {packet['toId']}"
            self.notify_data(message, message_type="INFO")
        if 'id' in packet:
            message = f"Packet ID: {packet['id']}"
            self.notify_data(message, message_type="INFO")
            message = f"Packet type: {packet['decoded']['portnum'].lower()}"
            self.notify_data(message, message_type="INFO")
        if 'rxSnr' in packet:
            message = f"SNR: {packet['rxSnr']}"
            self.notify_data(message, message_type="SNR")
        if 'rxRssi' in packet:
            message = f"RSSI: {packet['rxRssi']}"
            self.notify_data(message, message_type="RSSI")
        if 'hopLimit' in packet:
            message = f"Hop Limit: {packet['hopLimit']}"
            self.notify_data(message, message_type="INFO")
        if 'encrypted' in packet:
            message = f"Encrypted: {packet['encrypted']}"
            self.notify_data(message, message_type="INFO")

        node_from.rssi = str(
            round(
                packet["rxRssi"],
                2)) if "rxRssi" in packet else None
        node_from.snr = str(
            round(
                packet["rxSnr"],
                2)) if "rxSnr" in packet else None
        node_from.hopsaway = str(
            packet["hopsAway"]) if "hopsAway" in packet else None
        node_from.lastseen = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        if decoded["portnum"] == PacketInfoType.PCK_TELEMETRY_APP.value:
            node_from.battery_level = decoded["telemetry"]["deviceMetrics"]["batteryLevel"] if "deviceMetrics" in packet[
                "decoded"]["telemetry"] and "batteryLevel" in decoded["telemetry"]["deviceMetrics"] else None
            node_from.txairutil = str(
                round(
                    decoded["telemetry"]["deviceMetrics"]["airUtilTx"],
                    2)) if "deviceMetrics" in decoded["telemetry"] and "airUtilTx" in decoded["telemetry"]["deviceMetrics"] else None
            node_from.chutil = str(
                round(
                    decoded["telemetry"]["deviceMetrics"]["channelUtilization"],
                    2)) if "deviceMetrics" in decoded["telemetry"] and "channelUtilization" in decoded["telemetry"]["deviceMetrics"] else None
            node_from.voltage = str(
                round(
                    decoded["telemetry"]["deviceMetrics"]["voltage"],
                    2)) if "deviceMetrics" in decoded["telemetry"] and "voltage" in decoded["telemetry"]["deviceMetrics"] else None
            node_from.uptime = decoded["telemetry"]["deviceMetrics"]["uptimeSeconds"] if "deviceMetrics" in packet[
                "decoded"]["telemetry"] and "uptimeSeconds" in decoded["telemetry"]["deviceMetrics"] else None

        if decoded["portnum"] == PacketInfoType.PCK_POSITION_APP.value:
            node_from.lat = decoded["position"]["latitude"] if "latitude" in decoded["position"] else None
            node_from.lon = decoded["position"]["longitude"] if "longitude" in decoded["position"] else None
            node_from.alt = decoded["position"]["altitude"] if "altitude" in decoded["position"] else None

        if decoded["portnum"] == PacketInfoType.PCK_ROUTING_APP.value:
            ack_status = decoded["routing"]["errorReason"] == "NONE"
            trace = f"Ack packet from {packet['fromId']} for packet id {packet['decoded']['requestId']}: {ack_status}"
            self.notify_data(trace, "INFO")
            if decoded["routing"]["errorReason"] != "NONE":
                pass
            else:
                if str(packet["fromId"]) == str(self._local_board_id):
                    print(
                        f"Received an implicit ACK. Packet will likely arrive, but cannot be guaranteed."
                    )

                acked_message_id = decoded["requestId"]

                m = MeshtasticMessage(
                    mid=acked_message_id,
                    rx_rssi=packet['rxRssi'] if 'rxRssi' in packet else None,
                    rx_snr=packet['rxSnr'] if 'rxSnr' in packet else None,
                    channel_index=packet["channel"] if "channel" in packet else None,
                    hop_limit=packet['hopLimit'] if 'hopLimit' in packet else None,
                    hop_start=packet['hopStart'] if 'hopStart' in packet else None,
                    want_ack=False,
                    ack="✅",
                    public_key=packet["publicKey"] if "publicKey" in packet else "")
                self._data.store_or_update_messages(m)
                self.notify_message()

        if decoded["portnum"] == PacketInfoType.PCK_TRACEROUTE_APP.value:
            self.notify_frontend(MessageLevel.INFO, f"Traceoute completed.")
            route = self._extract_route_discovery(packet)
            neighbors = self._extract_route_neighbors(route)

            for k, v in neighbors.items():
                if k == node_from.id:
                    if not neighbors[node_from.id] in node_from.neighbors:
                        node_from.neighbors.append(neighbors[node_from.id])
                else:
                    n = self._data.get_node_from_id(k)
                    if n is None:
                        continue
                    updated_node = MeshtasticNode(
                        id=n.id, neighbors=n.neighbors)
                    if not neighbors[updated_node.id] in updated_node.neighbors:
                        updated_node.neighbors.append(
                            neighbors[updated_node.id])
                        nodes_to_update.append(updated_node)

            snr_towards: list = []
            snr_back: list = []

            # https://js.meshtastic.org/types/Protobuf.Mesh.RouteDiscovery.html
            # values scaled by 4
            SCALING_FACTOR = 4.0
            try:
                snr_towards = [str(float(x) / SCALING_FACTOR)
                               for x in decoded["traceroute"]["snrTowards"]]
            except Exception:
                pass
            try:
                snr_back = [str(float(x) / SCALING_FACTOR)
                            for x in decoded["traceroute"]["snrBack"]]
            except Exception:
                pass

            self.notify_traceroute(route, snr_towards, snr_back)

        if decoded["portnum"] == PacketInfoType.PCK_NEIGHBORINFO_APP.value:
            if "neighbors" in decoded["neighborinfo"]:
                node_from.neighbors = [
                    self._node_id_from_num(
                        x["nodeId"]) for x in decoded["neighborinfo"]["neighbors"]]

        if decoded["portnum"] == PacketInfoType.PCK_TEXT_MESSAGE_APP.value:
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
                    ack="✅",
                    public_key=packet["publicKey"] if "publicKey" in packet else "",
                    pki_encrypted=packet["pkiEncrypted"] if "pkiEncrypted" in packet else False,
                )

                self._data.store_or_update_messages(m)
                print(
                    Fore.GREEN + f"Received message: {m}")
                self.notify_frontend(
                    MessageLevel.INFO,
                    f"New message received from {packet['fromId']}")

                self.notify_message()
        if "payload" in packet["decoded"]:
            packet["decoded"].pop("payload")
        self.notify_data(str(packet["decoded"]), "INFO")

        nodes_to_update.append(node_from)
        self.update_nodes_info(nodes_to_update)

    def _extract_route_discovery(self, packet) -> list:
        route: list = []
        routeDiscovery = mesh_pb2.RouteDiscovery()
        try:
            routeDiscovery.ParseFromString(packet["decoded"]["payload"])
            asDict = google.protobuf.json_format.MessageToDict(routeDiscovery)
            route: list = [self._node_id_from_num(packet["to"])]
            if "route" in asDict:
                for nodeNum in asDict["route"]:
                    route.append(self._node_id_from_num(nodeNum))
            route.append(self._node_id_from_num(packet["from"]))
        except Exception as e:
            logging.warning(f"Could not extract route discovery {e}")

        return route

    def _extract_route_neighbors(self, route: list) -> dict:
        neighbors = {}
        if not route or len(route) <= 1:
            return {}
        for i in range(len(route) - 1):
            neighbors[route[i]] = route[i + 1]
        return neighbors

    @run_in_thread
    def send_text_message(self, message: MeshtasticMessage):
        if self._interface is None:
            return

        message.pki_encrypted = False
        if message.to_id != BROADCAST_ADDR:
            message.pki_encrypted = True

        message.ack = "❌"
        sent_packet = self._interface.sendData(
            data=message.content.encode("utf8"),
            destinationId=message.to_id,
            portNum=portnums_pb2.PortNum.TEXT_MESSAGE_APP,
            wantAck=message.want_ack,
            wantResponse=True,
            channelIndex=message.channel_index,
            onResponseAckPermitted=False,
            pkiEncrypted=message.pki_encrypted,
        )

        self._data.store_radiopacket(
            RadioPacket(
                date=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f"),
                pid=sent_packet.id,
                from_id=self._local_board_id,
                to_id=message.to_id,
                channel_id=sent_packet.channel,
                is_encrypted=message.pki_encrypted,
                payload=message.content.encode("utf8"),
                port_num=PacketInfoType.PCK_TEXT_MESSAGE_APP.value,
                snr=-1.0,
                rssi=-1.0,
                hoplimit=sent_packet.hop_limit
            )
        )

        self.notify_data("---------------", "INFO")
        trace = f"Message sent to {message.to_id}."
        self.notify_frontend(MessageLevel.INFO, trace)
        trace = f"Message sent with ID: {message.to_id} with details {sent_packet}"
        self.notify_data(trace, "INFO")
        message.mid = sent_packet.id
        self._data.set_message(message)
        self.notify_message()

    @run_in_thread
    def update_nodes_info(self, nodes: List[MeshtasticNode]) -> None:

        for n in nodes:
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
                    public_key=node["user"]["publicKey"] if "publicKey" in node["user"] else "",
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
                    rx_counter=0,
                )

                self._data.store_or_update_node(n, init=True)
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
            absp = os.path.abspath(fpath)
            trace = f"<a href='file://{absp}'>Exported chat to file: {fpath}</a>"
            self.notify_frontend(MessageLevel.INFO, trace)

    @run_in_thread
    def export_nodes(self) -> None:
        messages = [asdict(x) for x in self._data.get_nodes().values()]
        data_json = json.dumps(messages, indent=4)
        nnow = datetime.datetime.now().strftime("%Y-%m-%d__%H_%M_%S")
        fpath = f"nodes_{nnow}.json"
        with open(fpath, "w") as json_file:
            json_file.write(data_json)
            absp = os.path.abspath(fpath)
            trace = f"<a href='file://{absp}'>Exported nodes to file: {fpath}</a>"
            self.notify_frontend(MessageLevel.INFO, trace)

    @run_in_thread
    def send_traceroute(self,
                        dest: Union[int,
                                    str],
                        hopLimit: int,
                        channelIndex: int = 0):
        """Send the trace route"""
        if self._interface is None or not dest:
            return

        r = mesh_pb2.RouteDiscovery()
        try:
            self._interface.sendData(
                r.SerializeToString(),
                destinationId=dest,
                portNum=portnums_pb2.PortNum.TRACEROUTE_APP,
                wantResponse=True,
                channelIndex=channelIndex,
            )
        except Exception as e:
            print(f"Could not send traceroute: {e}")
        else:
            self._data.store_radiopacket(
                RadioPacket(
                    date=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f"),
                    pid=str(-1),
                    from_id=self._local_board_id,
                    to_id=dest,
                    channel_id=channelIndex,
                    is_encrypted=False,
                    payload=None,
                    port_num=PacketInfoType.PCK_TRACEROUTE_APP.value,
                    snr=-1.0,
                    rssi=-1.0,
                    hoplimit=hopLimit,
                )
            )

            self.notify_data("---------------", "INFO")
            trace = f"Traceroute sent to {dest}."
            self.notify_data(trace, "INFO")
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
