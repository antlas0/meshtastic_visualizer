#!/usr/bin/env python3

import queue
import base64
import logging
import datetime
from pubsub import pub
from typing import Union, Optional
import google.protobuf.json_format
from typing import List, Optional
import threading
from threading import Lock
import meshtastic
import meshtastic.serial_interface
import meshtastic.tcp_interface
from meshtastic import channel_pb2, portnums_pb2, mesh_pb2, config_pb2, telemetry_pb2
from PyQt6.QtCore import pyqtSignal, QObject


from .devices import list_serial_ports
from .resources import run_in_thread, \
    MessageLevel, \
    Channel, \
    MeshtasticNode, \
    MeshtasticMessage, \
    PacketInfoType, \
    NodeMetrics, \
    RadioPacket, \
    Packet, \
    ConnectionKind


from .meshtastic_datastore import MeshtasticDataStore


# Enable logging but set to ERROR level to suppress debug/info messages
logging.basicConfig(level=logging.ERROR)

FILE_IDENTIFIER = b'FILEDATA:'
ANNOUNCE_IDENTIFIER = b'FILEINFO:'
CHUNK_SIZE = 100  # Chunk size in bytes
BROADCAST_ADDR = "^all"


class MeshtasticManager(QObject, threading.Thread):

    notify_frontend_signal = pyqtSignal(MessageLevel, str)
    refresh_ui_signal = pyqtSignal()
    notify_local_device_configuration_signal = pyqtSignal(str)
    notify_new_packet = pyqtSignal(Packet)
    notify_message_signal = pyqtSignal()
    notify_traceroute_signal = pyqtSignal(list, list, list)
    notify_channels_signal = pyqtSignal()
    notify_nodes_update = pyqtSignal(MeshtasticNode)
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
        self._is_serial_connected = False
        self._is_tcp_connected = False

    def is_connected(self) -> bool:
        return self._is_serial_connected or self._is_tcp_connected

    def is_serial_connected(self) -> bool:
        return self._is_serial_connected

    def is_tcp_connected(self) -> bool:
        return self._is_tcp_connected

    def set_store(self, store: MeshtasticDataStore) -> None:
        self._data = store

    def get_data_store(self) -> MeshtasticDataStore:
        return self._data

    def get_meshtastic_devices(self) -> List[str]:
        return list_serial_ports()

    @run_in_thread
    def connect_device(self, connection_kind:ConnectionKind, target:str, resetDB: bool = False) -> bool:
        res = False
        if self._interface is not None:
            self.refresh_ui_signal.emit()
            return res
        try:
            if connection_kind == ConnectionKind.SERIAL:
                self._interface = meshtastic.serial_interface.SerialInterface(devPath=target)
            if connection_kind == ConnectionKind.TCP:
                if target.startswith("http://"):
                    target = target.replace("http://", "")
                self._interface = meshtastic.tcp_interface.TCPInterface(hostname=target)
        except Exception as e:
            trace = f"Failed to connect to Meshtastic device {target}: {str(e)}"
            self.notify_frontend_signal.emit(MessageLevel.ERROR, trace)
            self.refresh_ui_signal.emit()
        else:
            # Subscribe to received message events
            pub.subscribe(self.on_receive, "meshtastic.receive")
            trace = f"Successfully connected to Meshtastic device {target}"
            if connection_kind == ConnectionKind.SERIAL:
                self._is_serial_connected = True
            if connection_kind == ConnectionKind.TCP:
                self._is_tcp_connected = True
            self.retrieve_channels()

            node = self._interface.getMyNodeInfo()
            self._local_board_id = node["user"]["id"]
            if resetDB:
                self.reset_local_node_db()
            self.load_local_nodedb()
            self.load_local_node_configuration()
            self.get_local_node_details()
            self.notify_frontend_signal.emit(MessageLevel.INFO, trace)
            res = True
        finally:
            pass
        self.refresh_ui_signal.emit()
        return res

    @run_in_thread
    def disconnect_device(self) -> bool:
        res = False
        if self._interface is None:
            self.refresh_ui_signal.emit()
            return False

        try:
            self._interface.close()
            del self._interface
            self._interface = None
        except Exception as e:
            trace = f"Failed to disconnect from Meshtastic device: {str(e)}"
            self.notify_frontend_signal.emit(MessageLevel.ERROR, trace)
        else:
            trace = f"Meshtastic device disconnected."
            self._is_serial_connected = False
            self._is_tcp_connected = False
            self.notify_frontend_signal.emit(MessageLevel.INFO, trace)
            res = True
        finally:
            pass

        self.refresh_ui_signal.emit()
        return res

    @run_in_thread
    def reset_local_node_db(self) -> None:
        if self._interface is None:
            return
        node = self._interface.getNode(
            self._local_board_id, False).resetNodeDb()

    def get_local_node_details(self) -> None:
        conf = {}
        try:
            conf = str(self._interface.getNode("^local").localConfig)
        except Exception as e:
            pass
        else:
            self.notify_local_device_configuration_signal.emit(conf)

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
            lat=str(
                node["position"]["latitude"]) if "position" in node and "latitude" in node["position"] else None,
            lon=str(
                node["position"]["longitude"] if "position" in node and "longitude" in node["position"] else None),
            lastseen=datetime.datetime.fromtimestamp(
                node["lastHeard"]) if "lastHeard" in node and node["lastHeard"] is not None else None,
            battery_level=batlevel,
            hopsaway=int(
                    node["hopsAway"]) if "hopsAway" in node else None,
            snr=round(
                node["snr"],
                2) if "snr" in node else None,
            txairutil=round(
                node["deviceMetrics"]["airUtilTx"],
                2) if "deviceMetrics" in node and "airUtilTx" in node["deviceMetrics"] else None,
            chutil=round(
                node["deviceMetrics"]["channelUtilization"],
                2) if "deviceMetrics" in node and "channelUtilization" in node["deviceMetrics"] else None,
            uptime=node["deviceMetrics"]["uptimeSeconds"] if "deviceMetrics" in node and "uptimeSeconds" in node["deviceMetrics"] else None,
            is_local=True,
            public_key=node["user"]["publicKey"])

        self._local_board_id = node["user"]["id"]

        self._data.set_local_node_config(n)

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

        if decoded["portnum"] == portnums_pb2.UNKNOWN_APP:
            return

        nodes_to_update: list = []

        node_from = MeshtasticNode(
            id=self._node_id_from_num(
                packet["from"])
        )
        node_from.is_local = node_from.id == self._local_board_id

        received_packet = RadioPacket(
            date=datetime.datetime.now(),
            pid=packet["id"],
            from_id=self._node_id_from_num(packet['from']),
            to_id=self._node_id_from_num(packet['to']),
            is_encrypted=packet["pkiEncrypted"] if "pkiEncrypted" in packet else False,
            payload=decoded['payload'],
            decoded=str(decoded),
            port_num=decoded["portnum"],
            snr=packet["rxSnr"] if "rxSnr" in packet else None,
            rssi=packet["rxRssi"] if "rxRssi" in packet else None,
            hop_limit=packet["hopLimit"] if "hopLimit" in packet else None,
            hop_start=packet["hopStart"] if "hopStart" in packet else None,
            priority=packet["priority"] if "priority" in packet else None,
        )
        self._data.store_radiopacket(received_packet)

        node_from.rssi = round(
            packet["rxRssi"],
            2) if "rxRssi" in packet else None
        node_from.snr = round(
            packet["rxSnr"],
            2) if "rxSnr" in packet else None
        if "hopsAway" in packet:
            node_from.hopsaway = int(packet["hopsAway"])
        elif ("hopLimit" in packet and "hopStart" in packet):
            node_from.hopsaway = (
                int(packet["hopStart"]) - int(packet["hopLimit"]))
        if node_from.hopsaway is not None and node_from.hopsaway == 0:
            self._data.add_neighbor(self._local_board_id, node_from.id)

        node_from.lastseen = datetime.datetime.now()

        if decoded["portnum"] == PacketInfoType.PCK_TELEMETRY_APP.value:
            env = telemetry_pb2.Telemetry()
            try:
                env.ParseFromString(decoded["payload"])
            except Exception as e:
                pass
            else:
                node_from.lastseen = datetime.datetime.now()
                node_from.chutil = round(
                    env.device_metrics.channel_utilization, 2)
                node_from.txairutil = round(
                    env.device_metrics.air_util_tx, 2)
                node_from.battery_level = env.device_metrics.battery_level
                node_from.voltage = round(env.device_metrics.voltage, 2)
                node_from.uptime = env.device_metrics.uptime_seconds

                nm = NodeMetrics(
                    node_id=node_from.id,
                    timestamp=int(round(datetime.datetime.now().timestamp())),
                    uptime=int(node_from.uptime) if node_from.uptime is not None else None,
                    air_util_tx=float(node_from.txairutil) if node_from.txairutil is not None else None,
                    channel_utilization=float(node_from.chutil) if node_from.chutil is not None else None,
                    battery_level=float(node_from.battery_level) if node_from.battery_level is not None else None,
                    voltage=float(node_from.voltage) if node_from.voltage is not None else None,
                )
                self._data.store_or_update_node_metrics(nm)
                self.notify_nodes_metrics_signal.emit()

        if decoded["portnum"] == PacketInfoType.PCK_POSITION_APP.value:
            position = mesh_pb2.Position()
            try:
                position.ParseFromString(decoded["payload"])

            except Exception as e:
                pass
            else:
                if position.latitude_i != 0 and position.longitude_i != 0:
                    node_from.lat = str(
                        round(position.latitude_i * 1e-7, 7))
                    node_from.lon = str(
                        round(position.longitude_i * 1e-7, 7))
                    node_from.alt = str(position.altitude)

        if decoded["portnum"] == PacketInfoType.PCK_ROUTING_APP.value:
            ack_label = decoded["routing"]["errorReason"]
            acked_message_id = decoded["requestId"]

            ack_status = {
                "MAX_RETRANSMIT": False,
                "NONE": True,
                "NO_RESPONSE": False,
                "PKI_FAILED": False,
            }

            p = self._data.get_radio_packet(acked_message_id)
            if p and p.port_num == PacketInfoType.PCK_TEXT_MESSAGE_APP.value:
                m = MeshtasticMessage(
                    mid=acked_message_id,
                    ack_status=ack_status[ack_label] if ack_label in ack_status else None,
                    ack_by=packet['fromId'])
                self._data.store_or_update_messages(m, only_update=True)
                self.notify_message_signal.emit()

        if decoded["portnum"] == PacketInfoType.PCK_TRACEROUTE_APP.value:
            route = self._extract_route_discovery(packet)
            neighbors = self._extract_route_neighbors(route)

            for k, v in neighbors.items():
                self._data.add_neighbor(k, v)

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

            nodes_to_update.append(
                MeshtasticNode(
                    id=neighbors[self._local_board_id],
                    hopsaway=0,
                )
            )
            self.notify_traceroute_signal.emit(route, snr_towards, snr_back)
        if decoded["portnum"] == PacketInfoType.PCK_NODEINFO_APP.value:
            info = mesh_pb2.User()
            try:
                info.ParseFromString(decoded["payload"])
            except Exception as e:
                pass
            else:
                node_from.long_name = info.long_name
                node_from.short_name = info.short_name
                node_from.hardware = mesh_pb2.HardwareModel.Name(info.hw_model)
                node_from.role = config_pb2.Config.DeviceConfig.Role.Name(
                    info.role)
                node_from.public_key = str(info.public_key)

        if decoded["portnum"] == PacketInfoType.PCK_NEIGHBORINFO_APP.value:
            if "neighbors" in decoded["neighborinfo"]:
                for x in decoded["neighborinfo"]["neighbors"]:
                    self._data.add_neighbor(
                        node_from.id, self._node_id_from_num(
                            x["nodeId"]))

        if decoded["portnum"] == PacketInfoType.PCK_TEXT_MESSAGE_APP.value:
            data = decoded['payload']
            try:
                current_message = data.decode('utf-8').strip()
            except UnicodeDecodeError:
                print(f"Received non-text payload: {decoded['payload']}")
                return
            else:
                if len(current_message) == 0:
                    return

                m = MeshtasticMessage(
                    mid=packet["id"],
                    date=datetime.datetime.now(),
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
                    public_key=packet["publicKey"] if "publicKey" in packet else "",
                    pki_encrypted=packet["pkiEncrypted"] if "pkiEncrypted" in packet else False,
                )

                if m.to_id == self._local_board_id:
                    m.ack_status = True
                    m.ack_by = self._local_board_id

                self._data.store_or_update_messages(m)
                self.notify_message_signal.emit()

        # update node whose packet was received
        self._data.store_or_update_node(node_from)
        self._data.update_node_rx_counter(node_from)

        # update nodes consequent to received info
        self.update_nodes_info(nodes_to_update)
        self.notify_nodes_update.emit(node_from)
        self.notify_new_packet.emit(received_packet)

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

        sent_packet = self._interface.sendData(
            data=message.content.encode("utf8"),
            destinationId=message.to_id,
            portNum=portnums_pb2.PortNum.TEXT_MESSAGE_APP,
            wantAck=message.want_ack,
            channelIndex=message.channel_index,
            onResponseAckPermitted=False,
            pkiEncrypted=message.pki_encrypted,
        )
        sent_packet = RadioPacket(
            date=datetime.datetime.now(),
            pid=sent_packet.id,
            from_id=self._local_board_id,
            to_id=message.to_id,
            is_encrypted=message.pki_encrypted,
            payload=message.content.encode("utf8"),
            port_num=PacketInfoType.PCK_TEXT_MESSAGE_APP.value,
            snr=None,
            rssi=None,
            hop_limit=sent_packet.hop_limit,
            priority=sent_packet.priority,
        )

        self._data.store_radiopacket(sent_packet)
        message.mid = sent_packet.pid
        self.notify_new_packet.emit(sent_packet)
        self._data.store_or_update_messages(message)
        self.notify_message_signal.emit()

    @run_in_thread
    def update_nodes_info(self, nodes: List[MeshtasticNode]) -> None:
        for n in nodes:
            self._data.store_or_update_node(n)

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
                        node["lastHeard"]) if "lastHeard" in node and node["lastHeard"] is not None else None,
                    id=node["user"]["id"],
                    battery_level=batlevel,
                    hopsaway=int(
                        node["hopsAway"]) if "hopsAway" in node else None,
                    snr=round(
                            node["snr"],
                            2) if "snr" in node else None,
                    txairutil=round(
                            node["deviceMetrics"]["airUtilTx"],
                            2) if "deviceMetrics" in node and "airUtilTx" in node["deviceMetrics"] else None,
                    chutil=round(
                            node["deviceMetrics"]["channelUtilization"],
                            2) if "deviceMetrics" in node and "channelUtilization" in node["deviceMetrics"] else None,
                    uptime=node["deviceMetrics"]["uptimeSeconds"] if "deviceMetrics" in node and "uptimeSeconds" in node["deviceMetrics"] else None,
                    rx_counter=0,
                )

                self._data.store_or_update_node(n, init=True)
                self.notify_nodes_update.emit(n)

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
            self.notify_frontend_signal.emit(MessageLevel.ERROR, trace)
            self.notify_channels_signal.emit()
        else:
            self.notify_channels_signal.emit()

    @run_in_thread
    def send_traceroute(self,
                        dest: Union[int,
                                    str],
                        channelIndex: int = 0,
                        hopLimit: int = 5):
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
            self.notify_frontend_signal.emit(
                MessageLevel.INFO,
                f"Traceroute sent to {dest}")

            sent_packet = RadioPacket(
                date=datetime.datetime.now(),
                pid=str(-1),
                from_id=self._local_board_id,
                to_id=dest,
                is_encrypted=False,
                payload=None,
                port_num=PacketInfoType.PCK_TRACEROUTE_APP.value,
                snr=None,
                rssi=None,
                hop_limit=hopLimit,
            )

            self._data.store_radiopacket(sent_packet)
            self.notify_new_packet.emit(sent_packet)

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
