#!/usr/bin/env python3

import time
import queue
import ssl
import datetime
import base64
import logging
import google.protobuf.json_format
import threading
from PyQt6.QtCore import pyqtSignal, QObject
from meshtastic.protobuf import mesh_pb2, mqtt_pb2, portnums_pb2, telemetry_pb2, config_pb2
import paho.mqtt.client as mqtt
from paho.mqtt.client import MessageState

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

from .resources import run_in_thread, \
    MessageLevel, \
    MeshtasticNode, \
    MeshtasticMessage, \
    NodeMetrics, \
    MeshtasticMQTTClientSettings, \
    Packet, \
    MQTTPacket, \
    TIME_FORMAT

from .datastore import MeshtasticDataStore


# Enable logging but set to ERROR level to suppress debug/info messages
logging.basicConfig(level=logging.ERROR)


class MeshtasticMQTT(QObject, threading.Thread):

    notify_frontend_signal = pyqtSignal(MessageLevel, str)
    refresh_ui_signal = pyqtSignal()
    notify_nodes_update = pyqtSignal(MeshtasticNode)
    notify_nodes_metrics_signal = pyqtSignal()
    notify_message_signal = pyqtSignal()
    notify_new_packet = pyqtSignal(Packet)
    notify_mqtt_logs = pyqtSignal(str)

    def __init__(self) -> None:
        super().__init__()
        self.daemon = True
        self._client = None
        self._subscribe_topic = None
        self._client = mqtt.Client(
            mqtt.CallbackAPIVersion.VERSION2,
            client_id="",
            clean_session=True,
            userdata=None)
        self._mqtt_settings = MeshtasticMQTTClientSettings()
        self._client.on_connect = self.on_connect
        self._client.on_disconnect = self.on_disconnect
        self._client.on_message = self.on_message
        self.task_queue = queue.Queue()
        self._store = None
        self._mqtt_thread = None

    def set_store(self, store: MeshtasticDataStore) -> None:
        self._store = store

    def setup(self) -> bool:
        return True

    @run_in_thread
    def configure_and_start(
            self,
            settings: MeshtasticMQTTClientSettings) -> None:
        self._mqtt_settings = settings
        self.connect_mqtt()

    def disconnect_mqtt(self) -> bool:
        if self._client.is_connected():
            self._client.disconnect()
            self._mqtt_thread.join()
        return True

    def is_connected(self) -> bool:
        return self._client.is_connected()

    def connect_mqtt(self) -> None:
        if not self._client.is_connected():
            key = self._mqtt_settings.key
            if self._mqtt_settings.key == "AQ==":
                key = "1PG7OiApB1nwvP+rz05pAQ=="

            padded_key = key.ljust(len(key) + ((4 - (len(key) % 4)) % 4), '=')
            replaced_key = padded_key.replace('-', '+').replace('_', '/')
            key = replaced_key
            self._client.username_pw_set(
                self._mqtt_settings.username,
                self._mqtt_settings.password)
            if self._mqtt_settings.port == 8883 and self._mqtt_settings.tls is False:
                self._client.tls_set(
                    ca_certs="cacert.pem",
                    tls_version=ssl.PROTOCOL_TLSv1_2)
                self._client.tls_insecure_set(False)
            self._mqtt_settings.tls = True
            try:
                self._client.connect(
                    self._mqtt_settings.host, self._mqtt_settings.port, 60)
            except Exception as e:
                self.notify_frontend_signal.emit(
                    MessageLevel.ERROR,
                    f"Could not connect to MQTT server {self._mqtt_settings.host}:{self._mqtt_settings.port}")
            else:
                self.notify_frontend_signal.emit(
                    MessageLevel.INFO,
                    f"Succesfully connected to MQTT server {self._mqtt_settings.host}:{self._mqtt_settings.port}")
                self._mqtt_thread = threading.Thread(
                    target=self._client.loop_start)
                self._mqtt_thread.start()

    def on_connect(self, client, userdata, flags, reason_code, properties):
        if not reason_code.is_failure:
            if self._client.is_connected():
                self.notify_frontend_signal.emit(
                    MessageLevel.INFO,
                    f"Connected to {self._mqtt_settings.host}:{self._mqtt_settings.port}")
                try:
                    self._client.subscribe(self._mqtt_settings.topic)
                except Exception as e:
                    self.notify_frontend_signal.emit(
                        MessageLevel.ERROR,
                        f"Could not subscribe to topic {self._mqtt_settings.topic}")
                else:
                    self.notify_frontend_signal.emit(
                        MessageLevel.INFO, f"Subscribed to root topic {self._mqtt_settings.topic}")
            else:
                self.notify_frontend_signal.emit(
                    MessageLevel.ERROR,
                    f"Failed to connect to {self._mqtt_settings.host}:{self._mqtt_settings.port}")
        else:
            self.notify_frontend_signal.emit(
                MessageLevel.ERROR,
                f"Failed to connect to {self._mqtt_settings.host}:{self._mqtt_settings.port}: {reason_code.names[reason_code.value]}")
            time.sleep(2)
        self.refresh_ui_signal.emit()

    def on_disconnect(self, client, userdata, flags, reason_code, properties):
        self.notify_frontend_signal.emit(
            MessageLevel.INFO,
            f"Disconnected from {self._mqtt_settings.host}:{self._mqtt_settings.port}")
        self.refresh_ui_signal.emit()

    def xor_hash(data: bytes) -> int:
        """Return XOR hash of all bytes in the provided string."""
        result = 0
        for char in data:
            result ^= char
        return result

    def decode_encrypted(self, mp) -> bool:
        """Decrypt a meshtastic message."""
        try:
            # Convert key to bytes
            key_bytes = base64.b64decode(
                self._mqtt_settings.key.encode('ascii'))

            nonce_packet_id = getattr(mp, "id").to_bytes(8, "little")
            nonce_from_node = getattr(mp, "from").to_bytes(8, "little")

            # Put both parts into a single byte array.
            nonce = nonce_packet_id + nonce_from_node

            cipher = Cipher(
                algorithms.AES(key_bytes),
                modes.CTR(nonce),
                backend=default_backend())
            decryptor = cipher.decryptor()
            decrypted_bytes = decryptor.update(
                getattr(mp, "encrypted")) + decryptor.finalize()

            data = mesh_pb2.Data()
            data.ParseFromString(decrypted_bytes)
            mp.decoded.CopyFrom(data)

        except Exception as e:
            return False
        else:
            return True

    def node_number_to_id(self, node_number):
        return f"!{hex(node_number)[2:]}"

    def on_message(self, client, userdata, msg):
        se = mqtt_pb2.ServiceEnvelope()
        is_encrypted: bool = False
        if msg.state == MessageState.MQTT_MS_INVALID:
            pass
        try:
            se.ParseFromString(msg.payload)
            mp = se.packet
        except Exception as e:
            pass
        else:
            if len(msg.payload) > self._mqtt_settings.max_msg_len:
                print(MessageLevel.ERROR, 'Message too long: ' +
                      str(len(msg.payload)) + ' bytes long, skipping.')
                return

            decrypted: bool = False
            if mp.HasField("encrypted") and not mp.HasField("decoded"):
                is_encrypted = True
                if self.decode_encrypted(mp):
                    decrypted = True

            if is_encrypted and not decrypted:
                return

            if decrypted and mp.decoded.portnum == portnums_pb2.UNKNOWN_APP:
                return

            strl = []
            strl.append(
                f"{self.node_number_to_id(getattr(se.packet, 'from'))}")
            strl.append(
                f"->{self.node_number_to_id(getattr(se.packet, 'to'))}")
            strl.append(f"[{se.channel_id}]")
            strl.append("{" + f"{se.gateway_id}" + "}")
            strl.append(f"pid:{se.packet.id}")
            if is_encrypted:
                strl.append("|e|")
                if decrypted:
                    strl.append(
                        f"pn:{portnums_pb2.PortNum.Name(se.packet.decoded.portnum)}")
            else:
                strl.append("|!e|")
                strl.append(
                    f"pn:{portnums_pb2.PortNum.Name(se.packet.decoded.portnum)}")

            received_packet = MQTTPacket(
                date=datetime.datetime.now(),
                pid=se.packet.id,
                from_id=self.node_number_to_id(
                    getattr(
                        se.packet,
                        'from')),
                to_id=self.node_number_to_id(
                    getattr(
                        se.packet,
                        'to')),
                channel_id=se.channel_id,
                is_encrypted=is_encrypted,
                is_decrypted=decrypted,
                gateway_id=se.gateway_id,
                payload=mp.decoded.payload,
                port_num=portnums_pb2.PortNum.Name(
                    se.packet.decoded.portnum),
                rssi=mp.rx_rssi,
                snr=mp.rx_snr,
                hop_limit=se.packet.hop_limit,
                hop_start=se.packet.hop_start,
            )
            node_from = MeshtasticNode(
                id=self.node_number_to_id(getattr(se.packet, 'from')),
                lastseen=datetime.datetime.now(),
                rssi=mp.rx_rssi,
                snr=mp.rx_snr,
            )

            if received_packet.hop_limit is not None and received_packet.hop_start is not None:
                received_packet.hopsaway = max(0, received_packet.hop_start - received_packet.hop_limit)
            for f in ["relay_node", "next_hop"]:
                if getattr(se.packet, f) != 0:
                    setattr(received_packet, f, f"{getattr(se.packet, f):0x}")
                    setattr(node_from, f, f"{getattr(se.packet, f):0x}")

            self._store.store_mqtt_packet(received_packet)
            self.notify_new_packet.emit(received_packet)
            self.notify_mqtt_logs.emit(" ".join(strl))

            self._store.store_or_update_node(MeshtasticNode(
                id=se.gateway_id,
                is_mqtt_gateway=True,
            ))

            if mp.decoded.portnum == portnums_pb2.TEXT_MESSAGE_APP:
                text_payload = ""
                try:
                    text_payload = mp.decoded.payload.decode("utf-8")
                except Exception as e:
                    pass
                else:
                    m = MeshtasticMessage(
                        from_id=self.node_number_to_id(
                            getattr(
                                mp,
                                "from")),
                        to_id=self.node_number_to_id(
                            getattr(
                                mp,
                                "to")),
                        content=text_payload,
                        mid=mp.id,
                        hop_limit=mp.hop_limit,
                        hop_start=mp.hop_start,
                        channel_index=mp.channel,
                        date=datetime.datetime.fromtimestamp(
                            mp.rx_time),
                    )
                    self._store.store_or_update_messages(m)
                    self.notify_message_signal.emit()

            elif mp.decoded.portnum == portnums_pb2.NEIGHBORINFO_APP:
                neigh = mesh_pb2.NeighborInfo()
                try:
                    neigh.ParseFromString(mp.decoded.payload)
                except Exception as e:
                    pass
                else:
                    if getattr(mp, "from") != neigh.last_sent_by_id:
                        node_from.neighbors = [
                            self.node_number_to_id(
                                neigh.last_sent_by_id)]

            elif mp.decoded.portnum == portnums_pb2.NODEINFO_APP:
                info = mesh_pb2.User()
                try:
                    info.ParseFromString(mp.decoded.payload)
                except Exception as e:
                    pass
                else:
                    node_from.long_name = info.long_name
                    node_from.short_name = info.short_name
                    node_from.hardware = mesh_pb2.HardwareModel.Name(
                        info.hw_model)
                    node_from.snr = mp.rx_snr
                    node_from.rssi = mp.rx_rssi
                    node_from.role = config_pb2.Config.DeviceConfig.Role.Name(
                        info.role)
                    node_from.public_key = str(info.public_key)

            elif mp.decoded.portnum == portnums_pb2.MAP_REPORT_APP:
                mapreport = mqtt_pb2.MapReport()
                try:
                    mapreport.ParseFromString(mp.decoded.payload)
                except Exception as e:
                    pass
                else:
                    node_from.long_name = mapreport.long_name
                    node_from.lat = str(round(mapreport.latitude_i * 1e-7, 7))
                    node_from.lon = str(round(mapreport.longitude_i * 1e-7, 7))
                    node_from.alt = mapreport.altitude
                    node_from.hardware = mesh_pb2.HardwareModel.Name(
                        mapreport.hw_model)
                    node_from.role = config_pb2.Config.DeviceConfig.Role.Name(
                        mapreport.role)

            elif mp.decoded.portnum == portnums_pb2.POSITION_APP:
                position = mesh_pb2.Position()
                try:
                    position.ParseFromString(mp.decoded.payload)

                except Exception as e:
                    pass
                else:
                    if position.latitude_i != 0 and position.longitude_i != 0:
                        node_from.lat = str(
                            round(position.latitude_i * 1e-7, 7))
                        node_from.lon = str(
                            round(position.longitude_i * 1e-7, 7))
                        node_from.alt = str(position.altitude)
                        node_from.rssi = mp.rx_rssi
                        node_from.snr = mp.rx_snr

            elif mp.decoded.portnum == portnums_pb2.TELEMETRY_APP:
                env = telemetry_pb2.Telemetry()
                try:
                    env.ParseFromString(mp.decoded.payload)
                except Exception as e:
                    pass
                else:
                    node_from.lastseen = datetime.datetime.now()
                    nm = NodeMetrics(
                        node_id=node_from.id,
                        timestamp=int(round(datetime.datetime.now().timestamp())),
                    )
                    if env.HasField("device_metrics"):
                        node_from.txairutil = round(env.device_metrics.air_util_tx, 2)
                        node_from.battery_level = round(env.device_metrics.battery_level)
                        node_from.chutil = round(env.device_metrics.channel_utilization, 2)
                        node_from.voltage = round(env.device_metrics.voltage, 2)
                        node_from.uptime = env.device_metrics.uptime_seconds
                        nm.air_util_tx = round(env.device_metrics.air_util_tx, 2)
                        nm.battery_level = round(env.device_metrics.battery_level)
                        nm.channel_utilization = round(env.device_metrics.channel_utilization, 2)
                        nm.voltage = round(env.device_metrics.voltage, 2)
                        nm.uptime = env.device_metrics.uptime_seconds
                    if env.HasField("local_stats"):
                        nm.num_packets_tx = env.local_stats.num_packets_tx
                        nm.num_tx_relay = env.local_stats.num_tx_relay
                        nm.num_tx_relay_canceled = env.local_stats.num_tx_relay_canceled
                        node_from.tx_counter = (env.local_stats.num_packets_tx + env.local_stats.num_tx_relay)

                    self._store.store_or_update_node_metrics(nm)
                    self.notify_nodes_metrics_signal.emit()

            elif mp.decoded.portnum == portnums_pb2.TRACEROUTE_APP:
                if mp.decoded.payload:
                    routeDiscovery = mesh_pb2.RouteDiscovery()
                    routeDiscovery.ParseFromString(mp.decoded.payload)

                    asDict = google.protobuf.json_format.MessageToDict(
                        routeDiscovery)
                    print(asDict)

            self._store.store_or_update_node(node_from)
            self._store.update_node_rx_counter(node_from)
            node_from.hopsaway = max(0, int(se.packet.hop_start) - int(se.packet.hop_limit))
            if node_from.hopsaway is not None and node_from.hopsaway == 0:
                self._store.add_neighbor(node_from.id, se.gateway_id)
            self.notify_nodes_update.emit(node_from)

    def enqueue_task(self, task, *args, **kwargs):
        self.task_queue.put((task, args, kwargs))

    def quit(self):
        self.task_queue.put((None, [], {}))

    def run(self):
        while True:
            task, args, kwargs = self.task_queue.get()
            if task is None:
                break
            task(*args, **kwargs)
            self.task_queue.task_done()
