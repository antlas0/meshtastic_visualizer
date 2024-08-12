#!/usr/bin/env python3

import os
import time
import json
import time
import queue
import base64
import logging
import datetime
from pubsub import pub
from colorama import Fore, init
from dataclasses import fields
from typing import Union, Optional, Callable
import google.protobuf.json_format
from typing import List, Optional
import threading
import meshtastic
import meshtastic.serial_interface
from meshtastic import channel_pb2, portnums_pb2, mesh_pb2
from PyQt5.QtCore import pyqtSignal, QObject
from dataclasses import fields


from .devices import list_serial_ports
from .resources import run_in_thread, \
    MessageLevel, \
    MeshtasticConfigStore, \
    MeshtasticDataStore, \
    Channel, \
    MeshtasticNode, \
    MeshtasticMessage

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
        self._config.timeout = 15  # default
        self._config.retransmission_limit = 3  # default
        self._config.interface = None
        self._data.received_chunks = {}
        self._data.acknowledged_chunks = set()
        self._data.expected_chunks = {}
        self._config.tunnel = None  # Initialize the tunnel attribute
        # Create an empty object to hold acknowledgment flags
        self._data.acknowledgment = type('', (), {})()
        self._data.acknowledgment.receivedTraceRoute = False
        self.task_queue = queue.Queue()
        self.daemon = True

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

    def get_meshtastic_devices(self) -> List[str]:
        return list_serial_ports()

    def set_meshtastic_device(self, device: str) -> None:
        self._config.device_path = device

    def set_retransmission_limit(self, limit: int) -> None:
        self._config.retransmission_limit = limit

    def get_retransmission_limit(self) -> int:
        return self._config.retransmission_limit

    def get_channel_index_from_name(self, name: str) -> int:
        channels = self._config.get_channels()
        if channels is None:
            return -1
        channel = list(filter(lambda x: x.name == name, channels))
        if len(channel) != 1:
            return -1
        return channel[0].index

    def store_received_packet(self, packet: str) -> None:
        packets = self._data.get_received_packets()
        packets.append(packet)
        self._data.set_received_packets(packets)

    def store_or_update_node(self, node: MeshtasticNode) -> None:
        nodes = self._data.get_nodes()
        if not str(node.id) in nodes.keys():
            nodes[str(node.id)] = node
            if node.lastseen:
                node.firstseen = node.lastseen
            else:
                node.firstseen = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                node.firstseen = node.lastseen
        else:
            # update
            def __get_nodes_fields():
                return [field for field in fields(
                    MeshtasticNode) if not field.name.startswith('_')]

            tmp = nodes[str(node.id)].firstseen
            node.firstseen = tmp
            for f in __get_nodes_fields():
                if getattr(nodes[str(node.id)],
                           f.name) != getattr(node, f.name):
                    if getattr(node, f.name) is not None:
                        setattr(nodes[str(node.id)], f.name,
                                getattr(node, f.name))

    @run_in_thread
    def connect_device(self) -> bool:
        if self._config.interface is not None:
            return False
        try:
            self._config.interface = meshtastic.serial_interface.SerialInterface(
                devPath=self._config.device_path)
        except Exception as e:
            trace = f"Failed to connect to Meshtastic device {self._config.device_path}: {str(e)}"
            self._data.set_last_status(trace)
            self._data.set_is_connected(False)
            self.notify_frontend(MessageLevel.ERROR, trace)
            return False
        else:
            # Subscribe to received message events
            pub.subscribe(self.on_receive, "meshtastic.receive")
            trace = f"Successfully connected to Meshtastic device {self._config.device_path}"
            self._data.set_last_status(trace)
            self._data.set_is_connected(True)
            self.notify_frontend(MessageLevel.INFO, trace)
            self.retrieve_channels()
            self.retrieve_nodes()
            self.retrieve_local_node_configuration()
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
            self._data.set_last_status(trace)
            self.notify_frontend(MessageLevel.ERROR, trace)
            return False
        else:
            trace = f"Meshtastic device disconnected."
            self._data.set_last_status(trace)
            self._data.set_is_connected(False)
            self.notify_frontend(MessageLevel.INFO, trace)
            return True

    def set_destination_id(self, destination_id) -> None:
        self._config.destination_id = destination_id

    def get_destination_id(self) -> str:
        return self._config.destination_id

    @run_in_thread
    def retrieve_local_node_configuration(self) -> None:
        if self._config.interface is None:
            return

        node = self._config.interface.getMyNodeInfo()
        batlevel = node["deviceMetrics"]["batteryLevel"] if "deviceMetrics" in node else 0
        if batlevel > 100:
            batlevel = 100

        self._config.local_node_config = MeshtasticNode(
            long_name=node["user"]["longName"],
            short_name=node["user"]["shortName"],
            hardware=node["user"]["hwModel"],
            role=node["user"]["role"] if "role" in node["user"] else None,
            lat=str(node["position"]["latitude"]) if "position" in node and "latitude" in node["position"] else None,
            lon=str(node["position"]["longitude"] if "position" in node and "longitude" in node["position"] else None),
            lastseen=datetime.datetime.fromtimestamp(node["lastHeard"]).strftime('%Y-%m-%d %H:%M:%S') if "lastHeard" in node and node["lastHeard"] is not None else None,
            id=node["user"]["id"],
            batterylevel=batlevel,
            hopsaway=str(node["hopsAway"]) if "hopsAway" in node else None,
            snr=str(round(node["snr"], 2)) if "snr" in node else None,
            txairutil=str(round(node["deviceMetrics"]["airUtilTx"], 2)) if "deviceMetrics" in node and "airUtilTx" in node["deviceMetrics"] else None,
            chutil=str(round(node["deviceMetrics"]["channelUtilization"], 2)) if "deviceMetrics" in node and "channelUtilization" in node["deviceMetrics"] else None,
            uptime=node["deviceMetrics"]["uptimeSeconds"] if "deviceMetrics" in node and "uptimeSeconds" in node["deviceMetrics"] else None,
        )
        self.notify_frontend(
            MessageLevel.INFO,
            "Local node configuration retrieved.")

    @run_in_thread
    def on_ack(self, response, event):
        print(Fore.GREEN + "Acknowledgment received!")
        event.set()  # Signal that acknowledgment has been received
        self.store_received_packet("Acknowledgment received!")
        self.notify_data("Acknowledgment received!", "INFO")
        messages_list = self._data.get_messages()
        key = list(
            filter(
                lambda x: messages_list[x].mid == response["decoded"]["requestId"],
                messages_list.keys()))
        if len(key) == 0:
            return
        key = key[0]

        messages_list[key].date = datetime.datetime.now().strftime(
            "%Y-%m-%d %H:%M:%S")
        if "rxRssi" in response:
            messages_list[key].rx_rssi = response['rxRssi']
        if "rxSnr" in response:
            messages_list[key].rx_snr = response['rxSnr']
        if "rxhopLimit" in response:
            messages_list[key].hop_limit = response['hopLimit']
        if "hopStart" in response:
            messages_list[key].hop_start = response['hopStart']
        if "wantAck" in response:
            messages_list[key].want_ack = response['wantAck']
        messages_list[key].ack = "✅"
        self.notify_message()

    @run_in_thread
    def on_receive(self, packet, interface):
        self.notify_data("---------------", message_type="INFO")
        if 'fromId' in packet:
            message = f"From ID: {packet['fromId']}"
            print(Fore.LIGHTBLACK_EX + message)
            self.notify_data(message, message_type="INFO")
            self.store_received_packet(message)
        if 'toId' in packet:
            message = f"To ID: {packet['toId']}"
            print(Fore.LIGHTBLACK_EX + message)
            self.notify_data(message, message_type="INFO")
            self.store_received_packet(message)
        if 'id' in packet:
            message = f"Packet ID: {packet['id']}"
            print(Fore.LIGHTBLACK_EX + message)
            self.notify_data(message, message_type="INFO")
            self.store_received_packet(message)
        if "decoded" in packet and "portnum" in packet["decoded"]:
            message = f"Packet type: {packet['decoded']['portnum'].lower()}"
            print(Fore.LIGHTBLACK_EX + message)
            self.notify_data(message, message_type="INFO")
            self.store_received_packet(message)
        if 'rxSnr' in packet:
            message = f"Signal-to-Noise Ratio (SNR): {packet['rxSnr']}"
            print(Fore.LIGHTBLACK_EX + message)
            self.notify_data(message, message_type="SNR")
            self.store_received_packet(message)
        if 'rxRssi' in packet:
            message = f"Received Signal Strength Indicator (RSSI): {packet['rxRssi']}"
            print(Fore.BLUE + message)
            self.notify_data(message, message_type="RSSI")
            self.store_received_packet(message)
        if 'hopLimit' in packet:
            message = f"Hop Limit: {packet['hopLimit']}"
            print(Fore.LIGHTBLACK_EX + message)
            self.notify_data(message, message_type="INFO")
            self.store_received_packet(message)
        if 'encrypted' in packet:
            message = f"Encrypted: {packet['encrypted']}"
            print(Fore.LIGHTBLACK_EX + message)
            self.notify_data(message, message_type="INFO")
            self.store_received_packet(message)

        self.update_node_info(packet)

        if 'decoded' in packet:
            decoded = packet['decoded']
            if 'payload' in decoded and isinstance(
                    decoded['payload'],
                    bytes) and decoded["portnum"] == "TEXT_MESSAGE_APP":
                try:
                    data = decoded['payload']
                    # Use 'fromId' if available, otherwise fallback to
                    # 'from'
                    sender_id = packet.get('fromId', packet['from'])
                    if data.startswith(ANNOUNCE_IDENTIFIER):
                        # Handle file announcement
                        file_info = json.loads(
                            data[len(ANNOUNCE_IDENTIFIER):].decode('utf-8'))
                        file_name = file_info['name']
                        file_size = file_info['size']
                        total_chunks = file_info['total_chunks']
                        self._data.expected_chunks[file_name] = total_chunks
                        self._data.received_chunks[file_name] = [
                            None] * total_chunks
                        message = f"File announcement received: {file_name}, Size: {file_size} bytes, Total Chunks: {total_chunks}"
                        print(Fore.BLUE + message)
                        self.notify_data(
                            message=message, message_type="INFO")
                    elif data.startswith(FILE_IDENTIFIER):
                        # Extract file name and file data
                        parts = data[len(FILE_IDENTIFIER):].split(b':', 3)
                        if len(parts) == 4:
                            file_name = parts[0].decode('utf-8')
                            chunk_index = int(parts[1])
                            total_chunks = int(parts[2])
                            chunk_data = parts[3]

                            if file_name not in self._data.received_chunks:
                                self._data.received_chunks[file_name] = [
                                    None] * total_chunks

                            if self._data.received_chunks[file_name][chunk_index] is None:
                                self._data.received_chunks[file_name][chunk_index] = chunk_data
                                self.acknowledge_chunk(
                                    file_name, chunk_index, sender_id)  # Pass sender ID

                                if all(
                                        self._data.received_chunks[file_name]):
                                    complete_data = b''.join(
                                        self._data.received_chunks[file_name])
                                    self.save_file(
                                        file_name, complete_data)
                    else:
                        current_message = data.decode('utf-8').strip()
                        if len(current_message) > 0:
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
                                    from_id=packet['fromId'] if "fromId" in packet else None,
                                    to_id=packet['toId'] if "toId" in packet else None,
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
                                    MessageLevel.INFO, f"New message received from {packet['fromId']}")
                                self.notify_message()
                            else:
                                key = key[0]
                                messages_list[key].date = datetime.datetime.now().strftime(
                                    "%Y-%m-%d %H:%M:%S")
                                messages_list[key].rx_rssi = packet['rxRssi']
                                messages_list[key].rx_snr = packet['rxSnr']
                                messages_list[key].from_id = packet['fromId']
                                messages_list[key].to_id = packet['toId']
                                messages_list[key].hop_limit = packet['hopLimit']
                                messages_list[key].hop_start = packet['hopStart']
                                messages_list[key].want_ack = packet['wantAck']
                                messages_list[key].ack = ""
                                self.notify_frontend(
                                    MessageLevel.INFO, f"Updating message info from {packet['fromId']}")
                                self.notify_message()

                except UnicodeDecodeError:
                    print(
                        Fore.LIGHTBLACK_EX +
                        f"Received non-text payload: {decoded['payload']}")
                    self.notify_data(
                        f"Received non-text payload: {decoded['payload']}",
                        message_type="INFO")
                    self.store_received_packet(
                        f"Received non-text payload: {decoded['payload']}")

            else:
                print(Fore.LIGHTBLACK_EX +
                      f"Received packet without text payload: {decoded}")
                self.notify_data(
                    f"Received packet without text payload: {decoded}",
                    message_type="INFO")
                self.store_received_packet(
                    f"Received packet without text payload: {decoded}")

        else:
            print(
                Fore.LIGHTBLACK_EX +
                f"Received packet without 'decoded' field: {packet}")
            self.notify_data(
                f"Received packet without 'decoded' field: {packet}",
                message_type="INFO")
            self.store_received_packet(
                f"Received packet without 'decoded' field: {packet}")

        # Print additional details if available

    @run_in_thread
    def acknowledge_chunk(self, file_name, chunk_index, sender_id):
        """Send an acknowledgment for a received chunk to the sender."""
        ack_message = f"ACK:{file_name}:{chunk_index}"
        self._config.interface.sendText(ack_message, sender_id)
        print(
            Fore.GREEN +
            f"Acknowledgment sent for chunk {chunk_index} of {file_name} to {sender_id}")

    @run_in_thread
    def request_missing_chunks(self, file_name):
        """Request missing chunks from the sender"""
        missing_chunks = [i for i, chunk in enumerate(
            self._data.received_chunks[file_name]) if chunk is None]
        if missing_chunks:
            request_message = f"REQ:{file_name}:{','.join(map(str, missing_chunks))}"
            self._config.interface.sendText(
                request_message, self._config.destination_id)
            print(
                Fore.MAGENTA +
                f"Requesting missing chunks for {file_name}: {missing_chunks}")

    @run_in_thread
    def save_file(self, file_name, file_data):
        try:
            file_path = os.path.join('received_files', file_name)
            os.makedirs(os.path.dirname(file_path), exist_ok=True)
            with open(file_path, 'wb') as file:
                file.write(file_data)
            print(Fore.GREEN + f"File saved: {file_path}")
        except Exception as e:
            print(Fore.RED + f"Failed to save file: {str(e)}")

    @run_in_thread
    def send_text_message(self, message: MeshtasticMessage):
        if self._config.interface is None:
            return

        ack_event = threading.Event()  # Create an event object to wait for acknowledgment

        def callback(response):
            self.on_ack(response, ack_event)

        message.ack = "❌"
        if message.want_ack:
            print(Fore.LIGHTBLACK_EX + "Sending message, waiting ACK...")
        sent_packet = self._config.interface.sendText(
            text=message.content,
            destinationId=message.to_id,
            wantAck=message.want_ack,
            wantResponse=True,
            onResponse=callback,
            channelIndex=message.channel_index,
        )
        trace = f"Message sent with ID: {sent_packet.id}"
        message.mid = sent_packet.id
        self._data.get_messages()[str(message.mid)] = message
        self.notify_frontend(MessageLevel.INFO, trace)
        self.notify_message()
        # Wait for acknowledgment or timeout after the set period
        ack_event.wait(timeout=self._config.get_timeout())
        if not ack_event.is_set():
            trace = "Acknowledgment not received within timeout period."
            self._data.set_last_status(trace)
            self.notify_frontend(MessageLevel.ERROR, trace)

    def announce_file(self, file_name, file_size, total_chunks):
        """Announce the file details before sending chunks"""
        file_info = {
            "name": file_name,
            "size": file_size,
            "total_chunks": total_chunks
        }
        message = ANNOUNCE_IDENTIFIER + json.dumps(file_info).encode('utf-8')
        self.send_data(message, 0)

    @run_in_thread
    def send_data_in_chunks(self,
                            data,
                            file_name,
                            progress_callback: Optional[Callable[[int,
                                                                  int],
                                                                 None]] = None,
                            channel_index=0):
        if self._config.interface is None:
            return

        def callback(response, event):
            self.on_ack(response, event)

        total_chunks = (len(data) + CHUNK_SIZE - 1) // CHUNK_SIZE
        self.announce_file(file_name, len(data), total_chunks)

        for i in range(total_chunks):
            start = i * CHUNK_SIZE
            end = start + CHUNK_SIZE
            chunk = data[start:end]
            chunk_identifier = FILE_IDENTIFIER + \
                f'{file_name}:{i}:{total_chunks}'.encode('utf-8') + b':'
            chunk_data = chunk_identifier + chunk

            retries = 0
            while retries < self._config.get_retransmission_limit():
                ack_event = threading.Event()  # Create an event object to wait for acknowledgment

                print(
                    Fore.LIGHTBLACK_EX +
                    f"Sending chunk {i+1}/{total_chunks}, attempt {retries + 1}...")
                sent_packet = self._config.interface.sendData(
                    data=chunk_data,
                    destinationId=self._config.get_destination_id(),
                    wantAck=True,
                    wantResponse=True,
                    onResponse=lambda response: callback(response, ack_event),
                    channelIndex=channel_index
                )
                print(
                    Fore.LIGHTBLACK_EX +
                    f"Chunk {i+1}/{total_chunks} sent with ID: {sent_packet.id}")
                # Wait for acknowledgment or timeout after the set period
                ack_event.wait(timeout=self._config.get_timeout())

                if ack_event.is_set():
                    self._data.acknowledged_chunks.add((file_name, i))
                    if progress_callback:
                        progress_callback(i + 1, total_chunks)
                    break
                else:
                    print(
                        Fore.MAGENTA +
                        f"Acknowledgment not received for chunk {i+1}/{total_chunks} within timeout period.")
                    retries += 1
                    time.sleep(2)  # Add a small delay before retrying

            if retries == self._config.get_retransmission_limit():
                print(
                    Fore.RED +
                    f"Failed to send chunk {i+1}/{total_chunks} after {self._config.retransmission_limit} attempts. Aborting.")
                return  # Abort if the maximum number of retransmissions is reached

    # @run_in_thread
    def send_data(self, data, channel_index):
        if self._config.interface is None:
            return

        ack_event = threading.Event()  # Create an event object to wait for acknowledgment

        def callback(response):
            self.on_ack(response, ack_event)

        try:
            print(Fore.LIGHTBLACK_EX + "Attempting to send data...")
            sent_packet = self._config.interface.sendData(
                data=data,
                destinationId=self._config.get_destination_id(),
                wantAck=True,
                wantResponse=True,
                onResponse=callback,
                channelIndex=channel_index
            )
            print(Fore.LIGHTBLACK_EX + f"Data sent with ID: {sent_packet.id}")
            # Wait for acknowledgment or timeout after the set period
            ack_event.wait(timeout=self._config.get_timeout())
            if not ack_event.is_set():
                print(
                    Fore.MAGENTA +
                    "Acknowledgment not received within timeout period.")
        except Exception as e:
            print(Fore.RED + f"Failed to send data: {str(e)}")

    @run_in_thread
    def update_node_info(self, packet) -> None:

        n = MeshtasticNode(
            id=self._nodeNumToId(
                packet["from"])
        )

        if packet["decoded"]["portnum"] == "POSITION_APP":
            n.lat = packet["decoded"]["position"]["latitude"] if "latitude" in packet["decoded"]["position"] else None
            n.lon = packet["decoded"]["position"]["longitude"] if "longitude" in packet["decoded"]["position"] else None
            n.alt = packet["decoded"]["position"]["altitude"] if "altitude" in packet["decoded"]["position"] else None

        if packet["decoded"]["portnum"] == "TELEMETRY_APP":
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

        if packet["decoded"]["portnum"] == "NEIGHBORINFO_APP":
            if "neighbors" in packet["decoded"]["neighborinfo"]:
                n.neighbors = [
                    self._nodeNumToId(
                        x["nodeId"]) for x in packet["decoded"]["neighborinfo"]["neighbors"]]

        n.rssi = str(
            round(
                packet["rxRssi"],
                2)) if "rxRssi" in packet else None
        n.snr = str(
            round(
                packet["rxSnr"],
                2)) if "rxSnr" in packet else None

        n.lastseen = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')

        self.store_or_update_node(n)
        self.notify_frontend(MessageLevel.INFO, f"Updated node {n.id}.")

    @run_in_thread
    def retrieve_nodes(self, include_self: bool = True) -> list:
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
            self._data.set_last_status(trace)
            self.notify_frontend(MessageLevel.ERROR, trace)
            self.notify_channels()
        else:
            self._data.set_last_status(f"Channels retrieved.")
            self.notify_frontend(MessageLevel.INFO, "Channels retrieved.")
            self.notify_channels()

    def set_psk(self, index, psk):
        """Set the PSK for a given channel index."""
        if self._config.interface is None:
            return

        try:
            if index < len(self._config.interface.localNode.channels):
                self._config.interface.localNode.channels[index].settings.psk = psk
                self._config.interface.localNode.writeChannel(index)
                trace = f"PSK for channel {index} set successfully."
                self._data.set_last_status(trace)
                self.notify_frontend(MessageLevel.INFO, trace)
            else:
                trace = f"Invalid channel index: {index}"
                self._data.set_last_status(trace)
                self.notify_frontend(MessageLevel.ERROR, trace)
        except Exception as e:
            trace = f"Failed to set PSK: {str(e)}"
            self._data.set_last_status(trace)
            self.notify_frontend(MessageLevel.ERROR, trace)

    def add_channel(self, name):
        if self._config.interface is None:
            return

        disabled_channel = self._config.interface.localNode.getDisabledChannel()
        if not disabled_channel:
            trace = "No available disabled channel to add a new one."
            self._data.set_last_status(trace)
            self.notify_frontend(MessageLevel.ERROR, trace)
        try:
            disabled_channel.role = channel_pb2.Channel.Role.SECONDARY
            disabled_channel.settings.name = name
            # Using the same PSK as primary for simplicity
            disabled_channel.settings.psk = self._config.interface.localNode.channels[
                0].settings.psk
            self._config.interface.localNode.writeChannel(
                disabled_channel.index)
        except Exception as e:
            trace = f"Failed to add channel: {str(e)}"
            self._data.set_last_status(trace)
            self.notify_frontend(MessageLevel.ERROR, trace)
        else:
            trace = f"Successfully added channel: {name}."
            self._data.set_last_status(trace)
            self.notify_frontend(MessageLevel.INFO, trace)

    def get_device_ip(self):
        """Get the device IP address"""
        if not self._config.interface:
            return None
        node_num = self._config.interface.myInfo.my_node_num
        ip_address = f"10.115.{(node_num >> 8) & 0xff}.{node_num & 0xff}"
        return ip_address

    @run_in_thread
    def sendTraceRoute(self,
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
            onResponse=self.onResponseTraceRoute,
            channelIndex=channelIndex,
        )
        # extend timeout based on number of nodes, limit by configured hopLimit
        waitFactor = min(len(self._config.interface.nodes) -
                         1 if self._config.interface.nodes else 0, hopLimit)
        self.notify_frontend(
            MessageLevel.INFO,
            f"Traceoute started to {dest}.")
        self.waitForTraceRoute(waitFactor)

    def onResponseTraceRoute(self, p: dict):
        """on response for trace route"""
        self.notify_frontend(MessageLevel.INFO, f"Traceoute completed.")
        routeDiscovery = mesh_pb2.RouteDiscovery()
        routeDiscovery.ParseFromString(p["decoded"]["payload"])
        asDict = google.protobuf.json_format.MessageToDict(routeDiscovery)

        route: list = [self._nodeNumToId(p["to"])]
        if "route" in asDict:
            for nodeNum in asDict["route"]:
                route.append(self._nodeNumToId(nodeNum))
        route.append(self._nodeNumToId(p["from"]))
        self._data.acknowledgment.receivedTraceRoute = True
        self.notify_traceroute(route)

    def waitForTraceRoute(self, waitFactor):
        """Wait for trace route response"""
        timeout = self._config.get_timeout() + waitFactor * 5
        start_time = time.time()
        while time.time() - start_time < timeout:
            if self._data.acknowledgment.receivedTraceRoute:
                return True
            time.sleep(0.5)
        print(
            Fore.MAGENTA +
            "Trace route response not received within timeout period.")
        self.notify_frontend(MessageLevel.ERROR, f"Traceoute not completed.")
        return False

    def _nodeNumToId(self, nodeNum):
        """Convert node number to node ID"""
        if self._config.interface is None:
            return ""

        for node in self._config.interface.nodesByNum.values():
            if node["num"] == nodeNum:
                return node["user"]["id"]
        return f"!{nodeNum:08x}"

    def set_timeout(self, timeout) -> None:
        self._config.timeout = int(timeout)

    def get_timeout(self) -> int:
        return self._config.timeout

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
