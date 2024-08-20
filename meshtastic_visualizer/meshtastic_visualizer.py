#!/usr/bin/env python3


import hashlib
import io
import folium
import humanize
from threading import Lock
from datetime import datetime
from typing import List
from PyQt6 import QtWidgets, uic
from PyQt6.QtGui import QTextCursor
from PyQt6.QtWidgets import QTableWidgetItem
from PyQt6.QtWebEngineWidgets import QWebEngineView
from PyQt6.QtCore import pyqtSignal

from .meshtastic_manager import MeshtasticManager
from .resources import MessageLevel, \
    MeshtasticMessage, \
    TEXT_MESSAGE_MAX_CHARS


class MeshtasticQtApp(QtWidgets.QMainWindow):
    connect_device_signal = pyqtSignal(bool)
    disconnect_device_signal = pyqtSignal()
    scan_mesh_signal = pyqtSignal()
    send_message_signal = pyqtSignal(MeshtasticMessage)
    retrieve_channels_signal = pyqtSignal()
    traceroute_signal = pyqtSignal(str, int, int)

    def __init__(self):
        self._lock = Lock()
        super(MeshtasticQtApp, self).__init__()
        uic.loadUi('resources/app.ui', self)
        self.show()

        self._markers: list = []
        self._links: list = []
        self._map = None
        self._markers_group = folium.FeatureGroup(name="Stations")
        self._link_group = folium.FeatureGroup(name="Links")

        # Variables
        self.status_var: str = ""
        self.device_path: str = ""
        self.active_channel: str = ""
        self.destination_id: str = ""
        self._friends: dict = {}
        self._local_board_id: str = ""
        self._action_buttons = []
        # Set up the UI elements
        self.setup_ui()

        self._manager = MeshtasticManager(
            dev_path=None,  # set afterwards
        )
        self._manager.start()

        self._manager.notify_frontend_signal.connect(self.refresh)
        self._manager.notify_data_signal.connect(self.update_received_data)
        self._manager.notify_message_signal.connect(
            self.update_received_message)
        self._manager.notify_traceroute_signal.connect(self.update_traceroute)
        self._manager.notify_channels_signal.connect(
            self.update_channels_table)
        self._manager.notify_nodes_signal.connect(self.update_nodes_map)
        self._manager.notify_nodes_signal.connect(self.update_nodes_table)

        for i, device in enumerate(self._manager.get_meshtastic_devices()):
            self.device_combobox.insertItem(i, device)

        self.connect_device_signal.connect(self._manager.connect_device)
        self.disconnect_device_signal.connect(self._manager.disconnect_device)
        self.send_message_signal.connect(self._manager.send_text_message)
        self.retrieve_channels_signal.connect(self._manager.retrieve_channels)
        self.scan_mesh_signal.connect(self.update_nodes_map)
        self.scan_mesh_signal.connect(self.update_nodes_table)
        self.traceroute_signal.connect(self._manager.send_traceroute)
        self.export_chat_button.pressed.connect(self._manager.export_chat)
        self.export_radio_button.pressed.connect(self.export_radio)

    def connect_device_event(self, resetDB:bool):
        self.connect_device_signal.emit(resetDB)

    def disconnect_device_event(self):
        self.disconnect_device_signal.emit()

    def scan_mesh_event(self):
        self.scan_mesh_signal.emit()

    def retrieve_channels_event(self):
        self.retrieve_channels_signal.emit()

    def traceroute_event(self, dest_id: str, maxhops: int, channel_index: int):
        self.traceroute_signal.emit(dest_id, maxhops, channel_index)

    def send_message_event(self, message: MeshtasticMessage):
        self.send_message_signal.emit(message)

    def set_status(self, loglevel: MessageLevel, message: str) -> None:
        if loglevel.value == MessageLevel.ERROR.value:
            self.notification_label.setText(message)

        if loglevel.value == MessageLevel.INFO.value or loglevel.value == MessageLevel.UNKNOWN.value:
            self.notification_label.setText(message)

    def setup_ui(self) -> None:
        self.connect_button.clicked.connect(self.connect_device)
        self.disconnect_button.clicked.connect(self.disconnect_device)
        self.scan_button.clicked.connect(self.scan_mesh)
        self.send_button.clicked.connect(self.send_message)
        self.traceroute_button.clicked.connect(self.traceroute)
        self.message_textedit.textChanged.connect(self.update_text_message_length)
        self.remaining_chars_label.setText(f"{TEXT_MESSAGE_MAX_CHARS}/{TEXT_MESSAGE_MAX_CHARS}")
        self.init_map()

        self.messages_table.setColumnCount(
            len(self._get_meshtastic_message_fields()))
        self.messages_table.setHorizontalHeaderLabels(
            self._get_meshtastic_message_fields())
        self.traceroute_table.setColumnCount(1)
        self.traceroute_table.setHorizontalHeaderLabels(["Id"])
        self.batterylevel_progressbar.hide()
        self.connect_button.setEnabled(True)
        self.disconnect_button.setEnabled(False)
        self._action_buttons = [
            self.scan_button,
            self.traceroute_button,
            self.send_button,
            self.export_chat_button,
            self.export_radio_button,
        ]
        for button in self._action_buttons:
            button.setEnabled(False)

    def _get_meshtastic_message_fields(self) -> list:
        return [
            "date",
            "ack",
            "from_id",
            "to_id",
            "channel_index",
            "content",
            "rx_rssi",
            "rx_snr",
            "hop_start",
            "hop_limit",
            "want_ack"]

    def refresh(
            self,
            status: MessageLevel = MessageLevel.UNKNOWN,
            message=None) -> None:
        """
        Refresh all UI at once
        """
        self._lock.acquire()

        config = self._manager.get_config()
        data = self._manager.get_data()
        if message is not None:
            self.set_status(status, message)

        if data.get_is_connected():
            self.connect_button.setEnabled(False)
            self.disconnect_button.setEnabled(True)
            for button in self._action_buttons:
                button.setEnabled(True)
        else:
            self.connect_button.setEnabled(True)
            self.disconnect_button.setEnabled(False)
            for button in self._action_buttons:
                button.setEnabled(False)

        self.update_local_node_config()

        self._lock.release()

    def connect_device(self):
        device_path = self.device_combobox.currentText()
        if device_path:
            self.set_status(MessageLevel.INFO, f"Connecting to {device_path}.")
            self.connect_device_event(self.reset_nodedb_checkbox.isChecked())
        else:
            self.set_status(MessageLevel.ERROR,
                            f"Cannot connect. Please specify a device path.")

    def disconnect_device(self) -> None:
        for i, device in enumerate(self._manager.get_meshtastic_devices()):
            self.device_combobox.clear()
            self.device_combobox.insertItem(i, device)
        self.disconnect_device_event()

    def update_traceroute(self, route: list) -> None:
        self.traceroute_table.clear()
        self.traceroute_table.setRowCount(0)
        for hop in route:
            device = self._manager.get_long_name_from_id(hop)
            if hop == self._local_board_id:
                device = "Me"
            row_position = self.traceroute_table.rowCount()
            self.traceroute_table.insertRow(row_position)
            self.traceroute_table.setItem(
                row_position, 0, QTableWidgetItem(device))
            self.traceroute_table.resizeColumnsToContents()

    def update_text_message_length(self):
        current_text = self.message_textedit.toPlainText()

        if len(current_text) > TEXT_MESSAGE_MAX_CHARS:
            self.message_textedit.blockSignals(True) 
            self.message_textedit.setPlainText(current_text[:TEXT_MESSAGE_MAX_CHARS])
            cursor = self.message_textedit.textCursor()
            cursor.setPosition(TEXT_MESSAGE_MAX_CHARS)
            self.message_textedit.setTextCursor(cursor)
            self.message_textedit.blockSignals(False)

        remaining_chars = TEXT_MESSAGE_MAX_CHARS - len(self.message_textedit.toPlainText())
        self.remaining_chars_label.setText(f"{remaining_chars}/{TEXT_MESSAGE_MAX_CHARS}")


    def init_map(self):
        self._map = folium.Map(zoom_start=7)
        self.update_map_in_widget()

    def update_map_in_widget(self):
        data = io.BytesIO()
        self._map.save(data, close_file=False)
        data.seek(0)
        self.nodes_map.setHtml(data.getvalue().decode())

    def update_nodes_map(self):
        # we re-create from scratch every time
        # using this method we od have easy access to the Dom anyway
        def __link_color(node_id: str) -> str:
            hash_object = hashlib.md5(node_id.encode())
            color = '#' + hash_object.hexdigest()[:6]
            return color

        del self._map
        self._map = None
        self._map = folium.Map(zoom_start=7)

        # Add a new marker
        nodes = self._manager.get_nodes()
        if nodes is None:
            return

        self._markers = []
        self._links = []

        # in case of links traczing, pre-create a dict(node_id, [lat, lon])
        nodes_coords = {
            x["user"]["id"]: [
                float(
                    x["position"]["latitude"]), float(
                    x["position"]["longitude"])] for __, x in nodes.items() if "position" in x and "latitude" in x["position"] and "longitude" in x["position"]}

        for __, node in nodes.items():
            strl = []
            strl.append(f"<b>Name:</b> {node['user']['longName']}</br>")
            strl.append(f"<b>id:</b> {node['user']['id']}</br>")
            if 'hwModel' in node["user"]:
                strl.append(f"<b>Hardware:</b> {node['user']['hwModel']}</br>")

            if "deviceMetrics" in node:
                if 'batteryLevel' in node["deviceMetrics"]:
                    strl.append(    
                        f"<b>Battery Level:</b> {node['deviceMetrics']['batteryLevel']} %</br>")
                if 'airUtilTx' in node["deviceMetrics"]:
                    strl.append(f"<b>Air Util. Tx:</b> {round(node['deviceMetrics']['airUtilTx'], 2)} %</br>")
                if 'channelUtilization' in node["deviceMetrics"]:
                    strl.append(f"<b>Channel utilization:</b> {round(node['deviceMetrics']['channelUtilization'], 2)} %</br>")
                if 'uptimeSeconds'in node["deviceMetrics"]:
                    strl.append(
                        f"<b>Uptime:</b> {humanize.precisedelta(node['deviceMetrics']['uptimeSeconds'])}</br>")

            if 'rssi' in node:
                strl.append(f"<b>RSSI:</b> {node['rssi']} dBm</br>")
            if 'snr' in node:
                strl.append(f"<b>SNR:</b> {node['snr']}</br>")
            if 'lastHeard'in node and node["lastHeard"] is not None:
                strl.append(
                    f"<b>Last Heard:</b> {humanize.naturaldelta(datetime.fromtimestamp(node['lastHeard']))}</br>")

            if "position" in node is not None and "position" in node is not None and "latitude" in node["position"] and "longitude" in node["position"]:
                popup_content = "".join(strl)
                popup = folium.Popup(
                    popup_content, max_width=300, min_width=250)
                color = "blue"
                if node["user"]["id"] == self._local_board_id:
                    color = "orange"

                marker = folium.Marker(
                    location=[
                        node["position"]["latitude"],
                        node["position"]["longitude"],],
                    popup=popup,
                    icon=folium.Icon(color=color),
                )
                marker.add_to(self._markers_group)
                self._markers.append(marker)
            neighbors = self._manager.get_neighbors()
            if neighbors and node["user"]["id"] in neighbors.keys():
                for neighbor in neighbors[node["user"]["id"]]:
                    # we can trace a link
                    if neighbor in nodes_coords.keys():
                        link_coords = [
                            nodes_coords[node["user"]["id"]],
                            nodes_coords[neighbor],
                        ]
                        if link_coords[0][0] is not None \
                                and link_coords[0][1] is not None \
                                and link_coords[1][0] is not None\
                                and link_coords[1][1] is not None:
                            link = folium.PolyLine(
                                link_coords, color=__link_color(node["user"]["id"]))
                            link.add_to(self._link_group)
                            self._links.append(link)
        if self._markers:
            markers_lat = [x.location[0] for x in self._markers]
            markers_lon = [x.location[1] for x in self._markers]
            self._map.fit_bounds([[min(markers_lat), min(markers_lon)], [
                                 max(markers_lat), max(markers_lon)]])
            self._markers_group.add_to(self._map)
        if self._links:
            self._link_group.add_to(self._map)
            folium.LayerControl().add_to(self._map)

        self.update_map_in_widget()

    def send_message(self):

        message = self.message_textedit.toPlainText()
        channel_name = self.channel_combobox.currentText()
        recipient = self._manager.get_id_from_long_name(self.recipient_combobox.currentText())
        channel_index = self._manager.get_channel_index_from_name(channel_name)
        # Update timeout before sending
        if channel_index != -1 and message:
            m = MeshtasticMessage(
                mid=-1,
                date=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                from_id="Me",
                to_id=recipient,
                content=message,
                rx_rssi="",
                rx_snr="",
                hop_limit="",
                hop_start="",
                want_ack=True,
                channel_index=channel_index,
            )
            self.send_message_event(m)
            self.message_textedit.clear()

    def update_nodes_table(self) -> None:
        nodes = self._manager.get_nodes()
        if not nodes:
            return

        self.recipient_combobox.clear()
        self.tr_dest_combobox.clear()
        self.recipient_combobox.insertItem(0, "All")
        for i, node in enumerate(nodes.values()):
            if node["user"]["id"] == self._local_board_id:
                continue
            self.tr_dest_combobox.insertItem(i + 1, node["user"]["longName"])
            self.recipient_combobox.insertItem(i + 1, node["user"]["longName"])

        rows: list[dict[str, any]] = []
        for __, node in nodes.items():
            user = node["user"] if "user" in node else {}
            device_metrics = node["deviceMetrics"] if "deviceMetrics" in node else {}
            position = node["position"] if "position" in node else {}

            row = {"User": "", "ID": ""}

            row.update(
                {
                    "User": user.get("longName", ""),
                    "AKA": user.get("shortName", ""),
                    "ID": user.get("id", ""),
                    "Hardware": user.get("hwModel", ""),
                }
            )
            row.update(
                {
                    "Latitude": position.get("latitude", None),
                    "Longitude": position.get("longitude", None),
                }
            )

            row.update({"Battery": device_metrics.get("batteryLevel", "")})
            row.update(
                {
                    "Channel util. (%)": round(device_metrics["channelUtilization"],2) if "channelUtilization" in device_metrics else "" ,
                    "Tx air util. (%)": round(device_metrics["airUtilTx"],2) if "airUtilTx" in device_metrics else "" ,
                    "RSSI": node["rssi"] if "rssi" in node else "",
                }
            )

            row.update(
                {
                    "SNR": node.get("snr", ""),
                    "Hops Away": node.get("hopsaway", ""),
                    "Last Seen": humanize.naturaltime(datetime.fromtimestamp(node["lastHeard"])) if "lastHeard" in node and node["lastHeard"] is not None else "",
                    "Uptime": humanize.precisedelta(device_metrics["uptimeSeconds"]) if "uptimeSeconds" in device_metrics else "",
                }
            )

            rows.append(row)

        rows.sort(key=lambda r: r.get("LastHeard", "") or "0000", reverse=True)

        self.mesh_table.clear()
        self.mesh_table.setRowCount(0)
        columns = [
            "User",
            "ID",
            "AKA",
            "Hardware",
            "Latitude",
            "Longitude",
            "Battery",
            "Channel util. (%)",
            "Tx air util. (%)",
            "RSSI",
            "SNR",
            "Hops Away",
            "Last Seen",
            "Uptime"]
        self.mesh_table.setColumnCount(len(columns))
        self.mesh_table.setHorizontalHeaderLabels(columns)
        for row in rows:
            row_position = self.mesh_table.rowCount()
            self.mesh_table.insertRow(row_position)
            for i, elt in enumerate(columns):
                data = str(row[elt])
                if data == "None": data = "" 
                self.mesh_table.setItem(
                    row_position, i, QTableWidgetItem(data))
                self.mesh_table.resizeColumnsToContents()

    def scan_mesh(self):
        self.scan_mesh_event()

    def get_channel_names(self) -> List[str]:
        config = self._manager.get_config()
        channels = config.get_channels()
        if not channels:
            return []
        return [channel.name for channel in channels]

    def update_channels_table(self):
        config = self._manager.get_config()
        channels = config.get_channels()
        if not channels:
            return

        for cb in ["channel_combobox", "tr_channel_combobox"]:
            getattr(self, cb).clear()
            for i, channel in enumerate(channels):
                getattr(self, cb).insertItem(i, channel.name)

        rows: list[dict[str, any]] = []
        for channel in channels:
            row = {
                "Index": channel.index,
                "Name": channel.name,
                "Role": channel.role,
                "PSK": channel.psk}
            rows.append(row)

        self.channels_table.clear()
        self.channels_table.setRowCount(0)
        columns = ["Index", "Name", "Role", "PSK"]
        for i in range(self.channels_table.rowCount()):
            self.channels_table.removeRow(i)
        self.channels_table.setColumnCount(len(columns))
        self.channels_table.setHorizontalHeaderLabels(
            columns)

        for row in rows:
            row_position = self.channels_table.rowCount()
            self.channels_table.insertRow(row_position)
            for i, elt in enumerate(columns):
                self.channels_table.setItem(
                    row_position, i, QTableWidgetItem(str(row[elt])))
                self.channels_table.resizeColumnsToContents()

    def retrieve_channels(self):
        self.retrieve_channels_event()

    def update_local_node_config(self):
        self._local_board_id = self._manager._local_board_id
        if self._local_board_id:
            node = self._manager.get_node_from_id(self._local_board_id)
            if node is not None:
                self.devicename_label.setText(node["user"]["longName"])
                self.batterylevel_progressbar.setValue(node["deviceMetrics"]["batteryLevel"])
                self.batterylevel_progressbar.show()
                self.id_label.setText(str(node["user"]["id"]))
                # self.air_util_tx_label.setText(str(round(node["deviceMetrics"]["airUtilTx"], 2)))
                self.hardware_label.setText(str(node["user"]["hwModel"]))

    def traceroute(self):
        dest_id = self._manager.get_id_from_long_name(self.tr_dest_combobox.currentText())
        channel_name = self.tr_channel_combobox.currentText()
        maxhops = self.tr_maxhops_spinbox.value()
        channel_index = self._manager.get_channel_index_from_name(channel_name)

        self.traceroute_event(
            dest_id=dest_id,
            maxhops=maxhops,
            channel_index=channel_index,
        )

    def update_received_message(self) -> None:
        self.messages_table.clear()
        self.messages_table.setRowCount(0)
        columns = self._get_meshtastic_message_fields()
        self.messages_table.setColumnCount(len(columns))
        self.messages_table.setHorizontalHeaderLabels(columns)

        channels = self._manager._config.get_channels()
        messages = self._manager._data.get_messages().values()
        for message in messages:
            data = []
            for column in columns:
                if column == "from_id" or column == "to_id":
                    if getattr(message, column) == self._local_board_id:
                        data.append("Me")
                    elif getattr(message, column) in self._friends.keys():
                        data.append(self._friends[getattr(message, column)])
                    else:
                        data.append(getattr(message, column))
                elif column == "channel_index":
                    name = "DM"
                    for ch in channels:
                        if ch.index == message.channel_index:
                            name = ch.name
                    data.append(name)

                else:
                    data.append(getattr(message, column))

            row_position = self.messages_table.rowCount()
            self.messages_table.insertRow(row_position)
            for i, elt in enumerate(data):
                self.messages_table.setItem(
                    row_position, i, QTableWidgetItem(str(elt)))
                self.messages_table.resizeColumnsToContents()

    def update_received_data(self, message: str, message_type: str):
        self.output_textedit.setReadOnly(True)
        tmp = [
            self.output_textedit.toPlainText()
        ]
        if self.output_textedit.toPlainText() != "":
            tmp.append("\n")
        nnow = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        tmp.append(f"[{nnow}] {message}")
        self.output_textedit.setText("".join(tmp))
        cursor = QTextCursor(self.output_textedit.textCursor())
        cursor.setPosition(len(self.output_textedit.toPlainText()))
        self.output_textedit.setTextCursor(cursor)

    def export_radio(self) -> None:
        nnow = datetime.now().strftime("%Y-%m-%d__%H_%M_%S")
        fpath = f"radio_{nnow}.log"
        with open(fpath, "w") as text_file:
            text_file.write(self.output_textedit.toPlainText())
            trace = f"Exported radio to file: {fpath}"
            self.set_status(MessageLevel.INFO, trace)

    def quit(self) -> None:
        self._manager.quit()
        self.master.quit()

    def run(self):
        self._manager.start()
        self.master.mainloop()
