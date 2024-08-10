#!/usr/bin/env python3


import json
import os
import io
import folium
from threading import Lock
from datetime import datetime
from typing import List
from PyQt5 import QtWidgets, uic
from PyQt5.QtWidgets import QTableWidgetItem
from PyQt5.QtWebEngineWidgets import QWebEngineView
from PyQt5.QtCore import pyqtSignal

from .meshtastic_manager import MeshtasticManager
from .resources import MessageLevel, \
    MeshtasticMessage


class MeshtasticQtApp(QtWidgets.QMainWindow):
    connect_device_signal = pyqtSignal()
    disconnect_device_signal = pyqtSignal()
    scan_mesh_signal = pyqtSignal()
    send_message_signal = pyqtSignal(MeshtasticMessage)
    retrieve_channels_signal = pyqtSignal()
    retrieve_local_node_config_signal = pyqtSignal()
    traceroute_signal = pyqtSignal(str, int, int)

    def __init__(self):
        self._lock = Lock()
        super(MeshtasticQtApp, self).__init__()
        uic.loadUi('resources/app.ui', self)
        self.show()

        self._markers: list = []
        self._map = None

        # Variables
        self.status_var: str = ""
        self.device_path: str = ""
        self.active_channel: str = ""
        self.destination_id: str = ""
        self._friends: list = []
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
        self.scan_mesh_signal.connect(self._manager.retrieve_nodes)
        self.retrieve_local_node_config_signal.connect(
            self._manager.retrieve_local_node_configuration)
        self.traceroute_signal.connect(self._manager.sendTraceRoute)
        # Load friends/addresses from JSON file
        self.load_friends()

    def connect_device_event(self):
        self.connect_device_signal.emit()

    def disconnect_device_event(self):
        self.disconnect_device_signal.emit()

    def scan_mesh_event(self):
        self.scan_mesh_signal.emit()

    def retrieve_channels_event(self):
        self.retrieve_channels_signal.emit()

    def traceroute_event(self, dest_id: str, maxhops: int, channel_index: int):
        self.traceroute_signal.emit(dest_id, maxhops, channel_index)

    def retrieve_local_node_config_event(self):
        self.retrieve_local_node_config_signal.emit()

    def send_message_event(self, message: MeshtasticMessage):
        self.send_message_signal.emit(message)

    def update_status(
            self,
            status: MessageLevel = MessageLevel.UNKNOWN) -> None:
        data = self._manager.get_data()
        last_status = data.get_last_status()
        self.set_status(status, last_status)

    def set_status(self, loglevel: MessageLevel, message: str) -> None:
        if loglevel.value == MessageLevel.ERROR.value:
            self.notification_label.setText(message)

        if loglevel.value == MessageLevel.INFO.value or loglevel.value == MessageLevel.UNKNOWN.value:
            self.notification_label.setText(message)

    def setup_ui(self) -> None:
        self.refresh_button.clicked.connect(self.refresh)
        self.connect_button.clicked.connect(self.connect_device)
        self.disconnect_button.clicked.connect(self.disconnect_device)
        self.scan_button.clicked.connect(self.scan_mesh)
        self.send_button.clicked.connect(self.send_message)
        self.traceroute_button.clicked.connect(self.traceroute)
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
        ]
        for button in self._action_buttons:
            button.setEnabled(False)

    def _get_meshtastic_message_fields(self) -> list:
        return [
            "date",
            "ack",
            "from_id",
            "to_id",
            "content",
            "rx_rssi",
            "rx_snr",
            "channel_index",
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

        mapping = {
            "timeout_linedit": config.get_timeout,
            "retransmission_linedit": config.get_retransmission_limit,
        }

        for label, value in mapping.items():
            getattr(self, label).setText(str(value()))

        self.update_local_node_config()

        self._lock.release()

    def connect_device(self):
        device_path = self.device_combobox.currentText()
        if device_path:
            self.set_status(MessageLevel.INFO, f"Connecting to {device_path}.")
            self._manager.set_meshtastic_device(device_path)
            self.connect_device_event()
        else:
            self.set_status(MessageLevel.ERROR,
                            f"Cannot connect. Please specify a device path.")

    def disconnect_device(self):
        self.disconnect_device_event()

    def update_traceroute(self, route: list) -> None:
        for hop in route:
            device = hop
            if hop == self._local_board_id:
                device = "Me"
            elif hop in self._friends:
                device = self._friends[hop]

            self.traceroute_table.insertRow(self.traceroute_table.rowCount())
            self.traceroute_table.setItem(
                self.traceroute_table.rowCount() - 1, 0, QTableWidgetItem(device))
            self.traceroute_table.resizeColumnsToContents()

    def init_map(self):
        self._map = folium.Map(zoom_start=7)
        self.update_map()

    def update_map(self):
        data = io.BytesIO()
        self._map.save(data, close_file=False)
        data.seek(0)
        self.nodes_map.setHtml(data.getvalue().decode())

    def update_nodes_map(self):
        # Add a new marker
        nodes = self._manager._data.get_nodes()
        if nodes is None:
            return

        self._markers = []
        for node_id, node in nodes.items():
            strl = []
            strl.append(f"<b>Name:</b> {node.long_name}</br>")
            strl.append(f"<b>id:</b> {node.id}</br>")
            strl.append(f"<b>Hardware:</b> {node.hardware}</br>")
            strl.append(f"<b>Battery Level:</b> {node.batterylevel} %</br>")
            strl.append(f"<b>Role:</b> {node.role}</br>")
            strl.append(f"<b>Hops Away:</b> {node.hopsaway}</br>")
            strl.append(f"<b>Air Util. Tx:</b> {node.txairutil} %</br>")
            if node.lat is not None and node.lon is not None:
                popup_content = "".join(strl)
                popup = folium.Popup(
                    popup_content, max_width=300, min_width=250)
                marker = folium.Marker(
                    location=[
                        node.lat,
                        node.lon],
                    popup=popup,
                )
                marker.add_to(self._map)
                self._markers.append(marker)
        if self._markers:
            markers_lat = [x.location[0] for x in self._markers]
            markers_lon = [x.location[1] for x in self._markers]
            self._map.fit_bounds([[min(markers_lat), min(markers_lon)], [
                                 max(markers_lat), max(markers_lon)]])

        self.update_map()

    # def on_friend_select(self, event):
    #     if not self.friends_listbox.curselection():
    #         return
    #     selected_friend = self.friends_listbox.get(self.friends_listbox.curselection())
    #     self.destination_id.set(selected_friend)
    #     if self._manager:
    #         self._manager.set_destination_id(selected_friend)
    #     self.set_status(MessageLevel.INFO, f"Destination ID set to {selected_friend}")

    # def add_friend(self):
    #     new_friend = simpledialog.askstring("Add Friend", "Enter friend address:")
    #     if new_friend:
    #         self._friends.append(new_friend)
    #         self.update_friends_list()
    #         self.save_friends()

    # def remove_friend(self):
    #     selected_friend = self.friends_listbox.curselection()
    #     if selected_friend:
    #         self._friends.pop(selected_friend[0])
    #         self.update_friends_list()
    #         self.save_friends()

    def update_friends_list(self):
        self.friends_list.clear()
        for id, friend in self._friends.items():
            self.friends_list.addItem(f"{id}: {friend}")

    def save_friends(self):
        with open("friends.json", "w") as file:
            json.dump(self._friends, file)

    def load_friends(self):
        if os.path.exists("friends.json"):
            with open("friends.json", "r") as file:
                self._friends = json.load(file)
            self.update_friends_list()

    def send_message(self):
        message = self.message_textedit.toPlainText()
        channel_name = self.channel_combobox.currentText()
        recipient = self.recipient_combobox.currentText()
        channel_index = self._manager.get_channel_index_from_name(channel_name)
        # Update timeout before sending
        self._manager.set_timeout(self.timeout_linedit.text())
        self._manager.set_retransmission_limit(
            self.retransmission_linedit.text())  # Update timeout before sending
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

    # def send_file(self):

    #     file_path = filedialog.askopenfilename()
    #     if file_path:
    #         try:
    #             channel_index = int(self.file_channel_entry.get())
    #         except ValueError:
    #             self.set_status(MessageLevel.ERROR, "Invalid channel index")
    #             return
    #         threading.Thread(target=self.send_file_in_chunks, args=(file_path, channel_index)).start()

    # def send_file_in_chunks(self, file_path, channel_index):
    # self._manager.set_timeout(self.timeout.get())  # Update timeout before
    # sending

    #     def progress_callback(current_chunk, total_chunks):
    #         self.progress_bar['maximum'] = total_chunks
    #         self.progress_bar['value'] = current_chunk
    #         self.master.update_idletasks()

    #     try:
    #         with open(file_path, 'rb') as file:
    #             file_data = file.read()
    #             file_name = os.path.basename(file_path)
    #             self._manager.send_data_in_chunks(file_data, file_name, progress_callback, channel_index)
    #             self.update_history(f"Me: Sent file {file_name}")

    #     except Exception as e:
    #         self.set_status(MessageLevel.ERROR, f"Failed to send file: {str(e)}")

    def update_nodes_table(self) -> None:
        nodes = self._manager.get_data().get_nodes()
        if nodes is None:
            return

        self.recipient_combobox.clear()
        self.tr_dest_combobox.clear()
        self.recipient_combobox.insertItem(0, "^all")
        for i, node in enumerate(nodes.values()):
            if node.id == self._local_board_id:
                continue
            self.tr_dest_combobox.insertItem(i + 1, node.id)
            self.recipient_combobox.insertItem(i + 1, node.id)

        rows: list[dict[str, any]] = []
        for node_id, node in nodes.items():
            row = {"User": "", "ID": ""}

            row.update(
                {
                    "User": node.long_name,
                    "AKA": node.short_name,
                    "ID": node.id,
                    "Role": node.role,
                    "Hardware": node.hardware,
                }
            )
            row.update(
                {
                    "Latitude": node.lat,
                    "Longitude": node.lon,
                    "Altitude": node.alt,
                }
            )

            row.update({"Battery": node.batterylevel})
            row.update(
                {
                    "Channel util.": node.chutil,
                    "Tx air util.": node.txairutil,
                }
            )

            row.update(
                {
                    "SNR": node.snr,
                    "Hops Away": node.hopsaway,
                    "LastHeard": node.lastseen,
                    "Since": node.firstseen,
                    "Uptime": node.uptime,
                }
            )

            rows.append(row)

        rows.sort(key=lambda r: r.get("LastHeard") or "0000", reverse=True)

        self.mesh_table.clear()
        self.mesh_table.setRowCount(0)
        columns = self._get_meshtastic_message_fields()
        columns = [
            "User",
            "ID",
            "AKA",
            "Role",
            "Hardware",
            "Latitude",
            "Longitude",
            "Battery",
            "Channel util.",
            "Tx air util.",
            "SNR",
            "Hops Away",
            "LastHeard",
            "Since",
            "Uptime"]
        self.mesh_table.setColumnCount(len(columns))
        self.mesh_table.setHorizontalHeaderLabels(columns)
        for row in rows:
            row_position = self.mesh_table.rowCount()
            self.mesh_table.insertRow(row_position)
            for i, elt in enumerate(columns):
                self.mesh_table.setItem(
                    row_position, i, QTableWidgetItem(str(row[elt])))
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
        for i in range(self.channels_table.rowCount()):
            self.channels_table.removeRow(i)
        self.channels_table.setColumnCount(4)
        self.channels_table.setHorizontalHeaderLabels(
            ["Index", "Name", "Role", "PSK"])

        for row in rows:
            self.channels_table.insertRow(self.channels_table.rowCount())
            for i, elt in enumerate(row.values()):
                self.channels_table.setItem(
                    self.channels_table.rowCount() - 1,
                    i,
                    QTableWidgetItem(
                        str(elt)))
                self.channels_table.resizeColumnsToContents()

    def retrieve_channels(self):
        self.retrieve_channels_event()

    def update_local_node_config(self):
        cfg = self._manager.get_config().local_node_config
        if cfg is None:
            return

        self._local_board_id = cfg.id
        self.devicename_label.setText(cfg.long_name)
        self.batterylevel_progressbar.setValue(cfg.batterylevel)
        self.batterylevel_progressbar.show()
        self.role_label.setText(f"{cfg.role}")
        self.txairutil_label.setText(str(cfg.txairutil))
        self.chutil_label.setText(str(cfg.chutil))
        self.id_label.setText(str(cfg.id))
        self.hardware_label.setText(str(cfg.hardware))

    # def set_psk(self):

    #     psk_base64 = self.psk_base64_entry.get()
    #     try:
    #         index = int(self.channel_index_entry.get())
    #     except ValueError:
    #         self.set_status(MessageLevel.ERROR, f"Invalid channel index {index}.")
    #         return

    #     try:
    #         psk_bytes = base64.b64decode(psk_base64)
    #         self._manager.set_psk(index, psk_bytes)
    #         self.set_status(MessageLevel.INFO, f"PSK for channel {index} set successfully.")
    #     except Exception as e:
    #         self.set_status(MessageLevel.ERROR, f"Failed to set PSK: {str(e)}")

    # def add_channel(self):
    #     name = self.new_channel_entry.get()
    #     if not name:
    #         self.set_status(MessageLevel.ERROR, "Channel name cannot be empty")
    #         return
    #     try:
    #         self._manager.add_channel(name)
    #         self.set_status(MessageLevel.INFO, f"Channel '{name}' added successfully.")
    #     except Exception as e:
    #         self.set_status(MessageLevel.ERROR, f"Failed to add channel: {str(e)}")

    def traceroute(self):
        dest_id = self.tr_dest_combobox.currentText()
        channel_name = self.tr_channel_combobox.currentText()
        maxhops = self.tr_maxhops_spinbox.value()
        channel_index = self._manager.get_channel_index_from_name(channel_name)

        self.traceroute_event(
            dest_id=dest_id,
            maxhops=maxhops,
            channel_index=channel_index,
        )

    # def open_tunnel_client(self):
    #     tunnel_client_window = tk.Toplevel(self.master)
    #     tunnel_client_window.title("Tunnel Client")

    #     ip_address = self._manager.get_device_ip()
    #     if ip_address:
    #         message = f"Tunnel Client Setup\nDevice IP Address: {ip_address}"
    #     else:
    #         message = "Tunnel Client Setup\nDevice IP Address: Not available"

    #     tk.Label(tunnel_client_window, text=message).pack(padx=5, pady=5)

    #     tk.Label(tunnel_client_window, text="Destination IP:").pack(padx=10, pady=5)
    #     dest_ip_entry = tk.Entry(tunnel_client_window)
    #     dest_ip_entry.pack(padx=10, pady=5)

    #     tk.Label(tunnel_client_window, text="Message:").pack(padx=10, pady=5)
    #     message_entry = tk.Entry(tunnel_client_window)
    #     message_entry.pack(padx=10, pady=5)

    #     def send_packet():
    #         dest_ip = dest_ip_entry.get()
    #         message = message_entry.get()
    #         if dest_ip and message:
    #             self._manager.send_tunnel_packet(dest_ip, message)
    #         else:
    #             self.set_status(MessageLevel.ERROR, "Destination IP and message cannot be empty")

    #     send_button = tk.Button(tunnel_client_window, text="Send Packet", command=send_packet)
    #     send_button.pack(padx=5, pady=5)

    #     def on_close_tunnel_client():
    #         self._manager.close_tunnel()
    #         tunnel_client_window.destroy()

    #     tunnel_client_window.protocol("WM_DELETE_WINDOW", on_close_tunnel_client)

    #     self._manager.start_tunnel_client()

    # def open_tunnel_gateway(self):
    #     tunnel_gateway_window = tk.Toplevel(self.master)
    #     tunnel_gateway_window.title("Tunnel Gateway")

    #     ip_address = self._manager.get_device_ip()
    #     if ip_address:
    #         message = f"Tunnel Gateway Setup\nDevice IP Address: {ip_address}"
    #     else:
    #         message = "Tunnel Gateway Setup\nDevice IP Address: Not available"

    #     tk.Label(tunnel_gateway_window, text=message).pack(padx=5, pady=5)
    #     self._manager.start_tunnel_gateway()

    # def open_browser(self):
    #     # Open a new window with a browser
    #     browser_window = tk.Toplevel(self.master)
    #     browser_window.title("Browser")

    #     # Create a webview window
    #     webview.create_window('Browser', 'https://www.google.com')

    #     # Start the webview window
    #     webview.start()

    def update_received_message(self) -> None:
        self.messages_table.clear()
        self.messages_table.setRowCount(0)
        columns = self._get_meshtastic_message_fields()
        self.messages_table.setColumnCount(len(columns))
        self.messages_table.setHorizontalHeaderLabels(columns)

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

    def quit(self) -> None:
        self._manager.quit()
        self.master.quit()

    def run(self):
        self._manager.start()
        self.master.mainloop()
