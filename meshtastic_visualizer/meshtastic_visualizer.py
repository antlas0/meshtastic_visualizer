#!/usr/bin/env python3


import hashlib
import os
import io
import folium
from folium.plugins import MousePosition, MeasureControl
from threading import Lock
from datetime import datetime, timedelta
from typing import List
from PyQt6 import QtCore
from PyQt6 import QtWidgets, uic
from PyQt6.QtGui import QTextCursor
from PyQt6.QtGui import QFont
from PyQt6.QtWidgets import QTableWidgetItem, QListWidgetItem, QTreeWidgetItem
from PyQt6.QtWebEngineWidgets import QWebEngineView
from PyQt6.QtCore import pyqtSignal, QSettings
import pyqtgraph as pg
from pyqtgraph import DateAxisItem
from dataclasses import asdict

from .meshtastic_manager import MeshtasticManager
from .resources import MessageLevel, \
    MeshtasticMessage, \
    TEXT_MESSAGE_MAX_CHARS, \
    MeshtasticMQTTClientSettings, \
    MAINWINDOW_STYLESHEET

from .meshtastic_mqtt import MeshtasticMQTT
from .meshtastic_datastore import MeshtasticDataStore


class MeshtasticQtApp(QtWidgets.QMainWindow):
    connect_device_signal = pyqtSignal(bool)
    disconnect_device_signal = pyqtSignal()
    get_nodes_signal = pyqtSignal()
    send_message_signal = pyqtSignal(MeshtasticMessage)
    retrieve_channels_signal = pyqtSignal()
    retrieve_local_node_config_signal = pyqtSignal()
    traceroute_signal = pyqtSignal(str, int, int)
    mqtt_connect_signal = pyqtSignal(MeshtasticMQTTClientSettings)

    def __init__(self):
        self._lock = Lock()
        super(MeshtasticQtApp, self).__init__()
        uic.loadUi('resources/app.ui', self)
        self.setWindowFlags(QtCore.Qt.WindowType.CustomizeWindowHint |
                            QtCore.Qt.WindowType.WindowCloseButtonHint | QtCore.Qt.WindowType.WindowMinimizeButtonHint)
        self.setFixedSize(self.size())
        self.show()

        self._map = None
        self._plot_widget = None
        self._settings = QSettings("antlas0", "meshtastic_visualizer")

        # Variables
        self.status_var: str = ""
        self._local_board_id: str = ""
        self._action_buttons = []
        self.setup_ui()

        self._store = MeshtasticDataStore()
        self._manager = MeshtasticManager()
        self._manager.set_store(self._store)
        self._manager.start()

        self._mqtt_manager = MeshtasticMQTT()
        self._mqtt_manager.set_store(self._store)
        self._mqtt_manager.start()

        self._manager.notify_frontend_signal.connect(self.refresh)
        self._mqtt_manager.notify_frontend_signal.connect(self.refresh)
        self._manager.notify_nodes_metrics_signal.connect(
            self.update_nodes_metrics)
        self._mqtt_manager.notify_nodes_metrics_signal.connect(
            self.update_nodes_metrics)
        self._manager.notify_radio_log_signal.connect(self.update_radio_log)
        self._manager.notify_radio_log_signal.connect(
            self.update_packets_treeview)
        self._manager.notify_message_signal.connect(
            self.update_received_message)
        self._mqtt_manager.notify_message_signal.connect(
            self.update_received_message)
        self._mqtt_manager.notify_mqtt_enveloppe_signal.connect(
            self.update_packets_treeview)
        self._manager.notify_traceroute_signal.connect(self.update_traceroute)
        self._manager.notify_channels_signal.connect(
            self.update_channels_list)
        self._manager.notify_nodes_map_signal.connect(self.update_nodes_map)
        self._manager.notify_nodes_table_signal.connect(
            self.update_nodes_table)
        self._mqtt_manager.notify_nodes_map_signal.connect(
            self.update_nodes_map)
        self._mqtt_manager.notify_nodes_table_signal.connect(
            self.update_nodes_table)
        self._mqtt_manager.notify_mqtt_enveloppe_signal.connect(
            self.update_received_mqtt_log)

        self._update_meshtastic_devices()

        self.connect_device_signal.connect(self._manager.connect_device)
        self.disconnect_device_signal.connect(self._manager.disconnect_device)
        self.send_message_signal.connect(self._manager.send_text_message)
        self.retrieve_channels_signal.connect(self._manager.retrieve_channels)
        self.get_nodes_signal.connect(self.update_nodes_map)
        self.retrieve_local_node_config_signal.connect(
            self._manager.load_local_node_configuration)
        self.traceroute_signal.connect(self._manager.send_traceroute)
        self.mqtt_connect_signal.connect(
            self._mqtt_manager.configure_and_start)
        self.export_chat_button.pressed.connect(self._manager.export_chat)
        self.export_nodes_button.pressed.connect(self._manager.export_nodes)
        self.export_radio_button.pressed.connect(self.export_radio)
        self.clear_radio_button.pressed.connect(self.output_textedit.clear)
        self.clear_mqtt_button.pressed.connect(self.mqtt_output_textedit.clear)
        self.clear_messages_button.pressed.connect(self.clear_messages_table)
        self.clear_messages_button.pressed.connect(self._store.clear_messages)
        self.clear_nodes_button.pressed.connect(self.clear_nodes)
        self.clear_packets_button.pressed.connect(self.clear_packets)
        self.export_mqtt_button.pressed.connect(self.export_mqtt_logs)
        for i, metric in enumerate(
                self._store.get_node_metrics_fields()):
            self.nm_metric_combobox.insertItem(
                i + 1, metric)
        self.nodes_filter_linedit.textChanged.connect(self.update_nodes_table)
        self.mqtt_connect_button.pressed.connect(self.connect_mqtt)
        self.mqtt_disconnect_button.pressed.connect(
            self._mqtt_manager.disconnect_mqtt)

    def connect_device_event(self, resetDB: bool):
        self.connect_device_signal.emit(resetDB)

    def disconnect_device_event(self):
        self.disconnect_device_signal.emit()

    def get_nodes_event(self):
        self.get_nodes_signal.emit()

    def retrieve_channels_event(self):
        self.retrieve_channels_signal.emit()

    def traceroute_event(self, dest_id: str, maxhops: int, channel_index: int):
        self.traceroute_signal.emit(dest_id, maxhops, channel_index)

    def mqtt_connect_event(self, settings: MeshtasticMQTTClientSettings):
        self.mqtt_connect_signal.emit(settings)

    def retrieve_local_node_config_event(self):
        self.retrieve_local_node_config_signal.emit()

    def send_message_event(self, message: MeshtasticMessage):
        self.send_message_signal.emit(message)

    def set_status(self, loglevel: MessageLevel, message: str) -> None:
        if loglevel.value == MessageLevel.ERROR.value:
            self.notification_bar.setText(message)

        if loglevel.value == MessageLevel.INFO.value or loglevel.value == MessageLevel.UNKNOWN.value:
            self.notification_bar.setText(message)

    def _update_meshtastic_devices(self) -> None:
        self.device_combobox.clear()
        for i, device in enumerate(self._manager.get_meshtastic_devices()):
            self.device_combobox.insertItem(i, device)

    def setup_ui(self) -> None:
        self.tabWidget.currentChanged.connect(self.remove_notification_badge)
        self.notification_bar.setOpenExternalLinks(True)
        self.connect_button.clicked.connect(self.connect_device)
        self.scan_com_button.clicked.connect(self._update_meshtastic_devices)
        self.disconnect_button.clicked.connect(self.disconnect_device)
        self.refresh_map_button.clicked.connect(self.get_nodes)
        self.send_button.clicked.connect(self.send_message)
        self.traceroute_button.clicked.connect(self.traceroute)
        self.nm_update_button.setEnabled(False)
        self.nm_update_button.pressed.connect(self.update_nodes_metrics)
        self.nm_node_combobox.currentIndexChanged.connect(
            self.update_metrics_buttons)
        self.nm_metric_combobox.currentIndexChanged.connect(
            self.update_metrics_buttons)
        self.msg_node_list.itemClicked.connect(self.update_recipient)
        self.msg_channel_list.itemClicked.connect(self.update_dest_channel)
        self.mesh_table.cellClicked.connect(self.mesh_table_is_clicked)
        self.message_textedit.textChanged.connect(
            self.update_text_message_length)
        self.remaining_chars_label.setText(
            f"{TEXT_MESSAGE_MAX_CHARS}/{TEXT_MESSAGE_MAX_CHARS}")
        self.init_map()

        self.messages_table.setColumnCount(
            len(self._get_meshtastic_message_header_fields().keys()))
        self.messages_table.setHorizontalHeaderLabels(
            list(self._get_meshtastic_message_header_fields().values()))
        self.traceroute_table.setColumnCount(3)
        self.traceroute_table.setHorizontalHeaderLabels(
            ["Id", "SNR To", "SNR Back"])
        self.batterylevel_progressbar.hide()
        self.connect_button.setEnabled(True)
        self.disconnect_button.setEnabled(False)
        self._action_buttons = [
            self.traceroute_button,
            self.send_button,
            self.message_textedit,
        ]
        for button in self._action_buttons:
            button.setEnabled(False)
        self._plot_widget = pg.PlotWidget()
        self._plot_widget.setBackground('w')
        self._plot_widget.getPlotItem().getAxis('left').setPen(pg.mkPen(color='k'))
        self._plot_widget.getPlotItem().getAxis('bottom').setPen(pg.mkPen(color='k'))
        self._plot_widget.getPlotItem().getAxis('left').setTextPen(pg.mkPen(color='k'))
        self._plot_widget.getPlotItem().getAxis(
            'bottom').setTextPen(pg.mkPen(color='k'))
        self._plot_widget.addLegend()
        self._plot_widget.setMouseEnabled(x=False, y=False)
        self._plot_widget.setAxisItems({'bottom': DateAxisItem()})
        self.plot_layout.addWidget(self._plot_widget)
        self._plot_item = self._plot_widget.plot(
            pen=pg.mkPen(
                '#007aff',
                width=1),
            symbol='o',
            symbolPen='b',
            symbolSize=8)

        self.mqtt_disconnect_button.setEnabled(False)
        self.nodes_total_lcd.setDecMode()
        self.packets_total_lcd.setDecMode()
        self.nodes_gps_lcd.setDecMode()
        self.nodes_recently_lcd.setDecMode()
        self.mqtt_host_linedit.setText(self._settings.value("mqtt_host", ""))
        self.mqtt_port_spinbox.setValue(
            int(self._settings.value("mqtt_port", 1883)))
        self.mqtt_username_linedit.setText(
            self._settings.value("mqtt_username", ""))
        self.mqtt_password_linedit.setText(
            self._settings.value("mqtt_password", ""))
        self.mqtt_topic_linedit.setText(self._settings.value("mqtt_topic", ""))
        self.mqtt_key_linedit.setText(self._settings.value("mqtt_key", "AQ=="))
        self.packets_treewidget.setHeaderLabels(["Packet", "Details"])
        self.packettype_combobox.insertItem(0, "All")
        self.packettype_combobox.currentIndexChanged.connect(
            self.clean_packets_treeview)
        self.setStyleSheet(MAINWINDOW_STYLESHEET)

    def clear_messages_table(self) -> None:
        self.messages_table.setRowCount(0)

    def clear_nodes(self) -> None:
        self._store.clear_nodes()
        self._store.clear_nodes_metrics()
        self.mesh_table.setRowCount(0)
        self.msg_node_list.clear()
        self.nm_node_combobox.clear()
        self.nodes_total_lcd.display(0)
        self.nodes_gps_lcd.display(0)
        self.nodes_recently_lcd.display(0)

    def clear_packets(self) -> None:
        self._store.clear_radio_packets()
        self._store.clear_mqtt_packets()
        self.packets_treewidget.clear()
        self.packettype_combobox.clear()
        self.packettype_combobox.insertItem(0, "All")
        self.packets_total_lcd.display(0)

    def _get_meshtastic_message_header_fields(self) -> dict:
        return {
            "date": "Date",
            "ack": "Ack",
            "pki_encrypted": "Encrypted",
            "from_id": "From",
            "to_id": "To",
            "channel_index": "Channel",
            "content": "Message",
        }

    def remove_notification_badge(self, index):
        if index == 1:
            self.tabWidget.setTabText(2, "Messages")

    def refresh(
            self,
            status: MessageLevel = MessageLevel.UNKNOWN,
            message=None) -> None:
        """
        Refresh all UI at once
        """
        self._lock.acquire()

        data = self._store
        if message is not None:
            self.set_status(status, message)

        if data.is_connected():
            self.connect_button.setEnabled(False)
            self.disconnect_button.setEnabled(True)
            for button in self._action_buttons:
                button.setEnabled(True)
        else:
            self.connect_button.setEnabled(True)
            self.disconnect_button.setEnabled(False)
            for button in self._action_buttons:
                button.setEnabled(False)

        if self._mqtt_manager.is_connected():
            self.mqtt_connect_button.setEnabled(False)
            self.mqtt_disconnect_button.setEnabled(True)
            self.mqtt_host_linedit.setEnabled(False)
            self.mqtt_port_spinbox.setEnabled(False)
            self.mqtt_username_linedit.setEnabled(False)
            self.mqtt_password_linedit.setEnabled(False)
            self.mqtt_topic_linedit.setEnabled(False)
            self.mqtt_key_linedit.setEnabled(False)
        else:
            self.mqtt_connect_button.setEnabled(True)
            self.mqtt_disconnect_button.setEnabled(False)
            self.mqtt_host_linedit.setEnabled(True)
            self.mqtt_port_spinbox.setEnabled(True)
            self.mqtt_username_linedit.setEnabled(True)
            self.mqtt_password_linedit.setEnabled(True)
            self.mqtt_topic_linedit.setEnabled(True)
            self.mqtt_key_linedit.setEnabled(True)

        self._lock.release()

    def connect_device(self):
        device_path = self.device_combobox.currentText()
        if device_path:
            self._manager.set_meshtastic_device(device_path)
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

    def update_traceroute(
            self,
            route: list,
            snr_towards: list,
            snr_back: list) -> None:
        self.traceroute_table.clear()
        self.traceroute_table.setRowCount(0)
        self.traceroute_table.setColumnCount(3)
        self.traceroute_table.setHorizontalHeaderLabels(
            ["Id", "SNR To", "SNR Back"])
        for hop in route:
            device = self._store.get_long_name_from_id(hop)
            if hop == self._local_board_id:
                device = "Me"
            row_position = self.traceroute_table.rowCount()
            self.traceroute_table.insertRow(row_position)
            self.traceroute_table.setItem(
                row_position, 0, QTableWidgetItem(device))
            self.traceroute_table.resizeColumnsToContents()

        for i in range(len(snr_towards)):
            self.traceroute_table.setItem(
                i, 1, QTableWidgetItem("↓" + str(snr_towards[i])))
        for i in range(len(snr_back)):
            self.traceroute_table.setItem(
                i, 2, QTableWidgetItem("↑" + str(snr_back[i])))
        self.traceroute_table.resizeColumnsToContents()

    def update_text_message_length(self):
        current_text = self.message_textedit.toPlainText()

        if len(current_text) > TEXT_MESSAGE_MAX_CHARS:
            self.message_textedit.blockSignals(True)
            self.message_textedit.setPlainText(
                current_text[:TEXT_MESSAGE_MAX_CHARS])
            cursor = self.message_textedit.textCursor()
            cursor.setPosition(TEXT_MESSAGE_MAX_CHARS)
            self.message_textedit.setTextCursor(cursor)
            self.message_textedit.blockSignals(False)

        remaining_chars = TEXT_MESSAGE_MAX_CHARS - \
            len(self.message_textedit.toPlainText())
        self.remaining_chars_label.setText(
            f"{remaining_chars}/{TEXT_MESSAGE_MAX_CHARS}")

    def mesh_table_is_clicked(self, row, column) -> None:
        node_id = self.mesh_table.item(row, 2).text()
        long_name = self.mesh_table.item(row, 1).text()
        if self._local_board_id and node_id == self._local_board_id:
            long_name = "Me"

        self.nm_node_combobox.setCurrentText(long_name)

    def init_map(self):
        self._map = folium.Map(zoom_start=7)
        MousePosition().add_to(self._map)
        MeasureControl().add_to(self._map)
        self.update_map_in_widget()

    def update_map_in_widget(self):
        data = io.BytesIO()
        self._map.save(data, close_file=False)
        data.seek(0)
        html = data.getvalue().decode()
        data.close()
        del data
        self.nodes_map.setHtml(html)

    def update_nodes_map(self):
        # we re-create from scratch every time
        # using this method we od have easy access to the Dom anyway
        def __link_color(node_id: str) -> str:
            hash_object = hashlib.md5(node_id.encode())
            color = '#' + hash_object.hexdigest()[:6]
            return color

        del self._map
        self._map = None
        self._map = folium.Map(zoom_start=7, control_scale=True, no_touch=True)
        MousePosition().add_to(self._map)
        MeasureControl().add_to(self._map)

        # Add a new marker
        nodes = self._store.get_nodes()
        if nodes is None:
            return

        markers_group = folium.FeatureGroup(name="Stations")
        links_group = folium.FeatureGroup(name="Links")
        markers: list = []
        links: list = []

        # in case of links tracing, pre-create a dict(node_id, [lat, lon])
        nodes_coords = {
            x.id: [
                float(
                    x.lat), float(
                    x.lon)] for __, x in nodes.items() if x.lat is not None and x.lon is not None}

        for node_id, node in nodes.items():
            if node.lat is None or node.lon is None:
                continue
            strl = []
            strl.append(f"<b>Name:</b> {node.long_name}</br>")
            strl.append(f"<b>id:</b> {node.id}</br>")
            if node.hardware:
                strl.append(f"<b>Hardware:</b> {node.hardware}</br>")
            if node.battery_level:
                strl.append(
                    f"<b>Battery Level:</b> {node.battery_level} %</br>")
            if node.role:
                strl.append(f"<b>Role:</b> {node.role}</br>")
            if node.hopsaway:
                strl.append(f"<b>Hops Away:</b> {node.hopsaway}</br>")
            if node.txairutil:
                strl.append(f"<b>Air Util. Tx:</b> {node.txairutil} %</br>")
            if node.rssi:
                strl.append(f"<b>RSSI:</b> {node.rssi} dBm</br>")
            if node.snr:
                strl.append(f"<b>SNR:</b> {node.snr}</br>")
            if node.lastseen:
                strl.append(f"<b>Last seen:</b> {node.lastseen}</br>")
            popup_content = "".join(strl)
            popup = folium.Popup(
                popup_content, max_width=300, min_width=250)
            color = "blue"
            if node.rx_counter > 0:
                color = "green"
            if node.id == self._local_board_id:
                color = "orange"

            marker = folium.Marker(
                location=[
                    node.lat,
                    node.lon],
                tooltip=popup_content,
                popup=popup,
                icon=folium.Icon(color=color),
            )
            marker.add_to(markers_group)
            markers.append(marker)

            # neighbors
            if node.neighbors is not None:
                for neighbor in node.neighbors:
                    # we can trace a link
                    if neighbor in nodes_coords.keys():
                        link_coords = [
                            nodes_coords[node.id],
                            nodes_coords[neighbor],
                        ]
                        if link_coords[0][0] is not None \
                                and link_coords[0][1] is not None \
                                and link_coords[1][0] is not None\
                                and link_coords[1][1] is not None:
                            link = folium.PolyLine(
                                link_coords, color=__link_color(node.id))
                            link.add_to(links_group)
                            links.append(link)
        if markers:
            markers_group.add_to(self._map)
            markers_lat = [x.location[0] for x in markers]
            markers_lon = [x.location[1] for x in markers]
            self._map.fit_bounds([[min(markers_lat), min(markers_lon)], [
                                 max(markers_lat), max(markers_lon)]])
        if links:
            links_group.add_to(self._map)
            folium.LayerControl().add_to(self._map)
        del nodes
        self.update_map_in_widget()

    def clean_plot(self) -> None:
        self._plot_item.setData(
            x=None,
            y=None)
        self._plot_widget.setTitle("No data")

    def update_metrics_buttons(self) -> None:
        self.nm_update_button.setEnabled(True)

    def update_nodes_metrics(self) -> str:
        self.nm_update_button.setEnabled(False)
        node_id = self._store.get_id_from_long_name(
            self.nm_node_combobox.currentText())
        metric_name = self.nm_metric_combobox.currentText()
        if not node_id or not metric_name:
            self.clean_plot()
            return
        self.refresh_metrics_plot(node_id=node_id, metric_name=metric_name)

    def refresh_metrics_plot(self, node_id: str, metric_name: str) -> None:
        self._lock.acquire()
        metric = self._store.get_node_metrics(node_id, metric_name)
        if "timestamp" not in metric or metric_name not in metric:
            self.clean_plot()
            self._lock.release()
            return
        if len(
                list(
                    filter(
                lambda x: x is not None,
                metric[metric_name]))) == 0:
            self.clean_plot()
            self._lock.release()
            return

        if len(
            metric["timestamp"]) == len(
            metric[metric_name]) and len(
                metric[metric_name]) > 0:
            none_indexes = [
                i for i, v in enumerate(
                    metric[metric_name]) if v is None]
            for i in reversed(none_indexes):
                metric["timestamp"].pop(i)
                metric[metric_name].pop(i)

            self._plot_item.setData(
                x=metric["timestamp"],
                y=metric[metric_name])
            self._plot_widget.getPlotItem().getViewBox().setRange(
                xRange=(min(metric["timestamp"]), max(metric["timestamp"])),
                yRange=(min(metric[metric_name]), max(metric[metric_name])),
            )
            self._plot_widget.setLabel('left', metric_name, units='')
            self._plot_widget.setLabel('bottom', 'Timestamp', units='')
            self._plot_widget.setTitle(
                f'{metric_name} vs time for node {self._store.get_long_name_from_id(node_id)}')
        self._lock.release()

    def send_message(self):
        message = self.message_textedit.toPlainText()
        channel_name = self.msg_channel_label.text()
        recipient = self._store.get_id_from_long_name(
            self.msg_to_label.text())
        channel_index = self._manager.get_data_store(
        ).get_channel_index_from_name(channel_name)
        # Update timeout before sending
        if channel_index != -1 and message:
            m = MeshtasticMessage(
                mid=-1,
                date=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                from_id=self._local_board_id,
                to_id=recipient,
                content=message,
                want_ack=True,
                channel_index=channel_index,
            )
            self.send_message_event(m)
            self.message_textedit.clear()

    def update_nodes_table(self) -> None:
        nodes = self._store.get_nodes()
        if nodes is None:
            return

        self.update_local_node_config()

        # update LCD widgets
        self.nodes_total_lcd.display(len(nodes.values()))
        positioned_nodes = list(
            filter(
                lambda x: x.lat is not None and x.lon is not None and x.lat and x.lon,
                nodes.values()))
        self.nodes_gps_lcd.display(len(positioned_nodes))
        recently_seen = list(
            filter(
                lambda x: datetime.strptime(
                    x.lastseen,
                    "%Y-%m-%d %H:%M:%S") > datetime.now() -
                timedelta(
                    minutes=30) if x.lastseen is not None else False,
                nodes.values()))
        self.nodes_recently_lcd.display(len(recently_seen))

        # filter by nodes_filter
        filtered = nodes.values()  # nofilter
        if len(self.nodes_filter_linedit.text()) != 0:
            # first search in long_name, then in id
            pattern = self.nodes_filter_linedit.text()
            filtered = list(filter(lambda x: pattern.lower() in x.long_name.lower(
            ) if x.long_name is not None else False, nodes.values()))
            if not filtered:
                filtered = list(
                    filter(
                        lambda x: pattern.lower() in x.id.lower(),
                        nodes.values()))

        # update table
        current_row = None
        if self.msg_node_list.currentRow():
            current_row = self.msg_node_list.currentRow()
        self.msg_node_list.clear()
        current_nm_node = self.nm_node_combobox.currentText()
        self.nm_node_combobox.clear()
        self.msg_node_list.insertItem(0, "All")
        self.nm_node_combobox.insertItem(
            0, "Me")
        for i, node in enumerate(filtered):
            if node.id == self._local_board_id:
                continue
            self.msg_node_list.insertItem(
                i + 1, node.long_name if node.long_name else node.id)
            self.nm_node_combobox.insertItem(
                i + 2, node.long_name if node.long_name else node.id)
        self.nm_node_combobox.setCurrentText(current_nm_node)
        if current_row:
            self.msg_node_list.setCurrentRow(current_row)

        rows: list[dict[str, any]] = []
        for node in filtered:
            row = {"Status": "", "User": "", "ID": ""}

            status_line = []

            if node.lastseen:
                recently_seen = datetime.strptime(
                    node.lastseen, "%Y-%m-%d %H:%M:%S") > datetime.now() - timedelta(minutes=30)
                if recently_seen:
                    status_line.append("📶")
            if node.rx_counter > 0:
                status_line.append(f"{node.rx_counter}✉️")
            if node.has_location():
                status_line.append("🌐")
            if node.public_key:
                status_line.append("🔑")
            row.update(
                {
                    "Status": " ".join(status_line),
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
                    "Public key": node.public_key,
                    "Last seen": node.lastseen,
                }
            )
            rows.append(row)

        rows.sort(key=lambda r: r.get("LastHeard") or "0000", reverse=True)

        columns = [
            "Status",
            "User",
            "AKA",
            "ID",
            "Role",
            "Hardware",
            "Latitude",
            "Longitude",
            "Public key",
            "Last seen",
        ]

        del nodes
        self.mesh_table.setRowCount(len(rows))
        self.mesh_table.setColumnCount(len(columns))
        self.mesh_table.setHorizontalHeaderLabels(columns)

        for row_idx, row_data in enumerate(rows):
            for col_idx, value in enumerate(row_data.values()):
                current_item = self.mesh_table.item(row_idx, col_idx)
                data = str(value)
                if data == "None":
                    data = ""
                if current_item is None:
                    self.mesh_table.setItem(
                        row_idx, col_idx, QTableWidgetItem(data))
                elif current_item.text() != value:
                    current_item.setText(data)
        self.mesh_table.resizeColumnsToContents()

    def get_nodes(self):
        self.get_nodes_event()

    def get_channel_names(self) -> List[str]:
        config = self._store
        channels = config.get_channels()
        if not channels:
            return []
        return [channel.name for channel in channels]

    def update_channels_list(self):
        config = self._store
        channels = config.get_channels()
        if not channels:
            return
        for cb in ["msg_channel_list"]:
            getattr(self, cb).clear()
            for i, channel in enumerate(channels):
                getattr(self, cb).insertItem(i, channel.name)

    def retrieve_channels(self):
        self.retrieve_channels_event()

    def update_local_node_config(self):
        cfg = self._store.get_local_node_config()
        if cfg is None:
            return

        self._local_board_id = cfg.id
        self.devicename_label.setText(cfg.long_name)
        self.publickey_label.setText(cfg.public_key)
        self.hardware_label.setText(cfg.hardware)
        self.role_label.setText(cfg.role)
        self.batterylevel_progressbar.setValue(cfg.battery_level)
        self.batterylevel_progressbar.show()
        self.id_label.setText(str(cfg.id))

    def traceroute(self):
        dest_id = self._store.get_id_from_long_name(
            self.tr_dest_label.text())
        channel_name = self.tr_channel_label.text()
        maxhops = self.tr_maxhops_spinbox.value()
        channel_index = self._manager.get_data_store(
        ).get_channel_index_from_name(channel_name)
        self.traceroute_table.setRowCount(0)
        self.traceroute_table.setColumnCount(3)
        self.traceroute_table.setHorizontalHeaderLabels(
            ["Id", "SNR To", "SNR Back"])
        self.traceroute_event(
            dest_id=dest_id,
            maxhops=maxhops,
            channel_index=channel_index,
        )

    def update_received_message(self) -> None:
        if self.tabWidget.currentIndex() != 2:
            self.tabWidget.setTabText(2, "Messages ✉")

        headers = self._get_meshtastic_message_header_fields()
        columns = list(headers.keys())
        self.messages_table.setColumnCount(len(columns))
        self.messages_table.setHorizontalHeaderLabels(headers.values())

        channels = self._store.get_channels()
        messages = self._store.get_messages()
        self.messages_table.setRowCount(len(messages))
        rows: list[dict[str, any]] = []

        for message in messages:
            data = {}
            for column in columns:
                if column == "from_id" or column == "to_id":
                    data[headers[column]] = self._store.get_long_name_from_id(
                        getattr(
                            message, column))
                elif column == "channel_index":
                    name = "/"
                    if channels is not None:
                        for ch in channels:
                            if ch.index == message.channel_index:
                                name = ch.name
                    else:
                        name = message.channel_index
                    data[headers[column]] = name
                elif column == "ack":
                    label = "❔"
                    if getattr(message, column) is True:
                        label = "✅"
                    if getattr(message, column) is False:
                        label = "❌"
                    data[headers[column]] = label
                elif column == "pki_encrypted":
                    label = "⚠️"
                    if getattr(message, column) is True:
                        label = "🔒"
                    data[headers[column]] = label
                else:
                    data[headers[column]] = getattr(message, column)
            rows.append(data)

        for row_idx, row_data in enumerate(rows):
            for col_idx, value in enumerate(row_data.values()):
                current_item = self.messages_table.item(row_idx, col_idx)
                if current_item is None:
                    self.messages_table.setItem(
                        row_idx, col_idx, QTableWidgetItem(str(value)))
                elif current_item.text() != value:
                    current_item.setText(str(value))
        self.messages_table.resizeColumnsToContents()

    def clean_packets_treeview(self) -> None:
        self.packets_treewidget.clear()
        self.update_packets_treeview()

    def update_packets_treeview(self) -> None:
        # Example: Modify existing items or add new ones
        packets = self._store.get_mqttpackets() + self._store.get_radiopackets()
        alreading_existing_packets = [
            self.packets_treewidget.topLevelItem(i).text(0) for i in range(
                self.packets_treewidget.topLevelItemCount())]

        filtered_packets = packets
        if self.packettype_combobox.currentText() != "All":
            filtered_packets = list(
                filter(
                    lambda x: x.port_num == self.packettype_combobox.currentText(),
                    packets))

        for packet in filtered_packets:
            if self.packettype_combobox.findText(packet.port_num) == -1:
                self.packettype_combobox.insertItem(
                    1000, packet.port_num)  # insert last

            if str(packet.date) in alreading_existing_packets:
                continue
            category_item = QTreeWidgetItem([str(packet.date), ""])
            self.packets_treewidget.addTopLevelItem(category_item)
            for sub_item, value in asdict(packet).items():
                sub_item_widget = QTreeWidgetItem([str(sub_item), str(value)])
                category_item.addChild(sub_item_widget)
        self.packets_treewidget.resizeColumnToContents(0)
        self.packets_treewidget.resizeColumnToContents(1)
        self.packets_total_lcd.display(len(packets))

    def update_radio_log(self, message: str, message_type: str):
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

    def update_received_mqtt_log(self, log: str):
        self.mqtt_output_textedit.setReadOnly(True)
        tmp = [
            self.mqtt_output_textedit.toPlainText()
        ]
        if self.mqtt_output_textedit.toPlainText() != "":
            tmp.append("\n")
        nnow = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        tmp.append(f"[{nnow}] {log}")
        self.mqtt_output_textedit.setText("".join(tmp))
        cursor = QTextCursor(self.mqtt_output_textedit.textCursor())
        cursor.setPosition(len(self.mqtt_output_textedit.toPlainText()))
        self.mqtt_output_textedit.setTextCursor(cursor)

    def update_recipient(self, item: QListWidgetItem) -> None:
        self.msg_to_label.setText(item.text())
        self.tr_dest_label.setText(item.text())

    def update_dest_channel(self, item: QListWidgetItem) -> None:
        self.msg_channel_label.setText(item.text())
        self.tr_channel_label.setText(item.text())

    def connect_mqtt(self) -> None:
        m = MeshtasticMQTTClientSettings()
        m.host = self.mqtt_host_linedit.text()
        m.port = self.mqtt_port_spinbox.value()
        m.username = self.mqtt_username_linedit.text()
        m.password = self.mqtt_password_linedit.text()
        m.topic = self.mqtt_topic_linedit.text()
        m.key = self.mqtt_key_linedit.text()
        self._settings.setValue("mqtt_host", m.host)
        self._settings.setValue("mqtt_port", m.port)
        self._settings.setValue("mqtt_username", m.username)
        self._settings.setValue("mqtt_password", m.password)
        self._settings.setValue("mqtt_topic", m.topic)
        self._settings.setValue("mqtt_key", m.key)

        self.mqtt_connect_event(m)

    def export_radio(self) -> None:
        nnow = datetime.now().strftime("%Y-%m-%d__%H_%M_%S")
        fpath = f"radio_{nnow}.log"
        with open(fpath, "w") as text_file:
            text_file.write(self.output_textedit.toPlainText())
            absp = os.path.abspath(fpath)
            trace = f"<a href='file://{absp}'>Exported radio to file: {fpath}</a>"
            self.set_status(MessageLevel.INFO, trace)

    def export_mqtt_logs(self) -> None:
        nnow = datetime.now().strftime("%Y-%m-%d__%H_%M_%S")
        fpath = f"mqtt_logs_{nnow}.log"
        with open(fpath, "w") as text_file:
            text_file.write(self.mqtt_output_textedit.toPlainText())
            absp = os.path.abspath(fpath)
            trace = f"<a href='file://{absp}'>Exported mqtt logs to file: {fpath}</a>"
            self.set_status(MessageLevel.INFO, trace)

    def quit(self) -> None:
        self._manager.quit()
        self._mqtt_manager.quit()
        self.master.quit()

    def run(self):
        self.master.mainloop()
