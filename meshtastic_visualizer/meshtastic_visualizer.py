#!/usr/bin/env python3


import os
import json
from threading import Lock
from datetime import datetime, timedelta
from typing import List
from PyQt6 import QtCore
from PyQt6 import QtWidgets, uic
from PyQt6.QtGui import QTextCursor
from PyQt6.QtWidgets import QTableWidgetItem, QListWidgetItem, QTreeWidgetItem, QPushButton
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
    MAINWINDOW_STYLESHEET, \
    TIME_FORMAT, \
    DEFAULT_TRACEROUTE_CHANNEL

from .meshtastic_mqtt import MeshtasticMQTT
from .meshtastic_datastore import MeshtasticDataStore
from .mapper import Mapper


class MeshtasticQtApp(QtWidgets.QMainWindow):
    connect_device_signal = pyqtSignal(bool)
    disconnect_device_signal = pyqtSignal()
    get_nodes_signal = pyqtSignal()
    send_message_signal = pyqtSignal(MeshtasticMessage)
    retrieve_channels_signal = pyqtSignal()
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
        self._telemetry_plot_widget = pg.PlotWidget()
        self._packets_plot_widget = pg.PlotWidget()
        self._telemetry_plot_item = self._telemetry_plot_widget.plot(
                pen=pg.mkPen(
                    '#007aff',
                    width=1),
                symbol='o',
                symbolPen='b',
                symbolSize=8)
        self._packets_plot_item = self._packets_plot_widget.plot(
                pen=pg.mkPen(
                    '#007aff',
                    width=1),
                symbol='o',
                symbolPen='b',
                symbolSize=8)
        self._settings = QSettings("antlas0", "meshtastic_visualizer")

        # Variables
        self.status_var: str = ""
        self._local_board_id: str = ""
        self._action_buttons = []
        self._traceroute_buttons = []
        self.setup_ui()

        self._store = MeshtasticDataStore()
        self._manager = MeshtasticManager()
        self._manager.set_store(self._store)
        self._manager.start()

        self._mqtt_manager = MeshtasticMQTT()
        self._mqtt_manager.set_store(self._store)
        self._mqtt_manager.start()

        self._manager.refresh_ui_signal.connect(self.refresh_ui)
        self._mqtt_manager.refresh_ui_signal.connect(self.refresh_ui)
        self._manager.notify_frontend_signal.connect(
            self.refresh_status_header)
        self._mqtt_manager.notify_frontend_signal.connect(
            self.refresh_status_header)
        self._manager.notify_nodes_metrics_signal.connect(
            self.update_nodes_metrics)
        self._mqtt_manager.notify_nodes_metrics_signal.connect(
            self.update_nodes_metrics)
        self._manager.notify_local_device_configuration_signal.connect(self.update_device_details)
        self._manager.notify_packet_received.connect(
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
        self._manager.notify_nodes_table_signal.connect(
            self.update_nodes_table)
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
        self.traceroute_signal.connect(self._manager.send_traceroute)
        self.mqtt_connect_signal.connect(
            self._mqtt_manager.configure_and_start)
        self.export_chat_button.pressed.connect(self.export_chat)
        self.export_packets_button.pressed.connect(self.export_packets)
        self.export_nodes_button.pressed.connect(self.export_nodes)
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
        for i, metric in enumerate(
                self._store.get_packet_metrics_fields()):
            self.pm_metric_combobox.insertItem(
                i + 1, metric)
        self.nodes_filter_linedit.textChanged.connect(self.update_nodes_table)
        self.shortcut_filter_combobox.currentTextChanged.connect(self.update_nodes_table)
        self.mqtt_connect_button.pressed.connect(self.connect_mqtt)
        self.mqtt_disconnect_button.pressed.connect(
            self._mqtt_manager.disconnect_mqtt)

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
        self.nm_update_button.setEnabled(False)
        self.pm_update_button.setEnabled(False)
        self.nm_update_button.pressed.connect(self.update_nodes_metrics)
        self.nm_node_combobox.currentTextChanged.connect(
            self.update_node_metrics_buttons)
        self.nm_metric_combobox.currentTextChanged.connect(
            self.update_node_metrics_buttons)
        self.pm_update_button.pressed.connect(self.update_packets_metrics)
        self.pm_node_combobox.currentTextChanged.connect(
            self.update_packets_metrics_buttons)
        self.pm_metric_combobox.currentTextChanged.connect(
            self.update_packets_metrics_buttons
        )
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
            self.send_button,
            self.message_textedit,
        ]
        for button in self._action_buttons:
            button.setEnabled(False)

        for i, f in enumerate(["All", "Recently seen", "Neighbors", "1-hop", "2-hops", "3-hops", "4-hops", "5-hops", "6-hops", "7-hops"]):
            self.shortcut_filter_combobox.insertItem(i , f)

        for p in ["telemetry", "packets"]:
            widget = {
                "telemetry": self._telemetry_plot_widget,
                "packets": self._packets_plot_widget,
            }
            layout = {
                "telemetry": self.telemetry_plot_layout,
                "packets": self.packets_plot_layout,
            }
            plot_item = {
                "telemetry": self._telemetry_plot_item,
                "packets": self._packets_plot_item,
            }
            widget[p].setBackground('w')
            widget[p].getPlotItem().getAxis('left').setPen(pg.mkPen(color='k'))
            widget[p].getPlotItem().getAxis('bottom').setPen(pg.mkPen(color='k'))
            widget[p].getPlotItem().getAxis('left').setTextPen(pg.mkPen(color='k'))
            widget[p].getPlotItem().getAxis(
                'bottom').setTextPen(pg.mkPen(color='k'))
            widget[p].addLegend()
            widget[p].setMouseEnabled(x=False, y=False)
            widget[p].setAxisItems({'bottom': DateAxisItem()})
            layout[p].addWidget(widget[p])
            plot_item[p] = widget[p].plot(
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
        self.packetsource_combobox.insertItem(0, "All")
        self.packetsource_combobox.currentIndexChanged.connect(
            self.clean_packets_treeview)
        self.setStyleSheet(MAINWINDOW_STYLESHEET)

    def clear_messages_table(self) -> None:
        self.messages_table.setRowCount(0)

    def clear_nodes(self) -> None:
        self._store.clear_nodes()
        self._store.clear_nodes_metrics()
        self.mesh_table.setRowCount(0)
        self.nm_node_combobox.clear()
        self.nodes_total_lcd.display(0)
        self.nodes_gps_lcd.display(0)
        self.nodes_recently_lcd.display(0)
        self.messagerecipient_combobox.clear()
        self._telemetry_plot_item.setData(
                x=None,
                y=None)
        self._telemetry_plot_widget.setTitle("No data")

    def clear_packets(self) -> None:
        self._store.clear_radio_packets()
        self._store.clear_mqtt_packets()
        self.packets_treewidget.clear()
        self.packettype_combobox.clear()
        self.packettype_combobox.insertItem(0, "All")
        self.packetsource_combobox.clear()
        self.packetsource_combobox.insertItem(0, "All")
        self.packets_total_lcd.display(0)
        self.pm_node_combobox.clear()
        self._packets_plot_item.setData(
                x=None,
                y=None)
        self._packets_plot_widget.setTitle("No data")

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
        if index == 2:
            self.tabWidget.setTabText(3, "Messages")

    def refresh_ui(self) -> None:
        self._lock.acquire()
        if self._manager.is_connected():
            self.connect_button.setEnabled(False)
            self.disconnect_button.setEnabled(True)
            for button in self._action_buttons:
                button.setEnabled(True)
            for button in self._traceroute_buttons:
                button.setEnabled(True)
        else:
            self.connect_button.setEnabled(True)
            self.disconnect_button.setEnabled(False)
            for button in self._action_buttons:
                button.setEnabled(False)
            for button in self._traceroute_buttons:
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

    def refresh_status_header(
            self,
            status: MessageLevel = MessageLevel.UNKNOWN,
            message=None) -> None:
        """
        Update header status bar
        """
        self._lock.acquire()
        if message is not None:
            self.set_status(status, message)
        self._lock.release()

    def connect_device(self):
        device_path = self.device_combobox.currentText()
        if device_path:
            self._manager.set_meshtastic_device(device_path)
            self.set_status(MessageLevel.INFO, f"Connecting to {device_path}.")
            self.connect_device_signal.emit(self.reset_nodedb_checkbox.isChecked())
        else:
            self.set_status(MessageLevel.ERROR,
                            f"Cannot connect. Please specify a device path.")

    def disconnect_device(self) -> None:
        for i, device in enumerate(self._manager.get_meshtastic_devices()):
            self.device_combobox.clear()
            self.device_combobox.insertItem(i, device)
        self.disconnect_device_signal.emit()

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
            len(self.message_textedit.toPlainText().encode("utf-8"))
        self.remaining_chars_label.setText(
            f"{remaining_chars}/{TEXT_MESSAGE_MAX_CHARS}")

    def mesh_table_is_clicked(self, row, column) -> None:
        node_id = self.mesh_table.item(row, 2).text()
        long_name = self._store.get_long_name_from_id(node_id)
        if self._local_board_id and node_id == self._local_board_id:
            long_name = "Me"
        self.nm_node_combobox.setCurrentText(long_name)

    def init_map(self):
        self._map = Mapper()
        self.update_map_in_widget()

    def update_map_in_widget(self):
        self.nodes_map.setHtml(self._map.convert2html())

    def update_nodes_map(self):
        self._map.update(self._store.get_nodes())
        self.update_map_in_widget()

    def clean_plot(self, kind:str="") -> None:
        to_clean = [kind]
        if not kind:
            to_clean = ["telemetry", "packets"]
        for p in to_clean:
            widget = {
                "telemetry": self._telemetry_plot_widget,
                "packets": self._packets_plot_widget,
            }
            plot_item = {
                "telemetry": self._telemetry_plot_item,
                "packets": self._packets_plot_item,
            }
            plot_item[p].setData(
                x=None,
                y=None)
            widget[p].setTitle("No data")

    def update_node_metrics_buttons(self) -> None:
        self.nm_update_button.setEnabled(True)

    def update_packets_metrics_buttons(self) -> None:
        self.pm_update_button.setEnabled(True)

    def update_nodes_metrics(self) -> str:
        self.nm_update_button.setEnabled(False)
        node_id = self._store.get_id_from_long_name(
            self.nm_node_combobox.currentText())
        metric_name = self.nm_metric_combobox.currentText()
        if not node_id or not metric_name:
            self.clean_plot(kind="telemetry")
            return
        self.refresh_plot(node_id=node_id, metric_name=metric_name, kind="telemetry")

    def update_packets_metrics(self) -> str:
        self.pm_update_button.setEnabled(False)
        node_id = self._store.get_id_from_long_name(
            self.pm_node_combobox.currentText())
        metric_name = self.pm_metric_combobox.currentText()
        if not node_id or not metric_name:
            self.clean_plot(kind="packets")
            return
        self.refresh_plot(node_id=node_id, metric_name=metric_name, kind="packets")

    def refresh_plot(self, node_id: str, metric_name: str, kind:str) -> None:
        self._lock.acquire()
        metric = None
        if kind == "telemetry":
            metric = self._store.get_node_metrics(node_id, metric_name)
        elif kind == "packets":
            metric = self._store.get_packet_metrics(node_id, metric_name)
        else:
            self.clean_plot(kind=kind)
            self._lock.release()
            return
        if "timestamp" not in metric or metric_name not in metric:
            self.clean_plot(kind=kind)
            self._lock.release()
            return
        if len(
                list(
                    filter(
                lambda x: x is not None,
                metric[metric_name]))) == 0:
            self.clean_plot(kind=kind)
            self._lock.release()
            return

        if len(
            metric["timestamp"]) == len(
            metric[metric_name]) and len(
                metric[metric_name]) > 0:

            target_widget = {
                "telemetry": self._telemetry_plot_widget,
                "packets": self._packets_plot_widget,
            }
            target_item = {
                "telemetry": self._telemetry_plot_item,
                "packets": self._packets_plot_item,
            }
            none_indexes = [
                i for i, v in enumerate(
                    metric[metric_name]) if v is None]
            for i in reversed(none_indexes):
                metric["timestamp"].pop(i)
                metric[metric_name].pop(i)

            target_item[kind].setData(
                x=metric["timestamp"],
                y=metric[metric_name])
            target_widget[kind].getPlotItem().getViewBox().setRange(
                xRange=(min(metric["timestamp"]), max(metric["timestamp"])),
                yRange=(min(metric[metric_name]), max(metric[metric_name])),
            )
            target_widget[kind].setLabel('left', metric_name, units='')
            target_widget[kind].setLabel('bottom', 'Timestamp', units='')
            target_widget[kind].setTitle(
                f'{metric_name} vs time for node {self._store.get_long_name_from_id(node_id)}')
        self._lock.release()

    def send_message(self):
        message = self.message_textedit.toPlainText()
        channel_name = self.messagechannel_combobox.currentText()
        recipient = self._store.get_id_from_long_name(
            self.messagerecipient_combobox.currentText())
        channel_index = -1
        try:
            channel_index = self._manager.get_data_store(
            ).get_channel_index_from_name(channel_name)
        except Exception:
            channel_index = 0 # this is the default and seems to be standard before 2.5.X firmwares
        finally:
            pass

        # Update timeout before sending
        if channel_index != -1 and message:
            m = MeshtasticMessage(
                mid=-1,
                date=datetime.now(),
                from_id=self._local_board_id,
                to_id=recipient,
                content=message,
                want_ack=True,
                channel_index=channel_index,
            )
            self.send_message_signal.emit(m)
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
        recently_seen = list(filter(lambda x: x.rx_counter > 0, nodes.values()))
        self.nodes_recently_lcd.display(len(recently_seen))

        # filter by nodes_filter
        filtered = nodes.values()  # nofilter
        hopfilter = {
            "1-hop":1,
            "2-hops":2,
            "3-hops":3,
            "4-hops":4,
            "5-hops":5,
            "6-hops":6,
            "7-hops":7,
        }
        if self.shortcut_filter_combobox.currentText() == "Recently seen":
            filtered = recently_seen
        elif self.shortcut_filter_combobox.currentText() == "Neighbors":
            filtered = list(filter(lambda x: x.hopsaway == 0, nodes.values()))
        elif self.shortcut_filter_combobox.currentText() in hopfilter.keys():
            filtered = list(filter(lambda x: x.hopsaway == hopfilter[self.shortcut_filter_combobox.currentText()], nodes.values()))

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

        # update multiples inputs
        # TODO: create a dedicated signal for that
        # messages nodes
        current_recipient = None
        if self.messagerecipient_combobox.currentText():
            current_recipient = self.messagerecipient_combobox.currentText()
        self.messagerecipient_combobox.clear()
        self.messagerecipient_combobox.insertItem(0, "All")

        # network metrics nodes
        current_nm_node = self.nm_node_combobox.currentText()
        self.nm_node_combobox.clear()
        self.nm_node_combobox.insertItem(
            0, "Me")
        for i, node in enumerate(filtered):
            if node.id == self._local_board_id:
                continue
            self.messagerecipient_combobox.insertItem(
                i + 1, node.long_name if node.long_name else node.id)
            self.nm_node_combobox.insertItem(
                i, node.long_name if node.long_name else node.id)
        self.nm_node_combobox.setCurrentText(current_nm_node)
        if current_recipient:
            self.messagerecipient_combobox.setCurrentText(current_recipient)

        # update table
        rows: list[dict[str, any]] = []
        for node in filtered:
            row = {"Status": "", "User": "", "ID": ""}

            status_line = []

            if node.lastseen:
                recently_seen = node.lastseen > datetime.now() - timedelta(minutes=30)
                if recently_seen: status_line.append("📶")
            if node.rx_counter > 0: status_line.append(f"{node.rx_counter}✉️")
            if node.has_location(): status_line.append("📍")
            if node.public_key: status_line.append("🔑")
            if node.is_mqtt_gateway: status_line.append("🖥️")
            if node.hopsaway is not None: status_line.append(f"{node.hopsaway}✈️")

            row.update(
                {
                    "Status": " ".join(status_line),
                    "User": node.long_name,
                    "AKA": node.short_name,
                    "ID": node.id,
                    "Action": None,
                    "Role": node.role,
                    "Hardware": node.hardware,
                }
            )
            node.date2str()
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
            "Action",
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
                current_widget = self.mesh_table.cellWidget(row_idx, col_idx)
                if current_item is None and current_widget is None:
                    if col_idx == 4: # insert widget in cell
                        btn = QPushButton("Traceroute")
                        btn.setEnabled(self._manager.is_connected())
                        self.mesh_table.setCellWidget(row_idx, col_idx, btn)
                        self._traceroute_buttons.append(btn)
                        btn.clicked.connect(lambda: self.traceroute(self.mesh_table.item(self.mesh_table.indexAt(self.sender().pos()).row(), 2).text()))
                    else:
                        data = str(value)
                        if data == "None":
                            data = ""
                        self.mesh_table.setItem(row_idx, col_idx, QTableWidgetItem(data))
                if current_item is not None:
                    if current_item.text() != str(value):
                        data = str(value)
                        if data == "None":
                            data = ""
                        current_item.setText(data)
        self.mesh_table.resizeColumnsToContents()

    def get_nodes(self):
        self.get_nodes_signal.emit()

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
        for cb in ["messagechannel_combobox"]:
            getattr(self, cb).clear()
            for i, channel in enumerate(channels):
                getattr(self, cb).insertItem(i, channel.name)

    def retrieve_channels(self):
        self.retrieve_channels_signal.emit()

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

    def traceroute(self, dest_id:str="", maxhops:int=5, dummy:bool=False):
        self.traceroute_table.setRowCount(0)
        self.traceroute_table.setColumnCount(3)
        self.traceroute_table.setHorizontalHeaderLabels(
            ["Id", "SNR To", "SNR Back"])
        self.traceroute_signal.emit(dest_id, DEFAULT_TRACEROUTE_CHANNEL, maxhops)

    def update_received_message(self) -> None:
        if self.tabWidget.currentIndex() != 3:
            self.tabWidget.setTabText(3, "Messages 🔴")

        headers = self._get_meshtastic_message_header_fields()
        columns = list(headers.keys())
        self.messages_table.setColumnCount(len(columns))
        self.messages_table.setHorizontalHeaderLabels(headers.values())

        channels = self._store.get_channels()
        messages = self._store.get_messages()
        self.messages_table.setRowCount(len(messages))
        rows: list[dict[str, any]] = []

        for message in messages:
            message.date2str("%Y-%m-%d %H:%M:%S")
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
                    if getattr(message, "ack_status") is not None:
                        if getattr(message, "ack_status") is True:
                            if getattr(message, "ack_by") is not None:
                                if getattr(message, "ack_by") != getattr(message, "to_id"):
                                    label = "☁️"
                                else:
                                    label = "✅"
                        else:
                            label = "❌"
                    data[headers["ack"]] = label
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
        packets = self._store.get_radio_packets()
        alreading_existing_packets = [
            self.packets_treewidget.topLevelItem(i).text(0) for i in range(
                self.packets_treewidget.topLevelItemCount())]

        current_pm_node = self.pm_node_combobox.currentText()
        self.pm_node_combobox.clear()
        inserted = []
        for i, packet in enumerate(packets):
            name = self._store.get_long_name_from_id(packet.from_id)
            if name not in inserted:
                self.pm_node_combobox.insertItem(i, name)
                inserted.append(name)
        self.pm_node_combobox.setCurrentText(current_pm_node)

        filtered_packets = packets
        if self.packettype_combobox.currentText() != "All":
            filtered_packets = list(
                filter(
                    lambda x: x.port_num == self.packettype_combobox.currentText(),
                    packets))

        if self.packetsource_combobox.currentText() != "All":
            filtered_packets = list(
                filter(
                    lambda x: x.from_id == self._store.get_id_from_long_name(self.packetsource_combobox.currentText()),
                    filtered_packets))

        for packet in filtered_packets:
            packet.date2str()
            if self.packettype_combobox.findText(packet.port_num) == -1:
                self.packettype_combobox.insertItem(
                    1000, packet.port_num)  # insert last

            if self.packetsource_combobox.findText(self._store.get_long_name_from_id(packet.from_id)) == -1:
                self.packetsource_combobox.insertItem(
                    100000, self._store.get_long_name_from_id(packet.from_id))  # insert last

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
        nnow = datetime.now().strftime(TIME_FORMAT)
        tmp.append(f"[{nnow}] {message}")
        self.output_textedit.setText("".join(tmp))
        cursor = QTextCursor(self.output_textedit.textCursor())
        cursor.setPosition(len(self.output_textedit.toPlainText()))
        self.output_textedit.setTextCursor(cursor)

    def update_device_details(self, configuration: dict):
        self.output_textedit.setText(configuration)
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
        nnow = datetime.now().strftime(TIME_FORMAT)
        tmp.append(f"[{nnow}] {log}")
        self.mqtt_output_textedit.setText("".join(tmp))
        cursor = QTextCursor(self.mqtt_output_textedit.textCursor())
        cursor.setPosition(len(self.mqtt_output_textedit.toPlainText()))
        self.mqtt_output_textedit.setTextCursor(cursor)

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
        self.mqtt_connect_signal.emit(m)

    def export_mqtt_logs(self) -> None:
        nnow = datetime.now().strftime("%Y-%m-%d__%H_%M_%S")
        fpath = f"mqtt_logs_{nnow}.log"
        with open(fpath, "w") as text_file:
            text_file.write(self.mqtt_output_textedit.toPlainText())
            absp = os.path.abspath(fpath)
            trace = f"<a href='file://{absp}'>Exported mqtt logs to file: {fpath}</a>"
            self.set_status(MessageLevel.INFO, trace)

    def export_packets(self) -> None:
        packets = self._store.get_radio_packets()
        [x.date2str() for x in packets]
        packets_list = [asdict(x) for x in packets]
        for p in packets_list:
            try:
                p["payload"] = str(p["payload"])
            except Exception as e:
                p["payload"] = "convertion error"
        data_json = json.dumps(packets_list, indent=4)
        nnow = datetime.now().strftime("%Y-%m-%d__%H_%M_%S")
        fpath = f"packet_{nnow}.json"
        with open(fpath, "w") as json_file:
            json_file.write(data_json)
            absp = os.path.abspath(fpath)
            trace = f"<a href='file://{absp}'>Exported packets to file: {fpath}</a>"
            self.set_status(MessageLevel.INFO, trace)

    def export_chat(self) -> None:
        messages = self._store.get_messages()
        [x.date2str() for x in messages]
        messages = [asdict(x) for x in messages]
        data_json = json.dumps(messages, indent=4)
        nnow = datetime.now().strftime("%Y-%m-%d__%H_%M_%S")
        fpath = f"messages_{nnow}.json"
        with open(fpath, "w") as json_file:
            json_file.write(data_json)
            absp = os.path.abspath(fpath)
            trace = f"<a href='file://{absp}'>Exported chat to file: {fpath}</a>"
            self.set_status(MessageLevel.INFO, trace)

    def export_nodes(self) -> None:
        nodes = self._store.get_nodes().values()
        [x.date2str() for x in nodes]
        nodes = [asdict(x) for x in nodes]
        data_json = json.dumps(nodes, indent=4)
        nnow = datetime.now().strftime("%Y-%m-%d__%H_%M_%S")
        fpath = f"nodes_{nnow}.json"
        with open(fpath, "w") as json_file:
            json_file.write(data_json)
            absp = os.path.abspath(fpath)
            trace = f"<a href='file://{absp}'>Exported nodes to file: {fpath}</a>"
            self.set_status(MessageLevel.INFO, trace)

    def quit(self) -> None:
        self._manager.quit()
        self._mqtt_manager.quit()
        self.master.quit()

    def run(self):
        self.master.mainloop()
