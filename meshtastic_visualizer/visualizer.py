#!/usr/bin/env python3


import os
import re
import json
from threading import Lock
from datetime import datetime
from typing import List, Optional
from PyQt6 import QtCore
from PyQt6 import QtWidgets, uic
from PyQt6.QtGui import QTextCursor
from PyQt6.QtWidgets import QTableWidgetItem, QTreeWidgetItem, QPushButton, QFileDialog
from PyQt6.QtCore import pyqtSignal, QSettings
import pyqtgraph as pg
from pyqtgraph import DateAxisItem
from dataclasses import asdict

from .manager import MeshtasticManager
from .resources import MessageLevel, \
    MeshtasticMessage, \
    MeshtasticNode, \
    Packet, \
    TEXT_MESSAGE_MAX_CHARS, \
    MeshtasticMQTTClientSettings, \
    TIME_FORMAT, \
    DEFAULT_TRACEROUTE_CHANNEL, \
    ConnectionKind, \
    PacketInfoType, \
    BROADCAST_ADDR, \
    BROADCAST_NAME
from .node_actions_widget import NodeActionsWidget

from .mqtt import MeshtasticMQTT
from .datastore import MeshtasticDataStore
from .mapper import Mapper


class MeshtasticQtApp(QtWidgets.QMainWindow):
    connect_device_signal = pyqtSignal(ConnectionKind, str, bool)
    disconnect_device_signal = pyqtSignal()
    scan_serial_devices_signal = pyqtSignal()
    scan_ble_devices_signal = pyqtSignal()
    get_nodes_signal = pyqtSignal()
    send_message_signal = pyqtSignal(MeshtasticMessage)
    retrieve_channels_signal = pyqtSignal()
    traceroute_signal = pyqtSignal(str, int, int)
    send_telemetry_signal = pyqtSignal()
    send_position_signal = pyqtSignal()
    mqtt_connect_signal = pyqtSignal(MeshtasticMQTTClientSettings)

    def __init__(self):
        self._lock = Lock()
        super(MeshtasticQtApp, self).__init__()
        uic.loadUi('resources/app.ui', self)
        self.setWindowFlags(QtCore.Qt.WindowType.CustomizeWindowHint |
                            QtCore.Qt.WindowType.WindowCloseButtonHint | QtCore.Qt.WindowType.WindowMinimizeButtonHint)
        self.setFixedSize(self.size())
        self.show()
        self._settings = QSettings("antlas0", "meshtastic_visualizer")

        self._map = None
        self._map_custom_tiles_uri = self._settings.value("map_custom_tiles_uri", "")
        self._local_board_ln = ""
        self._telemetry_plot_widget = pg.PlotWidget()
        self._telemetry_plot_widget.plotItem.getViewBox().setMouseMode(pg.ViewBox.RectMode)
        self._packets_plot_widget = pg.PlotWidget()
        self._packets_plot_widget.plotItem.getViewBox().setMouseMode(pg.ViewBox.RectMode)
        self._telemetry_plot_item = pg.ScatterPlotItem(
            pen=pg.mkPen(
                '#007aff',
                width=1),
            symbol='o',
            symbolPen='b',
            symbolSize=8,
            hoverable=True)
        self._telemetry_plot_widget.addItem(self._telemetry_plot_item)
        self._packets_plot_item = pg.ScatterPlotItem(
            pen=pg.mkPen(
                '#007aff',
                width=1),
            symbol='o',
            symbolPen='b',
            symbolSize=8,
            hoverable=True)
        self._packets_plot_widget.addItem(self._packets_plot_item)

        # Variables
        self.status_var: str = ""
        self._local_board_id: str = ""
        self._action_buttons = []
        self._current_output_folder = self._settings.value("output_folder", os.getcwd())
        self._store = MeshtasticDataStore()
        self._manager = MeshtasticManager()
        self.setup_ui()

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
        self._manager.notify_local_device_configuration_signal.connect(
            self.update_device_details)
        self._manager.notify_new_packet.connect(
            self.update_packet_received)
        self._manager.notify_message_signal.connect(
            self.update_received_message)
        self._mqtt_manager.notify_message_signal.connect(
            self.update_received_message)
        self._mqtt_manager.notify_new_packet.connect(
            self.update_packet_received)
        self._manager.notify_traceroute_signal.connect(self.update_traceroute)
        self._manager.notify_channels_signal.connect(
            self.update_channels_list)
        self._manager.notify_channels_signal.connect(
            self.update_channels_table)
        self._manager.notify_nodes_update.connect(
            self.update_nodes)
        self._manager.notify_serial_devices_signal.connect(self._update_meshtastic_serial_devices)
        self._manager.notify_ble_devices_signal.connect(self._update_meshtastic_ble_devices)
        self._manager.notify_log_line.connect(self._update_device_logs)
        self._mqtt_manager.notify_nodes_update.connect(
            self.update_nodes)
        self._mqtt_manager.notify_mqtt_logs.connect(
            self.update_received_mqtt_log)

        self.connect_device_signal.connect(self._manager.connect_device)
        self.connect_device_signal.connect(self.clear_messages_table)
        self.disconnect_device_signal.connect(self._manager.disconnect_device)
        self.scan_ble_devices_signal.connect(self._manager.ble_scan_devices)
        self.scan_serial_devices_signal.connect(self._manager.serial_scan_devices)
        self.send_message_signal.connect(self._manager.send_text_message)
        self.retrieve_channels_signal.connect(self._manager.retrieve_channels)
        self.get_nodes_signal.connect(self.update_nodes_map)
        self.traceroute_signal.connect(self._manager.send_traceroute)
        self.send_position_signal.connect(self._manager.send_position)
        self.send_telemetry_signal.connect(self._manager.send_telemetry)
        self.mqtt_connect_signal.connect(
            self._mqtt_manager.configure_and_start)
        self.export_chat_button.pressed.connect(self.export_chat)
        self.export_packets_button.pressed.connect(self.export_packets)
        self.export_nodes_button.pressed.connect(self.export_nodes)
        self.export_node_metrics_button.pressed.connect(self.export_node_metrics)
        self.clear_mqtt_button.pressed.connect(self.mqtt_output_textedit.clear)
        self.clear_console_button.pressed.connect(self.console_logs_textedit.clear)
        self.clear_messages_button.pressed.connect(self.clear_messages_table)
        self.clear_messages_button.pressed.connect(self._store.clear_messages)
        self.clear_nodes_button.pressed.connect(self.clear_nodes)
        self.clear_node_metrics_button.pressed.connect(self.clear_nodes_metrics)
        self.clear_packets_button.pressed.connect(self.clear_packets)
        self.export_mqtt_button.pressed.connect(self.export_mqtt_logs)
        self.export_console_button.pressed.connect(self.export_console_logs)
        self.start_pause_console_button.clicked.connect(self._update_console_button)
        for i, metric in enumerate(
                self._store.get_node_metrics_fields()):
            self.nm_metric_combobox.insertItem(
                i + 1, metric)
        for i, metric in enumerate(
                self._store.get_packet_metrics_fields()):
            self.pm_metric_combobox.insertItem(
                i + 1, metric)
        self.nodes_filter_linedit.textChanged.connect(self.update_nodes)
        self.shortcut_filter_combobox.currentTextChanged.connect(self.update_nodes)
        self.mqtt_connect_button.pressed.connect(self.connect_mqtt)
        self.mqtt_disconnect_button.pressed.connect(self._mqtt_manager.disconnect_mqtt)

    def set_status(self, loglevel: MessageLevel, message: str) -> None:
        if loglevel.value == MessageLevel.ERROR.value:
            self.notification_bar.setText(message)

        if loglevel.value == MessageLevel.INFO.value or loglevel.value == MessageLevel.UNKNOWN.value:
            self.notification_bar.setText(message)

    def _update_device_logs(self, line:str) -> None:
        if not self.start_pause_console_button.isChecked():
            try:
                ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
                result = ansi_escape.sub('', line)
            except Exception as e:
                pass
            else:
                self.console_logs_textedit.append(result)

    def _request_meshtastic_serial_devices(self) -> None:
        self.set_status(MessageLevel.INFO, "Scanning serial devices.")
        self.serial_scan_button.setText("⌛ Serial Scan")
        self.serial_devices_combobox.clear()
        self.serial_connect_button.setEnabled(False)
        self.serial_scan_button.setEnabled(False)
        self.scan_serial_devices_signal.emit()

    def _update_meshtastic_serial_devices(self, devices:list) -> None:
        if len(devices) == 1:
            self.serial_devices_combobox.insertItem(0, devices[0])
            self.serial_devices_combobox.setCurrentText(devices[0])
        else:
            for i, device in enumerate(devices):
                self.serial_devices_combobox.insertItem(i, device)
        self.set_status(MessageLevel.INFO, f"Found {len(devices)} serial device(s).")
        self.serial_scan_button.setText("🔍 Serial Scan")
        self.serial_connect_button.setEnabled(True)
        self.serial_scan_button.setEnabled(True)

    def _request_meshtastic_ble_devices(self) -> None:
        self.set_status(MessageLevel.INFO, "Scanning bluetooth devices.")
        self.ble_scan_button.setText("⌛ BLE Scan")
        self.ble_address_combobox.clear()
        self.ble_connect_button.setEnabled(False)
        self.ble_scan_button.setEnabled(False)
        self.scan_ble_devices_signal.emit()

    def _update_meshtastic_ble_devices(self, devices:list) -> None:
        if len(devices) == 1:
            self.ble_address_combobox.insertItem(0, devices[0].address)
            self.ble_address_combobox.setCurrentText(devices[0].address)
        else:
            for i, device in enumerate(devices):
                self.ble_address_combobox.insertItem(i, device.address)
        self.set_status(MessageLevel.INFO, f"Found {len(devices)} bluetooth device(s).")
        self.ble_scan_button.setText("🔍 BLE Scan")
        self.ble_connect_button.setEnabled(True)
        self.ble_scan_button.setEnabled(True)

    def setup_ui(self) -> None:
        self.mynodeinfo_refresh_button.clicked.connect(self._manager.get_local_node_infos)
        if self._settings.value("serial_port", ""):
            self.serial_devices_combobox.insertItem(0, self._settings.value("serial_port", ""))
            self.serial_devices_combobox.setCurrentText(self._settings.value("serial_port", ""))
        if self._settings.value("ble_address", ""):
            self.ble_address_combobox.insertItem(0, self._settings.value("ble_address", ""))
            self.ble_address_combobox.setCurrentText(self._settings.value("ble_address", ""))
        self.tabWidget.currentChanged.connect(self.remove_notification_badge)
        self.notification_bar.setOpenExternalLinks(True)
        self.serial_connect_button.clicked.connect(self.connect_device_serial)
        self.tcp_connect_button.clicked.connect(self.connect_device_tcp)
        self.ble_connect_button.clicked.connect(self.connect_device_ble)
        self.output_folder_button.clicked.connect(self.choose_output_folder)
        self.output_folder_label.setReadOnly(True)
        self.output_folder_label.setText(os.path.basename(self._current_output_folder))
        self.serial_scan_button.clicked.connect(self._request_meshtastic_serial_devices)
        self.ble_scan_button.clicked.connect(self._request_meshtastic_ble_devices)
        self.serial_disconnect_button.clicked.connect(self.disconnect_device)
        self.tcp_disconnect_button.clicked.connect(self.disconnect_device)
        self.ble_disconnect_button.clicked.connect(self.disconnect_device)
        self.load_nodedb_checkbox.stateChanged.connect(self.load_nodedb_checkbox_bis.setChecked)
        self.load_nodedb_checkbox.stateChanged.connect(self.load_nodedb_checkbox_ter.setChecked)
        self.load_nodedb_checkbox_bis.stateChanged.connect(self.load_nodedb_checkbox.setChecked)
        self.load_nodedb_checkbox_bis.stateChanged.connect(self.load_nodedb_checkbox_ter.setChecked)
        self.load_nodedb_checkbox_ter.stateChanged.connect(self.load_nodedb_checkbox.setChecked)
        self.load_nodedb_checkbox_ter.stateChanged.connect(self.load_nodedb_checkbox_bis.setChecked)
        self.refresh_map_button.clicked.connect(self.get_nodes)
        self.send_button.clicked.connect(self.send_message)
        self.nm_update_button.setEnabled(False)
        self.nm_update_button.pressed.connect(self.update_nodes_metrics)
        self.nm_metric_combobox.currentTextChanged.connect(
            self.update_node_metrics_buttons)
        self.pm_update_button.pressed.connect(self.update_packets_metrics)
        self.messagechannel_combobox.textActivated.connect(
            self.update_received_message
        )
        self.mesh_table.cellClicked.connect(self.mesh_table_is_clicked)
        self.message_textedit.textChanged.connect(
            self.update_text_message_length)
        self.remaining_chars_label.setText(
            f"{TEXT_MESSAGE_MAX_CHARS}/{TEXT_MESSAGE_MAX_CHARS}")
        self.init_map()
        self.messages_table.setTextElideMode(QtCore.Qt.TextElideMode.ElideNone)
        self.messages_table.setColumnCount(
            len(self._get_meshtastic_message_header_fields().keys()))
        self.messages_table.setHorizontalHeaderLabels(
            list(self._get_meshtastic_message_header_fields().values()))
        self.traceroute_table.setColumnCount(3)
        self.traceroute_table.setHorizontalHeaderLabels(
            ["Id", "SNR To", "SNR Back"])
        self.batterylevel_progressbar.hide()
        self.serial_connect_button.setEnabled(True)
        self.serial_disconnect_button.setEnabled(False)
        self.tcp_connect_button.setEnabled(True)
        self.ble_connect_button.setEnabled(True)
        self.tcp_disconnect_button.setEnabled(False)
        self.ble_disconnect_button.setEnabled(False)
        self._action_buttons = [
            self.send_button,
            self.message_textedit,
            self.mynodeinfo_refresh_button,
        ]
        for button in self._action_buttons:
            button.setEnabled(False)

        for i, f in enumerate(["All", "Recently seen", "Positioned", "Neighbors", "1-hop",
                              "2-hops", "3-hops", "4-hops", "5-hops", "6-hops", "7-hops"]):
            self.shortcut_filter_combobox.insertItem(i, f)

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
            widget[p].getPlotItem().getAxis('bottom').setTextPen(pg.mkPen(color='k'))
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
        self.nodes_gps_lcd.setDecMode()
        self.node_packets_number.setDecMode()
        self.nodes_recently_lcd.setDecMode()
        self.ipaddress_textedit.setText(self._settings.value("tcp", "http://192.168.1.1"))
        self.mqtt_host_linedit.setText(self._settings.value("mqtt_host", ""))
        self.mqtt_port_spinbox.setValue(
            int(self._settings.value("mqtt_port", 1883)))
        self.mqtt_username_linedit.setText(
            self._settings.value("mqtt_username", ""))
        self.mqtt_password_linedit.setText(
            self._settings.value("mqtt_password", ""))
        self.mqtt_topic_linedit.setText(self._settings.value("mqtt_topic", ""))
        self.mqtt_key_linedit.setText(self._settings.value("mqtt_key", "AQ=="))
        self.packets_treewidget.itemClicked.connect(self.adjust_packets_treeview)
        self.packets_treewidget.setWordWrap(True)
        self.packets_treewidget.setTextElideMode(QtCore.Qt.TextElideMode.ElideNone)
        self.packets_treewidget.setHeaderLabels(["Packet", "Details"])
        self.packettype_combobox.insertItem(0, "All")
        self.packettype_combobox.currentIndexChanged.connect(
            self.update_packets_filtered)
        self.packetsource_combobox.insertItem(0, "All")
        self.packetsource_combobox.currentTextChanged.connect(
            self.update_packets_filtered)
        self.packetmedium_combobox.insertItem(0, "All")
        self.packetmedium_combobox.insertItem(1, "Radio")
        self.packetmedium_combobox.insertItem(2, "MQTT")
        self.packetmedium_combobox.currentIndexChanged.connect(self.update_packets_filtered)

        self.activate_custom_tiles_checkbox.setChecked(False)
        self.custom_tiles_uri_linedit.setVisible(False)
        self.activate_custom_tiles_checkbox.stateChanged.connect(self.activate_custom_tiles)
        self.custom_tiles_uri_linedit.textChanged.connect(self.update_custom_tiles)

    def choose_output_folder(self):
        dialog = QFileDialog(self)
        dialog.setDirectory(self._current_output_folder if self._current_output_folder else os.getcwd())
        dialog.setFileMode(QFileDialog.FileMode.Directory)
        dialog.setViewMode(QFileDialog.ViewMode.List)
        if dialog.exec():
            if len(dialog.selectedFiles()) == 1:
                self._current_output_folder = dialog.selectedFiles()[0]
                self._settings.setValue("output_folder", self._current_output_folder)
                self.refresh_status_header(MessageLevel.INFO, f"Output directory is set to: {self._current_output_folder}")
                self.output_folder_label.setText(os.path.basename(self._current_output_folder))

    def clear_messages_table(self) -> None:
        self.messages_table.setRowCount(0)

    def clear_nodes(self) -> None:
        self._store.clear_nodes()
        self._store.clear_nodes_metrics()
        self.update_channels_list()
        self.mesh_table.setRowCount(0)
        self.nm_node_label.clear()
        self.nodes_total_lcd.display(0)
        self.nodes_gps_lcd.display(0)
        self.nodes_recently_lcd.display(0)
        self._telemetry_plot_item.setData(
            x=None,
            y=None)
        self._telemetry_plot_widget.setTitle("No data")

    def clear_nodes_metrics(self) -> None:
        self._store.clear_nodes_metrics()
        self.nm_node_label.clear()
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
        self._packets_plot_item.setData(
            x=None,
            y=None)
        self._packets_plot_widget.setTitle("No data")
        self.reset_node_packets_counters()

    def _get_meshtastic_message_header_fields(self) -> dict:
        return {
            "date": "Date",
            "ack": "Ack",
            "pki_encrypted": "Encrypted",
            "from_id": "From",
            "content": "Message",
        }

    def remove_notification_badge(self, index):
        if index == 3:
            self.tabWidget.setTabText(3, "Messages")

    def refresh_ui(self) -> None:
        self._lock.acquire()
        self.serial_connect_button.setEnabled(True)
        self.serial_disconnect_button.setEnabled(False)
        self.serial_scan_button.setEnabled(True)
        self.tcp_connect_button.setEnabled(True)
        self.tcp_disconnect_button.setEnabled(False)
        self.ble_connect_button.setEnabled(True)
        self.ble_disconnect_button.setEnabled(False)
        self.ble_scan_button.setEnabled(True)
        for button in self._action_buttons:
            button.setEnabled(False)
        self.connection_tabs.setTabEnabled(0, True);
        self.connection_tabs.setTabEnabled(1, True);
        self.connection_tabs.setTabEnabled(2, True);

        if self._manager.is_serial_connected():
            self.serial_scan_button.setEnabled(False)
            self.serial_connect_button.setEnabled(False)
            self.serial_disconnect_button.setEnabled(True)
            for button in self._action_buttons:
                button.setEnabled(True)
            self.connection_tabs.setTabEnabled(0, True);
            self.connection_tabs.setTabEnabled(1, False);
            self.connection_tabs.setTabEnabled(2, False);

        if self._manager.is_tcp_connected():
            self.tcp_connect_button.setEnabled(False)
            self.tcp_disconnect_button.setEnabled(True)
            for button in self._action_buttons:
                button.setEnabled(True)
            self.connection_tabs.setTabEnabled(0, False);
            self.connection_tabs.setTabEnabled(1, True);
            self.connection_tabs.setTabEnabled(2, False);

        if self._manager.is_ble_connected():
            self.ble_scan_button.setEnabled(False)
            self.ble_connect_button.setEnabled(False)
            self.ble_disconnect_button.setEnabled(True)
            for button in self._action_buttons:
                button.setEnabled(True)
            self.connection_tabs.setTabEnabled(0, False);
            self.connection_tabs.setTabEnabled(1, False);
            self.connection_tabs.setTabEnabled(2, True);

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

    def connect_device_serial(self):
        self.connection_tabs.setTabEnabled(0, True);
        self.connection_tabs.setTabEnabled(1, False);
        self.connection_tabs.setTabEnabled(2, False);
        self.serial_scan_button.setEnabled(False)
        self.serial_connect_button.setEnabled(False)
        self.serial_disconnect_button.setEnabled(False)
        device_path = self.serial_devices_combobox.currentText()
        if device_path:
            self.set_status(MessageLevel.INFO, f"Connecting to {device_path}.")
            self.connect_device_signal.emit(ConnectionKind.SERIAL, device_path, self.load_nodedb_checkbox.isChecked())
            self._settings.setValue("serial_port", self.serial_devices_combobox.currentText())
        else:
            self.set_status(MessageLevel.ERROR, f"Cannot connect. Please specify a device path.")
            self.serial_connect_button.setEnabled(True)
            self.serial_scan_button.setEnabled(True)

    def connect_device_tcp(self):
        self.connection_tabs.setTabEnabled(0, False);
        self.connection_tabs.setTabEnabled(1, True);
        self.connection_tabs.setTabEnabled(2, False);
        self.tcp_connect_button.setEnabled(False)
        self.tcp_disconnect_button.setEnabled(False)
        ip = self.ipaddress_textedit.text()
        if ip:
            if "https" in ip:
                self.set_status(MessageLevel.INFO, "Cannot connect through https, only http.")
                return
            self.set_status(MessageLevel.INFO, f"Connecting to {ip}.")
            self._settings.setValue("tcp", ip)
            self.connect_device_signal.emit(ConnectionKind.TCP, ip, self.load_nodedb_checkbox_bis.isChecked())
        else:
            self.set_status(MessageLevel.ERROR, f"Cannot connect. Please specify an accessible ip address.")

    def connect_device_ble(self):
        self.connection_tabs.setTabEnabled(0, False);
        self.connection_tabs.setTabEnabled(1, False);
        self.connection_tabs.setTabEnabled(2, True);
        self.ble_scan_button.setEnabled(False)
        self.ble_connect_button.setEnabled(False)
        self.ble_disconnect_button.setEnabled(False)
        ble_address = self.ble_address_combobox.currentText()
        if ble_address:
            self.set_status(MessageLevel.INFO, f"Connecting to {ble_address}.")
            self._settings.setValue("ble_address", self.ble_address_combobox.currentText())
        else:
            self.set_status(MessageLevel.INFO,f"Connecting to first detected device.")
        self.connect_device_signal.emit(ConnectionKind.BLE, ble_address, self.load_nodedb_checkbox_ter.isChecked())

    def disconnect_device(self) -> None:
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
            row_position = self.traceroute_table.rowCount()
            self.traceroute_table.insertRow(row_position)
            self.traceroute_table.setItem(
                row_position, 0, QTableWidgetItem(device))
    
        for i in range(len(snr_towards)):
            self.traceroute_table.setItem(
                i, 1, QTableWidgetItem("↓" + str(snr_towards[i])))
        for i in range(len(snr_back)):
            self.traceroute_table.setItem(
                i, 2, QTableWidgetItem("↑" + str(snr_back[i])))
        self.traceroute_table.resizeColumnsToContents()
        self.traceroute_table.resizeRowsToContents()

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
        self.update_node_metrics_buttons()
        long_name = self._store.get_long_name_from_id(node_id)
        self.nm_node_label.setText(long_name)

    def activate_custom_tiles(self, activate:bool) -> None:
        self.custom_tiles_uri_linedit.setText(self._map_custom_tiles_uri)
        self.custom_tiles_uri_linedit.setVisible(activate)

    def update_custom_tiles(self) -> None:
        uri = self.custom_tiles_uri_linedit.text()
        self._settings.setValue("map_custom_tiles_uri", uri)
        self._map_custom_tiles_uri = uri

    def init_map(self):
        self._map = Mapper(custom_tiles_uri=self._map_custom_tiles_uri)
        self.update_map_in_widget()

    def update_map_in_widget(self):
        self.nodes_map.setHtml(self._map.convert2html())

    def update_nodes_map(self):
        self._map.update(self._store.get_nodes(), self._map_custom_tiles_uri)
        self.update_map_in_widget()

    def clean_plot(self, kind: str = "") -> None:
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

    def update_nodes_metrics(self) -> str:
        self.nm_update_button.setEnabled(False)
        node_id = self._store.get_id_from_long_name(self.nm_node_label.text())
        metric_name = self.nm_metric_combobox.currentText()
        if not node_id or not metric_name:
            self.clean_plot(kind="telemetry")
            return
        self.refresh_plot(
            node_id=node_id,
            metric_name=metric_name,
            kind="telemetry")

    def update_packets_metrics(self) -> str:
        node_id = self._store.get_id_from_long_name(
            self.packetsource_combobox.currentText())
        metric_name = self.pm_metric_combobox.currentText()
        if not node_id or not metric_name:
            self.clean_plot(kind="packets")
            return
        self.refresh_plot(
            node_id=node_id,
            metric_name=metric_name,
            kind="packets")

    def refresh_plot(self, node_id: str, metric_name: str, kind: str) -> None:
        self._lock.acquire()
        metric = None
        if kind == "telemetry":
            metric = self._store.get_node_metrics(node_id, metric_name)
        elif kind == "packets":
            metric = self._store.get_packet_metrics(node_id, metric_name, self.packettype_combobox.currentText())
        else:
            self.clean_plot(kind=kind)
            self._lock.release()
            return
        if "timestamp" not in metric or "value" not in metric:
            self.clean_plot(kind=kind)
            self._lock.release()
            return
        if len(
                list(
                    filter(
                lambda x: x is not None,
                metric["value"]))) == 0:
            self.clean_plot(kind=kind)
            self._lock.release()
            return

        if len(
            metric["timestamp"]) == len(
            metric["value"]) and len(
                metric["value"]) > 0:

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
                    metric["value"]) if v is None]
            for i in reversed(none_indexes):
                metric["timestamp"].pop(i)
                metric["value"].pop(i)

            target_item[kind].setData(
                x=metric["timestamp"],
                y=metric["value"])
            target_widget[kind].getPlotItem().getViewBox().setRange(
                xRange=(min(metric["timestamp"]), max(metric["timestamp"])),
                yRange=(min(metric["value"]), max(metric["value"])),
            )
            target_widget[kind].setLabel('left', "value", units='')
            target_widget[kind].setLabel('bottom', 'Timestamp', units='')
            target_widget[kind].setTitle(
                f'{metric_name} vs time for node {self._store.get_long_name_from_id(node_id)}')
        self._lock.release()

    def send_message(self):
        if not self._local_board_id:
            self.refresh_status_header(message="Not connected to a board, cannot send.")
            return

        message = self.message_textedit.toPlainText()
        recipient = self.messagechannel_combobox.currentText() # channel or DM ?
        if recipient in self.get_channel_names():
            # channel broadcast
            try:
                channel_index = self._store.get_channel_index_from_name(recipient)
                recipient = BROADCAST_NAME
            except Exception as e:
                raise e
        else:
            # DM
            recipient = self._store.get_id_from_short_name(self.messagechannel_combobox.currentText())
            channel_index = 0 # not really meaningful

        # Update timeout before sending
        if message:
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

    def explore_packets(self, node_id:str) -> None:
        self.packetsource_combobox.blockSignals(True)
        self.packetmedium_combobox.blockSignals(True)
        self.packettype_combobox.blockSignals(True)
        self.packetsource_combobox.setCurrentText("All")
        self.packettype_combobox.setCurrentText("All")
        self.packetmedium_combobox.setCurrentText("All")
        self.clean_plot(kind="packets")
        if self._store.has_seen_node_id(node_id):
            self.tabWidget.setCurrentIndex(2)
            self.packetsource_combobox.setCurrentText(node_id)
        self.update_packets_filtered()
        self.packetsource_combobox.blockSignals(False)
        self.packetmedium_combobox.blockSignals(False)
        self.packettype_combobox.blockSignals(False)

    def reset_node_packets_counters(self) -> None:
        self.messages_packets_number.setRange(0, 1)
        self.messages_packets_number.setValue(0)
        self.nodeinfo_packets_number.setRange(0, 1)
        self.nodeinfo_packets_number.setValue(0)
        self.position_packets_number.setRange(0, 1)
        self.position_packets_number.setValue(0)
        self.telemetry_packets_number.setRange(0, 1)
        self.telemetry_packets_number.setValue(0)
        self.neighbor_packets_number.setRange(0, 1)
        self.neighbor_packets_number.setValue(0)
        self.routing_packets_number.setRange(0, 1)
        self.routing_packets_number.setValue(0)
        self.storeforward_packets_number.setRange(0, 1)
        self.storeforward_packets_number.setValue(0)
        self.traceroute_packets_number.setRange(0, 1)
        self.traceroute_packets_number.setValue(0)
        self.admin_packets_number.setRange(0, 1)
        self.admin_packets_number.setValue(0)
        self.rangetest_packets_number.setRange(0, 1)
        self.rangetest_packets_number.setValue(0)
        self.mapreport_packets_number.setRange(0, 1)
        self.mapreport_packets_number.setValue(0)
        self.node_packets_number.display(0)

    def update_nodes(self, node:MeshtasticNode) -> None:
        self.update_local_node_config()
        nodes = self._store.get_nodes()
        if not nodes:
            return
        self.update_message_combobox() # for DM
        self.update_nodes_table(nodes)

    def apply_nodes_filter(self, nodes: List[MeshtasticNode]) -> List[MeshtasticNode]:
        filtered = nodes.values()  # nofilter
        hopfilter = {
            "1-hop": 1,
            "2-hops": 2,
            "3-hops": 3,
            "4-hops": 4,
            "5-hops": 5,
            "6-hops": 6,
            "7-hops": 7,
        }
        if self.shortcut_filter_combobox.currentText() == "Recently seen":
            recently_seen = list(filter(lambda x: x.rx_counter > 0,nodes.values()))
            filtered = recently_seen
        elif self.shortcut_filter_combobox.currentText() == "Positioned":
            filtered = list(filter(lambda x: x.has_location(), nodes.values()))
        elif self.shortcut_filter_combobox.currentText() == "Neighbors":
            filtered = list(filter(lambda x: x.hopsaway == 0, nodes.values()))
        elif self.shortcut_filter_combobox.currentText() in hopfilter.keys():
            filtered = list(filter(lambda x: x.hopsaway == hopfilter[self.shortcut_filter_combobox.currentText()], nodes.values()))
        if len(self.nodes_filter_linedit.text()) != 0:
            # first search in long_name, then in id, then in aka
            pattern = self.nodes_filter_linedit.text()
            filtered = list(filter(lambda x: pattern.lower() in x.short_name.lower() if x.short_name is not None else False, nodes.values()))
            if not filtered:
                filtered = list(filter(lambda x: pattern.lower() in x.long_name.lower() if x.long_name is not None else False,nodes.values()))
            if not filtered:
                filtered = list(filter(lambda x: pattern.lower() in x.id.lower(),nodes.values()))
        return filtered

    def update_nodes_table(self, nodes: List[MeshtasticNode]) -> None:
        # update LCD widgets
        self.nodes_total_lcd.display(len(nodes.values()))
        positioned_nodes = list(
            filter(
                lambda x: x.lat is not None and x.lon is not None and x.lat and x.lon,
                nodes.values()))
        self.nodes_gps_lcd.display(len(positioned_nodes))
        recently_seen = list(
            filter(
                lambda x: x.rx_counter > 0,
                nodes.values()))
        self.nodes_recently_lcd.display(len(recently_seen))

        filtered = self.apply_nodes_filter(nodes)

        # update table
        rows: list[dict[str, any]] = []
        for node in filtered:
            row = {"Status": "", "User": "", "ID": ""}

            status_line = []

            if node.is_mqtt_gateway:
                status_line.append("🖥️")
            else:
                status_line.append("📡")

            row.update(
                {
                    "Status": " ".join(status_line),
                    "User": node.long_name,
                    "AKA": node.short_name,
                    "ID": node.id,
                    "SNR": node.snr if node.snr is not None and node.hopsaway == 0 else "/",
                    "RSSI": node.rssi if node.rssi is not None and node.hopsaway == 0 else "/",
                    "Hops": f"✈️{node.hopsaway}" if node.hopsaway is not None else "/",
                    "RX": f"⬊{node.rx_counter}" if node.rx_counter is not None and node.rx_counter > 0 else "/",
                    "TX": f"⬈{node.tx_counter}" if node.tx_counter is not None and node.tx_counter > 0 else "/",
                    "Details": None,
                    "Action": None,
                    "Relay node": f"0x{node.relay_node}" if node.relay_node else "/",
                    "Next hop": f"0x{node.next_hop}" if node.next_hop else "/",
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
            "ID",
            "AKA",
            "SNR",
            "RSSI",
            "Hops",
            "RX",
            "TX",
            "Details",
            "Action",
            "Relay node",
            "Next hop",
            "Role",
            "Hardware",
            "Latitude",
            "Longitude",
            "Public key",
            "Last seen",
        ]

        del nodes
        self.mesh_table.setRowCount(0)
        self.mesh_table.setRowCount(len(rows))
        self.mesh_table.setColumnCount(len(columns))
        self.mesh_table.setHorizontalHeaderLabels(columns)

        for row_idx, row_data in enumerate(rows):
            for col_idx, value in enumerate(row_data.values()):
                current_item = self.mesh_table.item(row_idx, col_idx)
                current_widget = self.mesh_table.cellWidget(row_idx, col_idx)
                if current_item is None and current_widget is None:
                    if col_idx == 10:  # insert widget in cell
                        if self._manager.is_connected():
                            # get id to check if node is local
                            is_local = row_data["ID"] == self._local_board_id

                            self.mesh_table.setCellWidget(
                                row_idx,
                                col_idx,
                                NodeActionsWidget(
                                    parent=self,
                                    callback_traceroute=self.traceroute,
                                    callback_telemetry=lambda: self.send_telemetry_signal.emit(),
                                    callback_position=lambda: self.send_position_signal.emit(),
                                    is_local=is_local,
                                    node_id=row_data["ID"]
                                    )
                                )
                        else:
                            data = str(value)
                            if data == "None":
                                data = ""
                    if col_idx == 9:  # insert widget in cell
                        if self._store.has_seen_node_id(row_data["ID"]):
                            btn = QPushButton("See packets")
                            btn.setEnabled(True)
                            btn.setStyleSheet("QPushButton{font-size: 9pt;}")
                            self.mesh_table.setCellWidget(row_idx, col_idx, btn)
                            btn.clicked.connect(lambda: self.explore_packets(self.mesh_table.item(self.mesh_table.indexAt(self.sender().pos()).row(),2).text()))
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
        self.mesh_table.resizeRowsToContents()

    def get_nodes(self):
        self.get_nodes_signal.emit()

    def get_channel_names(self) -> List[str]:
        channels = self._store.get_channels()
        if not channels:
            return []
        return [channel.name for channel in channels]

    def update_channels_table(self):
        config = self._manager.get_data_store()
        channels = config.get_channels()
        if not channels:
            return

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
        self.channels_table.setHorizontalHeaderLabels(columns)

        for row in rows:
            row_position = self.channels_table.rowCount()
            self.channels_table.insertRow(row_position)
            for i, elt in enumerate(columns):
                self.channels_table.setItem(
                    row_position, i, QTableWidgetItem(str(row[elt])))
        self.channels_table.resizeColumnsToContents()
        self.channels_table.resizeRowsToContents()

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
        self._local_board_ln = cfg.long_name
        self.devicename_label.setText(cfg.long_name)
        self.publickey_label.setText(cfg.public_key)
        self.hardware_label.setText(cfg.hardware)
        self.role_label.setText(cfg.role)
        self.batterylevel_progressbar.setValue(cfg.battery_level)
        self.batterylevel_progressbar.show()
        self.id_label.setText(str(cfg.id))

    def traceroute(
            self,
            dest_id: str = "",
            maxhops: int = 5,
            dummy: bool = False):
        self.traceroute_table.setRowCount(0)
        self.traceroute_table.setColumnCount(3)
        self.traceroute_table.setHorizontalHeaderLabels(
            ["Id", "SNR To", "SNR Back"])
        self.traceroute_signal.emit(
            dest_id, DEFAULT_TRACEROUTE_CHANNEL, maxhops)

    def update_message_combobox(self) -> None:
        already_present = [self.messagechannel_combobox.itemText(i) for i in range(self.messagechannel_combobox.count())]
        for node in self._store.get_nodes().values():
            sn = self._store.get_short_name_from_id(node.id)
            if sn and sn not in already_present:
                self.messagechannel_combobox.insertItem(self.messagechannel_combobox.count(), sn)

    def update_received_message(self) -> None:
        if self.tabWidget.currentIndex() != 3:
            self.tabWidget.setTabText(3, "Messages 🔴")

        headers = self._get_meshtastic_message_header_fields()
        columns = list(headers.keys())
        self.messages_table.setColumnCount(len(columns))
        self.messages_table.setHorizontalHeaderLabels(headers.values())

        channels = self._store.get_channels()
        messages = self._store.get_messages()

        # filter by current channel
        current_channel = list(filter(lambda x: x.name == self.messagechannel_combobox.currentText(),  channels))
        filtered_messages = messages
        if len(current_channel) == 1:
            # group message
            filtered_messages = list(filter(lambda x: x.channel_index == current_channel[0].index and (x.to_id == BROADCAST_ADDR or x.to_id == BROADCAST_NAME), messages))
        else:
            # DM
            def __filter_dm(self, message, node_id):
                if (message.to_id != BROADCAST_ADDR and message.to_id != BROADCAST_NAME) and \
                    (message.from_id == self._store.get_id_from_short_name(node_id) or message.to_id == self._store.get_id_from_short_name(node_id)):
                    return True
                return False

            filtered_messages = list(filter(lambda x: __filter_dm(self, x, self.messagechannel_combobox.currentText()), messages))

        self.messages_table.setRowCount(len(filtered_messages))
        rows: list[dict[str, any]] = []

        for message in filtered_messages:
            message.date2str("%Y-%m-%d %H:%M:%S")
            data = {}
            for column in columns:
                if column == "from_id" or column == "to_id":
                    data[headers[column]] = self._store.get_short_name_from_id(
                        getattr(
                            message, column))
                elif column == "ack":
                    label = "❔"
                    if message.from_id != self._local_board_id:
                        label = "/"
                    if getattr(message, "ack_status") is not None:
                        if getattr(message, "ack_status") is True:
                            if getattr(message, "ack_by") is not None:
                                if getattr(
                                        message,
                                        "ack_by") != getattr(
                                        message,
                                        "to_id"):
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
                    item = QTableWidgetItem(str(value))
                    self.messages_table.setItem(row_idx, col_idx, item)
                    self.messages_table.scrollToItem(item,QtWidgets.QAbstractItemView.ScrollHint.EnsureVisible)
                elif current_item.text() != value:
                    current_item.setText(str(value))
        self.messages_table.resizeColumnsToContents()
        self.messages_table.resizeRowsToContents()

    def update_packets_filter(self, packets: List[Packet]) -> None:
        inserted = []
        for i, packet in enumerate(packets):
            if packet.from_id not in inserted:
                inserted.append(packet.from_id)
            if self.packettype_combobox.findText(packet.port_num) == -1:
                self.packettype_combobox.insertItem(
                    10000, packet.port_num)  # insert last

            if self.packetsource_combobox.findText(packet.from_id) == -1:
                self.packetsource_combobox.insertItem(
                    100000, packet.from_id)  # insert last

    def update_packets_filtered(self) -> None:
        self.reset_node_packets_counters()
        self.packets_treewidget.clear()
        self.update_packet_received(MeshtasticNode())

    def update_packet_received(self, packet:Optional[Packet]) -> None:
        packets = self._store.get_radio_packets() + self._store.get_mqtt_packets()
        self.update_packets_filter(packets)
        self.update_packets_widgets(packets)

    def adjust_packets_treeview(self, item, column):
        self.packets_treewidget.resizeColumnToContents(1)
        # self.packets_treewidget.header().stretchLastSection()
        # self.packets_treewidget.resizeColumnToContents(column)

    def apply_packets_filter(self, packets:List[Packet]) -> List[Packet]:
        if self.packetmedium_combobox.currentText() != "All":
            packets = list(
                    filter(
                    lambda x: x.source.lower() == self.packetmedium_combobox.currentText().lower(),
                    packets))
        if self.packetsource_combobox.currentText() != "All":
            packets = list(
                filter(
                    lambda x: x.from_id == self._store.get_id_from_long_name(
                        self.packetsource_combobox.currentText()),
                    packets))
        if self.packettype_combobox.currentText() != "All":
            packets = list(
                filter(
                    lambda x: x.port_num == self.packettype_combobox.currentText(),
                    packets))

        return packets

    def update_packets_widgets(self, packets: List[Packet]) -> None:
        alreading_existing_packets = [
            self.packets_treewidget.topLevelItem(i).text(0) for i in range(
                self.packets_treewidget.topLevelItemCount())]

        filtered_packets = self.apply_packets_filter(packets)

        for packet in filtered_packets:
            packet.date2str()
            if str(packet.date) in alreading_existing_packets:
                continue
            category_item = QTreeWidgetItem([str(packet.date), ""])
            self.packets_treewidget.addTopLevelItem(category_item)
            for sub_item, value in asdict(packet).items():
                sub_item_widget = QTreeWidgetItem([str(sub_item), str(value)])
                category_item.addChild(sub_item_widget)
        self.packets_treewidget.resizeColumnToContents(0)

        filtered_packets_number = len(filtered_packets)
        if filtered_packets_number > 0:
            self.messages_packets_number.setRange(0, filtered_packets_number)
            self.messages_packets_number.setValue(len(list(filter(lambda x: x.port_num == PacketInfoType.PCK_TEXT_MESSAGE_APP.value, filtered_packets))))
            self.nodeinfo_packets_number.setRange(0, filtered_packets_number)
            self.nodeinfo_packets_number.setValue(len(list(filter(lambda x: x.port_num == PacketInfoType.PCK_NODEINFO_APP.value, filtered_packets))))
            self.position_packets_number.setRange(0, filtered_packets_number)
            self.position_packets_number.setValue(len(list(filter(lambda x: x.port_num == PacketInfoType.PCK_POSITION_APP.value, filtered_packets))))
            self.telemetry_packets_number.setRange(0, filtered_packets_number)
            self.telemetry_packets_number.setValue(len(list(filter(lambda x: x.port_num == PacketInfoType.PCK_TELEMETRY_APP.value, filtered_packets))))
            self.neighbor_packets_number.setRange(0, filtered_packets_number)
            self.neighbor_packets_number.setValue(len(list(filter(lambda x: x.port_num == PacketInfoType.PCK_NEIGHBORINFO_APP.value, filtered_packets))))
            self.routing_packets_number.setRange(0, filtered_packets_number)
            self.routing_packets_number.setValue(len(list(filter(lambda x: x.port_num == PacketInfoType.PCK_ROUTING_APP.value, filtered_packets))))
            self.storeforward_packets_number.setRange(0, filtered_packets_number)
            self.storeforward_packets_number.setValue(len(list(filter(lambda x: x.port_num == PacketInfoType.PCK_STORE_FORWARD_APP.value, filtered_packets))))
            self.traceroute_packets_number.setRange(0, filtered_packets_number)
            self.traceroute_packets_number.setValue(len(list(filter(lambda x: x.port_num == PacketInfoType.PCK_TRACEROUTE_APP.value, filtered_packets))))
            self.admin_packets_number.setRange(0, filtered_packets_number)
            self.admin_packets_number.setValue(len(list(filter(lambda x: x.port_num == PacketInfoType.PCK_ADMIN_APP.value, filtered_packets))))
            self.rangetest_packets_number.setRange(0, filtered_packets_number)
            self.rangetest_packets_number.setValue(len(list(filter(lambda x: x.port_num == PacketInfoType.PCK_RANGE_TEST_APP.value, filtered_packets))))
            self.mapreport_packets_number.setRange(0, filtered_packets_number)
            self.mapreport_packets_number.setValue(len(list(filter(lambda x: x.port_num == PacketInfoType.PCK_MAP_REPORT_APP.value, filtered_packets))))
            self.node_packets_number.display(filtered_packets_number)

    def update_device_details(self, configuration: dict):
        self.output_textedit.setText(configuration)
        cursor = QTextCursor(self.output_textedit.textCursor())
        cursor.setPosition(0)
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

    def write_to_file(self, path:str, data:str, kind:str="") -> bool:
        res = False
        try:
            text_file = open(path, "w")
        except Exception as e:
            self.set_status(MessageLevel.ERROR, f"Could not write to {path}: {e}")
        else:
            text_file.write(data)
            absp = os.path.abspath(path)
            trace = f"<a href='file://{absp}'>Exported {kind} logs to file: {path}</a>"
            self.set_status(MessageLevel.INFO, trace)
            res = True
            text_file.close()
        finally:
            pass

        return res

    def export_mqtt_logs(self) -> None:
        nnow = datetime.now().strftime("%Y-%m-%d__%H_%M_%S")
        fpath = os.path.join(self._current_output_folder, f"mqtt_logs_{nnow}.log")
        self.write_to_file(fpath, self.mqtt_output_textedit.toPlainText(), "mqtt")

    def export_console_logs(self) -> None:
        nnow = datetime.now().strftime("%Y-%m-%d__%H_%M_%S")
        fpath = os.path.join(self._current_output_folder, f"console_logs_{nnow}.log")
        self.write_to_file(fpath, self.console_logs_textedit.toPlainText(), "console")

    def _update_console_button(self, activated:bool) -> None:
        if not activated: self.start_pause_console_button.setText("⏸️")
        if activated: self.start_pause_console_button.setText("▶️")

    def export_packets(self) -> None:
        packets = self._store.get_radio_packets() + self._store.get_mqtt_packets()
        packets = self.apply_packets_filter(packets)

        [x.date2str() for x in packets]
        packets_list = [asdict(x) for x in packets]
        for p in packets_list:
            try:
                p["payload"] = str(p["payload"])
            except Exception as e:
                p["payload"] = "convertion error"
        data_json = json.dumps(packets_list, indent=4)
        nnow = datetime.now().strftime("%Y-%m-%d__%H_%M_%S")
        fpath = os.path.join(self._current_output_folder, f"packet_{nnow}.json")
        self.write_to_file(fpath, data_json, "packets")

    def export_chat(self) -> None:
        messages = self._store.get_messages()
        [x.date2str() for x in messages]
        messages = [asdict(x) for x in messages]
        data_json = json.dumps(messages, indent=4)
        nnow = datetime.now().strftime("%Y-%m-%d__%H_%M_%S")
        fpath = os.path.join(self._current_output_folder, f"messages_{nnow}.json")
        self.write_to_file(fpath, data_json, "messages")

    def export_nodes(self) -> None:
        nodes = self._store.get_nodes().values()
        [x.date2str() for x in nodes]
        nodes = [asdict(x) for x in nodes]
        data_json = json.dumps(nodes, indent=4)
        nnow = datetime.now().strftime("%Y-%m-%d__%H_%M_%S")
        fpath = os.path.join(self._current_output_folder, f"nodes_{nnow}.json")
        self.write_to_file(fpath, data_json, "nodes")

    def export_node_metrics(self) -> None:
        metric_names = self._store.get_node_metrics_fields()
        node_id = self.nm_node_label.text()
        nnow = datetime.now()
        metrics = {
            "node_id": node_id,
            "date": nnow.strftime("%Y-%m-%d %H:%M:%S"),
            "metric": {},
        }
        if not node_id:
            return
        for metric in metric_names:
            metrics["metric"][metric] = self._store.get_node_metrics(self._store.get_id_from_long_name(node_id), metric)
        data_json = json.dumps(metrics, indent=4)
        fpath = os.path.join(self._current_output_folder, f"node_{node_id}_metrics_{nnow.strftime('%Y-%m-%d__%H_%M_%S')}.json")
        self.write_to_file(fpath, data_json, f"node {node_id} metrics")

    def closeEvent(self, event) -> None:
        self.quit()

    def quit(self) -> None:
        self._manager.quit()
        self._mqtt_manager.quit()
