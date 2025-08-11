from PyQt6.QtWidgets import QTableWidgetItem
from threading import Lock
from .node_actions_widget import NodeActionsWidget
from .packet_viewer_widget import PacketViewerWidget
from .resources import MeshtasticNode


class NodesTable:
    def __init__(self, parent, table, buttons_callbacks:dict) -> None:
        self._parent = parent
        self._buttons_callbacks = buttons_callbacks
        self._mesh_table = table
        self._default_placeholder = ""
        self._rx_icon = "⬊"
        self._tx_icon = "⬈"
        self._hops_icon = "✈️"
        self._lock = Lock()
        self._table_ln_column_index = 1
        self._table_id_column_index = 2
        self._table_sn_column_index = 3
        self._table_hops_column_index = 4
        self._table_rx_column_index = 7
        self._table_details_column_index = 9
        self._table_action_column_index = 10
        self._table_lat_column_index = 15
        self._table_lon_column_index = 16
        self._table_columns = [
                "Status",
                "Long Name",
                "ID",
                "Short Name",
                "Hops",
                "SNR",
                "RSSI",
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

    def clear(self) -> None:
        self._mesh_table.setRowCount(0)

    def update_lcds(self) -> None:
        # update LCD widgets
        self._parent.nodes_total_lcd.display(self._mesh_table.rowCount())
        positioned_nodes = list(
            filter(
                lambda x: self._mesh_table.item(x, self._table_lat_column_index) and self._mesh_table.item(x, self._table_lat_column_index).text() and self._mesh_table.item(x, self._table_lon_column_index).text(),
                range(self._mesh_table.rowCount())
                )
            )
        self._parent.nodes_gps_lcd.display(len(positioned_nodes))
        recently_seen = list(
            filter(
                lambda x: self._mesh_table.item(x, self._table_rx_column_index) and self._mesh_table.item(x, self._table_rx_column_index).text() and int(self._mesh_table.item(x, self._table_rx_column_index).text().replace(self._rx_icon, "")) > 0,
                range(self._mesh_table.rowCount())
                )
            )
        self._parent.nodes_recently_lcd.display(len(recently_seen))
    
    def filter_displayed_nodes(self) -> None:
        hopfilter = {
            "1-hop": 1,
            "2-hops": 2,
            "3-hops": 3,
            "4-hops": 4,
            "5-hops": 5,
            "6-hops": 6,
            "7-hops": 7,
        }
        for row in range(self._mesh_table.rowCount()):
            should_hide = False
            if self._parent.shortcut_filter_combobox.currentText() == "Recently seen":
                if not self._mesh_table.item(row, self._table_rx_column_index) \
                    or not self._mesh_table.item(row, self._table_rx_column_index).text() \
                        or int(self._mesh_table.item(row, self._table_rx_column_index).text().replace(self._rx_icon, "")) == 0:
                    should_hide = True
            if self._parent.shortcut_filter_combobox.currentText() == "Positioned":
                if not self._mesh_table.item(row, self._table_lat_column_index) \
                    or not self._mesh_table.item(row, self._table_lon_column_index) \
                        or not self._mesh_table.item(row, self._table_lat_column_index).text() \
                            or not self._mesh_table.item(row, self._table_lon_column_index).text():
                    should_hide = True
            if self._parent.shortcut_filter_combobox.currentText() == "Neighbors":
                if not self._mesh_table.item(row, self._table_hops_column_index) \
                    or not self._mesh_table.item(row, self._table_hops_column_index).text() \
                         or int(self._mesh_table.item(row, self._table_hops_column_index).text().replace(self._hops_icon, "")) != 0:
                    should_hide = True
            if self._parent.shortcut_filter_combobox.currentText() in hopfilter.keys():
                if not self._mesh_table.item(row, self._table_hops_column_index) \
                    or not self._mesh_table.item(row, self._table_hops_column_index).text() \
                        or int(self._mesh_table.item(row, self._table_hops_column_index).text().replace(self._hops_icon, "")) != hopfilter[self._parent.shortcut_filter_combobox.currentText()]:
                    should_hide = True
            if len(self._parent.nodes_filter_linedit.text()) != 0:
                pattern = self._parent.nodes_filter_linedit.text().lower()
                if pattern not in self._mesh_table.item(row, self._table_ln_column_index).text().lower() \
                    and pattern not in self._mesh_table.item(row, self._table_sn_column_index).text().lower() \
                    and pattern not in self._mesh_table.item(row, self._table_id_column_index).text().lower():
                    should_hide = True

            self._mesh_table.setRowHidden(row, should_hide)
        self._mesh_table.resizeColumnsToContents()
        self._mesh_table.resizeRowsToContents()


    def _generate_details_widget(self, node_id:str) -> PacketViewerWidget:
        return (
            PacketViewerWidget(
                parent=self,
                callback_packet_viewer=self._buttons_callbacks["explore_packets"],
                callback_telemetry_viewer=self._buttons_callbacks["view_telemetry"],
                has_telemetry=self._parent._store.has_node_metrics(node_id),
                node_id=node_id,
            )
        )

    def _generate_action_widget(self, node_id:str) -> NodeActionsWidget:
        return (
            NodeActionsWidget(
                parent=self._mesh_table,
                callback_traceroute=self._buttons_callbacks["traceroute"],
                callback_telemetry=self._buttons_callbacks["send_telemetry"],
                callback_position=self._buttons_callbacks["send_position"],
                callback_view_traceroute=self._buttons_callbacks["view_traceroute"],
                has_traceroute=self._parent._store.has_node_traceroute(node_id),
                is_local=(node_id == self._parent._local_board_id),
                node_id=node_id
            )
        )

    def update(self, node: MeshtasticNode) -> None:
        self._lock.acquire()
        # update table
        row_to_update = {"Status": None, "Long name": None, "ID": None}

        status_line = []

        if node.is_mqtt_gateway:
            status_line.append("🖥️")
        if node.has_node_info():
            status_line.append("👤")
        if node.has_telemetry:
            status_line.append("🔋")
        if node.has_local_stats:
            status_line.append("⚙️")
        if node.has_environment:
            status_line.append("☀️")
        if node.has_location():
            status_line.append("📍")

        row_to_update.update(
            {
                "Status": " ".join(status_line),
                "Long name": node.long_name,
                "ID": node.id,
                "Short name": node.short_name,
                "Hops": f"{self._hops_icon}{node.hopsaway}" if node.hopsaway is not None else None,
                "SNR": node.snr if node.snr is not None and node.hopsaway == 0 else None,
                "RSSI": node.rssi if node.rssi is not None and node.hopsaway == 0 else None,
                "RX": f"{self._rx_icon}{node.rx_counter}" if node.rx_counter is not None and node.rx_counter > 0 else None,
                "TX": f"{self._tx_icon}{node.tx_counter}" if node.tx_counter is not None and node.tx_counter > 0 else None,
                "Details": self._generate_details_widget(node.id),
                "Action": self._generate_action_widget(node.id),
                "Relay node": f"0x{node.relay_node}" if node.relay_node else None,
                "Next hop": f"0x{node.next_hop}" if node.next_hop else None,
                "Role": node.role,
                "Hardware": node.hardware,
            }
        )
        node.date2str()
        row_to_update.update(
            {
                "Latitude": node.lat,
                "Longitude": node.lon,
                "Public key": node.public_key,
                "Last seen": node.lastseen,
            }
        )

        found_row = -1
        for table_row in range(self._mesh_table.rowCount()):
            id_item = self._mesh_table.item(table_row, self._table_id_column_index)
            if id_item is None:
                continue
            if id_item.text() == row_to_update["ID"]:
                found_row = table_row
                break

        if found_row == -1:
            found_row = self._mesh_table.rowCount()
            self._mesh_table.setRowCount(self._mesh_table.rowCount()+1)

        self._mesh_table.setColumnCount(len(row_to_update.keys()))
        self._mesh_table.setHorizontalHeaderLabels(self._table_columns)

        for col_idx, value in enumerate(row_to_update.values()):
            if col_idx == self._table_action_column_index:  
                if self._parent._manager.is_connected():
                    self._mesh_table.setCellWidget(found_row, self._table_action_column_index, row_to_update["Action"])                                
                else:
                    self._mesh_table.setItem(found_row, col_idx, QTableWidgetItem(self._default_placeholder))
            elif col_idx == self._table_details_column_index:
                if self._parent._store.has_seen_node_id(row_to_update["ID"]):
                    self._mesh_table.setCellWidget(found_row, self._table_details_column_index, row_to_update["Details"]
                    )
                else:
                    self._mesh_table.setItem(found_row, col_idx, QTableWidgetItem(self._default_placeholder))
            else:
                current_item = self._mesh_table.item(found_row, col_idx)
                if value is not None:
                    if current_item is None or current_item.text() != str(value):
                        self._mesh_table.setItem(found_row, col_idx, QTableWidgetItem(str(value)))
                else:
                    if current_item is None:
                        self._mesh_table.setItem(found_row, col_idx, QTableWidgetItem(self._default_placeholder))

        self._mesh_table.resizeColumnsToContents()
        self._mesh_table.resizeRowsToContents()

        self.filter_displayed_nodes()
        self.update_lcds()
        self._lock.release()

