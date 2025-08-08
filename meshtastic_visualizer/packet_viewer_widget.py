#!/usr/bin/env python3

from PyQt6.QtWidgets import QWidget, QPushButton, QHBoxLayout

class PacketViewerWidget(QWidget):
    def __init__(self, parent, callback_packet_viewer, callback_telemetry_viewer, has_telemetry:bool, node_id:str=""):
        super(PacketViewerWidget,self).__init__()
        self._node_id = node_id
        self.parent = parent
        layout = QHBoxLayout()
        layout.setContentsMargins(0,0,0,0)
        layout.setSpacing(0)

        if has_telemetry:
            btn = QPushButton("See telemetry")
            btn.setStyleSheet("QPushButton{font-size: 9pt;}")
            btn.setEnabled(True)
            btn.clicked.connect(lambda: callback_telemetry_viewer(self._node_id))
            layout.addWidget(btn)

        btn = QPushButton("See packets")
        btn.setStyleSheet("QPushButton{font-size: 9pt;}")
        btn.setEnabled(True)
        btn.clicked.connect(lambda: callback_packet_viewer(self._node_id))
        layout.addWidget(btn)

        self.setLayout(layout)
    