#!/usr/bin/env python3

from PyQt6.QtWidgets import QWidget, QPushButton, QHBoxLayout

class NodeActionsWidget(QWidget):
    def __init__(self, parent, callback_traceroute, callback_telemetry, callback_position, is_local:bool=False, node_id:str=""):
        super(NodeActionsWidget,self).__init__(parent)
        self._node_id = node_id
        layout = QHBoxLayout()
        layout.setContentsMargins(0,0,0,0)
        layout.setSpacing(0)

        if not is_local:
            btn = QPushButton("Traceroute")
            btn.setStyleSheet("QPushButton{font-size: 9pt;}")
            btn.setEnabled(True)
            btn.clicked.connect(lambda: callback_traceroute(self._node_id))
            layout.addWidget(btn)

        # only add these button if this is the local node
        if is_local:
            btn = QPushButton("Send position")
            btn.setStyleSheet("QPushButton{font-size: 9pt;}")
            btn.setEnabled(True)
            btn.clicked.connect(callback_position)
            layout.addWidget(btn)

            btn = QPushButton("Send telemetry")
            btn.setStyleSheet("QPushButton{font-size: 9pt;}")
            btn.setEnabled(True)
            btn.clicked.connect(callback_telemetry)
            layout.addWidget(btn)

        self.setLayout(layout)
