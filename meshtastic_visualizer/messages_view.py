from typing import List

from .resources import MeshtasticMessage
from PyQt6.QtWidgets import QSizePolicy, QLabel, QVBoxLayout, QWidget, QScrollArea, QHBoxLayout, QFrame
from PyQt6.QtCore import Qt


class MessageBubble(QFrame):
    def __init__(self, name:str, message: MeshtasticMessage, time_format:str, is_sender: bool):
        super().__init__()
        self.setMaximumWidth(400)
        self.setSizePolicy(QSizePolicy.Policy.Maximum, QSizePolicy.Policy.Minimum)

        # Style the bubble appearance
        self.setStyleSheet(f"""
            QFrame {{
                background-color: {'#F3F5F2' if is_sender else '#FFFFFF'};
                border: 1px solid #ddd;
                border-radius: 0px;
                padding: 3px;
            }}
            QLabel {{
                font-size: 10px;
            }}
            .meta {{
                color: #666;
                font-size: 10px;
            }}
            .sender {{
                font-weight: bold;
                font-size: 9px;
            }}
        """)

        # Layouts
        layout = QVBoxLayout(self)
        layout.setSpacing(4)
        layout.setContentsMargins(3, 3, 3, 3)

        # Metadata (date + encryption status)
        date = message.date.strftime(time_format)
        self.meta_layout = QHBoxLayout()
        self.sender_label = QLabel(name)
        self.sender_label.setObjectName("sender")
        self.meta_layout.addWidget(self.sender_label)
        self.encryption_label = QLabel("🔒" if message.pki_encrypted else "⚠️")
        self.encryption_label.setObjectName("meta")
        self.encryption_label.setStyleSheet("color: #888; font-size: 11px;")
        self.date_label = QLabel(date)
        self.date_label.setObjectName("meta")
        self.date_label.setStyleSheet("color: #888; font-size: 11px;")
        self.date_label.setAlignment(Qt.AlignmentFlag.AlignRight)
        self.meta_layout.addWidget(self.encryption_label)
        self.meta_layout.addStretch()
        self.meta_layout.addWidget(self.date_label)
        self.meta_layout.addStretch()
        self.ack_label = QLabel("❔" if is_sender else "/")
        self.ack_label.setStyleSheet("color: #444; font-size: 11px;")
        self.ack_label.setAlignment(Qt.AlignmentFlag.AlignRight)
        self.meta_layout.addWidget(self.ack_label)
        layout.addLayout(self.meta_layout)

        self.content_label = QLabel(message.content)
        self.content_label.setWordWrap(True)
        self.content_label.setStyleSheet("font-size: 11px; border: none")
        self.content_label.setTextInteractionFlags(
                Qt.TextInteractionFlag.TextSelectableByMouse | Qt.TextInteractionFlag.TextSelectableByKeyboard
            )
        self.content_label.setSizePolicy(QSizePolicy.Policy.Preferred, QSizePolicy.Policy.Minimum)
        layout.addWidget(self.content_label)
        self.update_ack(message)

    def update_content(self, name, message: MeshtasticMessage):
        """Update the content of this bubble."""
        self.sender_label.setText(name)
        self.encryption_label.setText("🔒" if message.pki_encrypted else "⚠️")
        self.date_label.setText(message.date)
        self.content_label.setText(message.content)

    def update_ack(self, message: MeshtasticMessage):
        if getattr(message, "ack_status") is not None:
            if getattr(message, "ack_status") is True:
                if getattr(message, "ack_by") is not None:
                    if getattr(message,"ack_by") != getattr(message,"to_id"):
                        label = "☁️"
                    else:
                        label = "✅"
            else:
                label = "❌"
            self.ack_label.setText(label)

    def redraw(self) -> None:
        self.adjustSize()
        self.updateGeometry()
        self.repaint()


class MessagesView(QWidget):
    def __init__(self, store):
        super().__init__()
        self._local_board_id = ""
        self._store = store
        self._time_format = "%H:%M:%S"
        self.scroll = QScrollArea()
        self.resize(500, 600)
        self.scroll.setWidgetResizable(True)
        self.container = QWidget()
        self.container.setVisible(True)
        self.setVisible(True)
        self.message_layout = QVBoxLayout(self.container)
        self.message_layout.setAlignment(Qt.AlignmentFlag.AlignTop)
        self.scroll.setWidget(self.container)

        outer_layout = QVBoxLayout(self)
        outer_layout.addWidget(self.scroll)

        # Store current message widgets
        self.message_bubbles: dict[str, QFrame] = {}

    def set_local_board_id(self, local_board_id:str) -> None:
        self._local_board_id = local_board_id

    def update(self, messages: List[MeshtasticMessage]):
        """Update or insert messages based on unique ID."""
        # Add or update each message in the correct order

        if not messages:
            self.clear_messages()

        for msg in messages:
            if msg.mid in self.message_bubbles.keys():
                frame = self.message_bubbles[msg.mid]
                self._update_bubble(frame, self._store.get_short_name_from_id(msg.from_id), msg)
            else:
                frame = self._create_message_frame(self._store.get_short_name_from_id(msg.from_id), msg)
                self.message_bubbles[msg.mid] = frame
                self.message_layout.addWidget(self.message_bubbles[msg.mid])

    def clear_messages(self):
        """Clear all messages from the view."""
        for frame in self.message_bubbles.values():
            self.message_layout.removeWidget(frame)
            frame.deleteLater()
        self.message_bubbles.clear()

    def _create_message_frame(self, name:str, message: MeshtasticMessage) -> QWidget:
        """Create a new frame with MessageBubble inside."""
        is_sender = message.from_id == self._local_board_id
        bubble = MessageBubble(name, message, self._time_format, is_sender)

        wrapper = QHBoxLayout()
        wrapper.setContentsMargins(10, 5, 10, 5)

        if is_sender:
            wrapper.addStretch()
            wrapper.addWidget(bubble, 0, Qt.AlignmentFlag.AlignRight)
        else:
            wrapper.addWidget(bubble, 0, Qt.AlignmentFlag.AlignLeft)
            wrapper.addStretch()

        frame = QFrame()
        frame.setLayout(wrapper)
        frame.bubble = bubble  # Attach bubble for easy updates
        return frame

    def _update_bubble(self, frame: QFrame, name:str, message: MeshtasticMessage):
        """Update existing MessageBubble content."""
        bubble = frame.bubble
        bubble.update_ack(message)
        self.container.adjustSize()
        self.scroll.verticalScrollBar().setValue(self.scroll.verticalScrollBar().maximum())