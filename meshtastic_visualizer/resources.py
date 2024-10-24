#!/usr/bin/env python3

import enum
import datetime
from dataclasses import dataclass
from typing import List, Optional


TEXT_MESSAGE_MAX_CHARS = 237


class MessageLevel(enum.Enum):
    """
    Message criticality level
    displayed in the window
    """
    ERROR = 2
    INFO = 1
    UNKNOWN = 0


class PacketInfoType(enum.Enum):
    """
    Meshtastic packet type
    """
    PCK_NEIGHBORINFO_APP = "NEIGHBORINFO_APP"
    PCK_TELEMETRY_APP = "TELEMETRY_APP"
    PCK_POSITION_APP = "POSITION_APP"
    PCK_TEXT_MESSAGE_APP = "TEXT_MESSAGE_APP"
    PCK_ROUTING_APP = "ROUTING_APP"
    PCK_TRACEROUTE_APP = "TRACEROUTE_APP"
    PCK_STORE_FORWARD_APP = "STORE_FORWARD_APP"
    PCK_NODEINFO_APP = "NODEINFO_APP"
    PCK_UNKNOWN = ""


def create_getter(field_name):
    def getter(self):
        with self._lock:
            return getattr(self, f"{field_name}")
    getter.__name__ = f"get_{field_name}"
    return getter

# Function to create a setter method


def create_setter(field_name):
    def setter(self, value):
        with self._lock:
            setattr(self, f"{field_name}", value)
    setter.__name__ = f"set_{field_name}"
    return setter


def run_in_thread(method):
    def wrapper(self, *args, **kwargs):
        self.enqueue_task(method, self, *args, **kwargs)

    wrapper.__name__ = method.__name__
    wrapper.__doc__ = method.__doc__
    wrapper.__module__ = method.__module__

    return wrapper


@dataclass
class MeshtasticMessage:
    mid: int
    date: Optional[datetime.datetime] = None
    from_id: Optional[str] = None
    to_id: Optional[str] = None
    content: Optional[str] = None
    rx_snr: Optional[float] = None
    hop_limit: Optional[int] = None
    want_ack: Optional[bool] = None
    rx_rssi: Optional[int] = None
    hop_start: Optional[int] = None
    channel_index: Optional[int] = None
    ack: str = ""


@dataclass
class MeshtasticNode:
    long_name: Optional[str] = None
    short_name: Optional[str] = None
    id: Optional[str] = None
    role: Optional[str] = None
    hardware: Optional[str] = None
    lat: Optional[str] = None
    lon: Optional[str] = None
    alt: Optional[str] = None
    battery_level: Optional[int] = None
    voltage: Optional[float] = None
    chutil: Optional[str] = None
    txairutil: Optional[str] = None
    rssi: Optional[str] = None
    snr: Optional[str] = None
    neighbors: Optional[List[str]] = None
    hopsaway: Optional[str] = None
    firstseen: Optional[str] = None
    lastseen: Optional[str] = None
    uptime: Optional[int] = None
    is_local: Optional[bool] = None
    rx_counter: int = 0  # number of packets received from this node


@dataclass
class Channel:
    index: Optional[int] = None
    name: Optional[str] = None
    role: Optional[str] = None
    psk: Optional[str] = None


@dataclass
class NodeMetrics:
    node_id: str
    timestamp: int
    snr: Optional[float] = None
    rssi: Optional[float] = None
    uptime: Optional[int] = None
    hopsaway: Optional[int] = None
    voltage: Optional[int] = None
    air_util_tx: Optional[float] = None
    channel_utilization: Optional[float] = None
    battery_level: Optional[float] = None
    latitude: Optional[str] = None
    longitude: Optional[str] = None
    altitude: Optional[str] = None
    speed: Optional[str] = None


@dataclass
class MeshtasticMQTTClientSettings:
    host: Optional[str] = None
    port: Optional[int] = None
    username: Optional[str] = None
    password: Optional[str] = None
    topic: Optional[str] = None
    channel: Optional[str] = None
    key: Optional[str] = None
    tls: bool = True
    max_msg_len: int = 255


MAINWINDOW_STYLESHEET = """
    /* General Style for the Application */
    QMainWindow {
        background-color: #f0f0f5;
    }

    /* QLabel */
    QLabel {
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
        font-size: 12px;
        color: #333;
        padding: 1px;
    }

    /* QLineEdit */
    QLineEdit {
        background-color: #ffffff;
        border: 1px solid #d1d1d6;
        border-radius: 5px;
        padding: 1px;
        font-size: 12px;
        color: #333;
    }

    QLineEdit:focus {
        border: 1px solid #007aff;
    }

    /* QTextEdit */
    QTextEdit {
        background-color: #ffffff;
        border: 1px solid #d1d1d6;
        border-radius: 5px;
        padding: 1px;
        font-size: 12px;
        color: #333;
    }

    QTextEdit:focus {
        border: 1px solid #007aff;
    }

    /* QSpinBox */
    QSpinBox {
        background-color: #ffffff;
        border: 1px solid #d1d1d6;
        border-radius: 5px;
        padding: 1px;
        font-size: 12px;
        color: #333;
    }

    QSpinBox:focus {
        border: 1px solid #007aff;
    }

    /* QPushButton */
    QPushButton {
        background-color: #007aff;
        color: white;
        border: none;
        border-radius: 5px;
        padding: 1px 1px;
        font-size: 12px;
    }

    QPushButton:hover {
        background-color: #0051c1;
    }

    QPushButton:pressed {
        background-color: #00399a;
    }

    /* QCheckBox */
    QCheckBox {
        background-color: #ffffff;
        border: 1px solid #d1d1d6;
        border-radius: 5px;
        padding: 1px;
        font-size: 12px;
        color: #333;
    }


    /* QComboBox */
    QComboBox {
        background-color: #ffffff;
        border: 1px solid #d1d1d6;
        border-radius: 5px;
        padding: 1px;
        font-size: 12px;
        color: #333;
    }

    QComboBox:focus {
        border: 1px solid #007aff;
    }

    /* QGroupBox */
    QGroupBox {
        border: 1px solid #d1d1d6;
        border-radius: 5px;
        padding: 10px;
        font-size: 12px;
        color: #333;
    }

    QGroupBox::title {
        subcontrol-origin: margin;
        left: 10px;
        padding: 1px;
        font-weight: bold;
    }

    /* QListWidget */
    QListWidget {
        background-color: #ffffff;
        border: 1px solid #d1d1d6;
        border-radius: 5px;
        font-size: 12px;
        color: #333;
    }

    QListWidget::header {
        background-color: #f0f0f5;
        color: #007aff;
        font-weight: bold;
        font-size: 12px;
        padding: 1px;
    }

    QListWidget::item {
        padding: 1px;
    }

    QListWidget::item:selected {
        background-color: #007aff;
        color: white;
    }

    /* QTableWidget */
    QTableWidget {
        background-color: #ffffff;
        border: 1px solid #d1d1d6;
        font-size: 12px;
        color: #333;
    }

    QTableWidget::header {
        background-color: #f0f0f5;
        color: #007aff;
        font-weight: bold;
        font-size: 12px;
        padding: 1px;
    }

    QTableWidget::item {
        padding: 1px;
    }

    QTableWidget::item:selected {
        background-color: #007aff;
        color: white;
    }

    /* QTabBar::tab */
    QTabBar::tab {
        color: #333;
        border: 1px solid #999;      /* Border color for tabs */
        padding: 8px 12px;           /* Padding around the tab names */
        border-top-left-radius: 5px;
        border-top-right-radius: 5px;
        font-size: 12px;
    }

    /* Hover effect for tabs */
    QTabBar::tab:hover {
        background-color: #888;      /* Lighter background when hovering */
        font-size: 12px;
    }

    /* Selected tab */
    QTabBar::tab:selected {
        background-color: #007aff;   /* Background color for the selected tab */
        color: white;                /* Text color for the selected tab */
        border-bottom: 2px solid #007aff;  /* Bottom border to emphasize selected tab */
        font-size: 12px;
    }

    /* Disabled tabs */
    QTabBar::tab:disabled {
        color: #666;                 /* Dimmed text for disabled tabs */
        background-color: #333;
        font-size: 12px;
    }
"""
