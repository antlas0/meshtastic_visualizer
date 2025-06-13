import pyqtgraph as pg
from pyqtgraph import DateAxisItem, AxisItem
from enum import Enum
import numpy as np


class GraphKind(Enum):
    UNKNOWN=0
    TELEMETRY_TIMELINE=1
    PACKETS_TIMELINE=2


class MeshtasticGraphs:
    def __init__(self) -> None:
        self._telemetry_plot_widget = pg.PlotWidget()
        self._telemetry_plot_widget.plotItem.getViewBox().setMouseMode(pg.ViewBox.RectMode)
        self._packets_plot_widget = pg.PlotWidget()
        self._packets_plot_widget.plotItem.getViewBox().setMouseMode(pg.ViewBox.RectMode)
        self._telemetry_timeline_plot_item = self._telemetry_plot_widget.plot(pen=pg.mkPen('#007aff', width=1), symbol='o', symbolPen='b', symbolSize=8)
        self._packets_timeline_plot_item = self._packets_plot_widget.plot(pen=pg.mkPen('#007aff', width=1), symbol='o', symbolSize=8)

    def get_plot_item(self, kind:GraphKind) -> pg.GraphicsObject:
        if kind == GraphKind.PACKETS_TIMELINE: return self._packets_timeline_plot_item
        if kind == GraphKind.TELEMETRY_TIMELINE: return self._telemetry_timeline_plot_item

    def get_plot_widget(self, kind:GraphKind) -> pg.PlotWidget:
        if kind == GraphKind.PACKETS_TIMELINE: return self._packets_plot_widget
        if kind == GraphKind.TELEMETRY_TIMELINE: return self._telemetry_plot_widget

    def setup(self) -> bool:
        for kind in [GraphKind.PACKETS_TIMELINE, GraphKind.TELEMETRY_TIMELINE]:
            widget = self.get_plot_widget(kind)
            widget.setBackground('w')
            widget.getPlotItem().getAxis('left').setPen(pg.mkPen(color='k'))
            widget.getPlotItem().getAxis('bottom').setPen(pg.mkPen(color='k'))
            widget.getPlotItem().getAxis('left').setTextPen(pg.mkPen(color='k'))
            widget.getPlotItem().getAxis('bottom').setTextPen(pg.mkPen(color='k'))
            widget.addLegend()
            widget.setMouseEnabled(x=False, y=False)
            widget.setAxisItems({'bottom': DateAxisItem()})

        return True
    
    def clean_plot(self, kind:GraphKind) -> None:
        if item:= self.get_plot_item(kind):
            item.setData(x=None, y=None)
        if widget:= self.get_plot_widget(kind):
            widget.setTitle("No data")

    def generate_timeline(self, metric_name, timestamp, data, kind, long_name) -> None:
        widget = self.get_plot_widget(kind)
        item = self.get_plot_item(kind)

        item.setData(x=timestamp, y=data)
        widget.getPlotItem().getViewBox().setRange(
            xRange=(min(timestamp), max(timestamp)),
            yRange=(min(data), max(data)),
        )
        widget.setLabel('left', "value", units='')
        widget.setLabel('bottom', 'Timestamp', units='')
        widget.setTitle(f'{metric_name} vs time for node {long_name}')
