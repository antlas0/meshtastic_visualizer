#!/usr/bin/env python3


import hashlib
import datetime
import io
import folium
from typing import Optional
from folium.plugins import MousePosition, MeasureControl

from .datastore import MeshtasticDataStore

from .resources import CHARGING_TRESHOLD

class Mapper:
    """class that manages the map
    """
    def __init__(self, store:MeshtasticDataStore, custom_tiles_uri:Optional[str]=None) -> None:
        self._map = None
        self._store = store

        self.create_map(custom_tiles_uri)

    def create_map(self, custom_tiles_uri:Optional[str]=None) -> None:
        """create a map with initial parameters
        """
        if self._map:
            del self._map

        params = {}
        if custom_tiles_uri:
            params["tiles"] = custom_tiles_uri
            params["attr"] = "Custom Tiles"

        self._map = folium.Map(zoom_start=7, control_scale=True, no_touch=True, **params)
        MousePosition().add_to(self._map)
        MeasureControl().add_to(self._map)

    def convert2html(self) -> str:
        """convert map to html code

        Returns:
            str: html code to be integrated in other component
        """
        data = io.BytesIO()
        self._map.save(data, close_file=False)
        data.seek(0)
        html = data.getvalue().decode()
        data.close()
        del data
        return html

    def _link_color(self, snr: float) -> str:
        """returns a color from node condition

        Args:
            node_id (str): node id

        Returns:
            str: color code
        """
        if snr > 0.0:
            color = "#279b07"
        elif snr > -20.0:
            color = "#e5f71d"
        elif snr > -40.0:
            color = "#f4a111"
        else:
            color = "#f73127"

        return color

    def update(self, nodes: list, custom_tiles_uri:Optional[str]=None) -> None:
        """update map with nodes

        Args:
            nodes (list): nodes
        """
        self.create_map(custom_tiles_uri)

        if nodes is None or not nodes:
            return

        links_group = folium.FeatureGroup(name="Links")
        traces_group = folium.FeatureGroup(name="Traces")
        online_group = folium.FeatureGroup(name="Online")
        offline_group = folium.FeatureGroup(name="Offline")
        traces: dict = {}
        links: list = []
        online: list = []
        offline: list = []


        # remove any node that does not have full coordinates
        nodes_filtered = {}
        for node_id, details in nodes.items():
            if details.lat is not None and details.lat != "None" \
                and details.lon is not None and details.lon != "None":
                nodes_filtered[node_id] = details

        # display nodes
        for node_id, node in nodes_filtered.items():
            if node.lat is None or node.lon is None:
                continue

            # create lat,lon trace
            # check if moving or not
            try:
                timestamp = self._store.get_node_metrics(node_id, "lat")["timestamp"]
                lat = self._store.get_node_metrics(node_id, "lat")["value"]
                lon = self._store.get_node_metrics(node_id, "lon")["value"]
            except KeyError:
                pass
            else:
                if lat and lon and len(set(lat)) > 1  and len(set(lon)) > 1:
                    for i, elt in enumerate(timestamp):
                        if lat[i] is None or lon[i] is None:
                            continue
                        if i >= len(timestamp)-1:
                            continue
                        trace_coords = [
                            [float(lat[i]), float(lon[i])],
                            [float(lat[i+1]), float(lon[i+1])],
                        ]
                        tooltip = datetime.datetime.fromtimestamp(elt).strftime("%Y-%m-%d %H:%M:%S%z")
                        trace = folium.PolyLine(trace_coords, color="blue", tooltip=tooltip, dash_array="10")
                        trace.add_to(traces_group)
                        if not node_id in traces:
                            traces[node_id] = []
                        traces[node_id].append(trace)

            icon_name:str = "tower-cell"
            strl = []
            if node.long_name:
                strl.append(f"<b>👤 Name:</b> {node.long_name}</br>")
            strl.append(f"<b>🆔 id:</b> {node.id}</br>")
            if node.short_name:
                strl.append(f"<b>AKA:</b> {node.short_name}</br>")
            if node.hardware:
                strl.append(f"<b>🚲 Hardware:</b> {node.hardware}</br>")
            if node.battery_level:
                icon = "⚡"
                if node.voltage and node.voltage > CHARGING_TRESHOLD:
                    icon = "🔌"
                strl.append(
                    f"<b>{icon} Battery Level:</b> {node.battery_level} %</br>")
            if node.role:
                strl.append(f"<b>⚙️ Role:</b> {node.role}</br>")
            if node.hopsaway:
                strl.append(f"<b>📍 Hops Away:</b> {node.hopsaway}</br>")
            if node.txairutil:
                strl.append(f"<b>🔊 Air Util. Tx:</b> {node.txairutil} %</br>")
            if node.lastseen:
                strl.append(f"<b>⌛ Last seen:</b> {node.lastseen}</br>")
            if node.relay_node:
                strl.append(f"<b>📡 Relay node:</b> {node.relay_node}</br>")
            if node.next_hop:
                strl.append(f"<b>➡️ Next hop:</b> {node.next_hop}</br>")
            popup_content = "".join(strl)
            popup = folium.Popup(
                popup_content, max_width=300, min_width=250)
            color = "blue"
            if node.rx_counter > 0:
                color = "green"
            if node.is_local:
                color = "orange"
                icon_name = "walkie-talkie"
            if node.is_mqtt_gateway:
                icon_name = "network-wired"

            marker = folium.Marker(
                location=[
                    node.lat,
                    node.lon],
                tooltip=popup_content,
                popup=popup,
                icon=folium.Icon(color=color, icon=icon_name, prefix="fa"),
            )
            if node.rx_counter > 0:
                marker.add_to(online_group)
                online.append(marker)
            else:
                marker.add_to(offline_group)
                offline.append(marker)

        # neighbors of local node
        local_node = list(filter(lambda x: x.is_local, nodes.values()))
        if len(local_node) == 1:
            local_node = local_node[0]
            if local_node.neighbors is not None:
                for neigh_id in local_node.neighbors:
                    neigh_node  = self._store.get_node_from_id(neigh_id)
                    # we can trace a link
                    if neigh_node.has_location():
                        link_coords = [
                            [float(local_node.lat), float(local_node.lon)],
                            [float(neigh_node.lat), float(neigh_node.lon)],
                        ]
                        color = "grey"
                        tooltip = None
                        if neigh_node.hopsaway == 0:
                            color = self._link_color(neigh_node.snr)
                            tooltip = f"SNR: {neigh_node.snr}"
                        link = folium.PolyLine(link_coords, color=color, tooltip=tooltip)
                        link.add_to(links_group)
                        links.append(link)
        if online:
            online_group.add_to(self._map)
        if offline:
            offline_group.add_to(self._map)

        all_m = online + offline
        markers_lat = [x.location[0] for x in all_m]
        markers_lon = [x.location[1] for x in all_m]

        if markers_lat and markers_lon:
            self._map.fit_bounds(
                [[min(markers_lat), min(markers_lon)],
                    [max(markers_lat), max(markers_lon)]]
                )
        if links:
            links_group.add_to(self._map)

        if traces:
            traces_group.add_to(self._map)

        folium.LayerControl().add_to(self._map)   
        del nodes_filtered
