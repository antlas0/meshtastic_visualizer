#!/usr/bin/env python3


import hashlib
import io
import folium
from folium.plugins import MousePosition, MeasureControl


from .resources import CHARGING_TRESHOLD

class Mapper:
    """class that manages the map
    """
    def __init__(self) -> None:
        self._map = None
        self.create_map()

    def create_map(self) -> None:
        """create a map with initial parameters
        """
        if self._map:
            del self._map
        self._map = folium.Map(zoom_start=7, control_scale=True, no_touch=True)
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

    def _link_color(self, node_id: str) -> str:
        """returns a color from node condition

        Args:
            node_id (str): node id

        Returns:
            str: color code
        """
        hash_object = hashlib.md5(node_id.encode())
        color = '#' + hash_object.hexdigest()[:6]
        return color

    def update(self, nodes: list) -> None:
        """update map with nodes

        Args:
            nodes (list): nodes
        """
        if nodes is None or not nodes:
            return

        self.create_map()

        markers_group = folium.FeatureGroup(name="Stations")
        links_group = folium.FeatureGroup(name="Links")
        markers: list = []
        links: list = []

        # remove any node that does not have full coordinates
        nodes_filtered = {}
        for node_id, details in nodes.items():
            if details.lat is not None and details.lat != "None" \
                and details.lon is not None and details.lon != "None":
                nodes_filtered[node_id] = details

        # in case of links tracing, pre-create a dict(node_id, [lat, lon])
        nodes_coords = {
            x.id: [
                float(
                    x.lat), float(
                    x.lon)] for __, x in nodes_filtered.items()}

        for node_id, node in nodes_filtered.items():
            if node.lat is None or node.lon is None:
                continue
            icon_name:str = "tower-cell"
            strl = []
            if node.long_name:
                strl.append(f"<b>👤 Name:</b> {node.long_name}</br>")
            strl.append(f"<b>🆔 id:</b> {node.id}</br>")
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
                                link_coords, color=self._link_color(node.id))
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
        del nodes_filtered
