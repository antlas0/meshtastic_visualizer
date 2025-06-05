# Meshtastic Visualizer
Python PyQt graphical desktop app to interface with a Meshtastic node using a TCP, Bluetooth or serial connection. Possibility to subscribe to MQTT servers and retrieve nodes, messages,...
Objective is to use an already configured Meshtastic device, and be able to inspect messages, packets, metrics,...

Initial work based on original repository of "Meshtastic Chat Desktop"

Main framework used is PyQt6.
Linux compatible, debian based tested (should work on Windows, compatibility not ensured).

## Features
| Connection | Serial | TCP | Bluetooth |
|---|---|---|---|
|Availability|✅|✅|✅|


| Feature | Using local device | Using MQTT |
|---|---|---|
| Display nodes configuration (PK, hopsaway,...)|✅|✅|
| Display map of nodes |✅|✅|
| Display messages |✅|✅|
| Display packets |✅|✅|
| Send messages with acknowledgment|✅|❌|
| Perform traceroute (with SNR)|✅|❌|
| Export nodes (json) |✅|✅|
| Export messages and packets (json) |✅|✅|
| Export telemetry metrics (json) |✅|✅|
| Export mqtt logs |-|✅|
| Export radio serial console |✅|-|
| Nodes telemetry metrics plotting (CHutil, power,...) |✅|✅|
| Packets RF metrics plotting (RSSI, SNR,...) |✅|✅|
| Custom tiles server |✅|✅|

## How to donwload

```bash
$ git clone https://github.com/antlas0/meshtastic_visualizer.git
$ git checkout v1.8
```

## How to install and run
[uv](https://github.com/astral-sh/uv) is used to manage dependencies, venv and packaging.
To install dependencies and run on your computer:
```bash
$ uv run meshtastic_visualizer.py
```

Note: If you rely on Wayland, you may experience Qt event not properly managed. To fall back on a `X11` session, provide the following environment variable when launching the application: `XDG_SESSION_TYPE=x11`.
Otherwise, you can try `QT_QPA_PLATFORM=xcb`, by having previously installed `libxcb-cursor0` package.


## How to run with Docker

Based on X11, build the dockerfile and run the docker container. This example assumes your node is accessible at `/dev/ttyACM0`.
```bash
$ export DISPLAY=:0.0
$ xhost +local:docker
$ docker build . -t meshtastic_visualizer:latest
$ docker run -it \
    --env="DISPLAY=$DISPLAY" \
    --privileged \
    --volume="/var/run/dbus/:/var/run/dbus/" \
    --volume="/tmp/.X11-unix:/tmp/.X11-unix:rw" \
    --device=/dev/ttyACM0 \
    meshtastic_visualizer:latest
```

## How to use a local tiles server
To setup a local tiles server, one solution is to use Docker to run a server and point to it from the application.

To import and setup the server, we can rely on [openstreetmap-tile-server](https://github.com/Overv/openstreetmap-tile-server). Globally we will:
* Download the needed tiles in `.pbf` format along with the polylines in `.poly` format, from [https://download.geofabrik.de](https://download.geofabrik.de). Here is an example for all [France](https://download.geofabrik.de/europe/france.html).
* Import them in a Docker volume
```bash
$ docker run \
    -v /absolute/path/to/france.osm.pbf:/data/region.osm.pbf \
    -v /absolute/path/to/france.poly:/data/region.poly \
    -v osm-data:/data/database/ \
    overv/openstreetmap-tile-server \
    import
```
* Run the tile server with this volume, in this case it will be binded to `0.0.0.0:8080`
```bash
$ docker run \
    -p 8080:80 \
    -v osm-data:/data/database/ \
    -d overv/openstreetmap-tile-server \
    run
```
* Give to the applicaiton the tiles request `http://127.0.0.1:8080/tile/{z}/{x}/{y}.png`.
![Capture d’écran du 2025-06-05 15-46-54](https://github.com/user-attachments/assets/8ee0e3a1-730e-4d4c-8ad5-bbb55a1d771b)


## Todo
A lot ! Please fill an issue to add ideas or raise bugs.

Here is a list of things it could be intetesting to work on:

#### App features

 - [ ] Code factorisation
 - [x] Custom tile server
 - [ ] Theming
 - [ ] Quick node actions (shutdown,... TBD)
 - [ ] Traceroute results: review graphical display as not optimal
 - [ ] Map: add layer for only "online" nodes
 - [ ] Map: review "relay node" layer as not easily scalable

#### Packaging

 - [ ] Automate non-regression build
 - [ ] Add backend unitary testing
 - [ ] Make Docker image available without having to build it

## Contributing
Please open a Pull Request.

## Overview
![Capture d’écran du 2025-05-30 09-43-22](https://github.com/user-attachments/assets/2df80a1d-7895-498c-9389-684419566568)
![Capture d’écran du 2025-03-24 15-55-21](https://github.com/user-attachments/assets/dd2f10ae-442e-4958-ac51-50eafd4b5df1)
![Capture d’écran du 2025-03-24 15-55-30](https://github.com/user-attachments/assets/96f44374-dfa3-4e69-9d7f-a91b8038052b)
![Capture d’écran du 2025-03-24 15-55-36](https://github.com/user-attachments/assets/e16b66d1-79f4-4fc9-8d55-f1000f05ae13)
![Capture d’écran du 2025-05-30 09-43-36](https://github.com/user-attachments/assets/e0958a6a-ff74-4c32-b970-0664dcecf1c1)


