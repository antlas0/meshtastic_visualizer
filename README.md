# Meshtastic Visualizer
Python PyQt graphical desktop app to interface with a Meshtastic node using a TCP or serial connection. Possibility to subscribe to MQTT servers and retrieve nodes, messages,...
Objective is to use an already configured Meshtastic device, and be able to inspect messages, packets, metrics,...

Initial work based on original repository of "Meshtastic Chat Desktop"

Main framework used is PyQt6.
Linux compatible, debian based tested (should work on Windows, compatibility not ensured).

## Features
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
| Export events logs |✅|✅|
| Nodes telemetry metrics plotting (CHutil, power,...) |✅|✅|
| Packets RF metrics plotting (RSSI, SNR,...) |✅|✅|

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
    meshtastic_visualizer:latest \
    python -m meshtastic_visualizer
```

## How to install and run

To install on your computer:
```bash
$ python3 -m venv .venv
$ source .venv/bin/activate
$ python -m pip install -r requirements.txt
$ python -m meshtastic_visualizer
```
Note: If you rely on Wayland, you may experience Qt event not properly managed. To fall back on a `X11` session, provide the following environment variable when launching the application: `XDG_SESSION_TYPE=x11`.
Otherwise, you can try `QT_QPA_PLATFORM=xcb`, by having previously installed `libxcb-cursor0` package.


## Todo
A lot ! Please fill an issue to add ideas or raise bugs.
Code cleaning and going deeper in factorization becomes more and more needed :)


## Contributing
Please open a Pull Request.

## Overview
![Capture d’écran du 2025-03-24 15-55-08](https://github.com/user-attachments/assets/f79875b7-8167-46af-95a3-d24ada5dff36)
![Capture d’écran du 2025-03-24 15-55-21](https://github.com/user-attachments/assets/dd2f10ae-442e-4958-ac51-50eafd4b5df1)
![Capture d’écran du 2025-03-24 15-55-30](https://github.com/user-attachments/assets/96f44374-dfa3-4e69-9d7f-a91b8038052b)
![Capture d’écran du 2025-03-24 15-55-36](https://github.com/user-attachments/assets/e16b66d1-79f4-4fc9-8d55-f1000f05ae13)
![Capture d’écran du 2025-03-24 15-55-41](https://github.com/user-attachments/assets/d3e6b9b0-6600-49d9-a034-f38481c4ed42)
