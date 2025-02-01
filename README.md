# Meshtastic Visualizer
Python PyQt graphical desktop app to interface with a local Meshtastic node using an USB connection. Possibility to subscribe to MQTT servers and retrieve nodes, messages,...
Objective is to use an already configured Meshtastic device, and be able to inspect messages, packets, metrics,...

Initial work based on original repository of "Meshtastic Chat Desktop"

Main framework used is PyQt6.
Linux compatible, debian based tested (should work on Windows, compatibility not ensured).

Warning: Work in progress !

## Features
| Feature | Using local device | Using MQTT |
|---|---|---|
| Display nodes configuration (with public key)|✅|✅|
| Display map of nodes |✅|✅|
| Display messages |✅|✅|
| Display packets |✅|✅|
| Send messages with acknowledgment|✅|❌|
| Perform traceroute (with SNR)|✅|❌|
| Export nodes (json) |✅|✅|
| Export messages and packets (json) |✅|✅|
| Export events logs |✅|✅|
| Nodes telemetry metrics plotting (CHutil, power,...) |✅|✅|
| Packets RF metrics plotting (RSSI, SNR,...) |✅|✅|
## How to run 

Based on X11, build the dockerfile and run the docker container. This example assumes your node is accessible at `/dev/ttyACM0`.
```bash
$ export DISPLAY=:0.0
$ xhost +local:docker
$ docker build . -t meshtastic_visualizer:latest
$ docker run -it \
    --env="DISPLAY=$DISPLAY" \
    --volume="/tmp/.X11-unix:/tmp/.X11-unix:rw" \
    --device=/dev/ttyACM0 \
    meshtastic_visualizer:latest \
    python -m meshtastic_visualizer
```

## How to install

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

## Contributing
Please open a Pull Request.

## Overview
![Capture d’écran du 2025-02-01 15-47-45](https://github.com/user-attachments/assets/a1570525-a6f8-4118-a99b-662293ffa831)
![Capture d’écran du 2025-02-01 15-47-52](https://github.com/user-attachments/assets/08e10371-1732-4ae2-8c77-43b7a26f796b)
![Capture d’écran du 2025-02-01 15-47-58](https://github.com/user-attachments/assets/05ba32f0-8603-4b4f-b8db-70c5fef04f44)
![Capture d’écran du 2025-02-01 15-48-03](https://github.com/user-attachments/assets/0539358c-4c44-4850-b584-dadd41e7067a)
![Capture d’écran du 2025-02-01 15-48-08](https://github.com/user-attachments/assets/7fb9b61d-c212-483a-8da4-cee3505ca462)



