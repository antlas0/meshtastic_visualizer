# Meshtastic Visualizer
Python PyQt graphical desktop app to interface with a local Meshtastic node using an USB connection. Possibility to subscribe to MQTT servers and retrieve nodes, messages,...
Objective is to be able to use an already configured Meshtastic device, and be able to inspect messages, packets, metrics,...

Initial work based on original repository of "Meshtastic Chat Desktop"

Main framework used is PyQt6.
Linux compatible, debian based testes (should work on Windows, compatibility not ensured).

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
| Metrics plotting (RF, power,...) |✅|✅|

## Installation 
Using the `setup.py`:

```bash
$ python -m pip install .
```

## How to start

To run :
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
Automatic lintering is done with `autopep8` in a `pre-commit` hook. You will need to ensure `requirements_dev.txt` are installed.

## Overview
![Capture d’écran du 2024-12-15 13-45-37](https://github.com/user-attachments/assets/e1ecdbcc-2dc6-4ca4-841a-75abf75f3c97)
![Capture d’écran du 2024-12-15 13-45-21](https://github.com/user-attachments/assets/85d23338-3edc-4cb2-8240-0652767fc23c)
![Capture d’écran du 2024-12-15 13-45-03](https://github.com/user-attachments/assets/4d2a605c-72ee-4431-9306-dfa5f92323ad)
![Capture d’écran du 2024-12-15 13-45-32](https://github.com/user-attachments/assets/5fb386cb-1910-4969-b3f1-db626e2d7edb)




