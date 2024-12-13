# Meshtastic Visualizer
Python PyQt graphical desktop app to interface with a local Meshtastic node using an USB connection. Possibility to subscribe to MQTT servers and retrieve nodes, messages,...
Main framework used is PyQt6.

Work based on original repository of "Meshtastic Chat Desktop"

> Meshtastic Chat Desktop is a desktop application designed for Meshtastic device users who want to send and receive messages using their Meshtastic device via their desktop.

The objective is to provide a build on Linux (should work on Windows, compatibility not ensured).

## Features
| Feature | Using local device | Using MQTT |
|---|---|---|
| Display nodes configuration (with public key)|✅|✅|
| Display map of nodes |✅|✅|
| Display messages |✅|✅|
| Send messages with acknowledgment|✅|❌|
| Perform traceroute (with SNR)|✅|❌|
| Export nodes (json) |✅|✅|
| Export messages and packets (json) |✅|✅|
| Export events logs (json) |✅|✅|
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

## Todo
A lot ! Please fill an issue to add ideas or raise bugs.

## Contributing
Please open a Pull Request.
Automatic lintering is done with `autopep8` in a `pre-commit` hook. You will need to ensure `requirements_dev.txt` are installed.

## Overview
(Screenshots out of date)
![device](https://github.com/user-attachments/assets/6512218a-70ab-476a-98e2-a01cd0580b55)
![messages](https://github.com/user-attachments/assets/cfdd7f9e-481c-470b-96d9-a40280a65da2)
![map](https://github.com/user-attachments/assets/93682d59-0465-4236-9f4e-1ff0aeb2aa32)
![nodes](https://github.com/user-attachments/assets/76bc412d-2ffa-4e03-942a-64299a7e0969)


