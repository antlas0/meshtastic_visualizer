# Meshtastic Visualizer
Python PyQt graphical interface to interface with a local node.
Main framework used is PyQt6. (Screenshots may be out of date).

Work based on original repository of "Meshtastic Chat Desktop"

> Meshtastic Chat Desktop is a desktop application designed for Meshtastic device users who want to send and receive messages using their Meshtastic device via their desktop.

I forked the initial repo to work on the UI and backend interaction.  The objective is to provide a build on Linux (should work on Windows, compatibility not ensured) to be able to graphically view a meshtastic node, without re-doing what the Python Meshtastic CLI does best.

## Features
At the moment, what works :
* Display configuration of local and remote node
* Display Channels configuration (using local device)
* Display radio output (using local device)
* Print mesh information
* Perform traceroute (using local device)
* Display map of nodes
* Send message with acknowledgment (using local device)
* Export messages and metrics
* Export radio output logs
* Metrics plotting (RF, power,...)
* MQTT reader (only subscribing to updates, not pusblishing)

To run :
```bash
$ python3 -m venv .venv
$ source .venv/bin/activate
$ python -m pip install -r requirements.txt
$ python -m meshtastic_visualizer
```

or using the `setup.py`:

```bash
$ python -m pip install .
# Linux only
$ meshtastic_visualizer
```

Note: If you rely on Wayland, you may experience Qt event not properly managed. To fall back on a `X11` session, provide the following environment variable when launching the application: `XDG_SESSION_TYPE=x11`.

## Todo
A lot ! Please fill an issue to add ideas or raise bugs.

## Contributing
Please open a Pull Request.
Automatic lintering is done with `autopep8` in a `pre-commit` hook. You will need to ensure `requirements_dev.txt` are installed.

## Overview
![device](https://github.com/user-attachments/assets/6512218a-70ab-476a-98e2-a01cd0580b55)
![messages](https://github.com/user-attachments/assets/cfdd7f9e-481c-470b-96d9-a40280a65da2)
![map](https://github.com/user-attachments/assets/93682d59-0465-4236-9f4e-1ff0aeb2aa32)
![nodes](https://github.com/user-attachments/assets/76bc412d-2ffa-4e03-942a-64299a7e0969)


