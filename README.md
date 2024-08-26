# Meshtastic Visualizer
Python PyQt graphical interface to interface with a local node.

Work based on original repository of "Meshtastic Chat Desktop"

> Meshtastic Chat Desktop is a desktop application designed for Meshtastic device users who want to send and receive messages using their Meshtastic device via their desktop.

I forked the initial repo to work on the UI and backend interaction.  The objective is to provide a build on Linux to be able to graphically view a meshtastic node, without re-doing what the Python Meshtastic CLI does best.

## Features
I disabled working features from the original repo to focus on a basic working tool, and to better understand Meshtastic inner behavior.
Main framework used is PyQt6.

At the moment, what works :
* Display configuration of local and remote node
* Display Channels configuration
* Display radio output
* Print mesh information
* Perform traceroute
* Display map of nodes
* Send message with acknowledgment
* Export messages
* Export radio output logs
* Metrics plotting (RF, power,...)
* MQTT reader

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
![Capture d’écran du 2024-08-26 13-49-40](https://github.com/user-attachments/assets/b92509a6-77f0-4283-99f1-883cdbb604e2)

![messages](https://github.com/user-attachments/assets/145d0693-34ef-48e7-b969-29834183115a)
![map](https://github.com/user-attachments/assets/1a3cb9a0-a5d5-4ba6-ab32-1fee48642f8f)
![nodes](https://github.com/user-attachments/assets/cd912d34-d2ec-4872-9633-a37012d69ef1)



