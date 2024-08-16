# Meshtastic Visualizer
Python PyQt graphical interface to interface with a local node.

Work based on original repository of "Meshtastic Chat Desktop"

> Meshtastic Chat Desktop is a desktop application designed for Meshtastic device users who want to send and receive messages using their Meshtastic device via their desktop.

I forked the initial repo to work on the UI and backend interaction.  The objective is to provide a build on Linux to be able to graphically view a meshtastic node, without re-doing what the Python Meshtastic CLI does best.

## Features
I disabled working features from the original repo to focus on a basic working tool, and to better understand Meshtastic inner behavior.
Main framework used is PyQt5.

At the moment, what works :
* Display configuration of local node
* Display Channels configuration
* Display radio output
* Print mesh information
* Perform traceroute
* Display map of nodes
* Send message with acknowledgment

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
![device_tab](https://github.com/user-attachments/assets/bbcb0be0-c3a0-443e-9237-24b4936ffd7b)
![node_tab](https://github.com/user-attachments/assets/ca66273d-6d88-4355-8ef8-1489d16ebdd3)
![message_tab](https://github.com/user-attachments/assets/aa5dde74-786d-4746-8b8f-a9c11f6c368b)


