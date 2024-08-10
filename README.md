# Meshtastic Visualizer
Python PyQt graphical interface to interface with a local node.

Work based on original repository of "Meshtastic Chat Desktop"

> Meshtastic Chat Desktop is a desktop application designed for Meshtastic device users who want to send and receive messages using their Meshtastic device via their desktop. The application supports Windows, Linux, and Raspberry Pi.

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

## Todo
A lot ! Please fill an issue to add ideas or raise bugs.

## Overview
![scshot](https://github.com/user-attachments/assets/1ed2c771-8909-40da-9226-44018fca8d5b)

