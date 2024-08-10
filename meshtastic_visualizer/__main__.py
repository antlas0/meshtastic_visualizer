#!/usr/bin/env python3

import sys
from PyQt5 import QtWidgets

from .meshtastic_visualizer import MeshtasticQtApp

def main():
    app = QtWidgets.QApplication(sys.argv)
    window = MeshtasticQtApp()
    window.show()
    app.exec_()

if __name__ == "__main__":
    main()
