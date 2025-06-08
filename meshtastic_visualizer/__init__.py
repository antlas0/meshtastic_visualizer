
import sys
from PyQt6 import QtWidgets

from .visualizer import MeshtasticQtApp


def main():
    app = QtWidgets.QApplication(sys.argv)
    window = MeshtasticQtApp()
    window.show()
    app.exec()


if __name__ == "__main__":
    main()