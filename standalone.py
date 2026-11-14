#!/usr/bin/env python3
from pathlib import Path
import sys

APPLETS_ROOT = Path(__file__).resolve().parent.parent
if str(APPLETS_ROOT) not in sys.path:
    sys.path.insert(0, str(APPLETS_ROOT))

from PyQt6.QtWidgets import QApplication, QMainWindow
from linspectacles_dbus_inspector.dbus_inspector.applet import DBusInspectorTab, APPLET_NAME, APPLET_VERSION, APPLET_PUBLISHER
from linspectacles_dbus_inspector.dbus_inspector._support import STANDALONE_STYLESHEET


def main():
    app = QApplication([])
    app.setApplicationName(APPLET_NAME)
    app.setApplicationVersion(APPLET_VERSION)
    app.setOrganizationName(APPLET_PUBLISHER)
    app.setStyleSheet(STANDALONE_STYLESHEET)
    win = QMainWindow()
    win.setWindowTitle(f"{APPLET_NAME} {APPLET_VERSION} — LinSpectacles Applet")
    win.resize(1320, 800)
    win.setCentralWidget(DBusInspectorTab())
    win.show()
    return app.exec()


if __name__ == '__main__':
    raise SystemExit(main())
