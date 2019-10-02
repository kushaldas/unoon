#!/usr/bin/env python3
from PyQt5 import QtGui, QtWidgets
from PyQt5.QtCore import QThread, pyqtSignal
from PyQt5.QtWidgets import QTableWidgetItem
import subprocess
import os
import sys
import redis
import json
from pprint import pprint


class DataThread(QThread):
    signal = pyqtSignal("PyQt_PyObject")

    def __init__(self):
        QThread.__init__(self)
        self.cl = redis.Redis()

    # run method gets called when we start the thread
    def run(self):
        while True:
            data = self.cl.blpop("currentprocesses")
            self.signal.emit(data)


class FriendlyApp(QtWidgets.QMainWindow):
    def __init__(self, parent=None):
        super(FriendlyApp, self).__init__(parent)
        self.cl = redis.Redis()

        self.setMinimumWidth(1000)
        self.setMinimumHeight(600)

        header_labels = [
            "Executable",
            "Local Addr",
            "Remote Addr",
            "status",
            "PID",
            "User",
        ]

        # get a current processes table widget
        self.pTable = QtWidgets.QTableWidget()
        self.pTable.setColumnCount(6)

        self.pTable.setHorizontalHeaderLabels(header_labels)
        header = self.pTable.horizontalHeader()
        header.setSectionResizeMode(0, QtWidgets.QHeaderView.ResizeToContents)
        header.setSectionResizeMode(1, QtWidgets.QHeaderView.ResizeToContents)
        header.setSectionResizeMode(2, QtWidgets.QHeaderView.ResizeToContents)

        # get a whitelisted processes table widget
        self.wTable = QtWidgets.QTableWidget()
        self.wTable.setColumnCount(6)

        self.wTable.setHorizontalHeaderLabels(header_labels)
        header = self.wTable.horizontalHeader()
        header.setSectionResizeMode(0, QtWidgets.QHeaderView.ResizeToContents)
        header.setSectionResizeMode(1, QtWidgets.QHeaderView.ResizeToContents)
        header.setSectionResizeMode(2, QtWidgets.QHeaderView.ResizeToContents)

        self.tabs = QtWidgets.QTabWidget()
        # layout = QtWidgets.QHBoxLayout()
        # layout.addWidget(self.pTable)

        self.tabs.addTab(self.pTable, "Current Processes")
        self.tabs.addTab(self.wTable, "Whitelisted Processes")
        self.setCentralWidget(self.tabs)

        # self.pTable.setSizeAdjustPolicy(QtWidgets.QAbstractScrollArea.AdjustToContents)
        self.pTable.setColumnWidth(0, 80)
        self.cp = {}
        self.tr = DataThread()
        self.tr.signal.connect(self.update_cp)
        self.tr.start()

    def update_cp(self, result):
        # data is the list of dicts with currentProcess struct
        data = {}
        data = json.loads(result[1])
        keys = data.keys()
        for key in keys:
            datum = data[key]
            ac = datum["Cmdline"].split(" ")[0]
            # print(ac)
            for con in datum["Connections"]:
                localcon = con["localaddr"]

                local = "{}:{}".format(localcon["ip"], localcon["port"])
                remotecon = con["remoteaddr"]

                # Find the hostname for the IP
                remote_ip = remotecon["ip"]
                remote_host_set = self.cl.smembers("ip:{}".format(remote_ip))
                if remote_host_set:
                    remote_host = list(remote_host_set)[0].decode("utf-8")
                else:
                    remote_host = remote_ip

                remote = "{}:{}".format(remote_host, remotecon["port"])
                cp_key = "{0}:{1}:{2}:{3}".format(ac, key, local, remote)
                if cp_key in self.cp:
                    continue

                # For new processes
                self.cp[cp_key] = datum

                num = self.pTable.rowCount() + 1
                self.pTable.setRowCount(num)
                self.pTable.setItem(num - 1, 0, QTableWidgetItem(ac))
                self.pTable.item(num - 1, 0).setToolTip(datum["Cmdline"])
                self.pTable.setItem(num - 1, 1, QTableWidgetItem(local))
                self.pTable.setItem(num - 1, 2, QTableWidgetItem(remote))
                self.pTable.setItem(num - 1, 3, QTableWidgetItem(con["status"]))
                self.pTable.setItem(num - 1, 4, QTableWidgetItem(key))
                self.pTable.setItem(num - 1, 5, QTableWidgetItem(str(con["uids"])))


def main():
    app = QtWidgets.QApplication(sys.argv)
    form = FriendlyApp()
    form.show()
    app.exec_()


if __name__ == "__main__":
    main()
