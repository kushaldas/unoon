#!/usr/bin/env python3
from PyQt5 import QtGui, QtWidgets, QtCore
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


class WhiteDialog(QtWidgets.QDialog):
    newwhitelist = QtCore.pyqtSignal(str)

    def __init__(self, text):
        super(WhiteDialog, self).__init__()
        self.setWindowTitle("Whitelist commands")
        self.setModal(True)
        self.setMinimumWidth(500)

        self.textbox = QtWidgets.QTextEdit()
        # We want only plain text
        self.textbox.setAcceptRichText(False)
        self.textbox.setPlainText(text)

        # Dialog buttons
        ok_button = QtWidgets.QPushButton("Save")
        ok_button.clicked.connect(self.save)
        c_button = QtWidgets.QPushButton("cancel")
        c_button.clicked.connect(self.cancel)

        button_hboxlayout = QtWidgets.QHBoxLayout()
        button_hboxlayout.addStretch()
        button_hboxlayout.addWidget(c_button)
        button_hboxlayout.addWidget(ok_button)
        b = QtWidgets.QWidget()
        b.setLayout(button_hboxlayout)

        group_vboxlayout = QtWidgets.QVBoxLayout()
        group_vboxlayout.addWidget(self.textbox)
        group_vboxlayout.addWidget(b)

        groupbox = QtWidgets.QGroupBox("Whitelisted commands")
        groupbox.setLayout(group_vboxlayout)

        big_layout = QtWidgets.QVBoxLayout()
        big_layout.addWidget(groupbox)
        self.setLayout(big_layout)

    def save(self):
        "Saves the text from the textbox"
        text = self.textbox.toPlainText()
        with open("./whitelists.txt", "w") as fobj:
            fobj.write(text)

        self.newwhitelist.emit(text)
        self.close()

    def cancel(self):
        self.close()


class FriendlyApp(QtWidgets.QMainWindow):
    def __init__(self, parent=None):
        super(FriendlyApp, self).__init__(parent)
        self.cl = redis.Redis()

        self.whitelists_text = ""
        self.whitelist = []

        # TODO: Fix the path of the whitelist rules
        if os.path.exists("whitelists.txt"):
            with open("whitelists.txt") as fobj:
                self.whitelists_text = fobj.read()

        self.update_whitelist(self.whitelists_text)

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

        self.tabs.addTab(self.pTable, "Current Processes")
        self.tabs.addTab(self.wTable, "Whitelisted Processes")
        self.setCentralWidget(self.tabs)

        exitAction = QtWidgets.QAction("E&xit", self)
        exitAction.triggered.connect(self.exit_process)

        whitelistAction = QtWidgets.QAction("&Whistlist", self)
        whitelistAction.triggered.connect(self.show_whitelist)
        menu = self.menuBar()
        file = menu.addMenu("&File")
        file.addAction(exitAction)

        edit = menu.addMenu("&Edit")
        edit.addAction(whitelistAction)

        self.pTable.setColumnWidth(0, 80)
        self.cp = {}
        self.tr = DataThread()
        self.tr.signal.connect(self.update_cp)
        self.tr.start()

    def update_whitelist(self, text):
        # Create the current list of whitelisted commands
        self.whitelists_text = text
        for cmd in text.split("\n"):
            cmd = cmd.strip()
            self.whitelist.append(cmd)
        print(text)

    def show_whitelist(self):
        "Updates the current whitelist commands"
        self.whitedialog = WhiteDialog(self.whitelists_text)
        self.whitedialog.newwhitelist.connect(self.update_whitelist)
        self.whitedialog.exec_()

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

                whitelist_flag = False
                for cmd in self.whitelist:
                    # The following is True for whitelisted commands
                    if ac.startswith(cmd):
                        self.update_processtable(
                            self.wTable, datum, con, local, remote, key, ac
                        )
                        whitelist_flag = True
                        break
                if whitelist_flag:
                    continue

                self.update_processtable(
                    self.pTable, datum, con, local, remote, key, ac
                )

    def update_processtable(self, table, datum, con, local, remote, key, ac):
        "Updates the given table with the new data in a new row"
        num = table.rowCount() + 1
        table.setRowCount(num)
        table.setItem(num - 1, 0, QTableWidgetItem(ac))
        table.item(num - 1, 0).setToolTip(datum["Cmdline"])
        table.setItem(num - 1, 1, QTableWidgetItem(local))
        table.setItem(num - 1, 2, QTableWidgetItem(remote))
        table.setItem(num - 1, 3, QTableWidgetItem(con["status"]))
        table.setItem(num - 1, 4, QTableWidgetItem(key))
        table.setItem(num - 1, 5, QTableWidgetItem(str(con["uids"])))

    def exit_process(self):
        sys.exit(0)


def main():
    app = QtWidgets.QApplication(sys.argv)
    form = FriendlyApp()
    form.show()
    app.exec_()


if __name__ == "__main__":
    main()
