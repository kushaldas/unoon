#!/usr/bin/env python3
from PyQt5 import QtGui, QtWidgets, QtCore
from PyQt5.QtCore import QThread, pyqtSignal
from PyQt5.QtWidgets import QTableWidgetItem
from ucss import *
from db import Processhistory, create_session
import subprocess
import os
import sys
import redis
import json
import pwd
from datetime import datetime
from pprint import pprint
import yaml


PROCESSTYPE = 1
WHITETYPE = 2
LOGSTYPE = 3


def find_user(uid: int):
    "Find the username from the User ID"
    st = pwd.getpwuid(uid)
    return st.pw_name


class TableWidget(QtWidgets.QTableWidget):
    def __init__(self, tabletype=PROCESSTYPE):
        super(TableWidget, self).__init__()
        # PROCESSTYPE: this is a process table
        # WHITETYPE: this is a whitelisted table
        # LOGSTYPE: this is a history logs table
        self.tabletype = tabletype
        self.setIconSize(QtCore.QSize(25, 25))
        self.menu = QtWidgets.QMenu()
        action = QtWidgets.QAction("Mark as Whitelist", self)
        whitelisticon = QtGui.QIcon("./security_tick.png")
        action.setIcon(whitelisticon)
        action.triggered.connect(lambda: self.rightClickSlot())
        self.menu.addAction(action)

        self.setSelectionMode(QtWidgets.QAbstractItemView.SingleSelection)
        self.setColumnCount(7)
        if self.tabletype != LOGSTYPE:
            # The unique value is hidden for process and whitelist tables
            self.setColumnHidden(6, True)
        if self.tabletype != LOGSTYPE:
            header_labels = [
                "Executable",
                "Local Addr",
                "Remote Addr",
                "status",
                "PID",
                "User",
            ]
        else:
            header_labels = [
                "Executable",
                "Local Addr",
                "Remote Addr",
                "status",
                "PID",
                "User",
                "Time",
            ]
        self.setHorizontalHeaderLabels(header_labels)
        self.setHorizontalHeaderItem(
            0, QTableWidgetItem(QtGui.QIcon("terminal.png"), "Executable")
        )
        self.setHorizontalHeaderItem(
            2, QTableWidgetItem(QtGui.QIcon("cloud_up.png"), "Remote")
        )
        header = self.horizontalHeader()
        header.setSectionResizeMode(0, QtWidgets.QHeaderView.ResizeToContents)
        header.setSectionResizeMode(1, QtWidgets.QHeaderView.ResizeToContents)
        header.setSectionResizeMode(2, QtWidgets.QHeaderView.ResizeToContents)
        if self.tabletype == LOGSTYPE:
            header.setSectionResizeMode(6, QtWidgets.QHeaderView.ResizeToContents)

    def rightClickSlot(self):
        for i in self.selectionModel().selection().indexes():
            # TODO: find the item and open up the Dialog for adding in whitelist.
            print(i.row(), i.column())

    def contextMenuEvent(self, event):
        col = self.columnAt(event.pos().x())
        if col == 0:
            if self.tabletype == PROCESSTYPE:
                self.menu.popup(QtGui.QCursor.pos())


class DataThread(QThread):
    signal = pyqtSignal("PyQt_PyObject")

    def __init__(self, config={}):
        QThread.__init__(self)
        self.cl = redis.Redis(
            host=config["host"],
            port=config["port"],
            password=config["password"],
            db=config["db"],
        )

    # run method gets called when we start the thread
    def run(self):
        while True:
            data = self.cl.blpop("currentprocesses")
            self.signal.emit(data)


class WhitelistDialog(QtWidgets.QDialog):
    newwhitelist = QtCore.pyqtSignal(str)

    def __init__(self, text):
        super(WhitelistDialog, self).__init__()
        self.setWindowTitle("Whitelist commands")
        self.setModal(True)
        self.setMinimumWidth(700)

        self.textbox = QtWidgets.QTextEdit()
        # We want only plain text
        self.textbox.setAcceptRichText(False)
        self.textbox.setPlainText(text)

        whitelistlargeicon = QtWidgets.QLabel()
        whitepixmap = QtGui.QPixmap("security_tick_large.png")
        whitelistlargeicon.setPixmap(whitepixmap)
        whitelistlabel = QtWidgets.QLabel("List of Whitelisted commands")
        whitelistlabel.setStyleSheet(QWhiteListBannerCSS)

        banner_hboxlayout = QtWidgets.QHBoxLayout()
        banner_hboxlayout.addWidget(whitelistlargeicon)
        banner_hboxlayout.addWidget(whitelistlabel)
        banner_hboxlayout.addStretch()
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
        group_vboxlayout.addLayout(banner_hboxlayout)
        group_vboxlayout.addWidget(self.textbox)
        group_vboxlayout.addWidget(b)

        self.setLayout(group_vboxlayout)

    def save(self):
        "Saves the text from the textbox"
        text = self.textbox.toPlainText()
        with open("./whitelists.txt", "w") as fobj:
            fobj.write(text)

        self.newwhitelist.emit(text)
        self.close()

    def cancel(self):
        self.close()


class NewConnectionDialog(QtWidgets.QDialog):
    def __init__(self, datum, remote, pid, user):
        super(NewConnectionDialog, self).__init__()

        self.setWindowTitle("Alert")
        self.setWindowIcon(QtGui.QIcon("alert.png"))

        cmd_label = QtWidgets.QLabel(datum["Cmdline"])
        cmd_label.setStyleSheet("QLabel { font-weight: bold; font-size: 20px; }")
        cmd_label.setWordWrap(True)
        remote_label = QtWidgets.QLabel(remote)
        pid_label = QtWidgets.QLabel("PID: {}".format(pid))
        user_label = QtWidgets.QLabel("User: {}".format(user))
        cwd_label = QtWidgets.QLabel("Directory: {}".format(datum["Cwd"]))

        layout = QtWidgets.QVBoxLayout()
        layout.addWidget(cmd_label)
        layout.addWidget(remote_label)
        layout.addWidget(pid_label)
        layout.addWidget(user_label)
        layout.addWidget(cwd_label)
        self.setLayout(layout)

        self.show()


class MainWindow(QtWidgets.QMainWindow):
    def __init__(self, parent=None, config={}):
        super(MainWindow, self).__init__(parent)
        self.setWindowTitle("Unoon")

        self.cl = redis.Redis(
            host=config["host"],
            port=config["port"],
            password=config["password"],
            db=config["db"],
        )
        self.pid = str(os.getpid())
        self.session = create_session()

        # To store all alerts in runtime only
        # TODO: In future store this in sqlite
        self.logs = []

        self.whitelists_text = ""
        self.whitelist = []

        # TODO: Fix the path of the whitelist rules
        if os.path.exists("whitelists.txt"):
            with open("whitelists.txt") as fobj:
                self.whitelists_text = fobj.read()

        self.update_whitelist(self.whitelists_text)

        self.setMinimumWidth(1000)
        self.setMinimumHeight(600)

        # get a current processes table widget
        self.pTable = TableWidget(tabletype=PROCESSTYPE)

        # get a whitelisted processes table widget
        self.wTable = TableWidget(tabletype=WHITETYPE)

        # get a logs table to show history
        self.logsTable = TableWidget(tabletype=LOGSTYPE)

        self.tabs = QtWidgets.QTabWidget()
        self.tabs.setIconSize(QtCore.QSize(25, 25))
        self.tabs.setStyleSheet(QTAB)

        normalicon = QtGui.QIcon("./magnify.png")
        self.tabs.addTab(self.pTable, normalicon, "Current Processes")
        whitelisticon = QtGui.QIcon("./security_tick.png")
        self.tabs.addTab(self.wTable, whitelisticon, "Whitelisted Processes")
        logsicon = QtGui.QIcon("./logs.png")
        self.tabs.addTab(self.logsTable, logsicon, "History")
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

        self.shortcut1 = QtWidgets.QShortcut(QtGui.QKeySequence("Alt+1"), self)
        self.shortcut1.activated.connect(self.showcurrenttab)
        self.shortcut2 = QtWidgets.QShortcut(QtGui.QKeySequence("Alt+2"), self)
        self.shortcut2.activated.connect(self.showwhitelisttab)
        self.shortcut3 = QtWidgets.QShortcut(QtGui.QKeySequence("Alt+3"), self)
        self.shortcut3.activated.connect(self.showlogstab)

        self.first_run = True
        self.new_connection_dialogs = []
        self.cp = {}

        self.tr = DataThread(config)
        self.tr.signal.connect(self.update_cp)
        self.tr.start()

    def showcurrenttab(self):
        self.tabs.setCurrentIndex(0)

    def showwhitelisttab(self):
        self.tabs.setCurrentIndex(1)

    def showlogstab(self):
        self.tabs.setCurrentIndex(2)

    def update_whitelist(self, text):
        # Create the current list of whitelisted commands
        self.whitelist = []
        self.whitelists_text = text
        for cmd in text.split("\n"):
            cmd = cmd.strip()
            if cmd:
                self.whitelist.append(cmd)

    def show_whitelist(self):
        "Updates the current whitelist commands"
        self.whitelist_dialog = WhitelistDialog(self.whitelists_text)
        self.whitelist_dialog.newwhitelist.connect(self.update_whitelist)
        self.whitelist_dialog.exec_()

    def update_cp(self, result):
        # data is the list of dicts with currentProcess struct
        data = {}
        data = json.loads(result[1])
        pids = data.keys()
        current_keys = {}
        for pid in pids:
            # Skip desktop application itself
            if str(pid) == self.pid:
                continue
            datum = data[pid]
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
                cp_key = "{0}:{1}:{2}".format(ac, pid, remote)
                # record the key
                current_keys[cp_key] = True
                if cp_key in self.cp:
                    continue

                whitelist_flag = False
                for cmd in self.whitelist:
                    # The following is True for whitelisted commands
                    if ac.startswith(cmd):
                        self.update_processtable(
                            self.wTable, datum, con, local, remote, pid, ac, cp_key
                        )
                        whitelist_flag = True
                        break

                # Display popup
                if not self.first_run and cp_key not in self.cp and not whitelist_flag:
                    user = find_user(con["uids"][0])
                    d = NewConnectionDialog(datum, remote, pid, user)
                    self.new_connection_dialogs.append(d)
                    # Store for the runtime logs
                    self.logs.append((datum, con, local, remote, pid, ac, cp_key))

                phistory = Processhistory(
                    executable=ac.split()[0],
                    command=ac,
                    local_ip=con["localaddr"]["ip"],
                    local_port=con["localaddr"]["port"],
                    remote_ip=remote_host,
                    remote_port=con["remoteaddr"]["port"],
                    pid=pid,
                    realuid=con["uids"][0],
                    effectiveuid=con["uids"][1],
                    saveduid=con["uids"][2],
                    filesystemuid=con["uids"][3],
                    when=datetime.now(),
                )

                self.session.add(phistory)
                self.session.commit()

                # For new processes
                self.cp[cp_key] = datum

                if whitelist_flag:
                    continue

                self.update_processtable(
                    self.pTable, datum, con, local, remote, pid, ac, cp_key
                )
                self.update_processtable(
                    self.logsTable, datum, con, local, remote, pid, ac, cp_key, True
                )

        delkeys = []
        for key in self.cp.keys():
            if key not in current_keys:
                # means this connection is no longer there
                # Add to the list of keys to be deleted later
                delkeys.append(key)

                # Check in the normal process table
                items = self.pTable.findItems(key, QtCore.Qt.MatchFixedString)
                if items:
                    item = items[0]
                    self.pTable.removeRow(item.row())
                    continue

                # Check in the whitelisted process table
                items = self.wTable.findItems(key, QtCore.Qt.MatchFixedString)
                if items:
                    item = items[0]
                    self.wTable.removeRow(item.row())
                    continue

        # Clean the local keys from current processes+network connections
        for key in delkeys:
            del self.cp[key]
        if self.first_run:
            self.first_run = False

    def update_processtable(
        self, table, datum, con, local, remote, pid, ac, cp_key, history=False
    ):
        "Updates the given table with the new data in a new row"
        num = table.rowCount() + 1
        table.setRowCount(num)
        table.setItem(num - 1, 0, QTableWidgetItem(ac))
        table.item(num - 1, 0).setToolTip(datum["Cmdline"])
        table.setItem(num - 1, 1, QTableWidgetItem(local))
        table.setItem(num - 1, 2, QTableWidgetItem(remote))
        table.setItem(num - 1, 3, QTableWidgetItem(con["status"]))
        table.setItem(num - 1, 4, QTableWidgetItem(pid))
        user = find_user(con["uids"][0])
        table.setItem(num - 1, 5, QTableWidgetItem(user))

        if history:
            now = datetime.now()
            table.setItem(
                num - 1, 6, QTableWidgetItem(now.strftime("%Y:%m:%d:%H:%M:%S"))
            )
        else:
            table.setItem(num - 1, 6, QTableWidgetItem(cp_key))
        table.scrollToBottom()

    def exit_process(self):
        sys.exit(0)


def main():
    try:
        with open("/etc/unoon/unoon.yml") as fobj:
            config = yaml.safe_load(fobj.read())
    except:
        print("Error in reading configuration file. Using default values.")
        config = {"server": "localhost:6379", "password": "", "db": 0}

    host, port = config["server"].split(":")
    port = int(port)
    config["host"] = host
    config["port"] = port
    # first clean all old data
    r = redis.Redis(host=host, port=port, password=config["password"], db=config["db"])
    # TODO: In future we want a separate process to log details to DB
    r.delete("currentprocesses")
    app = QtWidgets.QApplication(sys.argv)
    form = MainWindow(config=config)
    form.show()
    app.exec_()


if __name__ == "__main__":
    main()
