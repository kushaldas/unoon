#!/usr/bin/env python3
from PyQt5 import QtGui, QtWidgets, QtCore


from PyQt5.QtGui import *
from PyQt5.QtWidgets import *
from PyQt5.QtCore import *
from PyQt5 import Qt

from PyQt5 import QtCore

from typing import Dict
import psutil

import subprocess
import os
import sys
import pwd
import redis
import json
import pwd
import base64
from datetime import datetime
from pprint import pprint
import yaml

# These are our own code
from ucss import *
from db import Processhistory, create_session
from systemnotify import SystemNotify

PROCESSTYPE = 1
WHITETYPE = 2
LOGSTYPE = 3

BASE_PATH = os.path.dirname(os.path.abspath(__file__))
whitelist_file = "/var/lib/unoon/whitelist.txt"


def find_user(uid: int) -> str:
    "Find the username from the User ID"
    try:
        st = pwd.getpwuid(uid)
        return st.pw_name
    except KeyError:
        # Fall back to uid if the uid is not present in the passwd
        # file i.e. process is running inside a container
        return str(uid)


def get_asset_path(file_name):
    "Return the absolute path for requested asset"
    return os.path.join(BASE_PATH, "assets", file_name)


class DataThread(QThread):
    signal = pyqtSignal("PyQt_PyObject")
    deletepid = pyqtSignal("PyQt_PyObject")
    path_signal = pyqtSignal("PyQt_PyObject")

    def __init__(self, config={}):
        QThread.__init__(self)
        self.cl = redis.Redis(
            host=config["host"],
            port=config["port"],
            password=config["password"],
            db=config["db"],
        )
        # To store pids with any network connection
        self.pids = {}
        self.pid = str(os.getpid())

    # run method gets called when we start the thread
    def run(self):
        while True:
            data = self.cl.blpop("background")
            server_data = json.loads(data[1])

            if "record_type" not in server_data:
                continue

            # skip the desktop application itself
            pid = str(server_data["pid"])
            if self.pid == pid:
                continue
            self.signal.emit(server_data)
            # if server_data["record_type"] == "connect":
            #     pprint(str(server_data))
            #     pid = str(server_data["pid"])
            #     # skip the desktop application
            #     if self.pid == pid:
            #         continue
            #     self.signal.emit(server_data)
            # elif server_data["record_type"] == "process_exit":
            #     # The exit or exit_group syscall can happen when a process is exiting
            #     # or when a thread inside of the process is exiting.
            #     # In the second case, the process is still alive.

            #     if not pid in self.pids:
            #         continue
            #     try:
            #         p = psutil.Process(int(server_data["pid"]))
            #         p.wait()
            #         del self.pids[pid]
            #         self.deletepid.emit(pid)
            #     except Exception as e:
            #         # Means the pid properly exited
            #         del self.pids[pid]
            #         self.deletepid.emit(pid)
            # elif server_data["record_type"] == "path":
            #     pprint(server_data)
            #     # TODO: verify if this is safe or not.
            #     if server_data["name"] == "/var/run/nscd/socket":
            #         continue
            #     self.path_signal.emit(server_data)


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
        whitepixmap = QtGui.QPixmap(get_asset_path("security_tick_large.png"))
        whitelistlargeicon.setPixmap(whitepixmap)
        whitelistlabel = QtWidgets.QLabel("List of Whitelisted commands")
        # whitelistlabel.setStyleSheet(QWhiteListBannerCSS)

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
        with open(whitelist_file, "w") as fobj:
            fobj.write(text)

        self.newwhitelist.emit(text)
        self.close()

    def cancel(self):
        self.close()


class UnoonFilterArea(QFrame):
    updateUnoonSignal = pyqtSignal("PyQt_PyObject")
    CSS = """
            QFrame#unoonFilterArea {
                background-color: #1E90FF;
                border: none;
            }
            QCheckBox {
                background-color: white;
                border-radius: 10px;
                color: black;
                font: 16px;
                min-height: 2em;
                min-width: 6em;
                padding: 5px

            }
    """

    def __init__(self, parent=None, path="", process=""):
        super(QWidget, self).__init__(parent)
        self.setObjectName("unoonFilterArea")
        self.setMinimumWidth(200)
        self.setMaximumWidth(200)
        self.setStyleSheet(self.CSS)
        layout = QVBoxLayout()
        self.showAllCheckBox = QCheckBox("Show All")
        self.showFileIssues = QCheckBox("File access")
        self.showWhitelist = QCheckBox("Whitelist network")
        self.showNormalNetwork = QCheckBox("Unknown network")
        layout.addWidget(self.showAllCheckBox)
        layout.addWidget(self.showFileIssues)
        layout.addWidget(self.showWhitelist)
        layout.addWidget(self.showNormalNetwork)
        layout.addStretch(2)
        self.setLayout(layout)

        # set the state
        # set = 0 when unchecked
        # set = 2 when checked
        self.showAllCheckBox.setCheckState(QtCore.Qt.Checked)
        self.showFileIssues.setCheckState(QtCore.Qt.Checked)
        self.showFileIssues.stateChanged.connect(self.updateFileFilter)
        self.showWhitelist.setCheckState(QtCore.Qt.Checked)
        self.showWhitelist.stateChanged.connect(self.updateWhitelistFilter)
        self.showNormalNetwork.setCheckState(QtCore.Qt.Checked)
        self.showNormalNetwork.stateChanged.connect(self.updateNormalNetworkFilter)
        self.boxes = {
            "FileFilter": True,
            "WhitelistFilter": True,
            "NormalNetworkFilter": True,
        }

    def updateFileFilter(self, state):
        if state == 0:
            # If showAllCheckBox is checked, it should be unchecked now
            if self.showAllCheckBox.checkState() == QtCore.Qt.Checked:
                self.showAllCheckBox.setCheckState(QtCore.Qt.Unchecked)
            self.boxes["FileFilter"] = False
        elif state == 2:
            # This is when the checkbox is checked
            self.boxes["FileFilter"] = True
        self.updateUnoonSignal.emit(self.boxes)

    def updateWhitelistFilter(self, state):
        if state == 0:
            # If showAllCheckBox is checked, it should be unchecked now
            if self.showAllCheckBox.checkState() == QtCore.Qt.Checked:
                self.showAllCheckBox.setCheckState(QtCore.Qt.Unchecked)
            self.boxes["WhitelistFilter"] = False
        elif state == 2:
            # This is when the checkbox is checked
            self.boxes["WhitelistFilter"] = True
        self.updateUnoonSignal.emit(self.boxes)

    def updateNormalNetworkFilter(self, state):
        if state == 0:
            # If showAllCheckBox is checked, it should be unchecked now
            if self.showAllCheckBox.checkState() == QtCore.Qt.Checked:
                self.showAllCheckBox.setCheckState(QtCore.Qt.Unchecked)
            self.boxes["NormalNetworkFilter"] = False
        elif state == 2:
            # This is when the checkbox is checked
            self.boxes["NormalNetworkFilter"] = True
        self.updateUnoonSignal.emit(self.boxes)


class UnoonFileItem(QFrame):
    CSS = """
            QFrame#unoonFileItem {
                border: 2px solid red;
            }
            background-color: rgb(255,255,255);
            border-radius: 20px;
            margin: 10px;
    """

    def __init__(
        self, parent=None, path="", process="", pid="", uniquehash="",
    ):
        super(QWidget, self).__init__(parent)
        self.setObjectName("unoonFileItem")
        self.typename = "FileFilter"
        self.uniquehash = uniquehash
        self.usage = 1
        self.mainlayout = QVBoxLayout()
        datalayout = QHBoxLayout()
        self.title_label = QLabel("")
        icon = QtGui.QPixmap(get_asset_path("fileicon.png"))
        self.title_label.setPixmap(icon)
        self.title_label.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Fixed)
        text = QLabel(f"{path}\n\nAccessed by: {process}")
        datalayout.addWidget(self.title_label)
        datalayout.addWidget(text)
        row = QWidget()
        row.setLayout(datalayout)
        self.mainlayout.addWidget(row)
        self.setLayout(self.mainlayout)
        self.setFrameStyle(QFrame.StyledPanel | QFrame.Raised)
        self.setStyleSheet(self.CSS)
        self.setMinimumSize(QSize(200, 130))

    def increaseUsage(self):
        self.usage += 1


class UnoonNetworkItem(QFrame):
    CSS = """
            QFrame#unoonNetworkItem {
                border: 2px solid #FFB90F;
                background-color: rgb(255,255,255);
                border-radius: 20px;
                margin: 10px;
            }
            QPushButton#blockIPButton {
                background-color: #E3E3E3;
                color: black;
            }
            QPushButton {

                background-color: dimgrey;
                color: white;
            }
    """
    CSS_WHITELIST = """
                QFrame#unoonNetworkItem {
                border: 2px solid green;
                background-color: rgb(255,255,255);
                border-radius: 20px;
                margin: 10px;
            }
            QPushButton#blockIPButton {
                background-color: #E3E3E3;
                color: black;
            }
            QPushButton {

                background-color: dimgrey;
                color: white;
            }
    """

    def __init__(
        self,
        parent=None,
        address="",
        process="",
        cwd="",
        whitelisted=False,
        pid="",
        uniquehash="",
    ):
        super(QWidget, self).__init__(parent)
        self.setObjectName("unoonNetworkItem")
        self.setStyleSheet(self.CSS)
        self.typename = "NormalNetworkFilter"

        self.process = process
        self.address = address

        # We will update the widget based on this hash
        self.uniquehash = uniquehash
        self.usage = 1
        if whitelisted:
            self.setStyleSheet(self.CSS_WHITELIST)
            self.typename = "WhitelistFilter"
        self.mainlayout = QVBoxLayout()
        datalayout = QHBoxLayout()
        self.title_label = QLabel("")
        icon = QtGui.QPixmap(get_asset_path("networkicon.png"))
        self.title_label.setPixmap(icon)
        self.title_label.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Fixed)
        self.processLabel = QLabel(
            f"{self.address}\n\nAccessed by: {process}  Usage: {self.usage}"
        )
        datalayout.addWidget(self.title_label)
        datalayout.addWidget(self.processLabel)
        row = QWidget()
        row.setLayout(datalayout)
        self.mainlayout.addWidget(row)

        # We can have blocking buttons here in another row.
        self.blockProcessButton = QPushButton("Block the process")
        self.blockIPButton = QPushButton("Block the IP")
        self.blockIPButton.setObjectName("blockIPButton")

        button_row_layout = QHBoxLayout()
        button_row_layout.addWidget(self.blockProcessButton)
        button_row_layout.addWidget(self.blockIPButton)

        button_row_layout.addSpacerItem(
            QSpacerItem(0, 0, QSizePolicy.MinimumExpanding, QSizePolicy.Minimum)
        )

        button_row = QWidget()
        button_row.setLayout(button_row_layout)
        self.mainlayout.addWidget(button_row)

        self.setLayout(self.mainlayout)
        self.setFrameStyle(QFrame.StyledPanel | QFrame.Raised)

    def increaseUsage(self):
        self.usage += 1
        self.processLabel.setText(
            f"{self.address}\n\nAccessed by: {self.process}  Usage: {self.usage}"
        )


class MainWindow(QtWidgets.QMainWindow):
    CSS = """
            background-color: rgb(255,255,255);
            QScrollArea {
                border: none;
                border-radius: 10px;
            }
    """

    def __init__(self, parent=None, config={}):
        super(MainWindow, self).__init__(parent)
        self.setWindowTitle("Unoon")
        toolbar = self.addToolBar("Mainbar")
        self.processlist = []
        self.unoonitems = []
        self.unoonhashes = {}
        self.viewFilter = {
            "FileFilter": True,
            "WhitelistFilter": True,
            "NormalNetworkFilter": True,
        }
        self.config = config

        self.cl = redis.Redis(
            host=config["host"],
            port=config["port"],
            password=config["password"],
            db=config["db"],
        )
        self.notifymachine = SystemNotify(config["user"], config["uid"])
        self.pid = str(os.getpid())
        self.session = create_session()

        # To store all alerts in runtime only
        # TODO: In future store this in sqlite
        self.logs = []

        self.whitelist_text = ""
        self.whitelist = []

        # TODO: Fix the path of the whitelist rules
        if os.path.exists(whitelist_file):
            with open(whitelist_file) as fobj:
                self.whitelist_text = fobj.read()

        self.update_whitelist(self.whitelist_text)

        self.setMinimumWidth(1000)
        self.setMinimumHeight(600)

        self.tabs = QtWidgets.QTabWidget()
        self.tabs.setIconSize(QtCore.QSize(25, 25))

        # The scroll area
        self.scrollarea = QScrollArea()
        self.scrollarea.setObjectName("scrollarea")

        self.widget_store_layout = QVBoxLayout()
        self.widget_store = QWidget()
        self.widget_store.setObjectName("widget_store")
        self.widget_store.setLayout(self.widget_store_layout)

        self.widget_store_layout.setSpacing(0)
        self.widget_store.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)

        # self.scrollarea.setHorizontalScrollBarPolicy(QtCore.Qt.ScrollBarAlwaysOff)
        self.scrollarea.setWidget(self.widget_store)
        self.scrollarea.setWidgetResizable(True)

        self.sb = self.scrollarea.verticalScrollBar()
        self.sb.rangeChanged.connect(self.update_scrollbar)

        # The left hand side bar
        self.filterArea = UnoonFilterArea()

        # Connect the signal to update the view
        self.filterArea.updateUnoonSignal.connect(self.updateUnoonView)

        hlayout = QHBoxLayout(self)
        hlayout.addWidget(self.filterArea)
        hlayout.addWidget(self.scrollarea)
        mainwidget = QWidget()
        mainwidget.setLayout(hlayout)

        self.tabs.addTab(mainwidget, "Notifications")
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

        self.shortcut1 = QtWidgets.QShortcut(QtGui.QKeySequence("Alt+1"), self)
        self.shortcut1.activated.connect(self.showcurrenttab)
        self.shortcut2 = QtWidgets.QShortcut(QtGui.QKeySequence("Alt+2"), self)
        self.shortcut2.activated.connect(self.showwhitelisttab)
        self.shortcut3 = QtWidgets.QShortcut(QtGui.QKeySequence("Alt+3"), self)
        self.shortcut3.activated.connect(self.showlogstab)

        self.first_run = True
        self.new_connection_dialogs = []
        self.fileaccess_dialogs = []
        self.cp = {}

        self.tr = DataThread(config)
        self.tr.signal.connect(self.update_cp)
        # self.tr.path_signal.connect(self.show_path_dialog)
        self.tr.start()
        self.setStyleSheet(self.CSS)

    def addUnoonItem(self, item, uniquehash):
        "Adds the item to the view and also the internal list"

        # if the hash exists, then get it and then update it
        if uniquehash in self.unoonhashes:
            item = self.unoonhashes[uniquehash]
            # First remove from view
            self.widget_store_layout.removeWidget(item)
            # Now increase the usage
            item.increaseUsage()
            # Now add back to the view at the end
            self.widget_store_layout.addWidget(item)
            # Update in the hashtable
            self.unoonhashes[uniquehash] = item
            return

        self.unoonhashes[uniquehash] = item
        if not self.viewFilter[item.typename]:
            item.hide()
        self.widget_store_layout.addWidget(item)

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

    def update_scrollbar(self, min_val, max_val):
        self.sb.setValue(max_val)

    def updateUnoonView(self, data: Dict):
        self.viewFilter = data
        names = [k for k, v in data.items() if v]
        for item in self.unoonhashes.values():
            if item.typename not in names:
                item.hide()
            else:
                item.show()

    def update_cp(self, result: Dict):
        "For a given process, update the widgets"
        current_keys = {}
        # for pid in pids:
        # Skip desktop application itself
        item = None
        try:
            pprint(result)
            if result["record_type"] == "connect" and result["family"] != "unix":
                # Find the hostname for the IP
                remote_ip = result["addr"]
                remote_host_set = self.cl.smembers("ip:{}".format(remote_ip))
                if remote_host_set:
                    remote_host = list(remote_host_set)[0].decode("utf-8")
                else:
                    remote_host = remote_ip

                remote = "{}:{}".format(remote_host, result["port"])

                # TODO: we will have to find why family = 0 for these situation
                if remote == ":":
                    return
                whitelist_flag = False
                exe = result["exe"]
                proctitle = result["proctitle"]

                # Now find if this is whitelisted
                for cmd in self.whitelist:
                    # The following is True for whitelisted commands
                    if exe.startswith(cmd):
                        whitelist_flag = True
                        break

                pid = ""
                line = f"{pid}:{remote}:{proctitle}"
                uniquehash = base64.encodebytes(line.encode("utf-8"))
                # Now create the widget
                item = UnoonNetworkItem(
                    address=remote, process=proctitle, whitelisted=whitelist_flag
                )
                # Now let us add the item to the view
                self.addUnoonItem(item, uniquehash)
                if not whitelist_flag:
                    self.notifymachine.notify("Network access", exe)

            elif result["record_type"] == "path":
                pid = result["pid"]
                path = result["name"]
                process = result["proctitle"]
                uniquehash = base64.encodebytes(
                    f"{pid}:{path}:{process}".encode("utf-8")
                )
                item = UnoonFileItem(path=result["name"], process=result["proctitle"])
                # Now let us add the item to the view
                self.addUnoonItem(item, uniquehash)
                self.notifymachine.notify("File accessed", path)

            # user = find_user(datum.uids().real)
            # Store for the runtime logs

            # phistory = Processhistory(
            #     executable=ac.split()[0],
            #     command=ac,
            #     local_ip=con.laddr.ip,
            #     local_port=con.laddr.port,
            #     remote_ip=remote_host,
            #     remote_port=con.raddr.port,
            #     pid=pid,
            #     realuid=datum.uids().real,
            #     effectiveuid=datum.uids().effective,
            #     saveduid=datum.uids().saved,
            #     filesystemuid=datum.uids().saved,
            #     when=datetime.now(),
            # )

            # self.session.add(phistory)
            # self.session.commit()

        except (FileNotFoundError, psutil.NoSuchProcess) as e:
            # TODO: do someting here
            return

    def exit_process(self):
        sys.exit(0)


def main():
    try:
        with open("/etc/unoon/unoon.yml") as fobj:
            config = yaml.safe_load(fobj.read())
    except:
        print("Error in reading configuration file. Using default values.")

        config = {
            "server": "localhost:6379",
            "password": "",
            "db": 0,
        }

    if "user" in config:
        user = pwd.getpwnam(config["user"])
        config["uid"] = user.pw_uid
    else:
        try:
            user = pwd.getpwuid(1000)
        except:
            print("Please setup an user account name in the configuration.")
            sys.exit(-1)
        config["user"] = user.pw_name
        config["uid"] = user.pw_uid

    host, port = config["server"].split(":")
    port = int(port)
    config["host"] = host
    config["port"] = port
    # first clean all old data
    r = redis.Redis(host=host, port=port, password=config["password"], db=config["db"])
    # TODO: In future we want a separate process to log details to DB
    r.delete("background")
    app = QtWidgets.QApplication(sys.argv)
    form = MainWindow(config=config)
    form.show()
    app.exec_()


if __name__ == "__main__":
    main()
