#!/usr/bin/env python3
from PyQt5 import QtGui, QtWidgets, QtCore


from PyQt5.QtGui import *
from PyQt5.QtWidgets import *
from PyQt5.QtCore import *
from PyQt5 import Qt

from PyQt5 import QtCore

from typing import Dict
import psutil
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


class UnoonFileItem(QFrame):
    CSS = """
            QFrame#unoonFileItem {
                border: 2px solid red;
            }
            background-color: rgb(255,255,255);
            border-radius: 20px;
            margin: 10px;
    """

    def __init__(self, parent=None, path="", process=""):
        super(QWidget, self).__init__(parent)
        self.setObjectName("unoonFileItem")
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

    def __init__(self, parent=None, address="", process="", cwd="", whitelisted=False):
        super(QWidget, self).__init__(parent)
        self.setObjectName("unoonNetworkItem")
        self.setStyleSheet(self.CSS)
        if whitelisted:
            self.setStyleSheet(self.CSS_WHITELIST)
        self.mainlayout = QVBoxLayout()
        datalayout = QHBoxLayout()
        self.title_label = QLabel("")
        icon = QtGui.QPixmap(get_asset_path("networkicon.png"))
        self.title_label.setPixmap(icon)
        self.title_label.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Fixed)
        text = QLabel(f"{address}\n\nAccessed by: {process}")
        datalayout.addWidget(self.title_label)
        datalayout.addWidget(text)
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


class MainWindow(QtWidgets.QMainWindow):
    CSS = """
            background-color: rgb(255,255,255);
    """

    def __init__(self, parent=None, config={}):
        super(MainWindow, self).__init__(parent)
        self.setWindowTitle("Unoon")
        toolbar = self.addToolBar("Mainbar")
        self.processlist = []

        self.cl = redis.Redis(
            host=config["host"],
            port=config["port"],
            password=config["password"],
            db=config["db"],
        )
        self.pid = str(os.getpid())
        self.session = create_session()

        self.setStyleSheet(self.CSS)

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

        self.widget_store_layout = QVBoxLayout()
        self.widget_store = QWidget()
        self.widget_store.setLayout(self.widget_store_layout)

        self.widget_store_layout.setSpacing(0)
        self.widget_store.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)

        self.scrollarea.setHorizontalScrollBarPolicy(QtCore.Qt.ScrollBarAlwaysOff)
        self.scrollarea.setWidget(self.widget_store)
        self.scrollarea.setWidgetResizable(True)

        self.sb = self.scrollarea.verticalScrollBar()
        self.sb.rangeChanged.connect(self.update_scrollbar)

        self.tabs.addTab(self.scrollarea, "Notifications")
        self.setCentralWidget(self.tabs)

        un = UnoonFileItem(
            path="/home/kdas/gocode/src/github.com/kushaldas/unoon",
            process="/usr/bin/hello",
        )
        self.widget_store_layout.addWidget(un)

        un2 = UnoonNetworkItem(address="kushaldas.in:443", process="/usr/bin/wget")
        self.widget_store_layout.addWidget(un2)

        un3 = UnoonNetworkItem(
            address="freedom.press:443", process="/usr/bin/nmap", whitelisted=True
        )
        self.widget_store_layout.addWidget(un3)

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

    def update_cp(self, result: Dict):
        "For a given process, update the widgets"
        current_keys = {}
        # for pid in pids:
        # Skip desktop application itself
        try:
            if result["record_type"] == "connect" and result["family"] != "unix":
                # Find the hostname for the IP
                remote_ip = result["addr"]
                remote_host_set = self.cl.smembers("ip:{}".format(remote_ip))
                if remote_host_set:
                    remote_host = list(remote_host_set)[0].decode("utf-8")
                else:
                    remote_host = remote_ip

                remote = "{}:{}".format(remote_host, result["port"])

                whitelist_flag = False
                exe = result["exe"]

                # Now find if this is whitelisted
                for cmd in self.whitelist:
                    # The following is True for whitelisted commands
                    if exe == cmd:
                        whitelist_flag = True
                        break

                # Now create the widget
                item = UnoonNetworkItem(
                    address=remote, process=exe, whitelisted=whitelist_flag
                )
                self.widget_store_layout.addWidget(item)

            elif result["record_type"] == "path":
                item = UnoonFileItem(path=result["name"], process=result["proctitle"])
                self.widget_store_layout.addWidget(item)

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
        config = {"server": "localhost:6379", "password": "", "db": 0}

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
