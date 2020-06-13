#!/usr/bin/env python3
from PyQt5 import QtGui, QtWidgets, QtCore


from PyQt5.QtGui import *
from PyQt5.QtWidgets import *
from PyQt5.QtCore import *
from PyQt5 import Qt

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
ALLOWEDTYPE = 2
LOGSTYPE = 3

BASE_PATH = os.path.dirname(os.path.abspath(__file__))
allowedlist_file = "/var/lib/unoon/allowedlist.txt"


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


class AllProcessesWindow(QtWidgets.QWidget):
    def __init__(self):
        super(AllProcessesWindow, self).__init__()
        self.data_store = {}
        self.setWindowTitle("Process Map")
        self.tree = QtWidgets.QTreeView(self)
        self.splitter = QtWidgets.QSplitter(self)
        self.splitter.setOrientation(QtCore.Qt.Vertical)

        self.splitter.addWidget(self.tree)

        # Now we will add an area to show the process details
        self.plabel = QtWidgets.QLabel()
        self.pix = QtGui.QPixmap(900, 150)
        self.pix.fill(QtGui.QColor(255, 255, 255))
        self.plabel.setPixmap(self.pix)
        self.plabel.setMargin(0)

        self.splitter.addWidget(self.plabel)
        self.splitter.setSizes([500, 150])
        layout = QtWidgets.QVBoxLayout(self)
        layout.addWidget(self.splitter)
        self.setGeometry(600, 50, 900, 650)

        self.model = QtGui.QStandardItemModel()
        self.model.setHorizontalHeaderLabels(
            ["Name", "Process ID", "Parent ID", "TTY", "User", "CWD"]
        )
        self.tree.header().setDefaultSectionSize(180)

        self.tree.header().setSectionResizeMode(QtWidgets.QHeaderView.ResizeToContents)

        self.tree.setModel(self.model)
        self.capture_process_data()
        self.parse_data()
        # When the user wants to see the processes, they should see in all expanded state
        self.tree.expandAll()
        # self.draw_process()
        # self.tree.clicked.connect(self.draw_process)
        self.tree.selectionModel().selectionChanged.connect(self.draw_selection)

    def capture_process_data(self):
        self.data = []
        for p in psutil.process_iter(
            attrs=[
                "name",
                "pid",
                "ppid",
                "exe",
                "cmdline",
                "cwd",
                "username",
                "terminal",
                "create_time",
                "connections",
                "open_files",
            ]
        ):
            try:
                self.data.append(p.info)
            except Exception as e:
                print("Exception for ", p, e)

    def draw_selection(self, a, b):
        indexes = a.indexes()
        pid_index = indexes[1]
        self.draw_process(pid_index)

    def draw_process(self, index):
        text = str(index.data())
        pid = index.siblingAtColumn(1)
        data = self.data_store[int(pid.data())]

        from pprint import pprint

        pprint(data)

        # TODO: calculate the final pixmap size

        pix = QtGui.QPixmap(900, 150)
        pix.fill(QtGui.QColor(255, 255, 255))
        self.plabel.setPixmap(pix)

        painter = QPainter(self.plabel.pixmap())

        pen = QPen()
        pen.setWidth(1)
        pen.setColor(QColor("black"))
        painter.setPen(pen)

        font = QFont()
        font.setFamily("Times")
        # font.setBold(True)
        font.setPointSize(20)
        painter.setFont(font)

        exe_icon = QPixmap(get_asset_path("exe_icon.png"))

        # Draw the exe icon
        painter.drawPixmap(0, 0, exe_icon)

        # Write the name of the exe path
        painter.drawText(50, 30, data["exe"])

        font.setPointSize(14)
        painter.setFont(font)

        # user icon
        user_icon = QPixmap(get_asset_path("user_icon.png"))

        # Draw the user icon
        painter.drawPixmap(12, 50, user_icon)
        painter.drawText(50, 70, data["username"])

        # cwd icon
        cwd_icon = QPixmap(get_asset_path("cwd_icon.png"))

        # Draw the cwd icon
        painter.drawPixmap(240, 50, cwd_icon)
        painter.drawText(280, 70, data["cwd"])

        # terminal icon
        terminal_icon = QPixmap(get_asset_path("terminal_icon.png"))

        # Draw the terminal icon
        painter.drawPixmap(12, 90, terminal_icon)
        painter.drawText(50, 110, str(data["terminal"]))

        # time icon
        time_icon = QPixmap(get_asset_path("time_icon.png"))

        date = datetime.fromtimestamp(data["create_time"])
        # Draw the time icon
        painter.drawPixmap(240, 90, time_icon)
        painter.drawText(280, 110, date.strftime("%c"))

        painter.end()

    def parse_data(self, root=None):

        data = self.data

        self.model.setRowCount(0)
        if not root:
            root = self.model.invisibleRootItem()
        seen = {}

        for value in data:
            if value["ppid"] == 0:
                parent = root
            else:
                pid = value["ppid"]
                if pid not in seen:
                    # TODO: Mark that parent is missing
                    # Not sure why the parents are missing, orphan processes here
                    parent = root
                else:
                    parent = seen[pid]
            pid = value["pid"]

            # store it
            self.data_store[pid] = value

            name = QtGui.QStandardItem(value["name"])
            name.setToolTip(" ".join(value["cmdline"]))
            name.setEditable(False)  # User should not be able to edit it
            pid_item = QtGui.QStandardItem(str(pid))
            pid_item.setEditable(False)
            ppid_item = QtGui.QStandardItem(str(value["ppid"]))
            ppid_item.setEditable(False)
            terminal_item = QtGui.QStandardItem(value["terminal"])
            terminal_item.setEditable(False)
            username_item = QtGui.QStandardItem(value["username"])
            username_item.setEditable(False)
            cwd_item = QtGui.QStandardItem(value["cwd"])
            cwd_item.setEditable(False)

            parent.appendRow(
                [name, pid_item, ppid_item, terminal_item, username_item, cwd_item,]
            )
            seen[pid] = parent.child(parent.rowCount() - 1)


class TableWidget(QtWidgets.QTableWidget):
    def __init__(self, tabletype=PROCESSTYPE):
        super(TableWidget, self).__init__()
        # PROCESSTYPE: this is a process table
        # ALLOWEDTYPE: this is a ALLOWED table
        # LOGSTYPE: this is a history logs table
        self.tabletype = tabletype
        self.setIconSize(QtCore.QSize(25, 25))
        self.menu = QtWidgets.QMenu()
        action = QtWidgets.QAction("Mark as ALLOWED", self)
        allowedlisticon = QtGui.QIcon(get_asset_path("security_tick.png"))
        action.setIcon(allowedlisticon)
        action.triggered.connect(lambda: self.rightClickSlot())
        self.menu.addAction(action)

        self.setSelectionMode(QtWidgets.QAbstractItemView.SingleSelection)
        self.setColumnCount(7)
        if self.tabletype != LOGSTYPE:
            # The unique value is hidden for process and allowedlist tables
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
            0,
            QTableWidgetItem(QtGui.QIcon(get_asset_path("terminal.png")), "Executable"),
        )
        self.setHorizontalHeaderItem(
            2, QTableWidgetItem(QtGui.QIcon(get_asset_path("cloud_up.png")), "Remote")
        )
        header = self.horizontalHeader()
        header.setSectionResizeMode(0, QtWidgets.QHeaderView.ResizeToContents)
        header.setSectionResizeMode(1, QtWidgets.QHeaderView.ResizeToContents)
        header.setSectionResizeMode(2, QtWidgets.QHeaderView.ResizeToContents)
        if self.tabletype == LOGSTYPE:
            header.setSectionResizeMode(6, QtWidgets.QHeaderView.ResizeToContents)

    def rightClickSlot(self):
        for i in self.selectionModel().selection().indexes():
            # TODO: find the item and open up the Dialog for adding in allowed list.
            print(i.row(), i.column())

    def contextMenuEvent(self, event):
        col = self.columnAt(event.pos().x())
        if col == 0:
            if self.tabletype == PROCESSTYPE:
                self.menu.popup(QtGui.QCursor.pos())


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

            if server_data["record_type"] == "connect":
                pid = str(server_data["pid"])
                # skip the desktop application
                if self.pid == pid:
                    continue
                try:
                    p = psutil.Process(int(pid))
                    self.pids[pid] = True

                    self.signal.emit(p)
                except Exception as e:
                    print("Missing process in first search", e)
            elif server_data["record_type"] == "process_exit":
                # The exit or exit_group syscall can happen when a process is exiting
                # or when a thread inside of the process is exiting.
                # In the second case, the process is still alive.

                if not pid in self.pids:
                    continue
                try:
                    p = psutil.Process(int(server_data["pid"]))
                    p.wait()
                    del self.pids[pid]
                    self.deletepid.emit(pid)
                except Exception as e:
                    # Means the pid properly exited
                    del self.pids[pid]
                    self.deletepid.emit(pid)
            elif server_data["record_type"] == "path":
                pprint(server_data)
                # TODO: verify if this is safe or not.
                if server_data["name"] == "/var/run/nscd/socket":
                    continue
                self.path_signal.emit(server_data)


class AllowedListDialog(QtWidgets.QDialog):
    newallowedlist = QtCore.pyqtSignal(str)

    def __init__(self, text):
        super(AllowedListDialog, self).__init__()
        self.setWindowTitle("Allowed commands")
        self.setModal(True)
        self.setMinimumWidth(700)

        self.textbox = QtWidgets.QTextEdit()
        # We want only plain text
        self.textbox.setAcceptRichText(False)
        self.textbox.setPlainText(text)

        allowedlistlargeicon = QtWidgets.QLabel()
        allowedpixmap = QtGui.QPixmap(get_asset_path("security_tick_large.png"))
        allowedlistlargeicon.setPixmap(allowedpixmap)
        allowedlistlabel = QtWidgets.QLabel("List of allowed commands")
        allowedlistlabel.setStyleSheet(QAllowedListBannerCSS)

        banner_hboxlayout = QtWidgets.QHBoxLayout()
        banner_hboxlayout.addWidget(allowedlistlargeicon)
        banner_hboxlayout.addWidget(allowedlistlabel)
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
        with open(allowedlist_file, "w") as fobj:
            fobj.write(text)

        self.newallowedlist.emit(text)
        self.close()

    def cancel(self):
        self.close()


# TODO: Looks really bad
class FileAccessDialog(QtWidgets.QDialog):
    def __init__(self, datum):
        super(FileAccessDialog, self).__init__()

        self.setWindowTitle("File acccessed")
        cmd_label = QtWidgets.QLabel(datum["proctitle"])
        filepath = QtWidgets.QLabel(datum["name"])
        exe_label = QtWidgets.QLabel(datum["exe"])

        layout = QtWidgets.QVBoxLayout()
        layout.addWidget(cmd_label)
        layout.addWidget(filepath)
        layout.addWidget(exe_label)
        self.setLayout(layout)
        self.show()


class NewConnectionDialog(QtWidgets.QDialog):
    def __init__(self, datum, remote, pid, user):
        super(NewConnectionDialog, self).__init__()

        self.setWindowTitle("Network Alert")
        self.setWindowIcon(QtGui.QIcon(get_asset_path("alert.png")))

        cmd_label = QtWidgets.QLabel(" ".join(datum.cmdline()))
        cmd_label.setStyleSheet("QLabel { font-weight: bold; font-size: 20px; }")
        cmd_label.setWordWrap(True)
        remote_label = QtWidgets.QLabel(remote)
        pid_label = QtWidgets.QLabel("PID: {}".format(pid))
        user_label = QtWidgets.QLabel("User: {}".format(user))
        cwd_label = QtWidgets.QLabel("Directory: {}".format(datum.cwd()))

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

        processMapAction = QtWidgets.QAction(
            QtGui.QIcon(get_asset_path("processes.png")), "Process Map", self
        )
        processMapAction.triggered.connect(self.show_processmap)

        toolbar = self.addToolBar("Mainbar")
        toolbar.addAction(processMapAction)
        self.processlist = []

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

        self.allowedlist_text = ""
        self.allowedlist = []

        # TODO: Fix the path of the allowedlist rules
        if os.path.exists(allowedlist_file):
            with open(allowedlist_file) as fobj:
                self.allowedlist_text = fobj.read()

        self.update_allowedlist(self.allowedlist_text)

        self.setMinimumWidth(1000)
        self.setMinimumHeight(600)

        # get a current processes table widget
        self.pTable = TableWidget(tabletype=PROCESSTYPE)

        # get a allowedlisted processes table widget
        self.wTable = TableWidget(tabletype=ALLOWEDTYPE)

        # get a logs table to show history
        self.logsTable = TableWidget(tabletype=LOGSTYPE)

        self.tabs = QtWidgets.QTabWidget()
        self.tabs.setIconSize(QtCore.QSize(25, 25))
        self.tabs.setStyleSheet(QTAB)

        normalicon = QtGui.QIcon(get_asset_path("magnify.png"))
        self.tabs.addTab(self.pTable, normalicon, "Current Processes")
        allowedlisticon = QtGui.QIcon(get_asset_path("security_tick.png"))
        self.tabs.addTab(self.wTable, allowedlisticon, "Allowed Processes")
        logsicon = QtGui.QIcon(get_asset_path("logs.png"))
        self.tabs.addTab(self.logsTable, logsicon, "History")
        self.setCentralWidget(self.tabs)

        exitAction = QtWidgets.QAction("E&xit", self)
        exitAction.triggered.connect(self.exit_process)

        allowedlistAction = QtWidgets.QAction("&Allowed list", self)
        allowedlistAction.triggered.connect(self.show_allowedlist)
        menu = self.menuBar()
        file = menu.addMenu("&File")
        file.addAction(exitAction)

        edit = menu.addMenu("&Edit")
        edit.addAction(allowedlistAction)

        self.pTable.setColumnWidth(0, 80)

        self.shortcut1 = QtWidgets.QShortcut(QtGui.QKeySequence("Alt+1"), self)
        self.shortcut1.activated.connect(self.showcurrenttab)
        self.shortcut2 = QtWidgets.QShortcut(QtGui.QKeySequence("Alt+2"), self)
        self.shortcut2.activated.connect(self.showallowedlisttab)
        self.shortcut3 = QtWidgets.QShortcut(QtGui.QKeySequence("Alt+3"), self)
        self.shortcut3.activated.connect(self.showlogstab)

        self.first_run = True
        self.new_connection_dialogs = []
        self.fileaccess_dialogs = []
        self.cp = {}

        self.tr = DataThread(config)
        self.tr.signal.connect(self.update_cp)
        self.tr.deletepid.connect(self.delete_pid)
        self.tr.path_signal.connect(self.show_path_dialog)
        self.tr.start()

    def showcurrenttab(self):
        self.tabs.setCurrentIndex(0)

    def showallowedlisttab(self):
        self.tabs.setCurrentIndex(1)

    def showlogstab(self):
        self.tabs.setCurrentIndex(2)

    def update_allowedlist(self, text):
        # Create the current list of allowedlisted commands
        self.allowedlist = []
        self.allowedlists_text = text
        for cmd in text.split("\n"):
            cmd = cmd.strip()
            if cmd:
                self.allowedlist.append(cmd)

    def show_path_dialog(self, data):
        d = FileAccessDialog(data)
        self.fileaccess_dialogs.append(d)

    def show_allowedlist(self):
        "Updates the current allowedlist commands"
        self.allowedlist_dialog = AllowedListDialog(self.allowedlists_text)
        self.allowedlist_dialog.newallowedlist.connect(self.update_allowedlist)
        self.allowedlist_dialog.exec_()

    def delete_pid(self, pid: str):
        "For the pid which is already gone"
        delkeys = []
        for key in self.cp.keys():
            key_pid = key.split(":")[1]
            if key_pid != pid:
                continue

            delkeys.append(key)

            # Check in the normal process table
            items = self.pTable.findItems(key, QtCore.Qt.MatchFixedString)
            if items:
                item = items[0]
                self.pTable.removeRow(item.row())
                continue

                # Check in the allowedlisted process table
            items = self.wTable.findItems(key, QtCore.Qt.MatchFixedString)
            if items:
                item = items[0]
                self.wTable.removeRow(item.row())
                continue

        # Clean the local keys from current processes+network connections
        for key in delkeys:
            del self.cp[key]

    def update_cp(self, result: psutil.Process):
        "For a given process, update the widgets"
        current_keys = {}
        # for pid in pids:
        # Skip desktop application itself
        try:
            datum = result
            pid = result.pid
            if str(pid) == self.pid:
                return
            try:
                ac = datum.cmdline()[0]
            except IndexError as e:
                print(e)
                print(datum.cmdline())
                return

            for con in datum.connections():
                localcon = con.laddr
                if localcon.ip == "224.0.0.251":
                    return
                local = "{}:{}".format(localcon.ip, localcon.port)
                remotecon = con.raddr

                # TODO: make sure we still show the listen calls
                if not remotecon:
                    return

                # Find the hostname for the IP
                remote_ip = remotecon.ip
                remote_host_set = self.cl.smembers("ip:{}".format(remote_ip))
                if remote_host_set:
                    remote_host = list(remote_host_set)[0].decode("utf-8")
                else:
                    remote_host = remote_ip

                remote = "{}:{}".format(remote_host, remotecon.port)

                # cp_key is the unique key to identify all unique connections from inside of a process to a remote
                cp_key = "pid:{0}:{1}:{2}".format(str(pid), ac, remote)
                # record the key
                current_keys[cp_key] = True
                if cp_key in self.cp:
                    continue

                allowedlist_flag = False
                for cmd in self.allowedlist:
                    # The following is True for allowedlisted commands
                    if ac.startswith(cmd):
                        self.update_processtable(
                            self.wTable, datum, con, local, remote, pid, ac, cp_key
                        )
                        allowedlist_flag = True
                        break

                # Display popup
                if not self.first_run and cp_key not in self.cp and not allowedlist_flag:
                    user = find_user(datum.uids().real)
                    d = NewConnectionDialog(datum, remote, pid, user)
                    self.new_connection_dialogs.append(d)
                    # Store for the runtime logs
                    self.logs.append((datum, con, local, remote, pid, ac, cp_key))

                phistory = Processhistory(
                    executable=ac.split()[0],
                    command=ac,
                    local_ip=con.laddr.ip,
                    local_port=con.laddr.port,
                    remote_ip=remote_host,
                    remote_port=con.raddr.port,
                    pid=pid,
                    realuid=datum.uids().real,
                    effectiveuid=datum.uids().effective,
                    saveduid=datum.uids().saved,
                    filesystemuid=datum.uids().saved,
                    when=datetime.now(),
                )

                self.session.add(phistory)
                self.session.commit()

                # For new processes
                self.cp[cp_key] = datum

                if allowedlist_flag:
                    continue

                self.update_processtable(
                    self.pTable, datum, con, local, remote, pid, ac, cp_key
                )
                self.update_processtable(
                    self.logsTable, datum, con, local, remote, pid, ac, cp_key, True
                )
        except (FileNotFoundError, psutil.NoSuchProcess) as e:
            # TODO: do someting here
            return
        delkeys = []
        for key in self.cp.keys():
            key_pid = key.split(":")[1]
            if key_pid != str(pid):
                continue
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

                # Check in the allowedlisted process table
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
        print(f"PID: {pid}")
        num = table.rowCount() + 1
        table.setRowCount(num)
        table.setItem(num - 1, 0, QTableWidgetItem(ac.split()[0]))
        table.item(num - 1, 0).setToolTip(ac)
        table.setItem(num - 1, 1, QTableWidgetItem(local))
        table.setItem(num - 1, 2, QTableWidgetItem(remote))
        table.setItem(num - 1, 3, QTableWidgetItem(con.status))
        table.setItem(num - 1, 4, QTableWidgetItem(str(pid)))
        user = find_user(datum.uids().real)
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

    def show_processmap(self):
        """
        We will take a state of current processes and show it via a window.
        """

        self.processMapwindow = AllProcessesWindow()
        self.processMapwindow.show()


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
