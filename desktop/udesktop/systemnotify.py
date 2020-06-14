import pwd
import subprocess


class SystemNotify:
    def __init__(self, user, uid):
        self.user = user
        self.uid = uid

    # TODO: Fix this strange way to create system notifications
    def notify(self, title="", text="", icon=""):
        try:
            cmd = f"""/usr/bin/su - {self.user} -c 'DISPLAY=:0 DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/{self.uid}/bus notify-send "{title}" "{text}"'"""
            subprocess.getoutput(cmd)
        except Exception as e:
            print(e)

