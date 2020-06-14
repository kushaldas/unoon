# Unoon

Unoon is a desktop tool Intrusion detection tool.
This is in the very early stage of development.

## License: GPLv3+

## Build instructions

### Install dependencies

Install [golang](https://golang.org/dl/) and configure go. Git clone this repo in `~/gocode/src/github.com/kushaldas/unoon`.

Install go dependences:

In fedora: `sudo dnf install libpcap-devel redis`

Start redis service:

```sh
sudo systemctl start redis
```

Install python dependencies:

In Fedora: `sudo dnf install python3-qt5 python3-redis python3-yaml python3-psutil audit`

### Build

Build the go portion with:

```sh
go build github.com/kushaldas/unoon/cmd/unoon
```

### Setting up audit rules

Put the following in the `/etc/audit/rules.d/audit.rules` file.

```
## First rule - delete all
-D

## Increase the buffers to survive stress events.
## Make this bigger for busy systems
-b 8192

## This determine how long to wait in burst of events
--backlog_wait_time 0

## Set failure mode to syslog
-f 1

-a exit,always -F arch=b64 -S connect,listen,bind -k unoon_network
-a always,exit -F arch=b64 -S exit,exit_group -k unoon_exit
```

Remember as this tool is in the development stage, we will keep changing and adding a lot more rules in the coming days.

In future we may add rules in a different way, but for now, we will use `auditd` itself.

```bash
$ sudo systemctl start auditd
$ sudo systemctl status auditd
$ sudo systemctl stop auditd
$ sudo auditctl -l
-a always,exit -F arch=b64 -S connect,bind,listen -F key=unoon_network
-a always,exit -F arch=b64 -S exit,exit_group -F key=unoon_exit

```

On Fedora you may have to use the `service` command.

```bash
$ sudo service auditd restart
$ sudo service auditd stop
```


The last command should show you output as shown above.

### configuration

You should run the redis server along with a password for production, and you
can provide the same using the following format in `/etc/unoon/unoon.yml`
file. You should atleast write the standard username who will receive the desktop
notifications.

If the file does not exist, it will assume no password is required, and it will also try
to find the user with uid `1000`.

```yaml
---
user: "kdas"
server: "localhost:6379"
password: "yourpassword"
db:     0
```

### Start

Start the backend:

```sh
sudo ./unoon
```

You can pass a different interface name with `-device` flag to the `unoon` executable.

Next, create the database directory and also the sqlite database.

```sh
sudo mkdir /var/lib/unoon
sudo python3 ./desktop/udesktop/db.py
```

Start the frontend:

```sh
sudo python3 ./desktop/udesktop/second.py
```
