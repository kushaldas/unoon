# Unoon

Unoon is a desktop tool to monitor processes with network connections.
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

In fedora: `sudo dnf install python3-pyqt5 python3-redis python3-yaml`

### Build

Build the go portion with:

```sh
go build github.com/kushaldas/unoon/cmd/unoon
```

### Redis server configuration

You should run the redis server along with a password for production, and you
can provide the same using the following format in `/etc/unoon/unoon.yml`
file.

If the file does not exists, it will assume no password is required.

```yaml
---
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

Start the frontend:

```sh
./desktop/main.py
```
