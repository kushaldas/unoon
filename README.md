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

In fedora: `sudo dnf install python3-pyqt5 python3-redis`

### Build

Build the go portion with:

```sh
go build github.com/kushaldas/unoon/cmd/unoon
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
