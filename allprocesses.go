package main

import (
	"strconv"
	"strings"

	"github.com/shirou/gopsutil/net"
	"github.com/shirou/gopsutil/process"
)

// ProcessDetails stores a currently running process with network connections.
type ProcessDetails struct {
	Name        string
	Pid         int32
	Cmdline     string
	Connections []net.ConnectionStat
}

// ProcessDB is a map with keys for each PID and value as ProcessDetails
type ProcessDB map[string]ProcessDetails

// processMap returns currently running processes with Network Connections.
func processMap() ProcessDB {
	//networkPS := make([]net.ConnectionStat, 1)
	allps, _ := process.Processes()
	localdb := make(ProcessDB, 1)
	for _, ps := range allps {
		name, _ := ps.Name()
		cmdline, _ := ps.Cmdline()
		pid := ps.Pid

		// fmt.Printf("%#v\n", name)
		cons, _ := ps.Connections()
		networkPS := make([]net.ConnectionStat, 0)
		for _, cs := range cons {
			laddr := cs.Laddr
			localIP := laddr.IP
			if localIP != "" && !strings.HasPrefix(localIP, "@") && !strings.HasPrefix(localIP, "/") {
				networkPS = append(networkPS, cs)
			}
		}
		if len(networkPS) > 0 {
			pd := ProcessDetails{name, pid, cmdline, networkPS}
			var key strings.Builder

			key.WriteString(strconv.Itoa(int(ps.Pid)))
			localdb[key.String()] = pd
		} else {
			continue
		}

	}
	return localdb
}
