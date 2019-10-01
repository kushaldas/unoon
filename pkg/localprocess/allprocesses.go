package localprocess

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"

	"github.com/go-redis/redis/v7"
	"github.com/google/gopacket"
	_ "github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/kushaldas/bomcapture/pkg/capturing"
	"github.com/shirou/gopsutil/net"
	"github.com/shirou/gopsutil/process"
)

// ProcessDetails stores a currently running process with network connections.
type ProcessDetails struct {
	Name        string
	Pid         int32
	Cmdline     string
	Cwd         string
	Connections []net.ConnectionStat
}

// ProcessDB is a map with keys for each PID and value as ProcessDetails
type ProcessDB map[string]ProcessDetails

// ProcessMap returns currently running processes with Network Connections.
func ProcessMap() ProcessDB {
	//networkPS := make([]net.ConnectionStat, 1)
	allps, _ := process.Processes()
	localdb := make(ProcessDB, 1)
	selfpid := os.Getpid()
	for _, ps := range allps {
		name, _ := ps.Name()
		cmdline, _ := ps.Cmdline()
		cwd, _ := ps.Cwd()
		if strings.HasPrefix(cmdline, "/usr/bin/redis-server ") == true {
			fmt.Println("Cmdline::", cmdline)
			// Not recording local redis server
			continue
		}
		pid := ps.Pid
		if selfpid == int(pid) {
			// no need to record the unoon process
			continue
		}

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
			pd := ProcessDetails{name, pid, cmdline, cwd, networkPS}
			var key strings.Builder

			key.WriteString(strconv.Itoa(int(ps.Pid)))
			localdb[key.String()] = pd
		} else {
			continue
		}

	}
	return localdb
}

func RecordDNS(device string) {

	inactive, err := pcap.NewInactiveHandle(device)
	if err != nil {
		log.Fatal(err)
	}
	defer inactive.CleanUp()

	// Finally, create the actual handle by calling Activate:
	handle, err := inactive.Activate() // after this, inactive is no longer valid
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	redisdb := redis.NewClient(&redis.Options{
		Addr:     "localhost:6379", // use default Addr
		Password: "",               // no password set
		DB:       0,                // use default DB
	})

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		res, err := capturing.ParsePacket(packet, true)
		if err == nil {
			if len(res) > 0 {

				data := res[0].(capturing.BDNS)
				for _, ip := range data.Ips {
					rname := fmt.Sprintf("ip:%s", ip)
					redisdb.SAdd(rname, data.Name)

				}

			}
		}

	}
}

func PushProcessDB(p ProcessDB, redisdb *redis.Client) {

	jsonstr, _ := json.Marshal(p)
	redisdb.RPush("currentprocesses", jsonstr)
}
