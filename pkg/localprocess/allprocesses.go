package localprocess

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/elastic/go-libaudit"
	"github.com/elastic/go-libaudit/auparse"
	"github.com/go-redis/redis/v7"
	"github.com/google/gopacket"
	_ "github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/kushaldas/bomcapture/pkg/capturing"
	"github.com/pkg/errors"
	"github.com/shirou/gopsutil/net"
	"github.com/shirou/gopsutil/process"
	log "github.com/sirupsen/logrus"
)

var (
	fs          = flag.NewFlagSet("audit", flag.ExitOnError)
	debug       = fs.Bool("d", false, "enable debug output to stderr")
	diag        = fs.String("diag", "", "dump raw information from kernel to file")
	rate        = fs.Uint("rate", 0, "rate limit in kernel (default 0, no rate limit)")
	backlog     = fs.Uint("backlog", 8192, "backlog limit")
	receiveOnly = fs.Bool("ro", false, "receive only using multicast, requires kernel 3.16+")
)

func enableLogger() {
	log.SetOutput(os.Stderr)
	log.SetLevel(log.DebugLevel)
	log.SetFormatter(&log.TextFormatter{
		FullTimestamp:   true,
		TimestampFormat: time.RFC3339Nano,
	})
}

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

func RecordDNS(device string, server string, password string, db int) {

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
		Addr:     server,
		Password: password,
		DB:       db,
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

func Read(redisdb *redis.Client) error {
	if os.Geteuid() != 0 {
		return errors.New("you must be root to receive audit data")
	}

	// Write netlink response to a file for further analysis or for writing
	// tests cases.
	var diagWriter io.Writer
	if *diag != "" {
		f, err := os.OpenFile(*diag, os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0600)
		if err != nil {
			return err
		}
		defer f.Close()
		diagWriter = f
	}

	log.Debugln("starting netlink client")

	var err error
	var client *libaudit.AuditClient
	if *receiveOnly {
		client, err = libaudit.NewMulticastAuditClient(diagWriter)
		if err != nil {
			return errors.Wrap(err, "failed to create receive-only audit client")
		}
		defer client.Close()
	} else {
		client, err = libaudit.NewAuditClient(diagWriter)
		if err != nil {
			return errors.Wrap(err, "failed to create audit client")
		}
		defer client.Close()

		status, err := client.GetStatus()
		if err != nil {
			return errors.Wrap(err, "failed to get audit status")
		}
		log.Infof("received audit status=%+v", status)

		if status.Enabled == 0 {
			log.Debugln("enabling auditing in the kernel")
			if err = client.SetEnabled(true, libaudit.WaitForReply); err != nil {
				return errors.Wrap(err, "failed to set enabled=true")
			}
		}

		if status.RateLimit != uint32(*rate) {
			log.Debugf("setting rate limit in kernel to %v", *rate)
			if err = client.SetRateLimit(uint32(*rate), libaudit.NoWait); err != nil {
				return errors.Wrap(err, "failed to set rate limit to unlimited")
			}
		}

		if status.BacklogLimit != uint32(*backlog) {
			log.Debugf("setting backlog limit in kernel to %v", *backlog)
			if err = client.SetBacklogLimit(uint32(*backlog), libaudit.NoWait); err != nil {
				return errors.Wrap(err, "failed to set backlog limit")
			}
		}

		log.Debugf("sending message to kernel registering our PID (%v) as the audit daemon", os.Getpid())
		if err = client.SetPID(libaudit.NoWait); err != nil {
			return errors.Wrap(err, "failed to set audit PID")
		}
	}

	return receive(client, redisdb)
}

func receive(r *libaudit.AuditClient, redisdb *redis.Client) error {

	localrecords := make(map[string]string, 10)
	fmt.Println("starting")
	for {
		rawEvent, err := r.Receive(false)
		if err != nil {
			return errors.Wrap(err, "receive failed")
		}

		// Messages from 1300-2999 are valid audit messages.
		if rawEvent.Type < auparse.AUDIT_USER_AUTH ||
			rawEvent.Type > auparse.AUDIT_LAST_USER_MSG2 {
			continue
		}

		//fmt.Printf("type=%v msg=%v\n", rawEvent.Type, string(rawEvent.Data))
		line := fmt.Sprintf("type=%v msg=%v", rawEvent.Type, string(rawEvent.Data))
		msg, err := auparse.ParseLogLine(line)
		if err != nil {
			return nil
		}

		data, _ := msg.Data()
		recordType := msg.RecordType.String()
		if recordType == "SYSCALL" {
			if data["syscall"] == "connect" && data["result"] == "success" {
				localrecords[data["sequence"]] = data["pid"]
			}
			if data["syscall"] == "exit_group" {
				processData := make(map[string]string, 4)
				processData["pid"] = data["pid"]
				processData["record_type"] = "process_exit"
				jsonData, _ := json.Marshal(processData)
				PushToDesktop(jsonData, redisdb)

			}
		} else if recordType == "SOCKADDR" {

			if val, ok := localrecords[data["sequence"]]; ok {
				data := msg.ToMapStr()
				data["pid"] = val
				data["record_type"] = "connect"
				jsonData, _ := json.MarshalIndent(data, "", "  ")
				PushToDesktop(jsonData, redisdb)
				// Now we have to clean up the localrecords for the sequence
				delete(localrecords, data["sequence"].(string))
			}

		}

	}
}

func PushToDesktop(data []byte, redisdb *redis.Client) {

	redisdb.RPush("background", data)
}
