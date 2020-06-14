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

// AuditEntry contains details about audit records
type AuditEntry map[string]string

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

	// This will record CWD values for similar records
	filesandcommands := make(map[string]AuditEntry, 1)
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
		//fmt.Println(":?", line)
		if recordType == "SYSCALL" {

			if data["syscall"] == "connect" {

				// We get `exit` value as EINPROGRESS when firefox is connecting to
				// port 0 of the IP. The result says failure, -115.
				//
				// The nearest disccussion I can find on the internet is below
				// https://linux-audit.redhat.narkive.com/fODvvkUi/auditd-reports-port-number-0-for-connect-system-call
				if data["result"] == "success" || data["exit"] == "EINPROGRESS" {
					if val, ok := filesandcommands[data["sequence"]]; ok {
						val["exe"] = data["exe"]
						val["pid"] = data["pid"]
						filesandcommands[data["sequence"]] = val
					} else {
						localData := make(AuditEntry, 1)
						localData["exe"] = data["exe"]
						localData["pid"] = data["pid"]
						filesandcommands[data["sequence"]] = localData
					}
				}
			} else if data["syscall"] == "openat" || data["syscall"] == "open" {
				// This is for the syscall related to recordType PATH
				// This call records the actual process which accessed the file/path.
				//
				if val, ok := filesandcommands[data["sequence"]]; ok {
					// Means we already have data
					val["exe"] = data["exe"]
					val["auid"] = data["auid"]
					val["uid"] = data["uid"]
					val["gid"] = data["gid"]
					val["euid"] = data["euid"]
					val["suid"] = data["suid"]
					val["fsuid"] = data["fsuid"]
					val["egid"] = data["egid"]
					val["sgid"] = data["sgid"]
					val["fsgid"] = data["fsgid"]
					val["pid"] = data["pid"]
					val["ppid"] = data["ppid"]
					val["record_type"] = "path"
					filesandcommands[data["sequence"]] = val
				} else {
					// Here the record is not there already
					localData := make(AuditEntry, 1)
					localData["exe"] = data["exe"]
					localData["auid"] = data["auid"]
					localData["uid"] = data["uid"]
					localData["gid"] = data["gid"]
					localData["euid"] = data["euid"]
					localData["suid"] = data["suid"]
					localData["fsuid"] = data["fsuid"]
					localData["egid"] = data["egid"]
					localData["sgid"] = data["sgid"]
					localData["fsgid"] = data["fsgid"]
					localData["pid"] = data["pid"]
					localData["ppid"] = data["ppid"]
					localData["record_type"] = "path"
					filesandcommands[data["sequence"]] = localData

				}
			}
		} else if recordType == "SOCKADDR" {
			if val, ok := filesandcommands[data["sequence"]]; ok {
				val["family"] = data["family"]
				val["port"] = data["port"]
				val["addr"] = data["addr"]
				val["record_type"] = "connect"
				filesandcommands[data["sequence"]] = val

			} else {
				// Here the record is not there already
				localData := make(AuditEntry, 1)
				localData["family"] = data["family"]
				localData["port"] = data["port"]
				localData["addr"] = data["addr"]
				localData["record_type"] = "connect"
				filesandcommands[data["sequence"]] = localData

			}

		} else if recordType == "CWD" {
			if val, ok := filesandcommands[data["sequence"]]; ok {
				// Means we already have data
				val["cwd"] = data["cwd"]
				filesandcommands[data["sequence"]] = val
			} else {
				// Here the record is not there already
				localData := make(AuditEntry, 1)
				localData["cwd"] = data["cwd"]
				filesandcommands[data["sequence"]] = localData

			}
		} else if recordType == "PATH" {
			if val, ok := filesandcommands[data["sequence"]]; ok {
				// Means we already have data
				val["name"] = data["name"]
				//val["record_type"] = "path"
				filesandcommands[data["sequence"]] = val
			} else {
				// Here the record is not there already
				localData := make(AuditEntry, 1)
				localData["name"] = data["name"]
				//localData["record_type"] = "path"
				filesandcommands[data["sequence"]] = localData

			}
		} else if recordType == "EOE" {
			if val, ok := filesandcommands[data["sequence"]]; ok {
				// If no exe mentioned here, means it is part of a different record,
				// not any file access record.
				if _, ok := val["exe"]; ok {
					jsonData, _ := json.MarshalIndent(val, "", "  ")
					// fmt.Println(val)
					PushToDesktop(jsonData, redisdb)
					// Now we have to clean up the localrecords for the sequence
					delete(filesandcommands, data["sequence"])
				}
			}
		} else if recordType == "PROCTITLE" {

			if val, ok := filesandcommands[data["sequence"]]; ok {
				// Means we already have data
				val["proctitle"] = data["proctitle"]
				filesandcommands[data["sequence"]] = val
			} else {
				// Here the record is not there already
				localData := make(AuditEntry, 1)
				localData["proctitle"] = data["proctitle"]
				filesandcommands[data["sequence"]] = localData

			}
		}

	}
}

func PushToDesktop(data []byte, redisdb *redis.Client) {

	redisdb.RPush("background", data)
}
