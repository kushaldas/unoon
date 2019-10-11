package main

import (
	"flag"
	"time"

	"github.com/go-redis/redis/v7"
	"github.com/kushaldas/unoon/pkg/localprocess"
)

var PDB localprocess.ProcessDB

func main() {

	device := flag.String("device", "wlp4s0", "The device from where we will capture DNS data  (as root).")
	flag.Parse()

	go localprocess.RecordDNS(*device)
	redisdb := redis.NewClient(&redis.Options{
		Addr:     "localhost:6379", // use default Addr
		Password: "",               // no password set
		DB:       0,                // use default DB
	})

	for {
		time.Sleep(2 * time.Second)
		allps := localprocess.ProcessMap()
		// Push all processes in one go
		localprocess.PushProcessDB(allps, redisdb)
	}

}
