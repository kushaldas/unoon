package main

import (
	"flag"
	"fmt"

	"github.com/go-redis/redis/v7"
	"github.com/kushaldas/unoon/pkg/localprocess"
	"github.com/spf13/viper"
)

var PDB localprocess.ProcessDB

func main() {

	flag.Parse()

	viper.SetConfigName("unoon")
	viper.AddConfigPath("/etc/unoon/")
	err := viper.ReadInConfig()

	if err != nil {
		fmt.Println("No configuration file loaded - using defaults")
	}

	viper.SetDefault("server", "localhost:6379")
	viper.SetDefault("password", "")
	viper.SetDefault("db", 0)

	redisdb := redis.NewClient(&redis.Options{
		Addr:     viper.GetString("server"),
		Password: viper.GetString("password"),
		DB:       viper.GetInt("db"),
	})

	// for {
	// 	time.Sleep(30 * time.Second)
	// 	allps := localprocess.ProcessMap()
	// 	// Push all processes in one go
	// 	localprocess.PushProcessDB(allps, redisdb)
	// }
	localprocess.Read(redisdb)
}
