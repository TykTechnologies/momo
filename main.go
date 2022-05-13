package main

import (
	"fmt"

	"github.com/spf13/viper"

	"github.com/TykTechnologies/momo/pkg/logger"

	"github.com/TykTechnologies/momo/core/server"
)

var (
	moduleName = "momo"
	log        = logger.GetAndExcludeLoggerFromTrace(moduleName)
)

func main() {
	server.Start()
}

func init() {
	viper.SetConfigName("momo")
	viper.AddConfigPath("/etc/momo/")
	viper.AddConfigPath("$HOME/.momo")
	viper.AddConfigPath(".")

	err := viper.ReadInConfig()
	if err != nil {
		log.Fatal(fmt.Errorf("fatal error config file: %s \n", err))
	}
}
