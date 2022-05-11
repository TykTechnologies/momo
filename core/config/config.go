// package config provides the basic configuration for momo
package config

import (
	"github.com/kelseyhightower/envconfig"
	"github.com/spf13/viper"

	"github.com/TykTechnologies/momo/pkg/logger"
	"github.com/TykTechnologies/momo/pkg/types"
)

type StoreOpts struct {
	Provider string
	MetaData map[string]string
}

// MomoConf describes the settings required for a Momo instance
type MomoConf struct {
	StorageTag string
	StoreType  types.StorageDriver
	TykAPITag  string
	Drivers    map[string]interface{}
}

type Config struct {
	Momo MomoConf
}

var (
	sConf      *Config
	moduleName = "momo.config"
	envPrefix  = "MOMO_"
	log        = logger.GetAndExcludeLoggerFromTrace(moduleName)
)

// GetConf will get the config data for the Momo Driver
var GetConf = func() *Config {
	if sConf == nil {
		sConf = &Config{}

		err := viper.Unmarshal(sConf)
		if err != nil {
			log.Fatal("Failed to unmarshal momo driver config: ", err)
		}

		if err := envconfig.Process(envPrefix, sConf); err != nil {
			log.Fatalf("failed to process config env vars: %v", err)
		}

		SetDefaults()
	}

	return sConf
}

// GetConf will get the config data for the Momo Driver
var GetSubConf = func(in interface{}, envTag string) error {
	log.Debug("using config file: ", viper.ConfigFileUsed())

	err := viper.Unmarshal(in)
	if err != nil {
		return err
	}

	log.Debug(in)

	if err := envconfig.Process(envTag, in); err != nil {
		log.Fatalf("failed to process config env vars: %v", err)
	}

	return nil
}

func SetDefaults() error {
	return nil
}

func GetModuleConf(into interface{}, prefix string, defaultHandler interface{}) error {
	return GetSubConf(into, prefix)
}
