package mongo

import (
	"github.com/TykTechnologies/momo/core/config"
	"github.com/TykTechnologies/momo/pkg/models"
)

type MgoStoreConf struct {
	ConnStr      string
	ControllerDb string
	Crypto       *models.SecureStore
	Opts         *config.StoreOpts
}

type Config struct {
	MongoStore map[string]*MgoStoreConf
}

var sconf *Config

// Variable so we can override
var GetConf = func() *Config {
	if sconf == nil {
		sconf = &Config{}

		err := config.GetModuleConf(sconf, "ARA_MONGO", nil)
		if err != nil {
			log.Fatal("Failed to unmarshal mongo driver config: ", err)
		}

		SetDefaults()
	}

	return sconf
}

func SetDefaults() {
	// Set Defaults?
}
